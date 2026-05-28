use crate::error::ArmorError;
use crate::manifest::drift::{DriftMode, HashBackend};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FailMode {
    /// On scanner verdict==block: log & pass through (warn-and-pass).
    Open,
    /// On scanner verdict==block: drop the call, return -32603 to client.
    Closed,
}

/// Default set of environment-variable keys that are stripped from the
/// upstream child process on `mcp-armor wrap`. v0.3 Feature A
/// (Zealynx forensic 2026 — registry-fetched MCP manifests can specify
/// `env:` for spawn, and these keys are *code-loaders* that allow
/// transparent RCE without touching the binary signature).
///
/// All seven defaults belong to one of three loader-class side channels:
/// - **Dynamic linker hijack:** `LD_PRELOAD`, `LD_LIBRARY_PATH`,
///   `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH` (macOS analogue).
/// - **Language runtime hijack:** `NODE_OPTIONS` (Node `--require`),
///   `PYTHONPATH` (Python `sys.path` prepend), `JAVA_TOOL_OPTIONS`
///   (JVM startup flags).
///
/// Operators may extend or override via `policy.deny_env_keys`. Keys are
/// matched case-insensitively on Unix (`LD_PRELOAD`/`ld_preload` both
/// caught) and case-insensitively on Windows (where env names are
/// case-insensitive at the OS level anyway).
pub const DEFAULT_DENY_ENV_KEYS: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "NODE_OPTIONS",
    "PYTHONPATH",
    "JAVA_TOOL_OPTIONS",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
// v0.6 introduces three additional bool toggles
// (`tools_list_drift_inbound_check`, `tools_list_jcs_canonicalize`,
// `inject_fingerprint_meta`) — clippy's `struct_excessive_bools` lint
// fires at 4+ bools. The natural alternative (a `flags: DriftFlags`
// sub-struct) makes the TOML-file authoring surface clumsier than the
// problem warrants (operators get `tools_list_jcs_canonicalize = true`
// at top level today; nested they'd write `[drift_flags] jcs = true`).
// Bools stay; the lint is silenced at struct scope.
#[allow(clippy::struct_excessive_bools)]
pub struct Policy {
    pub fail_mode: FailMode,
    pub scan_unicode: bool,
    /// Pattern ids to never block (override scanner verdict to allow).
    #[serde(default)]
    pub allow_patterns: Vec<String>,
    /// Server names whose tool calls bypass the scanner entirely.
    #[serde(default)]
    pub allow_servers: Vec<String>,
    /// v0.2 — per-tool pattern allowlist (REVIEW.md F3 Sub-b).
    ///
    /// Map `tool_name -> [pattern_ids]`. When a scanner match is on
    /// `tool_name` AND every matched pattern id is in this tool's list,
    /// the call passes despite the Block verdict. This is a strict
    /// subset of the global `allow_patterns` for the specific case
    /// "tool X is allowed to use shell-substitution syntax in its
    /// arguments because it is a code-interpreter".
    #[serde(default)]
    pub allow_patterns_per_tool: BTreeMap<String, Vec<String>>,
    /// v0.3 Feature A — environment-variable keys to STRIP from the
    /// child process env on `mcp-armor wrap`. Closes the Zealynx
    /// stdio-config side-channel where a registry-fetched MCP manifest
    /// can specify `env: { LD_PRELOAD: "/evil.so" }` and bypass the
    /// binary signature verify entirely (the env injection is upstream
    /// of `exec`).
    ///
    /// When omitted, [`DEFAULT_DENY_ENV_KEYS`] applies (7 loader-class
    /// keys covering glibc dynamic linker, macOS dyld, Node/Python/JVM
    /// runtime injection). Setting it to `[]` *disables* the guard;
    /// setting it to a custom list *replaces* the default (no merge).
    ///
    /// Scan is case-insensitive (`LD_PRELOAD`/`ld_preload` both caught).
    #[serde(default = "default_deny_env_keys")]
    pub deny_env_keys: Vec<String>,
    /// v0.3 Feature B — enable Stage 4 confusable / homoglyph
    /// detection in the scanner. When `true`, the scanner builds a
    /// Unicode UTS-39 skeleton from the payload and re-runs the
    /// pattern stages against the skeleton form. Catches
    /// Cherokee/Cyrillic/Greek homoglyph evasions (`іgnоre` with
    /// Cyrillic i/o vs. ASCII `ignore`). Default: `true`.
    #[serde(default = "default_scan_confusable")]
    pub scan_confusable: bool,
    /// v0.5 Layer 7 — Tools-list schema-drift detection mode.
    /// Closes the Rug-Pull / Silent Redefinition threat class
    /// (Invariant Labs, CyberArk Full-Schema Poisoning, OWASP MCP
    /// Tool Poisoning). Three modes:
    ///
    /// - `off`: Layer 7 bypassed entirely (no fingerprint, no log).
    /// - `warn`: default. Drift logs at `tracing::warn!`, tools/list
    ///   response passes through unchanged.
    /// - `block`: drift causes the proxy to replace the tools/list
    ///   response with a JSON-RPC error (code -32603, message
    ///   `tools/list drift detected by mcp-armor`). Operator clears
    ///   via `mcp-armor drift clear <program>` or
    ///   `mcp-armor drift trust <program>`.
    ///
    /// First-sight (no baseline yet) is *always* silently baselined
    /// regardless of mode — Layer 7 is fail-open on bootstrap.
    #[serde(default)]
    pub tools_list_drift_detection: DriftMode,
    /// v0.6 (carried-forward v0.5 backlog item — Inbound-side drift
    /// gate). When `true` AND `tools_list_drift_detection = "block"`
    /// AND a baseline already exists for this program, the proxy
    /// short-circuits any incoming `tools/list` request and replies
    /// with the inbound-block error directly — never spawning a
    /// round-trip to the upstream. Default: `false`. Use this in
    /// paranoid setups where the upstream is no longer trusted to even
    /// respond to a tools/list (e.g. when an in-flight drift
    /// investigation is open). The outbound gate is still active in
    /// the default setup; this flag is purely additive.
    #[serde(default)]
    pub tools_list_drift_inbound_check: bool,
    /// v0.6 — backend used to compute the per-tool description hash +
    /// the aggregate fingerprint. `blake3` is the default (3x faster
    /// with hardware acceleration). `sha256` is the FIPS-validated
    /// alternative for customers gated on FIPS 140-3 / PCI-DSS 3.5.1.2
    /// / HIPAA Security Rule §164.312(e)(2)(ii). Switching backends
    /// does NOT auto-rebaseline existing pins — each baseline records
    /// the backend it was pinned with and the compare path uses the
    /// baseline's own backend until the operator clears + re-pins.
    #[serde(default)]
    pub tools_list_hash_backend: HashBackend,
    /// v0.6 — when `true` and the crate was built with the
    /// `jcs-canonical` feature, each per-tool JSON sub-tree is
    /// canonicalised per RFC 8785 (JCS) before hashing. Without the
    /// feature, the flag is silently ignored (a one-shot
    /// `tracing::warn` surfaces the gap). Off by default — the v0.5
    /// heuristic is stable and the tools-history.toml schema records
    /// each baseline's canonicalisation flavour so a flip does not
    /// invalidate existing pins.
    #[serde(default)]
    pub tools_list_jcs_canonicalize: bool,
    /// v0.6 (SEP-2659 pattern) — when `true`, the proxy stamps each
    /// observed tools/list response with the per-program baseline's
    /// fingerprint under `_meta.dev.studiomeyer/armor.fingerprint`
    /// before forwarding it to the client. Lets downstream MCP
    /// clients (or other security sidecars sitting in line)
    /// correlate the manifest they see with the baseline mcp-armor
    /// pinned without round-tripping through the control plane. Off
    /// by default — additive feature.
    #[serde(default)]
    pub inject_fingerprint_meta: bool,
    pub version: String,
}

fn default_deny_env_keys() -> Vec<String> {
    DEFAULT_DENY_ENV_KEYS
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

fn default_scan_confusable() -> bool {
    true
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            fail_mode: FailMode::Closed,
            scan_unicode: true,
            allow_patterns: Vec::new(),
            allow_servers: Vec::new(),
            allow_patterns_per_tool: BTreeMap::new(),
            deny_env_keys: default_deny_env_keys(),
            scan_confusable: true,
            tools_list_drift_detection: DriftMode::default(),
            tools_list_drift_inbound_check: false,
            tools_list_hash_backend: HashBackend::default(),
            tools_list_jcs_canonicalize: false,
            inject_fingerprint_meta: false,
            version: "default".to_string(),
        }
    }
}

impl Policy {
    /// v0.3 Feature A — case-insensitive membership test against
    /// `deny_env_keys`. Returns `true` when `env_key` should be stripped
    /// from the child process env (or, on the operator side, warned about
    /// when present in the current process env at wrap startup).
    pub fn env_key_is_denied(&self, env_key: &str) -> bool {
        self.deny_env_keys
            .iter()
            .any(|k| k.eq_ignore_ascii_case(env_key))
    }

    /// v0.3 Feature A — sorted, deduplicated subset of the CURRENT
    /// process environment keys that match `deny_env_keys`. Used by the
    /// operator-facing `Cmd::Wrap` startup-warn to surface exactly which
    /// loader-class env keys the operator's shell is leaking into the
    /// sidecar (the child-side strip happens regardless in `run_proxy`).
    ///
    /// R1-fix (Architect MED): exposed as a `Policy` method so the
    /// binary (`src/main.rs`, separate compilation unit) can read it
    /// through the public API without needing crate-internal helpers.
    /// Snapshots `std::env::vars_os()` once at call time.
    #[must_use]
    pub fn leaked_loader_keys(&self) -> Vec<String> {
        self.leaked_loader_keys_from(std::env::vars_os().filter_map(|(k, _)| k.into_string().ok()))
    }

    /// v0.3 R1-fix — dependency-injection variant of
    /// [`Policy::leaked_loader_keys`]. Takes the env-key list as an
    /// iterator so tests don't have to mutate the actual process
    /// environment (data-race trap under multi-threaded `cargo test`).
    #[must_use]
    pub fn leaked_loader_keys_from<I>(&self, env_keys: I) -> Vec<String>
    where
        I: IntoIterator<Item = String>,
    {
        if self.deny_env_keys.is_empty() {
            return Vec::new();
        }
        let mut out: Vec<String> = Vec::new();
        for env_key in env_keys {
            if self.env_key_is_denied(&env_key) && !out.contains(&env_key) {
                out.push(env_key);
            }
        }
        out.sort();
        out
    }
}

impl Policy {
    /// v0.6 — assemble the [`FingerprintOpts`] bundle the drift
    /// pipeline consumes. Wraps the two policy toggles
    /// (`tools_list_hash_backend` + `tools_list_jcs_canonicalize`)
    /// into the cheap-to-clone shape the proxy hot path expects.
    #[must_use]
    pub fn drift_fingerprint_opts(&self) -> crate::manifest::drift::FingerprintOpts {
        crate::manifest::drift::FingerprintOpts {
            backend: self.tools_list_hash_backend,
            jcs_canonicalize: self.tools_list_jcs_canonicalize,
        }
    }
}

impl Policy {
    /// v0.2 — check whether `tool_name` has a per-tool allowlist that covers
    /// every supplied `matched_pattern`. Returns `true` only when every
    /// pattern in `matched_patterns` is listed in
    /// `allow_patterns_per_tool[tool_name]`. Used in the proxy hot-path to
    /// gate the Block-verdict-but-allow-this-tool override.
    pub fn tool_allows_patterns(&self, tool_name: &str, matched_patterns: &[String]) -> bool {
        if matched_patterns.is_empty() {
            return false;
        }
        let Some(allowed) = self.allow_patterns_per_tool.get(tool_name) else {
            return false;
        };
        matched_patterns.iter().all(|p| allowed.contains(p))
    }
}

/// Resolve a policy from `path` if Some, else from
/// `$XDG_CONFIG_HOME/mcp-armor/policy.toml` (or `~/.config/...`), else default.
pub fn load_policy(path: Option<&Path>) -> Result<(Policy, PathBuf), ArmorError> {
    let resolved = match path {
        Some(p) => p.to_path_buf(),
        None => default_path(),
    };
    if !resolved.exists() {
        return Ok((Policy::default(), resolved));
    }

    // v0.2 — file mode advisory.
    //
    // PLAN.md predicted-impact audit (Tool: armor_get_policy) flagged the
    // multi-user file-disclosure risk. We do a *warn-only* check (no Linux-
    // only build break) when the file is more permissive than 0o600. The
    // operator decides whether to act — refusing to load on every machine
    // that ships a 0o644 policy file would be hostile to existing setups.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&resolved) {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                tracing::warn!(
                    path = %resolved.display(),
                    mode = format!("0o{mode:o}"),
                    "policy file is world or group readable; consider `chmod 0600 {}`",
                    resolved.display()
                );
            }
        }
    }

    let raw = std::fs::read_to_string(&resolved)?;
    let p: Policy = toml::from_str(&raw)?;
    Ok((p, resolved))
}

pub fn default_path() -> PathBuf {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        return PathBuf::from(xdg).join("mcp-armor").join("policy.toml");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home)
            .join(".config")
            .join("mcp-armor")
            .join("policy.toml");
    }
    PathBuf::from("policy.toml")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn missing_file_returns_default() {
        let dir = tempdir().expect("tmp");
        let p = dir.path().join("nope.toml");
        let (pol, _) = load_policy(Some(&p)).expect("ok");
        assert_eq!(pol.fail_mode, FailMode::Closed);
        assert!(pol.scan_unicode);
        assert_eq!(pol.version, "default");
        assert!(pol.allow_patterns_per_tool.is_empty());
    }

    #[test]
    fn parses_valid_toml() {
        let dir = tempdir().expect("tmp");
        let p = dir.path().join("policy.toml");
        std::fs::write(
            &p,
            r#"
fail_mode = "open"
scan_unicode = false
allow_patterns = ["javascript_uri"]
allow_servers = ["my-trusted-server"]
version = "test-1"
"#,
        )
        .expect("write");
        let (pol, _) = load_policy(Some(&p)).expect("ok");
        assert_eq!(pol.fail_mode, FailMode::Open);
        assert!(!pol.scan_unicode);
        assert_eq!(pol.allow_patterns, vec!["javascript_uri".to_string()]);
        assert_eq!(pol.version, "test-1");
    }

    #[test]
    fn invalid_toml_fails_gracefully() {
        let dir = tempdir().expect("tmp");
        let p = dir.path().join("bad.toml");
        std::fs::write(&p, "this is = not = toml ===").expect("write");
        let r = load_policy(Some(&p));
        assert!(matches!(r, Err(ArmorError::Toml(_))));
    }

    /// v0.2 — per-tool allowlist parses from TOML and gates the Block.
    #[test]
    fn parses_per_tool_allowlist() {
        let dir = tempdir().expect("tmp");
        let p = dir.path().join("policy.toml");
        std::fs::write(
            &p,
            r#"
fail_mode = "closed"
scan_unicode = true
version = "per-tool-1"

[allow_patterns_per_tool]
"code-interpreter" = ["shell_substitution"]
"web-fetch" = ["javascript_uri", "localhost_callback"]
"#,
        )
        .expect("write");
        let (pol, _) = load_policy(Some(&p)).expect("ok");
        assert_eq!(pol.allow_patterns_per_tool.len(), 2);
        assert!(pol.tool_allows_patterns("code-interpreter", &["shell_substitution".to_string()]));
        assert!(!pol.tool_allows_patterns("code-interpreter", &["javascript_uri".to_string()]));
    }

    #[test]
    fn tool_allows_patterns_empty_matched_returns_false() {
        let p = Policy::default();
        assert!(!p.tool_allows_patterns("x", &[]));
    }

    #[test]
    fn tool_allows_patterns_unknown_tool_returns_false() {
        let mut p = Policy::default();
        p.allow_patterns_per_tool
            .insert("known".to_string(), vec!["shell_substitution".to_string()]);
        assert!(!p.tool_allows_patterns("unknown", &["shell_substitution".to_string()]));
    }

    /// v0.2 — only Block when *every* matched pattern is allowed for the tool.
    #[test]
    fn tool_allows_patterns_all_or_nothing() {
        let mut p = Policy::default();
        p.allow_patterns_per_tool
            .insert("x".to_string(), vec!["shell_substitution".to_string()]);
        // single matched pattern in allowlist → allow
        assert!(p.tool_allows_patterns("x", &["shell_substitution".to_string()]));
        // matched pattern NOT in allowlist → refuse to gate
        assert!(!p.tool_allows_patterns("x", &["javascript_uri".to_string()]));
        // mixed (one allowed, one not) → refuse to gate (strict subset)
        assert!(!p.tool_allows_patterns(
            "x",
            &[
                "shell_substitution".to_string(),
                "javascript_uri".to_string()
            ]
        ));
    }

    /// v0.3 Feature A — default policy denies the 7 loader-class env keys.
    #[test]
    fn default_policy_denies_loader_env_keys() {
        let p = Policy::default();
        for k in [
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH",
            "NODE_OPTIONS",
            "PYTHONPATH",
            "JAVA_TOOL_OPTIONS",
        ] {
            assert!(p.env_key_is_denied(k), "default policy must deny {k}");
        }
    }

    /// v0.3 Feature A — case-insensitive match for env keys.
    #[test]
    fn env_key_deny_is_case_insensitive() {
        let p = Policy::default();
        assert!(p.env_key_is_denied("ld_preload"));
        assert!(p.env_key_is_denied("Ld_PreLoad"));
        assert!(p.env_key_is_denied("LD_PRELOAD"));
        assert!(!p.env_key_is_denied("PATH"));
        assert!(!p.env_key_is_denied("HOME"));
    }

    /// v0.3 Feature A — empty deny_env_keys disables the guard.
    #[test]
    fn empty_deny_env_keys_disables_guard() {
        let dir = tempdir().expect("tmp");
        let p = dir.path().join("policy.toml");
        std::fs::write(
            &p,
            r#"
fail_mode = "closed"
scan_unicode = true
deny_env_keys = []
version = "no-env-guard"
"#,
        )
        .expect("write");
        let (pol, _) = load_policy(Some(&p)).expect("ok");
        assert!(!pol.env_key_is_denied("LD_PRELOAD"));
        assert!(pol.deny_env_keys.is_empty());
    }

    /// v0.3 Feature A — custom deny_env_keys REPLACES the default.
    #[test]
    fn custom_deny_env_keys_replaces_default() {
        let dir = tempdir().expect("tmp");
        let p = dir.path().join("policy.toml");
        std::fs::write(
            &p,
            r#"
fail_mode = "closed"
scan_unicode = true
deny_env_keys = ["MY_CUSTOM_LOADER"]
version = "custom-env-guard"
"#,
        )
        .expect("write");
        let (pol, _) = load_policy(Some(&p)).expect("ok");
        assert!(pol.env_key_is_denied("MY_CUSTOM_LOADER"));
        assert!(
            !pol.env_key_is_denied("LD_PRELOAD"),
            "custom list must REPLACE default, not merge"
        );
        assert_eq!(pol.deny_env_keys, vec!["MY_CUSTOM_LOADER".to_string()]);
    }

    /// v0.3 Feature B — scan_confusable defaults to true (opt-out, not opt-in).
    #[test]
    fn scan_confusable_defaults_to_true() {
        let p = Policy::default();
        assert!(p.scan_confusable);
    }

    /// v0.3 Feature B — policy file can disable Stage 4.
    #[test]
    fn scan_confusable_can_be_disabled_via_toml() {
        let dir = tempdir().expect("tmp");
        let p = dir.path().join("policy.toml");
        std::fs::write(
            &p,
            r#"
fail_mode = "closed"
scan_unicode = true
scan_confusable = false
version = "no-confusable"
"#,
        )
        .expect("write");
        let (pol, _) = load_policy(Some(&p)).expect("ok");
        assert!(!pol.scan_confusable);
    }

    // ─── v0.6 tests (S1233 follow-up) ───────────────────────────────────

    /// v0.6 — `tools_list_drift_inbound_check` defaults to `false`.
    #[test]
    fn drift_inbound_check_defaults_to_false() {
        let p = Policy::default();
        assert!(!p.tools_list_drift_inbound_check);
    }

    /// v0.6 — `tools_list_hash_backend` defaults to BLAKE3.
    #[test]
    fn hash_backend_defaults_to_blake3() {
        let p = Policy::default();
        assert_eq!(
            p.tools_list_hash_backend,
            crate::manifest::drift::HashBackend::Blake3
        );
    }

    /// v0.6 — `tools_list_jcs_canonicalize` defaults to `false`.
    #[test]
    fn jcs_canonicalize_defaults_to_false() {
        let p = Policy::default();
        assert!(!p.tools_list_jcs_canonicalize);
    }

    /// v0.6 — `inject_fingerprint_meta` defaults to `false`.
    #[test]
    fn inject_fingerprint_meta_defaults_to_false() {
        let p = Policy::default();
        assert!(!p.inject_fingerprint_meta);
    }

    /// v0.6 — `drift_fingerprint_opts()` reflects the policy fields.
    #[test]
    fn drift_fingerprint_opts_reflects_policy_fields() {
        let p = Policy {
            tools_list_hash_backend: crate::manifest::drift::HashBackend::Sha256,
            tools_list_jcs_canonicalize: true,
            ..Policy::default()
        };
        let opts = p.drift_fingerprint_opts();
        assert_eq!(opts.backend, crate::manifest::drift::HashBackend::Sha256);
        assert!(opts.jcs_canonicalize);
    }

    /// v0.6 — TOML parses `tools_list_hash_backend = "sha256"`.
    #[test]
    fn parses_v06_hash_backend_from_toml() {
        let dir = tempdir().expect("tmp");
        let p = dir.path().join("policy.toml");
        std::fs::write(
            &p,
            r#"
fail_mode = "closed"
scan_unicode = true
tools_list_hash_backend = "sha256"
version = "v06-sha256"
"#,
        )
        .expect("write");
        let (pol, _) = load_policy(Some(&p)).expect("ok");
        assert_eq!(
            pol.tools_list_hash_backend,
            crate::manifest::drift::HashBackend::Sha256
        );
    }

    /// v0.6 — TOML parses `tools_list_jcs_canonicalize = true`.
    #[test]
    fn parses_v06_jcs_toggle_from_toml() {
        let dir = tempdir().expect("tmp");
        let p = dir.path().join("policy.toml");
        std::fs::write(
            &p,
            r#"
fail_mode = "closed"
scan_unicode = true
tools_list_jcs_canonicalize = true
version = "v06-jcs"
"#,
        )
        .expect("write");
        let (pol, _) = load_policy(Some(&p)).expect("ok");
        assert!(pol.tools_list_jcs_canonicalize);
    }

    /// v0.6 — TOML parses `inject_fingerprint_meta = true`.
    #[test]
    fn parses_v06_inject_fingerprint_meta_from_toml() {
        let dir = tempdir().expect("tmp");
        let p = dir.path().join("policy.toml");
        std::fs::write(
            &p,
            r#"
fail_mode = "closed"
scan_unicode = true
inject_fingerprint_meta = true
version = "v06-meta"
"#,
        )
        .expect("write");
        let (pol, _) = load_policy(Some(&p)).expect("ok");
        assert!(pol.inject_fingerprint_meta);
    }

    /// v0.6 — TOML parses `tools_list_drift_inbound_check = true`.
    #[test]
    fn parses_v06_inbound_check_from_toml() {
        let dir = tempdir().expect("tmp");
        let p = dir.path().join("policy.toml");
        std::fs::write(
            &p,
            r#"
fail_mode = "closed"
scan_unicode = true
tools_list_drift_inbound_check = true
version = "v06-inbound"
"#,
        )
        .expect("write");
        let (pol, _) = load_policy(Some(&p)).expect("ok");
        assert!(pol.tools_list_drift_inbound_check);
    }

    /// v0.6 — a v0.5 policy file (missing all four v0.6 fields)
    /// loads cleanly with safe defaults.
    #[test]
    fn v05_policy_file_loads_with_v06_safe_defaults() {
        let dir = tempdir().expect("tmp");
        let p = dir.path().join("policy.toml");
        std::fs::write(
            &p,
            r#"
fail_mode = "closed"
scan_unicode = true
scan_confusable = true
tools_list_drift_detection = "warn"
version = "v05-as-loaded-by-v06"
"#,
        )
        .expect("write");
        let (pol, _) = load_policy(Some(&p)).expect("ok");
        assert!(!pol.tools_list_drift_inbound_check);
        assert_eq!(
            pol.tools_list_hash_backend,
            crate::manifest::drift::HashBackend::Blake3
        );
        assert!(!pol.tools_list_jcs_canonicalize);
        assert!(!pol.inject_fingerprint_meta);
    }

    /// v0.6 — `tools_list_hash_backend` rejects unknown values (it's
    /// an enum, not a free-form string).
    #[test]
    fn unknown_hash_backend_value_fails_to_parse() {
        let dir = tempdir().expect("tmp");
        let p = dir.path().join("policy.toml");
        std::fs::write(
            &p,
            r#"
fail_mode = "closed"
scan_unicode = true
tools_list_hash_backend = "md5"
version = "bogus"
"#,
        )
        .expect("write");
        let r = load_policy(Some(&p));
        assert!(matches!(r, Err(ArmorError::Toml(_))));
    }

    /// v0.2 — file mode advisory: load_policy must NOT refuse a 0o644 file,
    /// only emit a warn. Refusing would break setups that already ship
    /// world-readable policy files.
    #[cfg(unix)]
    #[test]
    fn permissive_mode_does_not_block_load() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().expect("tmp");
        let p = dir.path().join("policy.toml");
        std::fs::write(
            &p,
            r#"
fail_mode = "closed"
scan_unicode = true
version = "perm-test"
"#,
        )
        .expect("write");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let r = load_policy(Some(&p));
        assert!(r.is_ok(), "0o644 must load (warn-only)");
    }
}
