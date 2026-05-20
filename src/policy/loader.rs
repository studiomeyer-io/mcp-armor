use crate::error::ArmorError;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub version: String,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            fail_mode: FailMode::Closed,
            scan_unicode: true,
            allow_patterns: Vec::new(),
            allow_servers: Vec::new(),
            allow_patterns_per_tool: BTreeMap::new(),
            version: "default".to_string(),
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
