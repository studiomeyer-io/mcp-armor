//! Control-plane MCP server. Read-only inspection surface — 10 tools
//! (v0.5 final) that let a client app inspect policy + scan history +
//! TOFU keystore + Sigstore bundles + tools/list drift baselines
//! without touching the host file system.
//!
//! Implementation note: this is a hand-rolled line-delimited JSON-RPC 2.0
//! stdio server. v0.7 bumps `protocolVersion` from `2025-06-18` to
//! `2025-11-25` (the spec line that ratifies SEP-1319 task lifecycle,
//! structured-output `_meta` namespace, and tightens the `protocolVersion`
//! negotiation rules MCP clients use to detect server capability sets).
//! We continue to ship the hand-rolled JSON-RPC server as the DEFAULT
//! control plane because it is bench-verified (<5ms p99), audit-minimal
//! (one source file, zero extra deps), and identical in semantics to the
//! rmcp 1.5 control plane that v0.7 also wires up behind
//! `--features rmcp-control` (see `crate::rmcp_server`).

pub mod history;
pub mod tools;

use crate::cve::FEED;
use crate::error::ArmorError;
use crate::manifest::drift::{default_path as drift_default_path, History as DriftHistory};
use crate::manifest::sigstore::Bundle;
#[cfg(feature = "sigstore-bridge")]
use crate::manifest::sigstore::RekorLookup;
use crate::manifest::tofu::{default_path as keystore_default_path, Keystore, PinnedKey};
use crate::manifest::{verify, VerifyOutcome};
use crate::policy::{snapshot, Policy, PolicyHandle};
use crate::scanner::Scanner;
use history::ScanHistory;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// MCP spec version reported to clients on `initialize`. v0.7 bumps
/// from the v0.6 line (`2025-06-18`) to the current spec line. Clients
/// that don't recognise `2025-11-25` still see a well-formed `initialize`
/// response with a `protocolVersion` string and will fall back to feature
/// detection on `tools/list` shape — same as every prior bump.
///
/// `pub(crate)` v0.7 R2 Critic Finding 3 — the rmcp control-plane test
/// `handler_protocol_version_matches_hand_rolled_plane` compares the
/// rmcp `ProtocolVersion::default()` serialised string against this
/// constant to enforce cross-plane parity. The constant is only visible
/// inside the crate; no public API surface change.
pub(crate) const MCP_PROTOCOL_VERSION: &str = "2025-11-25";
const SERVER_NAME: &str = "mcp-armor-control";

/// Run the control-plane stdio server. Reads JSON-RPC from stdin, writes
/// responses to stdout, line-delimited.
///
/// v0.2 — takes a [`PolicyHandle`] so SIGHUP-driven reloads are visible to
/// `armor_get_policy` without restarting the process. Each request takes a
/// fresh snapshot of the policy (cheap clone of a small struct).
pub async fn run_control_plane(
    scanner: Arc<Scanner>,
    policy: PolicyHandle,
    history: Arc<ScanHistory>,
) -> Result<(), ArmorError> {
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin).lines();
    let mut stdout = tokio::io::stdout();

    while let Some(line) = reader.next_line().await? {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => {
                let resp = error_response(Value::Null, -32700, "parse error");
                write_line(&mut stdout, &resp).await?;
                continue;
            }
        };
        let snap = snapshot(&policy);
        let resp = handle_request(&req, &scanner, &snap, &history);
        if !resp.is_null() {
            write_line(&mut stdout, &resp).await?;
        }
    }
    Ok(())
}

async fn write_line(stdout: &mut tokio::io::Stdout, value: &Value) -> Result<(), ArmorError> {
    let mut s = serde_json::to_string(value)?;
    s.push('\n');
    stdout.write_all(s.as_bytes()).await?;
    stdout.flush().await?;
    Ok(())
}

fn error_response(id: Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message }
    })
}

fn ok_response(id: Value, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    })
}

/// Top-level dispatcher. Public for unit testability — handle a single
/// request and return the response value (or `Value::Null` for notifications).
pub fn handle_request(
    req: &Value,
    scanner: &Scanner,
    policy: &Policy,
    history: &ScanHistory,
) -> Value {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let is_notification = req.get("id").is_none();
    let method = match req.get("method").and_then(Value::as_str) {
        Some(m) => m,
        None => return error_response(id, -32600, "invalid request"),
    };
    let params = req.get("params").cloned().unwrap_or(Value::Null);

    match method {
        "initialize" => ok_response(id, initialize_result()),
        "ping" => ok_response(id, json!({})),
        "tools/list" => ok_response(id, tools::list()),
        "tools/call" => {
            let name = params
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            match dispatch_tool(&name, &args, scanner, policy, history) {
                Ok(value) => ok_response(
                    id,
                    json!({
                        "content": [{
                            "type": "text",
                            "text": value.to_string()
                        }],
                        "structuredContent": value,
                        "isError": false
                    }),
                ),
                Err(e) => ok_response(
                    id,
                    json!({
                        "content": [{
                            "type": "text",
                            "text": format!("error: {e}")
                        }],
                        "isError": true
                    }),
                ),
            }
        }
        "notifications/initialized" => Value::Null,
        _ if is_notification => Value::Null,
        _ => error_response(id, -32601, "method not found"),
    }
}

fn initialize_result() -> Value {
    json!({
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "capabilities": {
            "tools": { "listChanged": false }
        },
        "serverInfo": {
            "name": SERVER_NAME,
            "version": crate::VERSION
        }
    })
}

fn dispatch_tool(
    name: &str,
    args: &Value,
    scanner: &Scanner,
    policy: &Policy,
    history: &ScanHistory,
) -> Result<Value, ArmorError> {
    match name {
        "armor_scan_payload" => tool_scan_payload(args, scanner, policy, history),
        "armor_verify_manifest" => tool_verify_manifest(args),
        "armor_list_blocked" => Ok(tool_list_blocked(args, history)),
        "armor_get_policy" => Ok(tool_get_policy(policy)),
        "armor_check_cve" => tool_check_cve(args),
        "armor_simulate_attack" => tool_simulate_attack(args, scanner),
        // v0.2 — three new read-only inspection tools.
        "armor_get_keystore" => tool_get_keystore(args),
        "armor_verify_bundle" => tool_verify_bundle(args),
        "armor_rekor_lookup" => tool_rekor_lookup(args),
        "armor_get_drift_history" => tool_get_drift_history(args),
        _ => Err(ArmorError::UnknownTool(name.to_string())),
    }
}

// ── individual tools ─────────────────────────────────────────────────────────

fn tool_scan_payload(
    args: &Value,
    scanner: &Scanner,
    policy: &Policy,
    history: &ScanHistory,
) -> Result<Value, ArmorError> {
    let payload = args
        .get("payload")
        .and_then(Value::as_str)
        .ok_or_else(|| ArmorError::InvalidPattern("missing payload".into()))?;
    let direction = args
        .get("direction")
        .and_then(Value::as_str)
        .unwrap_or("inbound");
    if direction != "inbound" && direction != "outbound" {
        return Err(ArmorError::InvalidPattern(format!(
            "direction must be inbound|outbound, got {direction}"
        )));
    }
    // Honour the policy toggles here too — the control-plane scan_payload
    // tool is meant to mirror what the proxy hot-path does. v0.3 R1-CRIT
    // fix: previously called the v0.2 `scan_with(payload, scan_unicode)`
    // which hard-codes `scan_confusable=true`, leaving `policy.scan_confusable`
    // as a dead toggle. Now uses `scan_with_opts` to wire both gates.
    let result = scanner.scan_with_opts(payload, policy.scan_unicode, policy.scan_confusable);
    // P2 fix (S983): only record actual blocks to the audit ring buffer —
    // the buffer is named "blocked tool calls" in `armor_list_blocked`.
    // Recording every Allow scan would inflate the ring + flood the tool
    // output with non-actionable entries.
    if matches!(result.verdict, crate::scanner::ScanVerdict::Block) {
        history.record(direction, &result);
    }
    Ok(json!({
        "verdict": result.verdict,
        "matched_patterns": result.matched_patterns,
        "cve_refs": result.cve_refs,
        "latency_us": result.latency_us
    }))
}

fn tool_verify_manifest(args: &Value) -> Result<Value, ArmorError> {
    let tools_list = args
        .get("tools_list_response")
        .ok_or_else(|| ArmorError::InvalidPattern("missing tools_list_response".into()))?;
    let pk = args
        .get("public_key_b64")
        .and_then(Value::as_str)
        .ok_or_else(|| ArmorError::InvalidPattern("missing public_key_b64".into()))?;
    let sig = args
        .get("signature_b64")
        .and_then(Value::as_str)
        .ok_or_else(|| ArmorError::InvalidPattern("missing signature_b64".into()))?;
    let signed_at = args.get("signed_at_iso").and_then(Value::as_str);
    let outcome: VerifyOutcome = verify(tools_list, pk, sig, signed_at)?;
    Ok(serde_json::to_value(outcome)?)
}

fn tool_list_blocked(args: &Value, history: &ScanHistory) -> Value {
    let since = args.get("since_iso").and_then(Value::as_str);
    let limit = args
        .get("limit")
        .and_then(Value::as_u64)
        .map(|n| n as usize);
    let entries = history.snapshot(since, limit);
    json!({
        "blocked_calls": entries,
        "total": history.total_blocked()
    })
}

fn tool_get_policy(policy: &Policy) -> Value {
    // v0.4 (Round-3 review MEDIUM fix): `{:?}` emits the PathBuf with
    // Debug-quoting, e.g. `"/home/user/.config/...toml"`. Other tools
    // (`tool_get_keystore`) consistently use `.display()` which renders
    // the path verbatim. Aligning here removes the cosmetic drift and
    // avoids surprising JSON consumers.
    //
    // v0.5 R1 Analyst-W5 fix: surface every policy field that actually
    // gates proxy behaviour — `scan_confusable` (Stage 4 on/off),
    // `deny_env_keys` (Feature A loader-class strip), and
    // `tools_list_drift_detection` (Layer 7 mode). Without these, an
    // operator using `armor_get_policy` to verify their setup would
    // see only half the configuration.
    // v0.6 surfaces every drift-related toggle that the proxy hot
    // path consults so an operator inspecting the live config sees
    // the full v0.6 surface area in one call:
    // - tools_list_drift_inbound_check (item 5 of the v0.6 backlog)
    // - tools_list_hash_backend (BLAKE3 vs SHA-256 for FIPS)
    // - tools_list_jcs_canonicalize (RFC 8785)
    // - inject_fingerprint_meta (SEP-2659)
    json!({
        "policy_path": crate::policy::loader::default_path().display().to_string(),
        "rules": {
            "allow_patterns": policy.allow_patterns,
            "allow_servers": policy.allow_servers,
            "allow_patterns_per_tool": policy.allow_patterns_per_tool
        },
        "fail_mode": policy.fail_mode,
        "scan_unicode": policy.scan_unicode,
        "scan_confusable": policy.scan_confusable,
        "deny_env_keys": policy.deny_env_keys,
        "tools_list_drift_detection": policy.tools_list_drift_detection,
        "tools_list_drift_inbound_check": policy.tools_list_drift_inbound_check,
        "tools_list_hash_backend": policy.tools_list_hash_backend,
        "tools_list_jcs_canonicalize": policy.tools_list_jcs_canonicalize,
        "inject_fingerprint_meta": policy.inject_fingerprint_meta,
        "version": policy.version
    })
}

fn tool_check_cve(args: &Value) -> Result<Value, ArmorError> {
    let server_name = args
        .get("server_name")
        .and_then(Value::as_str)
        .ok_or_else(|| ArmorError::InvalidPattern("missing server_name".into()))?;
    let server_version = args.get("server_version").and_then(Value::as_str);
    let feed = FEED()?;
    // F6 fix (S983): two-stage match.
    //   1) Server-name substring match on `fixed_in` (legacy filter — keeps
    //      defense-in-depth entries that have `fixed_in = "n/a"` reachable
    //      via name match alone).
    //   2) When the caller supplies `server_version` AND the entry has
    //      `affected_versions` set, use `semver::VersionReq` to drop entries
    //      whose range does NOT cover the supplied version. Entries without
    //      a structured range stay in (best-effort) — operator can read
    //      `fixed_in` themselves.
    let mut affected = Vec::new();
    let needle = server_name.to_ascii_lowercase();
    let parsed_version: Option<semver::Version> =
        server_version.and_then(|v| semver::Version::parse(v.trim_start_matches('v')).ok());
    let mut version_match_used = false;
    for cve in &feed.cves {
        let fixed = cve.fixed_in.to_ascii_lowercase();
        if !fixed.contains(&needle) {
            continue;
        }
        // Version-aware filter — only when both sides supply structured data.
        if let (Some(parsed_v), Some(range_str)) =
            (parsed_version.as_ref(), cve.affected_versions.as_ref())
        {
            match semver::VersionReq::parse(range_str) {
                Ok(req) => {
                    version_match_used = true;
                    if !req.matches(parsed_v) {
                        continue;
                    }
                }
                Err(_) => {
                    // Malformed range in feed — fall back to inclusion.
                    // Better to over-report than silently drop a CVE.
                }
            }
        }
        affected.push(json!({
            "id": cve.id,
            "severity": cve.severity.as_str(),
            "title": cve.title,
            "fixed_in": cve.fixed_in,
            "affected_versions": cve.affected_versions
        }));
    }
    // v0.5 R2 Analyst-W2 fix: the feed is no longer OX-only. The
    // 2026-05-28 refresh wave merged in Lyrie MCP-1.4 batch + rmcp
    // DNS-rebinding + n8n-mcp credential leak + Excel-MCP path
    // traversal entries. Surface the full provenance list so tool
    // consumers know which advisories the answer is grounded in.
    Ok(json!({
        "affected_cves": affected,
        "server_version_queried": server_version,
        "version_match_used": version_match_used,
        "advisories_consulted": [
            "ox-advisory-2026-04-15",
            "lyrie-mcp-1.4-batch-2026-04",
            "nvd-rmcp-cve-2026-42559",
            "nvd-n8n-mcp-cve-2026-42282",
            "nvd-excel-mcp-cve-2026-40576",
            "ultraviolet-cyber-mcp-advisory-2026-05-27"
        ],
        "feed_generated": feed.generated,
        "cve_database_age_days": cve_database_age_days(&feed.generated)
    }))
}

fn tool_simulate_attack(args: &Value, scanner: &Scanner) -> Result<Value, ArmorError> {
    let cve_id = args
        .get("cve_id")
        .and_then(Value::as_str)
        .ok_or_else(|| ArmorError::InvalidPattern("missing cve_id".into()))?;
    let feed = FEED()?;
    let cve = feed
        .find(cve_id)
        .ok_or_else(|| ArmorError::UnknownCve(cve_id.to_string()))?;
    // Scanner runs on the static simulate_payload — never spawns the upstream
    // binary. Asserts the falsifiable Pillar-3 contract.
    let result = scanner.scan(&cve.simulate_payload);
    Ok(json!({
        "payload": cve.simulate_payload,
        "expected_verdict": "block",
        "actual_verdict": result.verdict,
        "scanner_path": ["aho", "regex", "unicode"],
        "matched_patterns": result.matched_patterns,
        "latency_us": result.latency_us
    }))
}

// ──── v0.2 new tools ────────────────────────────────────────────────────────

fn tool_get_keystore(_args: &Value) -> Result<Value, ArmorError> {
    // v0.2 SECURITY FIX (Round 1 H1): never accept a caller-supplied
    // keystore_path. The control plane is documented as read-only inspection;
    // honouring an arbitrary path turns this into a generic file-read oracle
    // (any TOML-parseable file on the host filesystem). Operators who want a
    // different keystore configure it at startup via the `--keystore` CLI
    // flag / `MCP_ARMOR_KEYSTORE` env var, which is read once by main.rs and
    // is not reachable from MCP clients.
    let path = keystore_default_path();
    let ks = Keystore::load(&path)?;
    let entries: Vec<Value> = ks
        .entries
        .iter()
        .map(|e: &PinnedKey| {
            json!({
                "server_name": e.server_name,
                "key_fingerprint": e.key_fingerprint,
                "pinned_at_iso": e.pinned_at_iso,
            })
        })
        .collect();
    Ok(json!({
        "keystore_path": path.display().to_string(),
        "schema_version": ks.schema_version,
        "pinned_entries": entries,
        "count": ks.len(),
    }))
}

fn tool_verify_bundle(args: &Value) -> Result<Value, ArmorError> {
    let raw = args
        .get("bundle_json")
        .and_then(Value::as_str)
        .ok_or_else(|| ArmorError::InvalidPattern("missing bundle_json".into()))?;
    let bundle = Bundle::parse(raw)?;
    let inclusion = crate::manifest::sigstore::verify_inclusion(&bundle)?;
    // v0.4 (Round-3 review HIGH fix): surface the inclusion `warning` field
    // and rename `structural_set_ok` → `shape_only_ok`. Consumers reading
    // the JSON should never mistake the shape check for a cryptographic
    // verify; the warning string is identical to
    // `manifest::sigstore::WARNING_SHAPE_ONLY` so it round-trips intact.
    Ok(json!({
        "bundle_parsed": true,
        "has_cert": bundle.cert_pem.is_some(),
        "has_rekor_bundle": bundle.rekor_bundle.is_some(),
        "shape_only_ok": inclusion.shape_only_ok,
        "partial": inclusion.partial,
        "note": inclusion.note,
        "warning": inclusion.warning,
        "log_index": inclusion.log_index,
        "integrated_time": inclusion.integrated_time,
    }))
}

// ──── v0.5 Layer 7 — drift history inspection ────────────────────────────

fn tool_get_drift_history(args: &Value) -> Result<Value, ArmorError> {
    // Match the keystore tool's stance: never honour a caller-supplied
    // path. The control plane is documented as read-only inspection;
    // honouring an arbitrary path would turn this into a generic
    // TOML-file oracle. Operators configure a non-default path at
    // startup via `--drift-history` / `MCP_ARMOR_DRIFT_HISTORY`.
    let path = drift_default_path();
    let history = DriftHistory::load(&path)?;
    let program_filter = args.get("program").and_then(Value::as_str);

    if let Some(program) = program_filter {
        return match history.find(program) {
            Some(entry) => Ok(json!({
                "history_path": path.display().to_string(),
                "schema_version": history.schema_version,
                "program": entry.program,
                "baseline_iso": entry.baseline_iso,
                "last_seen_iso": entry.last_seen_iso,
                "tools_count": entry.tools_count,
                "aggregate_hash": entry.aggregate_hash,
                "tools": entry.tools,
            })),
            None => Ok(json!({
                "history_path": path.display().to_string(),
                "schema_version": history.schema_version,
                "program": program,
                "baseline_present": false,
            })),
        };
    }

    let summary: Vec<Value> = history
        .programs
        .iter()
        .map(|p| {
            json!({
                "program": p.program,
                "tools_count": p.tools_count,
                "aggregate_hash": p.aggregate_hash,
                "baseline_iso": p.baseline_iso,
                "last_seen_iso": p.last_seen_iso,
            })
        })
        .collect();
    Ok(json!({
        "history_path": path.display().to_string(),
        "schema_version": history.schema_version,
        "count": history.len(),
        "programs": summary,
    }))
}

#[cfg(feature = "sigstore-bridge")]
fn tool_rekor_lookup(args: &Value) -> Result<Value, ArmorError> {
    let manifest = args
        .get("tools_list_response")
        .ok_or_else(|| ArmorError::InvalidPattern("missing tools_list_response".into()))?;
    let rekor_url = args.get("rekor_url").and_then(Value::as_str);
    let lookup: RekorLookup = crate::manifest::sigstore::lookup_rekor_by_hash(manifest, rekor_url)?;
    Ok(serde_json::to_value(lookup)?)
}

/// When the `sigstore-bridge` feature is off, the schema is still listed
/// in `tools/list` (so MCP clients see the surface) but the call returns a
/// clear "rebuild with --features sigstore-bridge" error.
#[cfg(not(feature = "sigstore-bridge"))]
fn tool_rekor_lookup(_args: &Value) -> Result<Value, ArmorError> {
    Err(ArmorError::InvalidPattern(
        "armor_rekor_lookup requires the `sigstore-bridge` Cargo feature. \
         Rebuild with `cargo install mcp-armor --features sigstore-bridge` \
         or run `mcp-armor sigstore rekor-lookup` from a build that has it."
            .to_string(),
    ))
}

fn cve_database_age_days(generated: &str) -> i64 {
    // Best-effort YYYY-MM-DD diff vs today — string-only, no chrono dep.
    use std::time::{SystemTime, UNIX_EPOCH};
    let parts: Vec<&str> = generated.split('-').collect();
    if parts.len() != 3 {
        return -1;
    }
    let (y, m, d) = match (
        parts[0].parse::<i64>(),
        parts[1].parse::<i64>(),
        parts[2].parse::<i64>(),
    ) {
        (Ok(y), Ok(m), Ok(d)) => (y, m, d),
        _ => return -1,
    };
    let secs = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(_) => return -1,
    };
    let today_days = secs / 86_400;
    // Civil-from-days simplified — only need a rough day-count.
    let approx_feed_days = (y - 1970) * 365 + (y - 1969) / 4 + month_days(m) + d - 1;
    today_days - approx_feed_days
}

fn month_days(month: i64) -> i64 {
    match month {
        1 => 0,
        2 => 31,
        3 => 59,
        4 => 90,
        5 => 120,
        6 => 151,
        7 => 181,
        8 => 212,
        9 => 243,
        10 => 273,
        11 => 304,
        12 => 334,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::Scanner;

    fn make_ctx() -> (Scanner, Policy, ScanHistory) {
        (
            Scanner::new().expect("scanner"),
            Policy::default(),
            ScanHistory::new(100),
        )
    }

    #[test]
    fn initialize_returns_protocol_version() {
        let (s, p, h) = make_ctx();
        let req = json!({"jsonrpc":"2.0","id":1,"method":"initialize"});
        let resp = handle_request(&req, &s, &p, &h);
        assert_eq!(resp["result"]["protocolVersion"], MCP_PROTOCOL_VERSION);
        assert_eq!(resp["result"]["serverInfo"]["name"], SERVER_NAME);
    }

    #[test]
    fn tools_list_returns_ten_tools_in_v05() {
        let (s, p, h) = make_ctx();
        let req = json!({"jsonrpc":"2.0","id":2,"method":"tools/list"});
        let resp = handle_request(&req, &s, &p, &h);
        let tools = resp["result"]["tools"].as_array().expect("array");
        assert_eq!(
            tools.len(),
            10,
            "v0.5 expects 10 control-plane tools (6 v0.1 + 3 v0.2 + 1 v0.5 drift)"
        );
    }

    /// v0.5 Layer 7 — `armor_get_drift_history` is read-only and returns
    /// the canonical default path regardless of caller-supplied args
    /// (mirrors `armor_get_keystore` H1 fix from v0.2 review).
    #[test]
    fn armor_get_drift_history_returns_default_path_summary() {
        let (s, p, h) = make_ctx();
        let req = json!({
            "jsonrpc":"2.0","id":1,"method":"tools/call",
            "params":{
                "name":"armor_get_drift_history",
                "arguments":{}
            }
        });
        let resp = handle_request(&req, &s, &p, &h);
        assert_eq!(resp["result"]["isError"], false);
        let path = resp["result"]["structuredContent"]["history_path"]
            .as_str()
            .expect("history_path");
        assert!(
            path.ends_with("tools-history.toml"),
            "expected default drift history path, got {path}"
        );
        assert_eq!(resp["result"]["structuredContent"]["schema_version"], 1);
    }

    /// v0.5 Layer 7 — when called with a program filter that has no
    /// pinned baseline, returns `baseline_present: false` cleanly
    /// instead of erroring out.
    #[test]
    fn armor_get_drift_history_unknown_program_returns_baseline_present_false() {
        let (s, p, h) = make_ctx();
        let req = json!({
            "jsonrpc":"2.0","id":1,"method":"tools/call",
            "params":{
                "name":"armor_get_drift_history",
                "arguments":{"program":"/bin/never-seen-this"}
            }
        });
        let resp = handle_request(&req, &s, &p, &h);
        assert_eq!(resp["result"]["isError"], false);
        assert_eq!(
            resp["result"]["structuredContent"]["baseline_present"],
            false
        );
    }

    #[test]
    fn armor_get_keystore_on_empty_default_path_returns_zero_entries() {
        let (s, p, h) = make_ctx();
        // Point at a known-empty temp path to avoid the operator's actual
        // keystore being read in CI.
        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("nope.toml");
        let req = json!({
            "jsonrpc":"2.0","id":1,"method":"tools/call",
            "params":{
                "name":"armor_get_keystore",
                "arguments":{"keystore_path": path.display().to_string()}
            }
        });
        let resp = handle_request(&req, &s, &p, &h);
        assert_eq!(resp["result"]["isError"], false);
        assert_eq!(resp["result"]["structuredContent"]["count"], 0);
        assert_eq!(resp["result"]["structuredContent"]["schema_version"], 1);
    }

    #[test]
    fn armor_verify_bundle_minimal_shape_succeeds() {
        let (s, p, h) = make_ctx();
        let req = json!({
            "jsonrpc":"2.0","id":1,"method":"tools/call",
            "params":{
                "name":"armor_verify_bundle",
                "arguments":{"bundle_json": r#"{"base64Signature":"SGVsbG8="}"#}
            }
        });
        let resp = handle_request(&req, &s, &p, &h);
        assert_eq!(resp["result"]["isError"], false);
        assert_eq!(resp["result"]["structuredContent"]["bundle_parsed"], true);
        assert_eq!(resp["result"]["structuredContent"]["has_cert"], false);
    }

    /// Round-1-review H1 regression: armor_get_keystore must ignore any
    /// caller-supplied `keystore_path` arg. Path-traversal vector closed.
    #[test]
    fn armor_get_keystore_ignores_caller_supplied_path() {
        let (s, p, h) = make_ctx();
        // Attacker tries to read /etc/passwd. The dispatcher must IGNORE
        // the keystore_path arg and fall back to the default path — which
        // either does not exist (returning an empty keystore) or contains
        // legitimately pinned keys, but in any case is NOT the path the
        // caller supplied.
        let req = json!({
            "jsonrpc":"2.0","id":1,"method":"tools/call",
            "params":{
                "name":"armor_get_keystore",
                "arguments":{"keystore_path": "/etc/passwd"}
            }
        });
        let resp = handle_request(&req, &s, &p, &h);
        assert_eq!(resp["result"]["isError"], false);
        let path = resp["result"]["structuredContent"]["keystore_path"]
            .as_str()
            .expect("keystore_path");
        assert!(
            !path.contains("/etc/passwd"),
            "armor_get_keystore must not honour caller-supplied path; got {path}"
        );
        // Default keystore path ends in keys.toml regardless of XDG state.
        assert!(
            path.ends_with("keys.toml"),
            "expected default keystore path ending in keys.toml, got {path}"
        );
    }

    /// When the sigstore-bridge feature is not compiled in, the rekor lookup
    /// tool must still be advertised in tools/list (so clients see the surface)
    /// but calls return a clear feature-disabled error.
    #[cfg(not(feature = "sigstore-bridge"))]
    #[test]
    fn armor_rekor_lookup_without_feature_returns_feature_disabled() {
        let (s, p, h) = make_ctx();
        let req = json!({
            "jsonrpc":"2.0","id":1,"method":"tools/call",
            "params":{
                "name":"armor_rekor_lookup",
                "arguments":{"tools_list_response":{"tools":[]}}
            }
        });
        let resp = handle_request(&req, &s, &p, &h);
        assert_eq!(resp["result"]["isError"], true);
        let text = resp["result"]["content"][0]["text"].as_str().expect("text");
        assert!(
            text.contains("sigstore-bridge"),
            "error message must point at the feature flag, got: {text}"
        );
    }

    #[test]
    fn unknown_method_returns_method_not_found() {
        let (s, p, h) = make_ctx();
        let req = json!({"jsonrpc":"2.0","id":3,"method":"does/not/exist"});
        let resp = handle_request(&req, &s, &p, &h);
        assert_eq!(resp["error"]["code"], -32601);
    }

    #[test]
    fn scan_tool_returns_verdict() {
        let (s, p, h) = make_ctx();
        let req = json!({
            "jsonrpc":"2.0","id":4,"method":"tools/call",
            "params":{
                "name":"armor_scan_payload",
                "arguments":{"payload":"ls; $(rm -rf /)","direction":"inbound"}
            }
        });
        let resp = handle_request(&req, &s, &p, &h);
        assert_eq!(resp["result"]["isError"], false);
        let structured = &resp["result"]["structuredContent"];
        assert_eq!(structured["verdict"], "block");
    }

    #[test]
    fn check_cve_returns_affected_for_fastmcp() {
        let (s, p, h) = make_ctx();
        let req = json!({
            "jsonrpc":"2.0","id":5,"method":"tools/call",
            "params":{
                "name":"armor_check_cve",
                "arguments":{"server_name":"fastmcp"}
            }
        });
        let resp = handle_request(&req, &s, &p, &h);
        let cves = resp["result"]["structuredContent"]["affected_cves"]
            .as_array()
            .expect("array");
        assert!(!cves.is_empty(), "expected fastmcp to be affected");
    }

    #[test]
    fn simulate_attack_blocks_known_cve() {
        let (s, p, h) = make_ctx();
        let req = json!({
            "jsonrpc":"2.0","id":6,"method":"tools/call",
            "params":{
                "name":"armor_simulate_attack",
                "arguments":{"cve_id":"CVE-2026-27124"}
            }
        });
        let resp = handle_request(&req, &s, &p, &h);
        let structured = &resp["result"]["structuredContent"];
        assert_eq!(structured["actual_verdict"], "block");
        assert_eq!(structured["expected_verdict"], "block");
    }

    #[test]
    fn get_policy_returns_default() {
        let (s, p, h) = make_ctx();
        let req = json!({"jsonrpc":"2.0","id":7,"method":"tools/call",
            "params":{"name":"armor_get_policy","arguments":{}}});
        let resp = handle_request(&req, &s, &p, &h);
        assert_eq!(resp["result"]["structuredContent"]["fail_mode"], "closed");
    }

    #[test]
    fn list_blocked_starts_empty() {
        let (s, p, h) = make_ctx();
        let req = json!({"jsonrpc":"2.0","id":8,"method":"tools/call",
            "params":{"name":"armor_list_blocked","arguments":{}}});
        let resp = handle_request(&req, &s, &p, &h);
        assert_eq!(resp["result"]["structuredContent"]["total"], 0);
    }

    #[test]
    fn invalid_request_no_method() {
        let (s, p, h) = make_ctx();
        let req = json!({"jsonrpc":"2.0","id":9});
        let resp = handle_request(&req, &s, &p, &h);
        assert_eq!(resp["error"]["code"], -32600);
    }
}
