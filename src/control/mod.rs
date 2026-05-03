//! Control-plane MCP server. Read-only inspection surface — 6 tools that
//! let a client app inspect policy + scan history without touching the file
//! system.
//!
//! Implementation note: this is a hand-rolled line-delimited JSON-RPC 2.0
//! stdio server (MCP spec 2025-06-18). PLAN.md R5 favours `rmcp` v1.6 — that
//! migration is on the v0.2 backlog (BUILDER_NOTES.md). The hand-rolled
//! server keeps v0.1 free of an extra crate dep until rmcp is bench-verified.

pub mod history;
pub mod tools;

use crate::cve::FEED;
use crate::error::ArmorError;
use crate::manifest::{verify, VerifyOutcome};
use crate::policy::Policy;
use crate::scanner::Scanner;
use history::ScanHistory;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const MCP_PROTOCOL_VERSION: &str = "2025-06-18";
const SERVER_NAME: &str = "mcp-armor-control";

/// Run the control-plane stdio server. Reads JSON-RPC from stdin, writes
/// responses to stdout, line-delimited.
pub async fn run_control_plane(
    scanner: Arc<Scanner>,
    policy: Arc<Policy>,
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
        let resp = handle_request(&req, &scanner, &policy, &history);
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
    // Honour the policy.scan_unicode toggle here too — the control-plane
    // scan_payload tool is meant to mirror what the proxy hot-path does.
    let result = scanner.scan_with(payload, policy.scan_unicode);
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
    json!({
        "policy_path": format!("{:?}", crate::policy::loader::default_path()),
        "rules": {
            "allow_patterns": policy.allow_patterns,
            "allow_servers": policy.allow_servers
        },
        "fail_mode": policy.fail_mode,
        "scan_unicode": policy.scan_unicode,
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
    Ok(json!({
        "affected_cves": affected,
        "server_version_queried": server_version,
        "version_match_used": version_match_used,
        "advisories_consulted": ["ox-advisory-2026-04-15"],
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
    fn tools_list_returns_six_tools() {
        let (s, p, h) = make_ctx();
        let req = json!({"jsonrpc":"2.0","id":2,"method":"tools/list"});
        let resp = handle_request(&req, &s, &p, &h);
        let tools = resp["result"]["tools"].as_array().expect("array");
        assert_eq!(tools.len(), 6, "expected 6 control-plane tools");
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
