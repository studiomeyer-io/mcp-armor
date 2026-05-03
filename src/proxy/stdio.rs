//! Stdio proxy: client stdin → scanner → upstream stdin; upstream stdout →
//! client stdout. Line-delimited JSON-RPC envelopes (MCP spec 2025-06-18).
//!
//! Hot-path budget: p99 <5ms (scanner only — proxy itself is just async I/O).
//! Scanner runs synchronously on the spawn-blocking thread to avoid
//! spawn-task overhead per line.

use crate::control::history::ScanHistory;
use crate::error::ArmorError;
use crate::policy::{FailMode, Policy};
use crate::scanner::{ScanResult, ScanVerdict, Scanner};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};

/// Block-verdict response sent back to the client when fail_mode=Closed and
/// the scanner blocks an inbound call.
fn block_response(id: Value, matched: &[String], cves: &[String]) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32603,
            "message": "blocked by mcp-armor",
            "data": {
                "matched_patterns": matched,
                "cve_refs": cves
            }
        }
    })
}

/// Decide whether `policy.allow_servers` says we should bypass the scanner
/// for this upstream binary. The match is case-sensitive on either the bare
/// program string (e.g. `npx`, `python`) or the file-name-component of an
/// absolute path (so `/usr/local/bin/some-server` matches `some-server`).
fn server_is_allowlisted(program: &str, allow_servers: &[String]) -> bool {
    if allow_servers.is_empty() {
        return false;
    }
    if allow_servers.iter().any(|s| s == program) {
        return true;
    }
    let basename = std::path::Path::new(program)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(program);
    allow_servers.iter().any(|s| s == basename)
}

/// Spawn `program` with `args` as the upstream MCP server, then ferry
/// JSON-RPC traffic between the parent stdio and the child while scanning.
///
/// `history` records every block-verdict in the hot path so SOC2-/DSGVO-
/// audit trails surface real proxy-level blocks via `armor_list_blocked`,
/// not just control-plane-triggered scans.
///
/// Returns once the upstream process exits or stdin EOFs.
pub async fn run_proxy(
    program: &str,
    args: &[String],
    scanner: Arc<Scanner>,
    policy: Arc<Policy>,
    history: Arc<ScanHistory>,
) -> Result<(), ArmorError> {
    let mut child: Child = Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()?;

    let mut child_stdin = child
        .stdin
        .take()
        .ok_or_else(|| ArmorError::InvalidPattern("child stdin not captured".into()))?;
    let child_stdout = child
        .stdout
        .take()
        .ok_or_else(|| ArmorError::InvalidPattern("child stdout not captured".into()))?;

    let scanner_in = scanner.clone();
    let policy_in = policy.clone();
    let history_in = history.clone();
    let bypass_scanner = server_is_allowlisted(program, &policy.allow_servers);
    if bypass_scanner {
        tracing::info!(
            program = program,
            "policy.allow_servers matched — scanner bypassed for this upstream"
        );
    }

    // Inbound: client → child, scanned (unless allowlisted).
    let inbound = tokio::spawn(async move {
        let stdin = tokio::io::stdin();
        let mut reader = BufReader::new(stdin).lines();
        let mut stdout = tokio::io::stdout();
        loop {
            let line = match reader.next_line().await {
                Ok(Some(line)) => line,
                Ok(None) => break,
                Err(e) => return Err::<(), ArmorError>(ArmorError::Io(e)),
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let envelope: Value = match serde_json::from_str(trimmed) {
                Ok(v) => v,
                Err(_) => {
                    // Malformed JSON — pass through unchanged. Upstream will
                    // reject it with -32700 itself.
                    let mut out = line.clone();
                    out.push('\n');
                    child_stdin.write_all(out.as_bytes()).await?;
                    continue;
                }
            };

            // Policy: allowlisted upstream binary skips the scanner entirely.
            if bypass_scanner {
                let mut out = line;
                out.push('\n');
                child_stdin.write_all(out.as_bytes()).await?;
                continue;
            }

            let scan_target = extract_scan_target(&envelope);
            let result = scanner_in.scan_with(&scan_target, policy_in.scan_unicode);

            let allow_pattern = !result.matched_patterns.is_empty()
                && result
                    .matched_patterns
                    .iter()
                    .all(|p| policy_in.allow_patterns.contains(p));

            let blocked = matches!(result.verdict, ScanVerdict::Block) && !allow_pattern;

            if blocked {
                history_in.record("inbound", &result);
            }

            if blocked && matches!(policy_in.fail_mode, FailMode::Closed) {
                let id = envelope.get("id").cloned().unwrap_or(Value::Null);
                let response = block_response(id, &result.matched_patterns, &result.cve_refs);
                let mut out = serde_json::to_string(&response)?;
                out.push('\n');
                stdout.write_all(out.as_bytes()).await?;
                stdout.flush().await?;
                tracing::warn!(
                    matched = ?result.matched_patterns,
                    cves = ?result.cve_refs,
                    latency_us = result.latency_us,
                    "blocked inbound call"
                );
                continue;
            }

            if blocked {
                tracing::warn!(
                    matched = ?result.matched_patterns,
                    cves = ?result.cve_refs,
                    "warn-and-pass (fail_mode=open)"
                );
            }

            let mut out = line;
            out.push('\n');
            child_stdin.write_all(out.as_bytes()).await?;
        }
        let _ = child_stdin.shutdown().await;
        Ok(())
    });

    // Outbound: child → client, scanned (warn-only — never block server output).
    let scanner_out = scanner.clone();
    let policy_out = policy.clone();
    let history_out = history.clone();
    let outbound = tokio::spawn(async move {
        let mut reader = BufReader::new(child_stdout).lines();
        let mut stdout = tokio::io::stdout();
        loop {
            let line = match reader.next_line().await {
                Ok(Some(line)) => line,
                Ok(None) => break,
                Err(e) => return Err::<(), ArmorError>(ArmorError::Io(e)),
            };
            let trimmed = line.trim();
            if !trimmed.is_empty() && !bypass_scanner {
                let result: ScanResult = scanner_out.scan_with(trimmed, policy_out.scan_unicode);
                if !result.matched_patterns.is_empty() {
                    let allow_pattern = result
                        .matched_patterns
                        .iter()
                        .all(|p| policy_out.allow_patterns.contains(p));
                    if !allow_pattern {
                        // Outbound is warn-only (we never tamper with server
                        // output) but the block still counts for the audit
                        // trail surfaced by armor_list_blocked.
                        history_out.record("outbound", &result);
                    }
                    tracing::warn!(
                        matched = ?result.matched_patterns,
                        cves = ?result.cve_refs,
                        latency_us = result.latency_us,
                        "outbound match (warn-only)"
                    );
                }
            }
            let mut out = line;
            out.push('\n');
            stdout.write_all(out.as_bytes()).await?;
            stdout.flush().await?;
        }
        Ok(())
    });

    // Wait for either direction to finish.
    let _ = tokio::try_join!(
        async {
            inbound
                .await
                .map_err(|e| ArmorError::InvalidPattern(e.to_string()))?
        },
        async {
            outbound
                .await
                .map_err(|e| ArmorError::InvalidPattern(e.to_string()))?
        }
    )?;

    let _ = child.wait().await?;
    Ok(())
}

/// Pluck the part of the envelope worth scanning. Concretely:
/// `params.arguments` plus the `params.name` (tool name). Keeps payload
/// small so scanner stays in p99 budget.
fn extract_scan_target(envelope: &Value) -> String {
    let mut buf = String::new();
    if let Some(params) = envelope.get("params") {
        if let Some(name) = params.get("name").and_then(Value::as_str) {
            buf.push_str(name);
            buf.push('\n');
        }
        if let Some(args) = params.get("arguments") {
            buf.push_str(&args.to_string());
        } else {
            buf.push_str(&params.to_string());
        }
    } else {
        buf.push_str(&envelope.to_string());
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_returns_args_text() {
        let env = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "echo",
                "arguments": {"text": "hello world"}
            }
        });
        let target = extract_scan_target(&env);
        assert!(target.contains("echo"));
        assert!(target.contains("hello world"));
    }

    #[test]
    fn extract_handles_missing_params() {
        let env = json!({"jsonrpc": "2.0", "id": 1});
        // Should not panic, returns the envelope dump.
        let target = extract_scan_target(&env);
        assert!(target.contains("jsonrpc"));
    }

    #[test]
    fn allowlist_empty_never_matches() {
        assert!(!server_is_allowlisted("npx", &[]));
    }

    #[test]
    fn allowlist_matches_program_directly() {
        let allow = vec!["my-trusted-server".to_string()];
        assert!(server_is_allowlisted("my-trusted-server", &allow));
        assert!(!server_is_allowlisted("npx", &allow));
    }

    #[test]
    fn allowlist_matches_basename_of_path() {
        let allow = vec!["some-server".to_string()];
        assert!(server_is_allowlisted("/usr/local/bin/some-server", &allow));
        assert!(!server_is_allowlisted(
            "/usr/local/bin/other-server",
            &allow
        ));
    }

    #[test]
    fn block_response_shape() {
        let r = block_response(
            json!(42),
            &["shell_substitution".to_string()],
            &["CVE-X".to_string()],
        );
        assert_eq!(r["error"]["code"], -32603);
        assert_eq!(r["id"], 42);
        assert_eq!(
            r["error"]["data"]["matched_patterns"][0],
            "shell_substitution"
        );
    }
}
