//! Stdio proxy: client stdin → scanner → upstream stdin; upstream stdout →
//! client stdout. Line-delimited JSON-RPC envelopes (MCP spec 2025-06-18).
//!
//! Hot-path budget: p99 <5ms (scanner only — proxy itself is just async I/O).
//! Scanner runs synchronously on the spawn-blocking thread to avoid
//! spawn-task overhead per line.

use crate::control::history::ScanHistory;
use crate::error::ArmorError;
use crate::policy::{snapshot, FailMode, Policy, PolicyHandle};
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
/// v0.2 — `policy` is a [`PolicyHandle`] (`Arc<RwLock<Policy>>`) so SIGHUP
/// reloads land in the running proxy. Each scanned envelope takes a fresh
/// per-message snapshot (cheap clone of a small struct) so the hot-path
/// never holds the read-lock across an `.await`.
///
/// Returns once the upstream process exits or stdin EOFs.
pub async fn run_proxy(
    program: &str,
    args: &[String],
    scanner: Arc<Scanner>,
    policy: PolicyHandle,
    history: Arc<ScanHistory>,
) -> Result<(), ArmorError> {
    // v0.3 Sahnehaube A — strip loader-class env keys from the child
    // process before spawn. Closes the Zealynx 2026 side-channel where a
    // registry-fetched MCP manifest can specify
    // `env: { LD_PRELOAD: "/evil.so" }` and bypass the binary signature
    // verify entirely (env injection is upstream of `exec`).
    //
    // We snapshot the policy once here at spawn-time. Re-evaluation on
    // SIGHUP reload is intentionally NOT done — env is a process-lifetime
    // attribute that cannot be changed after spawn. Operators who flip
    // `deny_env_keys` mid-flight should restart the wrap.
    let stripped_env_keys = snapshot(&policy).leaked_loader_keys();
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit());
    for key in &stripped_env_keys {
        cmd.env_remove(key);
    }
    if !stripped_env_keys.is_empty() {
        tracing::warn!(
            stripped = ?stripped_env_keys,
            program = program,
            "v0.3 Sahnehaube A: stripped loader-class env keys from child process before spawn — set policy.deny_env_keys=[] to disable"
        );
    }
    let mut child: Child = cmd.spawn()?;

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
    // v0.2 — initial startup advisory: scanner bypass status at boot. The
    // per-envelope hot-path below re-evaluates this against the *current*
    // policy snapshot, so a SIGHUP reload that removes a server from
    // `allow_servers` takes effect on the next message (Round 1 M4 fix).
    let startup_bypass = server_is_allowlisted(program, &snapshot(&policy).allow_servers);
    if startup_bypass {
        tracing::info!(
            program = program,
            "policy.allow_servers matched at startup — scanner bypassed for this upstream (re-evaluated per envelope, can be cleared via SIGHUP reload)"
        );
    }
    let program_name = program.to_string();
    let program_for_in = program.to_string();
    let program_for_out = program.to_string();

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

            // v0.2: fresh snapshot per envelope so a SIGHUP reload between
            // messages is visible immediately. Cheap struct-clone, drop the
            // read-lock before any .await.
            let pol: Policy = snapshot(&policy_in);

            // Policy: allowlisted upstream binary skips the scanner entirely.
            // Round 1 M4 fix: re-evaluated against the *current* snapshot so
            // a SIGHUP reload that removes a server from `allow_servers`
            // takes effect on the next envelope.
            if server_is_allowlisted(&program_for_in, &pol.allow_servers) {
                let mut out = line;
                out.push('\n');
                child_stdin.write_all(out.as_bytes()).await?;
                continue;
            }

            let scan_target = extract_scan_target(&envelope);
            // v0.3 R1-CRIT fix: thread `pol.scan_confusable` through so the
            // operator's policy.toml toggle is actually honoured. Before
            // this fix, `scan_with(payload, scan_unicode)` hard-coded
            // Stage 4 = on (`scan_confusable=true`) and the new
            // `policy.scan_confusable` field was a dead knob.
            let result =
                scanner_in.scan_with_opts(&scan_target, pol.scan_unicode, pol.scan_confusable);
            let tool_name = extract_tool_name(&envelope);

            let allow_pattern_global = !result.matched_patterns.is_empty()
                && result
                    .matched_patterns
                    .iter()
                    .all(|p| pol.allow_patterns.contains(p));

            // v0.2 — per-tool allowlist (REVIEW.md F3 Sub-b mitigation).
            let allow_pattern_per_tool = tool_name
                .as_deref()
                .is_some_and(|t| pol.tool_allows_patterns(t, &result.matched_patterns));

            let allow_pattern = allow_pattern_global || allow_pattern_per_tool;

            let blocked = matches!(result.verdict, ScanVerdict::Block) && !allow_pattern;

            if blocked {
                history_in.record("inbound", &result);
                // v0.2 — also push an OTLP span when the otlp feature is on.
                // No-op otherwise.
                crate::otel::emit_block_span(
                    "inbound",
                    &result.matched_patterns,
                    &result.cve_refs,
                    result.latency_us,
                );
            }

            if blocked && matches!(pol.fail_mode, FailMode::Closed) {
                let id = envelope.get("id").cloned().unwrap_or(Value::Null);
                let response = block_response(id, &result.matched_patterns, &result.cve_refs);
                let mut out = serde_json::to_string(&response)?;
                out.push('\n');
                stdout.write_all(out.as_bytes()).await?;
                stdout.flush().await?;
                tracing::warn!(
                    program = %program_name,
                    tool = %tool_name.as_deref().unwrap_or(""),
                    matched = ?result.matched_patterns,
                    cves = ?result.cve_refs,
                    latency_us = result.latency_us,
                    "blocked inbound call"
                );
                continue;
            }

            if blocked {
                tracing::warn!(
                    program = %program_name,
                    tool = %tool_name.as_deref().unwrap_or(""),
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
            if !trimmed.is_empty() {
                let pol: Policy = snapshot(&policy_out);
                // Round 1 M4 fix: outbound also re-evaluates allow_servers
                // per-line so SIGHUP reloads are honoured symmetrically.
                if !server_is_allowlisted(&program_for_out, &pol.allow_servers) {
                    // v0.3 R1-CRIT fix: thread `pol.scan_confusable` —
                    // see inbound-handler comment above for rationale.
                    let result: ScanResult =
                        scanner_out.scan_with_opts(trimmed, pol.scan_unicode, pol.scan_confusable);
                    if !result.matched_patterns.is_empty() {
                        // Note (Analyst observation 7): outbound intentionally
                        // applies only the *global* allow_patterns — never the
                        // per-tool allowlist — because outbound traffic is
                        // server→client and tool-name attribution is unreliable
                        // (the server may emit unrelated diagnostics). Outbound
                        // is also warn-only: matches never block, only log.
                        let allow_pattern = result
                            .matched_patterns
                            .iter()
                            .all(|p| pol.allow_patterns.contains(p));
                        if !allow_pattern {
                            history_out.record("outbound", &result);
                            crate::otel::emit_block_span(
                                "outbound",
                                &result.matched_patterns,
                                &result.cve_refs,
                                result.latency_us,
                            );
                        }
                        tracing::warn!(
                            matched = ?result.matched_patterns,
                            cves = ?result.cve_refs,
                            latency_us = result.latency_us,
                            "outbound match (warn-only)"
                        );
                    }
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

/// v0.2 — extract the tool name from a `tools/call` envelope. Used by the
/// per-tool allowlist to decide whether to override a Block verdict.
/// Returns `None` for non-tools/call methods or malformed envelopes.
fn extract_tool_name(envelope: &Value) -> Option<String> {
    let method = envelope.get("method").and_then(Value::as_str)?;
    if method != "tools/call" {
        return None;
    }
    envelope
        .get("params")
        .and_then(|p| p.get("name"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

// v0.3 Sahnehaube A — env-key strip lives on `Policy::leaked_loader_keys`
// (see `src/policy/loader.rs`). The proxy hot-path calls
// `snapshot(&policy).leaked_loader_keys()` at spawn-time and feeds the
// result into `cmd.env_remove(key)` for each match. R1-fix (Architect MED):
// the helper was originally a stand-alone `pub(crate)` function here, but
// the binary (`src/main.rs`, separate compilation unit) needs it for the
// startup-warn, so it's now a `Policy` method.

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

    // v0.2 — extract_tool_name covers
    #[test]
    fn extract_tool_name_returns_name_for_tools_call() {
        let env = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "echo", "arguments": {}}
        });
        assert_eq!(extract_tool_name(&env), Some("echo".to_string()));
    }

    #[test]
    fn extract_tool_name_returns_none_for_other_methods() {
        let env = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list"
        });
        assert_eq!(extract_tool_name(&env), None);
    }

    #[test]
    fn extract_tool_name_returns_none_when_params_missing() {
        let env = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call"
        });
        assert_eq!(extract_tool_name(&env), None);
    }
}
