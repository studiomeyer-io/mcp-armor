//! Stdio proxy: client stdin → scanner → upstream stdin; upstream stdout →
//! client stdout. Line-delimited JSON-RPC envelopes (MCP spec 2025-06-18).
//!
//! Hot-path budget: p99 <5ms (scanner only — proxy itself is just async I/O).
//! Scanner runs synchronously on the spawn-blocking thread to avoid
//! spawn-task overhead per line.

use crate::control::history::ScanHistory;
use crate::error::ArmorError;
use crate::manifest::drift::{
    self, default_path as drift_default_path, drift_block_inbound_response, drift_block_response,
    inject_fingerprint_meta, DriftKind, DriftMode, History as DriftHistory,
};
use crate::policy::{snapshot, FailMode, Policy, PolicyHandle};
use crate::scanner::{ScanResult, ScanVerdict, Scanner};
use serde_json::{json, Value};
use std::path::PathBuf;
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

// v0.6 — drift block JSON-RPC shape moved into `manifest::drift` so a
// future `armor_simulate_drift_block` control-plane tool can render
// the same shape without duplicating construction. `ERR_DRIFT_POLICY_VIOLATION`
// is now `drift::ERR_DRIFT_POLICY_VIOLATION` and `drift_block_response` +
// `drift_block_inbound_response` are imported at the top of this file.

/// v0.6 — decision returned by [`run_drift_check`] for an outbound
/// envelope. `PassThrough` = emit the original line unchanged.
/// `Replace(value)` = emit `value` instead of the original line
/// (block mode rejected the response). `PassThroughWithMeta(value)`
/// = emit `value` instead of the original line because the operator
/// asked us to stamp a `_meta.dev.studiomeyer/armor.fingerprint`
/// onto the tools/list envelope but the underlying response itself
/// is allowed through.
pub(crate) enum DriftDecision {
    PassThrough,
    Replace(Value),
    PassThroughWithMeta(Value),
}

/// v0.5 Layer 7 + v0.6 fingerprint-meta — outbound drift detection
/// sweep. Side-effects (history mutation + persist) happen inside.
///
/// Performs `load → observe → persist_locked_merge` per tools/list
/// response — drift detection runs on first-sight + every tools/list
/// refresh, never on tools/call traffic. Persist is atomic +
/// flock-serialised so two concurrent `wrap` processes booting against
/// the same upstream cannot race on the first-sight baseline.
///
/// Errors during load/persist are logged at `error` and the envelope
/// passes through — drift detection must never *block* a legitimate
/// response just because the history file is unreadable.
///
/// v0.6 — `policy` is now passed in to make the hash-backend + JCS +
/// fingerprint-meta toggles visible to the drift pipeline.
pub(crate) fn run_drift_check(
    program: &str,
    envelope: &Value,
    policy: &Policy,
    history_path: &std::path::Path,
) -> DriftDecision {
    let mode = policy.tools_list_drift_detection;
    if mode == DriftMode::Off {
        return DriftDecision::PassThrough;
    }

    // v0.5 R1 Research-P0 — surface `notifications/tools/list_changed`
    // at info-level so the operator can correlate "server announced a
    // refresh" with the subsequent drift signal that the next
    // tools/list response will emit. We intentionally do NOT auto-reset
    // the baseline here — a rug-pull attacker would just emit
    // list_changed and swap the schema invisibly. The notification is
    // surfaced, the next real tools/list response goes through the
    // normal drift check, and the operator gets the audit trail.
    if drift::looks_like_list_changed_notification(envelope) {
        tracing::info!(
            program = program,
            "drift: server emitted notifications/tools/list_changed — next tools/list will be drift-checked against the existing baseline (not auto-reset)"
        );
        return DriftDecision::PassThrough;
    }

    // v0.6 — symmetric surface for prompts/resources list_changed.
    // We don't fingerprint these envelopes yet (v0.8 backlog), but
    // surfacing the notification gives operators a complete audit
    // trail without filing a separate bug.
    if drift::looks_like_prompts_list_changed_notification(envelope) {
        tracing::info!(
            program = program,
            "drift: server emitted notifications/prompts/list_changed — fingerprinting of prompts/list is a v0.8 backlog item; the notification is surfaced for audit symmetry only"
        );
        return DriftDecision::PassThrough;
    }
    if drift::looks_like_resources_list_changed_notification(envelope) {
        tracing::info!(
            program = program,
            "drift: server emitted notifications/resources/list_changed — fingerprinting of resources/list is a v0.8 backlog item; the notification is surfaced for audit symmetry only"
        );
        return DriftDecision::PassThrough;
    }

    if !drift::looks_like_tools_list_response(envelope) {
        return DriftDecision::PassThrough;
    }

    let mut history = match DriftHistory::load(history_path) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(
                error = %e,
                path = %history_path.display(),
                "drift: load history failed — passing tools/list through"
            );
            return DriftDecision::PassThrough;
        }
    };

    let now = drift::now_iso();
    let opts = policy.drift_fingerprint_opts();
    let outcome = match history.observe_with_opts(program, envelope, &now, opts) {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(
                error = %e,
                program = program,
                "drift: observe failed (malformed tools/list?) — passing through"
            );
            return DriftDecision::PassThrough;
        }
    };

    let mutated = match &outcome {
        DriftKind::Unknown | DriftKind::Match => true,
        DriftKind::Drift(_) => false,
    };
    if mutated {
        // v0.5 R1 Critic-HIGH + Analyst-W3 fix: persist_locked_merge
        // re-loads under the flock and merges concurrent additions
        // before writing. Closes the multi-process lost-update race
        // that single-process persist_locked has (two `mcp-armor wrap`
        // instances against the same history file would otherwise
        // overwrite each other's first-sight entries).
        if let Err(e) = history.persist_locked_merge(history_path) {
            tracing::error!(
                error = %e,
                path = %history_path.display(),
                "drift: persist history failed — outcome not durable"
            );
        }
    }

    match outcome {
        DriftKind::Unknown => {
            tracing::info!(
                program = program,
                tools_count = history.find(program).map_or(0, |p| p.tools_count),
                history_path = %history_path.display(),
                "drift: first-sight baseline written for {}; clear via `mcp-armor drift clear {}` to re-baseline",
                program,
                program,
            );
            // v0.6 — even on first-sight, if the operator wants the
            // fingerprint stamped onto the envelope, do that now.
            if policy.inject_fingerprint_meta {
                if let Some(baseline) = history.find(program) {
                    return DriftDecision::PassThroughWithMeta(inject_fingerprint_meta(
                        envelope, baseline,
                    ));
                }
            }
            DriftDecision::PassThrough
        }
        DriftKind::Match => {
            // v0.6 — on Match, stamp the fingerprint into the response
            // envelope if the operator asked for it.
            if policy.inject_fingerprint_meta {
                if let Some(baseline) = history.find(program) {
                    return DriftDecision::PassThroughWithMeta(inject_fingerprint_meta(
                        envelope, baseline,
                    ));
                }
            }
            DriftDecision::PassThrough
        }
        DriftKind::Drift(detail) => {
            tracing::warn!(
                program = program,
                added = ?detail.added,
                removed = ?detail.removed,
                description_changed = ?detail.description_changed,
                params_changed = detail.params_changed.len(),
                mode = ?mode,
                "drift: tools/list shape changed since baseline {}",
                detail.baseline_iso
            );
            if mode == DriftMode::Block {
                let id = envelope.get("id").cloned().unwrap_or(Value::Null);
                DriftDecision::Replace(drift_block_response(id, program, &detail))
            } else {
                DriftDecision::PassThrough
            }
        }
    }
}

/// v0.6 — inbound-side drift gate. When `policy.tools_list_drift_detection`
/// is `Block` AND `policy.tools_list_drift_inbound_check` is `true`
/// AND a baseline already exists for `program`, refuse an inbound
/// `tools/list` REQUEST envelope before it reaches the upstream
/// server. Returns `Some(block_response)` when the inbound should be
/// short-circuited, `None` to let the request through unchanged.
///
/// This is purely additive — `tools_list_drift_inbound_check`
/// defaults to `false`. The outbound gate covers the same threat
/// class in the default setup; the inbound gate is for paranoid
/// deployments where the upstream is no longer trusted to even
/// respond to a tools/list (e.g. mid-investigation).
pub(crate) fn run_drift_check_inbound(
    program: &str,
    envelope: &Value,
    policy: &Policy,
    history_path: &std::path::Path,
) -> Option<Value> {
    if !policy.tools_list_drift_inbound_check {
        return None;
    }
    if policy.tools_list_drift_detection != DriftMode::Block {
        return None;
    }
    if !drift::looks_like_tools_list_request(envelope) {
        return None;
    }
    // Only block when a baseline already exists — otherwise we'd
    // prevent the first-sight bootstrap entirely.
    let history = DriftHistory::load(history_path).ok()?;
    history.find(program)?;
    tracing::warn!(
        program = program,
        history_path = %history_path.display(),
        "drift: inbound tools/list refused by paranoid policy (tools_list_drift_inbound_check=true + baseline already pinned)"
    );
    let id = envelope.get("id").cloned().unwrap_or(Value::Null);
    Some(drift_block_inbound_response(id, program))
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
///
/// v0.5 Layer 7 — `drift_history_path` (`Option<PathBuf>`) overrides
/// the default `~/.local/share/mcp-armor/tools-history.toml` path used
/// by the schema-drift detector. Passing `None` falls back to
/// [`drift::default_path`]. The detector is gated on
/// `policy.tools_list_drift_detection`; when that field is `off` the
/// path is ignored.
pub async fn run_proxy(
    program: &str,
    args: &[String],
    scanner: Arc<Scanner>,
    policy: PolicyHandle,
    history: Arc<ScanHistory>,
    drift_history_path: Option<PathBuf>,
) -> Result<(), ArmorError> {
    let drift_history_path = drift_history_path.unwrap_or_else(drift_default_path);
    // v0.3 Feature A — strip loader-class env keys from the child
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
            "v0.3 Feature A: stripped loader-class env keys from child process before spawn — set policy.deny_env_keys=[] to disable"
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
    let drift_history_path_in = drift_history_path.clone();
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

            // v0.6 — Inbound-side drift gate. When the operator has set
            // `tools_list_drift_detection = "block"` AND
            // `tools_list_drift_inbound_check = true` AND a baseline
            // exists for this program, refuse the request before it
            // reaches the upstream.
            if let Some(block) =
                run_drift_check_inbound(&program_for_in, &envelope, &pol, &drift_history_path_in)
            {
                let mut out = serde_json::to_string(&block)?;
                out.push('\n');
                stdout.write_all(out.as_bytes()).await?;
                stdout.flush().await?;
                continue;
            }

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
    let drift_history_path_out = drift_history_path.clone();
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
            // v0.5 Layer 7 + v0.6 fingerprint-meta — drift outcome.
            // `PassThrough` keeps the original line; `Replace(value)`
            // swaps in a JSON-RPC error (block mode); `PassThroughWithMeta(value)`
            // swaps in a stamped clone of the original envelope.
            let mut drift_decision: DriftDecision = DriftDecision::PassThrough;
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
                        // Outbound is warn-only (server→client traffic,
                        // tool-name attribution unreliable).
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

                // v0.5 Layer 7 + v0.6 fingerprint-meta — tools/list
                // schema-drift detection. Runs only when the envelope
                // looks like a tools/list response (cheap structural
                // pre-gate) and mode != Off. Decoupled from the
                // scanner above so allowlisted servers still get drift
                // coverage — rug-pulls don't care about `allow_servers`.
                if pol.tools_list_drift_detection != DriftMode::Off || pol.inject_fingerprint_meta {
                    if let Ok(envelope) = serde_json::from_str::<Value>(trimmed) {
                        drift_decision = run_drift_check(
                            &program_for_out,
                            &envelope,
                            &pol,
                            &drift_history_path_out,
                        );
                    }
                }
            }
            // v0.6 R1 Critic-MED + Analyst-W1 fix — split the
            // `Replace | PassThroughWithMeta` OR-arm into two distinct
            // arms. The serialisation step is identical *today*
            // (both variants carry a `Value` that we encode + append
            // a newline), but the semantics differ:
            //
            //   `Replace`               = BLOCK (JSON-RPC error -32001)
            //   `PassThroughWithMeta`   = ENRICH (success + _meta stamp)
            //
            // A future contributor adding per-decision-type tracing,
            // audit-log entries, or OTLP block-span labelling needs
            // the structural split to land BEFORE making that change.
            // The shared local + identical body keep behaviour
            // byte-identical to the v0.6.0-pre-R1 collapsed version.
            let encode = |v: &Value| -> Result<String, ArmorError> {
                let mut s = serde_json::to_string(v)?;
                s.push('\n');
                Ok(s)
            };
            let payload = match drift_decision {
                // BLOCK — replace the original line with the
                // JSON-RPC error envelope built by
                // `drift::drift_block_response`.
                DriftDecision::Replace(replacement) => encode(&replacement)?,
                // ENRICH — replace the original line with the
                // _meta-stamped clone built by
                // `drift::inject_fingerprint_meta`.
                DriftDecision::PassThroughWithMeta(stamped) => encode(&stamped)?,
                // PASS THROUGH — emit the original line unchanged.
                DriftDecision::PassThrough => {
                    let mut s = line;
                    s.push('\n');
                    s
                }
            };
            stdout.write_all(payload.as_bytes()).await?;
            stdout.flush().await?;
        }
        Ok(())
    });

    // v0.4 Round-3 review HIGH fix — zombie-child elimination.
    //
    // The v0.3 path used `tokio::try_join!(...)?` which short-circuits the
    // *first* error and drops the surviving direction. When `try_join` then
    // bailed out via `?` the function returned before `child.wait()` ran,
    // leaving the upstream process in a kernel ZOMBIE state for the
    // lifetime of mcp-armor. Long-running orchestrators (Claude Desktop,
    // Cursor) that re-wrap servers across reload cycles would accumulate
    // those zombies.
    //
    // v0.4 fix: drive both directions to completion via `tokio::join!`
    // (which never short-circuits), then ALWAYS issue `child.kill().await`
    // followed by `child.wait().await` so the child is reaped regardless
    // of which direction errored. `kill` on `tokio::process::Child` is
    // idempotent — calling it on a process that has already exited
    // returns `Ok(())`. Only after the child is reaped do we surface any
    // direction's error back to the caller.
    let (inbound_res, outbound_res) = tokio::join!(inbound, outbound);

    // Always reap the child — never leak a zombie even on inbound/outbound error.
    let _ = child.kill().await;
    let _ = child.wait().await;

    let inbound_res = inbound_res
        .map_err(|e| ArmorError::InvalidPattern(format!("inbound task join error: {e}")))?;
    let outbound_res = outbound_res
        .map_err(|e| ArmorError::InvalidPattern(format!("outbound task join error: {e}")))?;
    inbound_res?;
    outbound_res?;
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

// v0.3 Feature A — env-key strip lives on `Policy::leaked_loader_keys`
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
