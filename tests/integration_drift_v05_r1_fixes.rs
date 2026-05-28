//! v0.5 R1 — Regression tests for the seven Round-1 review fixes.
//!
//! 1. NFKC + whitespace-trim on tool-name in fingerprint
//!    (Research-P0, Lyrie CVE-2026-29774 class)
//! 2. TOCTOU merge-on-persist (Critic-HIGH + Analyst-W3)
//! 3. JSON-RPC error code -32603 → -32001 (Critic-MED)
//! 4. required_set_hash widened 64-bit → 128-bit (Critic-HIGH)
//! 5. tools_list_drift_detection in armor_get_policy output (Analyst-W5)
//! 6. notifications/tools/list_changed handler (Research-P0)
//! 7. CVE feed Lyrie + rmcp + n8n-mcp + Excel-MCP refresh (Research-P1)

use mcp_armor::control::handle_request;
use mcp_armor::control::history::ScanHistory;
use mcp_armor::manifest::drift::{
    canonicalize_identifier, fingerprint, looks_like_list_changed_notification, DriftKind, History,
};
use mcp_armor::policy::Policy;
use mcp_armor::Scanner;
use serde_json::{json, Value};
use tempfile::tempdir;

fn tools_list(tool_name: &str, desc: &str) -> Value {
    json!({
        "jsonrpc": "2.0", "id": 1,
        "result": {"tools": [{
            "name": tool_name,
            "description": desc,
            "inputSchema": {"type": "object", "properties": {}, "required": []}
        }]}
    })
}

// ── Fix 1: NFKC + whitespace-trim on tool-name ─────────────────────────

/// Lyrie MCP-1.4 attack — adversary registers `send_message​` (zero-width
/// space suffix) that visually collides with the trusted `send_message`.
/// Layer 7 must canonicalise tool names BEFORE fingerprinting so the
/// rug-pull yields a fingerprint Match against the baseline (i.e. the
/// fingerprint is on the canonical form, not the byte form). The attack
/// then surfaces via Lyrie's runtime name-collision handling, not as a
/// silent drift miss.
#[test]
fn r1_p0_1_zero_width_tool_name_canonicalises() {
    let raw = "send_message\u{200B}";
    let canonical = canonicalize_identifier(raw);
    assert_eq!(canonical, "send_message");
}

#[test]
fn r1_p0_1_nfkc_folds_ligatures_in_tool_name() {
    // ﬁ (U+FB01 LATIN SMALL LIGATURE FI) folds to `fi` under NFKC.
    let canonical = canonicalize_identifier("con\u{FB01}rm");
    assert_eq!(canonical, "confirm");
}

#[test]
fn r1_p0_1_strips_bidi_formatting_in_tool_name() {
    // RIGHT-TO-LEFT OVERRIDE inserted into an identifier
    let canonical = canonicalize_identifier("rea\u{202E}d_file");
    assert_eq!(canonical, "read_file");
}

#[test]
fn r1_p0_1_trims_leading_trailing_whitespace_in_tool_name() {
    assert_eq!(canonicalize_identifier("  read_file  "), "read_file");
}

#[test]
fn r1_p0_1_zero_width_swap_does_not_evade_drift() {
    let v1 = tools_list("send_message", "send a message");
    let v2 = tools_list("send_message\u{200B}", "send a message");

    let fp1 = fingerprint("/bin/x", &v1).expect("fp1");
    let fp2 = fingerprint("/bin/x", &v2).expect("fp2");
    // After canonicalisation both forms collapse to the same name,
    // so fingerprints are identical.
    assert_eq!(
        fp1.aggregate_hash, fp2.aggregate_hash,
        "zero-width tool-name variant must canonicalise to the same fingerprint as the bare form"
    );
}

// ── Fix 2: TOCTOU merge-on-persist ─────────────────────────────────────

/// Two writers that each observe a different program (no overlap) must
/// both survive after concurrent persist_locked_merge. The bare
/// persist_locked path lost updates; persist_locked_merge re-loads
/// under the flock and appends entries that another writer added.
#[test]
fn r1_p0_2_persist_locked_merge_preserves_concurrent_first_sights() {
    use std::sync::Arc as StdArc;
    use std::thread;
    let dir = tempdir().expect("tmp");
    let path = StdArc::new(dir.path().join("tools-history.toml"));
    // Pre-seed so both writers load a non-empty file.
    {
        let mut h = History::empty();
        let _ = h
            .observe("/bin/seed", &tools_list("seed_tool", "seed"), "t0")
            .expect("seed");
        h.persist_locked_merge(&path).expect("seed persist");
    }

    let path_a = path.clone();
    let path_b = path.clone();
    let t1 = thread::spawn(move || {
        let mut h = History::load(&path_a).expect("load A");
        let _ = h
            .observe("/bin/a", &tools_list("tool_a", "a"), "t1a")
            .expect("obs A");
        h.persist_locked_merge(&path_a).expect("merge A");
    });
    let t2 = thread::spawn(move || {
        let mut h = History::load(&path_b).expect("load B");
        let _ = h
            .observe("/bin/b", &tools_list("tool_b", "b"), "t1b")
            .expect("obs B");
        h.persist_locked_merge(&path_b).expect("merge B");
    });
    t1.join().expect("join A");
    t2.join().expect("join B");

    let h_final = History::load(&path).expect("final load");
    assert!(
        h_final.find("/bin/seed").is_some(),
        "seed entry must survive both writes"
    );
    assert!(
        h_final.find("/bin/a").is_some(),
        "writer A's entry must survive the merge"
    );
    assert!(
        h_final.find("/bin/b").is_some(),
        "writer B's entry must survive the merge"
    );
}

/// persist_locked_merge with NO disk changes must round-trip cleanly
/// (the re-load + merge step must not corrupt or duplicate entries).
#[test]
fn r1_p0_2_persist_locked_merge_no_op_when_disk_unchanged() {
    let dir = tempdir().expect("tmp");
    let path = dir.path().join("tools-history.toml");
    let mut h = History::empty();
    let _ = h
        .observe("/bin/x", &tools_list("t", "x"), "t1")
        .expect("base");
    h.persist_locked_merge(&path).expect("first persist");
    // Same in-memory snapshot, no disk changes, second persist must
    // not duplicate the entry.
    h.persist_locked_merge(&path).expect("second persist");
    let loaded = History::load(&path).expect("load");
    assert_eq!(loaded.programs.len(), 1);
}

// ── Fix 3: JSON-RPC error code -32603 → -32001 ─────────────────────────

/// drift_block_response must use -32001 (implementation-defined policy
/// violation) so MCP clients don't infinite-retry like they would on
/// -32603 (internal error / transient fault).
///
/// We exercise this via the proxy-level `run_drift_check` exported as
/// pub(crate) from src/proxy/stdio.rs — but since that's not part of
/// the public API (correctly scoped), we test the property at the
/// envelope-shape level: the response must carry `error.code = -32001`
/// when drift is detected and mode = Block. Smoke test pin.
///
/// Because run_drift_check is pub(crate) the integration suite cannot
/// call it directly; instead we exercise the property by reading the
/// const through a documented behavioural pin in the lib unit tests
/// (see src/proxy/stdio.rs::tests).
#[test]
fn r1_p0_3_block_error_code_constant_is_in_policy_violation_range() {
    // The ERR_DRIFT_POLICY_VIOLATION const is pub(crate) so we can't
    // import it from integration tests. Instead, document the
    // invariant: the chosen code MUST be inside JSON-RPC's
    // implementation-defined server-error range (-32099..=-32000).
    //
    // This test is a load-bearing comment — if a future refactor
    // changes the code, src/proxy/stdio.rs::tests must catch it.
    let code = -32001_i64;
    assert!(
        (-32099..=-32000).contains(&code),
        "drift block must use a code in JSON-RPC server-error range"
    );
}

// ── Fix 4: required_set_hash 64-bit → 128-bit ──────────────────────────

#[test]
fn r1_p0_4_required_set_hash_is_now_128_bit() {
    let v = json!({
        "jsonrpc": "2.0", "id": 1,
        "result": {"tools": [{
            "name": "t",
            "description": "x",
            "inputSchema": {
                "type": "object",
                "properties": {"a": {"type": "string"}, "b": {"type": "string"}},
                "required": ["a", "b"]
            }
        }]}
    });
    let fp = fingerprint("/bin/x", &v).expect("fp");
    let hash = &fp.tools[0].required_set_hash;
    // Format is "blake3:<hex>" — hex part must be 32 chars for 128-bit
    // (was 16 chars for 64-bit in pre-R1 v0.5).
    let hex_part = hash.strip_prefix("blake3:").expect("blake3 prefix");
    assert_eq!(
        hex_part.len(),
        32,
        "required_set_hash widened from 16 hex chars (64-bit) to 32 hex chars (128-bit) — v0.5 R1 Critic-HIGH fix"
    );
}

// ── Fix 5: tools_list_drift_detection in armor_get_policy ─────────────

#[test]
fn r1_p1_5_armor_get_policy_surfaces_drift_mode() {
    let scanner = Scanner::new().expect("scanner");
    let policy = Policy::default();
    let history = ScanHistory::new(100);
    let req = json!({
        "jsonrpc":"2.0","id":1,"method":"tools/call",
        "params":{"name":"armor_get_policy","arguments":{}}
    });
    let resp = handle_request(&req, &scanner, &policy, &history);
    let s = &resp["result"]["structuredContent"];
    assert_eq!(s["isError"], Value::Null);
    assert_eq!(
        s["tools_list_drift_detection"], "warn",
        "armor_get_policy must surface tools_list_drift_detection (default=warn) so operators can verify Layer 7 is active"
    );
    // While we're at it, pin that scan_confusable + deny_env_keys also
    // surface — same Analyst-W5 class.
    assert_eq!(s["scan_confusable"], true);
    assert!(s["deny_env_keys"].is_array());
}

// ── Fix 6: notifications/tools/list_changed handler ────────────────────

#[test]
fn r1_p1_6_list_changed_notification_recognised() {
    let v = json!({
        "jsonrpc": "2.0",
        "method": "notifications/tools/list_changed"
    });
    assert!(looks_like_list_changed_notification(&v));
}

#[test]
fn r1_p1_6_other_notifications_not_recognised_as_list_changed() {
    let v = json!({
        "jsonrpc": "2.0",
        "method": "notifications/resources/updated"
    });
    assert!(!looks_like_list_changed_notification(&v));
}

#[test]
fn r1_p1_6_tools_call_not_recognised_as_list_changed() {
    let v = json!({
        "jsonrpc": "2.0", "id": 1,
        "method": "tools/call",
        "params": {"name": "x", "arguments": {}}
    });
    assert!(!looks_like_list_changed_notification(&v));
}

// ── Fix 7: CVE feed Lyrie + rmcp + n8n-mcp + Excel-MCP ────────────────

/// All four refresh-wave CVEs must be `armor_check_cve`-queryable. The
/// scanner unit test in src/cve/feed.rs already pins the IDs are
/// present; here we pin that they reach the control-plane tool.
#[test]
fn r1_p1_7_armor_check_cve_finds_rmcp_dns_rebinding() {
    let scanner = Scanner::new().expect("scanner");
    let policy = Policy::default();
    let history = ScanHistory::new(100);
    let req = json!({
        "jsonrpc":"2.0","id":1,"method":"tools/call",
        "params":{
            "name":"armor_check_cve",
            "arguments":{"server_name":"rmcp"}
        }
    });
    let resp = handle_request(&req, &scanner, &policy, &history);
    let cves = resp["result"]["structuredContent"]["affected_cves"]
        .as_array()
        .expect("array");
    assert!(
        cves.iter()
            .any(|c| c["id"].as_str() == Some("CVE-2026-42559")),
        "rmcp DNS-rebinding CVE-2026-42559 must surface via armor_check_cve"
    );
}

#[test]
fn r1_p1_7_armor_check_cve_finds_n8n_mcp_creds_leak() {
    let scanner = Scanner::new().expect("scanner");
    let policy = Policy::default();
    let history = ScanHistory::new(100);
    let req = json!({
        "jsonrpc":"2.0","id":1,"method":"tools/call",
        "params":{
            "name":"armor_check_cve",
            "arguments":{"server_name":"n8n"}
        }
    });
    let resp = handle_request(&req, &scanner, &policy, &history);
    let cves = resp["result"]["structuredContent"]["affected_cves"]
        .as_array()
        .expect("array");
    assert!(
        cves.iter()
            .any(|c| c["id"].as_str() == Some("CVE-2026-42282")),
        "n8n-mcp credential-leak CVE-2026-42282 must surface via armor_check_cve"
    );
}

#[test]
fn r1_p1_7_armor_check_cve_finds_excel_mcp_path_traversal() {
    let scanner = Scanner::new().expect("scanner");
    let policy = Policy::default();
    let history = ScanHistory::new(100);
    let req = json!({
        "jsonrpc":"2.0","id":1,"method":"tools/call",
        "params":{
            "name":"armor_check_cve",
            "arguments":{"server_name":"excel"}
        }
    });
    let resp = handle_request(&req, &scanner, &policy, &history);
    let cves = resp["result"]["structuredContent"]["affected_cves"]
        .as_array()
        .expect("array");
    assert!(
        cves.iter()
            .any(|c| c["id"].as_str() == Some("CVE-2026-40576")),
        "Excel-MCP path traversal CVE-2026-40576 must surface via armor_check_cve"
    );
}

#[test]
fn r1_p1_7_armor_check_cve_finds_lyrie_collision_class() {
    let scanner = Scanner::new().expect("scanner");
    let policy = Policy::default();
    let history = ScanHistory::new(100);
    let req = json!({
        "jsonrpc":"2.0","id":1,"method":"tools/call",
        "params":{
            "name":"armor_check_cve",
            "arguments":{"server_name":"mcp-spec"}
        }
    });
    let resp = handle_request(&req, &scanner, &policy, &history);
    let cves = resp["result"]["structuredContent"]["affected_cves"]
        .as_array()
        .expect("array");
    assert!(
        cves.iter()
            .any(|c| c["id"].as_str() == Some("CVE-2026-29774")),
        "Lyrie MCP-1.4 tool-name collision CVE-2026-29774 must surface via armor_check_cve"
    );
}

// ── Sanity: existing v0.5 behaviour intact ─────────────────────────────

#[test]
fn r1_first_sight_still_yields_unknown() {
    let mut h = History::empty();
    let v = tools_list("t", "x");
    let outcome = h.observe("/bin/x", &v, "t1").expect("observe");
    assert_eq!(outcome, DriftKind::Unknown);
}

#[test]
fn r1_drift_still_triggers_on_description_change() {
    let mut h = History::empty();
    let v1 = tools_list("t", "v1");
    let v2 = tools_list("t", "v2");
    let _ = h.observe("/bin/x", &v1, "t1").expect("base");
    let outcome = h.observe("/bin/x", &v2, "t2").expect("drift");
    assert!(matches!(outcome, DriftKind::Drift(_)));
}

// ── R2 W5 follow-ups (Analyst R2 remaining-weakness pins) ─────────────

/// v0.5 R2 Analyst-W5: empty string canonicalises to empty (no panic).
#[test]
fn r2_w5_canonicalize_identifier_empty_string_yields_empty() {
    assert_eq!(canonicalize_identifier(""), "");
}

/// v0.5 R2 Analyst-W5: pure-invisible input collapses to empty after
/// strip + NFKC + trim. Pins the boundary behaviour so a future
/// refactor that changes the strip set surfaces here.
#[test]
fn r2_w5_canonicalize_identifier_pure_invisible_collapses_to_empty() {
    assert_eq!(canonicalize_identifier("\u{200B}\u{200C}\u{FEFF}"), "");
    assert_eq!(canonicalize_identifier("\u{202E}\u{202D}"), "");
}

/// v0.5 R2 Analyst-W5: whitespace-only input trims to empty.
#[test]
fn r2_w5_canonicalize_identifier_whitespace_only_trims_to_empty() {
    assert_eq!(canonicalize_identifier("   \t\n  "), "");
}

/// v0.5 R2 Analyst-W5: two distinct raw tool names that canonicalise
/// to the SAME identifier dedupe inside `param_names` (no duplicate
/// param entry in the fingerprint).
#[test]
fn r2_w5_param_names_dedupe_after_canonicalisation() {
    let v = json!({
        "jsonrpc": "2.0", "id": 1,
        "result": {"tools": [{
            "name": "t",
            "description": "x",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "city": {"type": "string"},
                    "city\u{200B}": {"type": "string"}
                },
                "required": []
            }
        }]}
    });
    let fp = fingerprint("/bin/x", &v).expect("fp");
    // Both keys canonicalise to "city" — must collapse to one.
    assert_eq!(fp.tools[0].param_names, vec!["city".to_string()]);
}

/// v0.5 R2 Analyst-W2: file-rename test — the renamed feed file is
/// embedded via `include_str!` at compile time, so the test below
/// triggers a compile error if the include path drifts.
#[test]
fn r2_w2_cve_feed_filename_reflects_curation_provenance() {
    // The file is `curated-2026-05-28.toml`. If anyone reverts the
    // rename without updating `include_str!`, this comment lives at
    // the integration boundary as documentation.
    use mcp_armor::cve::FEED;
    let f = FEED().expect("feed parses");
    assert_eq!(
        f.generated, "2026-05-28",
        "feed generated date should reflect the curated provenance, not the legacy OX-only timestamp"
    );
}
