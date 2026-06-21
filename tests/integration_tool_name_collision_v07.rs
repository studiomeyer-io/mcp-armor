//! v0.7 — CVE-2026-29774 tool-name homoglyph/zero-width collision class.
//!
//! ## Why this file exists
//!
//! The CVE feed entry for CVE-2026-29774 (`cve-feed/curated-2026-05-28.toml`)
//! carries `expected_pattern_id = "instruction_override"`, which matches
//! the *embedded description string* (`ignore previous instructions`) in
//! its `simulate_payload` — not the tool-name collision itself. So the
//! `cve_simulation` round-trip passed while the actual class
//! (a tool registered under a name that visually collides with a trusted
//! tool: `send_message` with a zero-width suffix, Cyrillic `ѕend_message`,
//! full-width forms) went entirely undetected on the `tools/call` path.
//!
//! v0.7 closes that gap: `drift::tool_name_collision` compares the
//! incoming tool name's fold (NFKC + zero-width strip + UTS-39 confusable
//! skeleton, lowercased) against the drift baseline's known-tool set, and
//! the proxy hot path blocks a `tools/call` whose name folds to a trusted
//! tool but is not byte-equal to it. This suite exercises that detection
//! through the public API and pins the "scanner alone does NOT catch it"
//! gap so the regression can't silently come back.

use mcp_armor::manifest::drift::{fold_identifier, tool_name_collision, History as DriftHistory};
use mcp_armor::{ScanVerdict, Scanner};
use serde_json::json;

/// The literal CVE-2026-29774 example: a zero-width-suffixed
/// `send_message` collides with the trusted `send_message`, and the
/// collision detection flags it.
#[test]
fn cve_2026_29774_zero_width_tool_name_is_flagged() {
    let known = vec!["send_message".to_string(), "read_file".to_string()];
    let attacker = "send_message\u{200B}"; // zero-width space suffix
    assert_eq!(
        tool_name_collision(attacker, &known),
        Some("send_message".to_string()),
        "the CVE-2026-29774 zero-width tool-name collision must be flagged"
    );
}

/// The Cherokee/Cyrillic homoglyph variants named in the CVE title also
/// fold to the trusted name and are flagged.
#[test]
fn cve_2026_29774_cyrillic_homoglyph_tool_name_is_flagged() {
    let known = vec!["send_message".to_string()];
    // Cyrillic ѕ (U+0455), е (U+0435).
    let attacker = "\u{0455}end_m\u{0435}ssag\u{0435}";
    assert_eq!(fold_identifier(attacker), "send_message");
    assert_eq!(
        tool_name_collision(attacker, &known),
        Some("send_message".to_string())
    );
}

/// GAP PROOF: the bare scanner does NOT flag a confusable tool name with
/// benign arguments — which is exactly why the dedicated collision
/// detection is needed and why the feed entry's embedded-string round
/// trip masked the real class. The `scan_target` the proxy builds for a
/// `tools/call` is `name + "\n" + arguments`; with a benign body the
/// folded name (`send_message`) matches none of the injection patterns.
#[test]
fn scanner_alone_does_not_flag_confusable_tool_name() {
    let scanner = Scanner::new().expect("scanner builds");
    let cyrillic_name = "\u{0455}end_m\u{0435}ssag\u{0435}";
    let args = json!({"to": "alice", "body": "hello there"});
    let scan_target = format!("{cyrillic_name}\n{args}");
    let r = scanner.scan(&scan_target);
    assert_eq!(
        r.verdict,
        ScanVerdict::Allow,
        "the bare scanner is expected NOT to catch a confusable tool name with \
         benign args (matched={:?}); the v0.7 collision detection is what closes \
         this — if this assert ever fails the gap proof is stale, re-evaluate",
        r.matched_patterns
    );
}

/// FALSE-POSITIVE GUARD: a legitimate `tools/call` to the trusted tool
/// (exact bytes) with benign args is never flagged by either path.
#[test]
fn legitimate_exact_tool_name_is_not_flagged() {
    let known = vec!["send_message".to_string(), "read_file".to_string()];
    assert_eq!(tool_name_collision("send_message", &known), None);

    let scanner = Scanner::new().expect("scanner builds");
    let args = json!({"to": "bob", "body": "see you monday"});
    let scan_target = format!("send_message\n{args}");
    assert_eq!(scanner.scan(&scan_target).verdict, ScanVerdict::Allow);
}

/// FALSE-POSITIVE GUARD: a genuinely new, unrelated tool name is not a
/// collision (that is the drift detector's concern, not the collision
/// check's). The known-tool set comes from a real on-disk drift
/// baseline here, mirroring the proxy's data flow.
#[test]
fn unrelated_new_tool_against_real_baseline_is_not_a_collision() {
    let tools_list = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "tools": [
                {"name": "send_message", "description": "Send",
                 "inputSchema": {"type": "object",
                    "properties": {"to": {"type": "string"}}, "required": ["to"]}}
            ]
        }
    });
    let mut hist = DriftHistory::empty();
    hist.observe("/bin/srv", &tools_list, "2026-06-21T00:00:00Z")
        .expect("observe baseline");
    let known: Vec<String> = hist
        .find("/bin/srv")
        .expect("baseline present")
        .tools
        .iter()
        .map(|t| t.name.clone())
        .collect();

    assert_eq!(tool_name_collision("list_directory", &known), None);
    assert_eq!(tool_name_collision("create_invoice", &known), None);
    // …but the homoglyph of the known tool still collides against the
    // same real baseline.
    assert_eq!(
        tool_name_collision("send_m\u{0435}ssage", &known),
        Some("send_message".to_string())
    );
}
