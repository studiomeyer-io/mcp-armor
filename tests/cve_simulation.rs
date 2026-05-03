//! Pillar-3 falsifiable test: every CVE in the curated feed has a
//! `simulate_payload` and an `expected_pattern_id`. The scanner must produce
//! `verdict == Block` for each. PLAN.md Success Criteria.

use mcp_armor::cve::FEED;
use mcp_armor::{ScanVerdict, Scanner};

#[test]
fn every_cve_simulate_payload_is_blocked() {
    let scanner = Scanner::new().expect("scanner builds");
    let feed = FEED().expect("cve feed parses");
    assert!(!feed.cves.is_empty(), "feed must contain at least one CVE");

    for cve in &feed.cves {
        let result = scanner.scan(&cve.simulate_payload);
        assert_eq!(
            result.verdict,
            ScanVerdict::Block,
            "{}: simulate_payload should block, got {:?} (matched={:?})",
            cve.id,
            result.verdict,
            result.matched_patterns
        );
        assert!(
            result.matched_patterns.contains(&cve.expected_pattern_id),
            "{}: scanner did not match expected_pattern_id={}, matched={:?}",
            cve.id,
            cve.expected_pattern_id,
            result.matched_patterns
        );
        assert!(
            result
                .cve_refs
                .iter()
                .any(|r| r.eq_ignore_ascii_case(&cve.id)),
            "{}: cve_refs should include this CVE, got {:?}",
            cve.id,
            result.cve_refs
        );
    }
}

#[test]
fn clean_payload_does_not_block() {
    let scanner = Scanner::new().expect("scanner");
    let r = scanner.scan("normal user input asking about the weather");
    assert_eq!(r.verdict, ScanVerdict::Allow);
    assert!(r.matched_patterns.is_empty());
}
