//! Every internal fixture tests a scanner signal, never a product exploit.
use mcp_armor::cve::simulations;
use mcp_armor::{ScanVerdict, Scanner};

#[test]
fn every_internal_simulation_retains_its_signal_without_claiming_a_cve() {
    let scanner = Scanner::new().expect("scanner");
    let feed = simulations().expect("simulations");
    assert_eq!(feed.simulations.len(), 16);
    for fixture in &feed.simulations {
        let result = scanner.scan(&fixture.simulate_payload);
        assert_eq!(
            result.verdict,
            ScanVerdict::Block,
            "{}: {:?}",
            fixture.id,
            result.matched_patterns
        );
        assert!(
            result
                .matched_patterns
                .contains(&fixture.expected_pattern_id),
            "{} missing {}",
            fixture.id,
            fixture.expected_pattern_id
        );
        assert!(
            result.cve_refs.is_empty(),
            "generic signal cannot prove a product vulnerability"
        );
        assert!(
            result.simulation_refs.contains(&fixture.id),
            "missing simulation ref {}",
            fixture.id
        );
        assert!(result
            .simulation_refs
            .iter()
            .all(|id| id.starts_with("ARMOR-SIM-")));
    }
}

#[test]
fn clean_payload_does_not_block() {
    let scanner = Scanner::new().expect("scanner");
    let result = scanner.scan("normal user input asking about the weather");
    assert_eq!(result.verdict, ScanVerdict::Allow);
    assert!(result.matched_patterns.is_empty());
    assert!(result.cve_refs.is_empty() && result.simulation_refs.is_empty());
}
