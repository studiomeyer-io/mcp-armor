use crate::error::ArmorError;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

const FEED_TOML: &str = include_str!("../../cve-feed/ox-advisory-2026-04-15.toml");

/// CVE severity level. Constrained enum (was `String` — F9 lift).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Cve {
    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub fixed_in: String,
    /// Optional semver `VersionReq` matching the affected version range
    /// (e.g. `"<2.4.0"`). Added in v0.1.0 to support `armor_check_cve`
    /// version-aware matching (Reviewer F6 fix, S983). When `None`, the
    /// caller falls back to the legacy substring match on `fixed_in`.
    #[serde(default)]
    pub affected_versions: Option<String>,
    pub simulate_payload: String,
    pub expected_pattern_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CveFeed {
    pub generated: String,
    pub schema_version: u32,
    pub cves: Vec<Cve>,
}

static FEED_CELL: OnceLock<CveFeed> = OnceLock::new();

/// Get the compiled-in feed. Parsed lazily on first call. Returns
/// `&'static CveFeed` so callers do not pay the parse cost more than once.
pub fn feed() -> Result<&'static CveFeed, ArmorError> {
    if let Some(f) = FEED_CELL.get() {
        return Ok(f);
    }
    let parsed: CveFeed = toml::from_str(FEED_TOML)?;
    let _ = FEED_CELL.set(parsed);
    Ok(FEED_CELL.get().expect("feed just set"))
}

/// Backwards-compatible alias kept for call sites that pre-date the rename.
#[doc(hidden)]
#[allow(non_snake_case)]
pub fn FEED() -> Result<&'static CveFeed, ArmorError> {
    feed()
}

impl CveFeed {
    pub fn find(&self, id: &str) -> Option<&Cve> {
        self.cves.iter().find(|c| c.id.eq_ignore_ascii_case(id))
    }

    pub fn ids(&self) -> Vec<String> {
        self.cves.iter().map(|c| c.id.clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feed_parses() {
        let f = FEED().expect("feed must parse");
        assert_eq!(
            f.cves.len(),
            10,
            "expected exactly 10 CVEs in OX advisory feed"
        );
    }

    #[test]
    fn every_cve_has_simulate_payload() {
        let f = FEED().expect("feed must parse");
        for c in &f.cves {
            assert!(
                !c.simulate_payload.is_empty(),
                "{} missing simulate_payload",
                c.id
            );
            assert!(
                !c.expected_pattern_id.is_empty(),
                "{} missing pattern id",
                c.id
            );
        }
    }

    #[test]
    fn find_is_case_insensitive() {
        let f = FEED().expect("feed must parse");
        assert!(f.find("cve-2026-27124").is_some());
        assert!(f.find("CVE-2026-27124").is_some());
        assert!(f.find("CVE-9999-0000").is_none());
    }
}
