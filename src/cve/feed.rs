use crate::error::ArmorError;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

const FEED_TOML: &str = include_str!("../../cve-feed/advisories-2026-11-01.toml");
const SIMULATIONS_TOML: &str = include_str!("../../cve-feed/simulations.toml");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    /// The checked primary evidence did not establish severity.
    Unknown,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Unknown => "unknown",
        }
    }
}

/// A primary-source-verified advisory. It does not assert that a scanner
/// pattern detects this product vulnerability or that wrapping fixes it.
#[derive(Debug, Clone, Deserialize)]
pub struct Cve {
    pub id: String,
    pub product: String,
    #[serde(default)]
    pub product_aliases: Vec<String>,
    pub severity: Severity,
    pub title: String,
    /// A verified fixed version, or the explicit value `unknown`.
    pub fixed_in: String,
    pub affected_versions: Option<String>,
    pub source_url: String,
    pub checked_at: String,
    /// Legacy source-compatibility fields. Genuine advisories do not carry
    /// generic scanner fixtures; these remain empty. Use `simulations()`.
    #[serde(default)]
    pub simulate_payload: String,
    #[serde(default)]
    pub expected_pattern_id: String,
}

impl Cve {
    pub fn matches_product(&self, name: &str) -> bool {
        self.product.eq_ignore_ascii_case(name.trim())
            || self
                .product_aliases
                .iter()
                .any(|alias| alias.eq_ignore_ascii_case(name.trim()))
    }

    /// `affected` only for the primary source's explicit affected range.
    /// A known affected example with no fixed version cannot establish the
    /// status of any other version. Direct comparisons include prereleases,
    /// unlike VersionReq's implicit exclusion of most prerelease versions.
    pub fn version_status(&self, version: Option<&str>) -> &'static str {
        let Some(raw) = version else {
            return "not_checked";
        };
        let Ok(version) = semver::Version::parse(raw.trim().trim_start_matches('v')) else {
            return "unknown";
        };
        let Some(range) = self.affected_versions.as_deref() else {
            return "unknown";
        };
        let (op, boundary) = if let Some(v) = range.strip_prefix("<=") {
            ("<=", v)
        } else if let Some(v) = range.strip_prefix('<') {
            ("<", v)
        } else if let Some(v) = range.strip_prefix('=') {
            ("=", v)
        } else {
            return "unknown";
        };
        let Ok(boundary) = semver::Version::parse(boundary.trim()) else {
            return "unknown";
        };
        let affected = match op {
            "<=" => version.cmp_precedence(&boundary).is_le(),
            "<" => version.cmp_precedence(&boundary).is_lt(),
            _ => version.cmp_precedence(&boundary).is_eq(),
        };
        if affected {
            return "affected";
        }
        if semver::Version::parse(&self.fixed_in)
            .is_ok_and(|fixed| version.cmp_precedence(&fixed).is_ge())
        {
            "not_affected"
        } else {
            "unknown"
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CveFeed {
    pub generated: String,
    pub schema_version: u32,
    pub cves: Vec<Cve>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Simulation {
    pub id: String,
    pub title: String,
    /// Migration alias for old armor_simulate_attack input only. It is not
    /// a claimed relationship between this fixture and the named CVE.
    pub legacy_cve_id: String,
    pub simulate_payload: String,
    pub expected_pattern_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SimulationFeed {
    pub generated: String,
    pub schema_version: u32,
    pub simulations: Vec<Simulation>,
}

impl SimulationFeed {
    pub fn find(&self, id: &str) -> Option<&Simulation> {
        self.simulations
            .iter()
            .find(|s| s.id.eq_ignore_ascii_case(id))
    }

    pub fn resolve_legacy(&self, id: &str) -> Option<&Simulation> {
        self.simulations
            .iter()
            .find(|s| s.legacy_cve_id.eq_ignore_ascii_case(id))
    }
}

static FEED_CELL: OnceLock<CveFeed> = OnceLock::new();
static SIMULATIONS_CELL: OnceLock<SimulationFeed> = OnceLock::new();

pub fn feed() -> Result<&'static CveFeed, ArmorError> {
    if let Some(f) = FEED_CELL.get() {
        return Ok(f);
    }
    let parsed: CveFeed = toml::from_str(FEED_TOML)?;
    let _ = FEED_CELL.set(parsed);
    Ok(FEED_CELL.get().expect("feed just set"))
}

pub fn simulations() -> Result<&'static SimulationFeed, ArmorError> {
    if let Some(f) = SIMULATIONS_CELL.get() {
        return Ok(f);
    }
    let parsed: SimulationFeed = toml::from_str(SIMULATIONS_TOML)?;
    let _ = SIMULATIONS_CELL.set(parsed);
    Ok(SIMULATIONS_CELL.get().expect("simulations just set"))
}

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
    fn real_advisories_have_primary_provenance_and_no_scanner_claims() {
        let f = FEED().expect("advisories");
        assert_eq!(f.cves.len(), 10);
        assert_eq!(f.generated, "2026-11-01");
        for c in &f.cves {
            assert!(c.id.starts_with("CVE-"));
            assert_eq!(
                c.source_url,
                format!("https://nvd.nist.gov/vuln/detail/{}", c.id)
            );
            assert_eq!(c.checked_at, "2026-11-01");
            assert!(!c.product.is_empty());
            assert!(c.simulate_payload.is_empty() && c.expected_pattern_id.is_empty());
        }
        for unrelated in [
            "CVE-2026-30888",
            "CVE-2026-29774",
            "CVE-2026-31955",
            "CVE-2026-31104",
            "CVE-2026-31312",
            "CVE-2026-53881",
        ] {
            assert!(
                f.find(unrelated).is_none(),
                "unrelated or unverified advisory: {unrelated}"
            );
        }
    }

    #[test]
    fn all_sixteen_internal_fixtures_keep_distinct_ids_and_payloads() {
        let f = simulations().expect("simulations");
        assert_eq!(f.simulations.len(), 16);
        let mut ids = std::collections::BTreeSet::new();
        for s in &f.simulations {
            assert!(s.id.starts_with("ARMOR-SIM-"));
            assert!(ids.insert(&s.id));
            assert!(!s.simulate_payload.is_empty() && !s.expected_pattern_id.is_empty());
            assert_eq!(f.find(&s.id).expect("lookup").id, s.id);
        }
    }

    #[test]
    fn prereleases_and_unknown_fixes_are_not_invented_safe_versions() {
        let f = FEED().expect("feed");
        let libre = f.find("CVE-2026-22252").expect("LibreChat");
        assert_eq!(libre.version_status(Some("0.8.2-rc1")), "affected");
        assert_eq!(libre.version_status(Some("0.8.2-rc2")), "not_affected");
        assert_eq!(libre.version_status(Some("0.8.2")), "not_affected");
        let windsurf = f.find("CVE-2026-30615").expect("Windsurf");
        assert_eq!(windsurf.fixed_in, "unknown");
        assert_eq!(windsurf.version_status(Some("1.9544.26")), "affected");
        assert_eq!(windsurf.version_status(Some("1.9544.27")), "unknown");
        assert_eq!(windsurf.version_status(Some("1.0.0")), "unknown");
        assert_eq!(windsurf.version_status(Some("garbage")), "unknown");
    }
}
