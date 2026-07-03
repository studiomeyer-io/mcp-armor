//! CVE feed compiled at build time from `cve-feed/curated-2026-07-03.toml`.
//! Static feed — updates ship as new releases (R3 in PLAN.md).

pub mod feed;

pub use feed::{Cve, CveFeed, Severity, FEED};
