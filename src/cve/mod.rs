//! CVE feed compiled at build time from `cve-feed/ox-advisory-2026-04-15.toml`.
//! Static feed — updates ship as new releases (R3 in PLAN.md).

pub mod feed;

pub use feed::{Cve, CveFeed, Severity, FEED};
