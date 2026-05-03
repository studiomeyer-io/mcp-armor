//! In-memory ring-buffer scan history. Default mode (no `audit-db` feature):
//! 10k-entry circular buffer, no disk write. Read by `armor_list_blocked`.

use crate::scanner::{ScanResult, ScanVerdict};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub ts_iso: String,
    pub direction: String,
    pub matched_patterns: Vec<String>,
    pub cve_refs: Vec<String>,
    pub latency_us: u64,
}

pub struct ScanHistory {
    inner: Mutex<RingBuffer>,
}

struct RingBuffer {
    entries: Vec<HistoryEntry>,
    cap: usize,
    head: usize,
    len: usize,
    total_blocked: u64,
}

impl ScanHistory {
    pub fn new(cap: usize) -> Self {
        let cap = cap.max(1);
        Self {
            inner: Mutex::new(RingBuffer {
                entries: Vec::with_capacity(cap),
                cap,
                head: 0,
                len: 0,
                total_blocked: 0,
            }),
        }
    }

    /// Record a scan result. Only block-verdict entries are kept (audit
    /// budget — allow-verdict scans would flood the buffer).
    pub fn record(&self, direction: &str, result: &ScanResult) {
        if !matches!(result.verdict, ScanVerdict::Block) {
            return;
        }
        let entry = HistoryEntry {
            ts_iso: now_iso(),
            direction: direction.to_string(),
            matched_patterns: result.matched_patterns.clone(),
            cve_refs: result.cve_refs.clone(),
            latency_us: result.latency_us,
        };
        let mut buf = self.inner.lock().expect("history mutex");
        buf.total_blocked += 1;
        if buf.entries.len() < buf.cap {
            buf.entries.push(entry);
            buf.len = buf.entries.len();
        } else {
            let head = buf.head;
            buf.entries[head] = entry;
            buf.head = (buf.head + 1) % buf.cap;
            buf.len = buf.cap;
        }
    }

    /// Return a snapshot of the buffer in chronological order. `since_iso`
    /// is a coarse string filter (lexicographic compare on ISO-8601). Limit
    /// caps the output count.
    pub fn snapshot(&self, since_iso: Option<&str>, limit: Option<usize>) -> Vec<HistoryEntry> {
        let buf = self.inner.lock().expect("history mutex");
        let mut out: Vec<HistoryEntry> = if buf.len < buf.cap {
            buf.entries.iter().cloned().collect()
        } else {
            let mut combined = Vec::with_capacity(buf.cap);
            combined.extend_from_slice(&buf.entries[buf.head..]);
            combined.extend_from_slice(&buf.entries[..buf.head]);
            combined
        };
        if let Some(s) = since_iso {
            out.retain(|e| e.ts_iso.as_str() >= s);
        }
        if let Some(n) = limit {
            out.truncate(n);
        }
        out
    }

    pub fn total_blocked(&self) -> u64 {
        self.inner.lock().expect("history mutex").total_blocked
    }
}

fn now_iso() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    format_rfc3339_utc(secs)
}

/// Format a Unix timestamp (seconds since 1970-01-01 UTC) as an RFC-3339
/// UTC string, e.g. `2026-05-03T14:23:45Z`. Pure-stdlib civil-from-days
/// (Howard Hinnant's algorithm shifted to a 1970 epoch); proleptic
/// Gregorian, valid 1970..9999. No chrono dep, no sub-second precision.
fn format_rfc3339_utc(unix_secs: i64) -> String {
    let secs_per_day: i64 = 86_400;
    let days = unix_secs.div_euclid(secs_per_day);
    let secs_in_day = unix_secs.rem_euclid(secs_per_day);
    let hour = secs_in_day / 3600;
    let minute = (secs_in_day % 3600) / 60;
    let second = secs_in_day % 60;

    let (year, month, day) = civil_from_days(days);

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Convert "days since 1970-01-01" into a (year, month, day) civil date.
/// Howard Hinnant's algorithm (proleptic Gregorian, correct for the full
/// 100/400 leap-year rule). Reference:
/// https://howardhinnant.github.io/date_algorithms.html#civil_from_days
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    // Shift epoch from 1970-01-01 to 0000-03-01 to simplify month math.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let year = y + i64::from(u8::from(m <= 2));
    (year, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block_result(pattern: &str) -> ScanResult {
        ScanResult {
            verdict: ScanVerdict::Block,
            matched_patterns: vec![pattern.to_string()],
            cve_refs: vec!["CVE-X".to_string()],
            latency_us: 42,
        }
    }

    #[test]
    fn allow_results_skipped() {
        let h = ScanHistory::new(10);
        let r = ScanResult {
            verdict: ScanVerdict::Allow,
            matched_patterns: vec![],
            cve_refs: vec![],
            latency_us: 5,
        };
        h.record("inbound", &r);
        assert_eq!(h.total_blocked(), 0);
        assert!(h.snapshot(None, None).is_empty());
    }

    #[test]
    fn block_results_kept() {
        let h = ScanHistory::new(10);
        h.record("inbound", &block_result("shell_substitution"));
        h.record("outbound", &block_result("javascript_uri"));
        assert_eq!(h.total_blocked(), 2);
        assert_eq!(h.snapshot(None, None).len(), 2);
    }

    #[test]
    fn ring_buffer_overwrites_oldest() {
        let h = ScanHistory::new(2);
        h.record("inbound", &block_result("a"));
        h.record("inbound", &block_result("b"));
        h.record("inbound", &block_result("c"));
        let snap = h.snapshot(None, None);
        assert_eq!(snap.len(), 2);
        assert_eq!(h.total_blocked(), 3);
        assert_eq!(snap[1].matched_patterns[0], "c");
    }

    #[test]
    fn rfc3339_unix_epoch() {
        assert_eq!(format_rfc3339_utc(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn rfc3339_known_date() {
        // 2026-05-03T12:34:56Z corresponds to a known unix timestamp:
        // (2026-1970)*365.25 ≈ 20_456 days plus leap days. Compute via
        // civil_from_days roundtrip rather than hand-magic.
        // 2026-05-03 = day 20_576 since 1970-01-01.
        let secs: i64 = 20_576 * 86_400 + 12 * 3600 + 34 * 60 + 56;
        assert_eq!(format_rfc3339_utc(secs), "2026-05-03T12:34:56Z");
    }

    #[test]
    fn rfc3339_handles_leap_year_feb_29() {
        // 2024-02-29 = day 19_782 since 1970-01-01.
        let secs: i64 = 19_782 * 86_400;
        assert_eq!(format_rfc3339_utc(secs), "2024-02-29T00:00:00Z");
    }

    #[test]
    fn rfc3339_lex_sortable_against_user_iso() {
        // The whole point of F7: a user-supplied ISO threshold like
        // "2026-01-01T00:00:00Z" must lex-compare correctly against the
        // generated entry timestamps.
        let secs: i64 = 20_576 * 86_400 + 12 * 3600;
        let ts = format_rfc3339_utc(secs);
        assert!(ts.as_str() > "2026-01-01T00:00:00Z");
        assert!(ts.as_str() < "2027-01-01T00:00:00Z");
    }

    #[test]
    fn limit_caps_output() {
        let h = ScanHistory::new(10);
        for _ in 0..5 {
            h.record("inbound", &block_result("a"));
        }
        assert_eq!(h.snapshot(None, Some(3)).len(), 3);
    }
}
