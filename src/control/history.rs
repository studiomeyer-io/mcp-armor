//! In-memory ring-buffer scan history: 10k-entry circular buffer, no disk
//! write. Read by `armor_list_blocked`.
//!
//! Persistent (SQLite-backed) history is a v0.3 backlog item. The v0.1/v0.2
//! `audit-db` Cargo feature was a non-functional declaration that landed
//! without a corresponding code path (Round-1-review finding A#2). It was
//! removed in v0.2.0 to avoid shipping the "empty feature flag" Lumina
//! anti-pattern (S982). v0.3 will re-introduce both the feature and the
//! `rusqlite`-backed implementation together.

use crate::scanner::{ScanResult, ScanVerdict};
use crate::util::now_iso;
use serde::{Deserialize, Serialize};
use std::sync::{Mutex, MutexGuard, PoisonError};

/// Recover the inner data on poison instead of panicking.
///
/// `expect()` on a poisoned mutex would crash the sidecar — fatal in a
/// stdio proxy where the parent client cannot restart us. The history is
/// audit/observability data, not a security gate; recovering the inner
/// `RingBuffer` is correct (worst case one entry was half-written).
fn lock_inner<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

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
        let mut buf = lock_inner(&self.inner);
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
        let buf = lock_inner(&self.inner);
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
        lock_inner(&self.inner).total_blocked
    }
}

// v0.6 — local rfc3339 + civil-from-days helpers collapsed into
// `crate::util` (`use crate::util::now_iso` at the top of this file).
// The v0.2 "deliberate de-dup avoidance" rationale was correct for
// two-call-sites; with v0.5 it grew to three (drift.rs joined) and
// the drift risk on the next shape change overtook the layering
// preservation argument. `crate::util` sits below `control` so the
// dependency direction is still intact.

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
        assert_eq!(crate::util::format_rfc3339_utc(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn rfc3339_known_date() {
        // 2026-05-03T12:34:56Z corresponds to a known unix timestamp:
        // (2026-1970)*365.25 ≈ 20_456 days plus leap days. Compute via
        // civil_from_days roundtrip rather than hand-magic.
        // 2026-05-03 = day 20_576 since 1970-01-01.
        let secs: i64 = 20_576 * 86_400 + 12 * 3600 + 34 * 60 + 56;
        assert_eq!(
            crate::util::format_rfc3339_utc(secs),
            "2026-05-03T12:34:56Z"
        );
    }

    #[test]
    fn rfc3339_handles_leap_year_feb_29() {
        // 2024-02-29 = day 19_782 since 1970-01-01.
        let secs: i64 = 19_782 * 86_400;
        assert_eq!(
            crate::util::format_rfc3339_utc(secs),
            "2024-02-29T00:00:00Z"
        );
    }

    #[test]
    fn rfc3339_lex_sortable_against_user_iso() {
        // The whole point of F7: a user-supplied ISO threshold like
        // "2026-01-01T00:00:00Z" must lex-compare correctly against the
        // generated entry timestamps.
        let secs: i64 = 20_576 * 86_400 + 12 * 3600;
        let ts = crate::util::format_rfc3339_utc(secs);
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

    /// Regression for v0.1.1 F2: a poisoned mutex must not crash the
    /// sidecar. `lock_inner` recovers the inner RingBuffer; subsequent
    /// reads return whatever the panicking writer left behind.
    #[test]
    fn recovers_from_poisoned_mutex() {
        use std::sync::Arc;
        use std::thread;

        let h = Arc::new(ScanHistory::new(10));
        h.record("inbound", &block_result("seed"));

        let h_clone = Arc::clone(&h);
        // Force a poison by panicking while holding the lock.
        let result = thread::spawn(move || {
            let _guard = lock_inner(&h_clone.inner);
            panic!("intentional panic to poison the mutex");
        })
        .join();
        assert!(result.is_err(), "thread should have panicked");

        // Now the lock is poisoned. Reads must still work, not crash.
        let snap = h.snapshot(None, None);
        assert_eq!(snap.len(), 1);
        assert_eq!(h.total_blocked(), 1);

        // Writes after poison must also work.
        h.record("inbound", &block_result("after-poison"));
        assert_eq!(h.total_blocked(), 2);
    }
}
