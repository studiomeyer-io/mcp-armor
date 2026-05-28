//! Shared utility helpers — RFC-3339 UTC formatting + civil-from-days +
//! short hex encoding.
//!
//! v0.6 (carried-forward v0.5 backlog item): collapses the three
//! identical copies of `format_rfc3339_utc` / `civil_from_days` /
//! `now_iso` / `hex_short` that previously lived in `manifest::drift`,
//! `manifest::tofu`, `control::history`, and `main.rs`. Keeping the
//! formatter colocated with the modules that consume it was a
//! deliberate v0.2 layering decision (`manifest` is supposed to sit
//! below `control` so it cannot depend on it), but with v0.5 the
//! sibling copies grew to three — drift risk on the next shape change
//! (e.g. fractional seconds, or a leap-second carve-out) outweighs the
//! original layering rationale. `util` is the lowest layer in the
//! crate (no other module depends on `manifest`, `control`, or
//! `proxy`), so the dependency direction stays intact.
//!
//! All functions here are pure — no I/O, no allocations beyond the
//! returned `String`. Safe under multi-threaded `cargo test`.

use std::time::{SystemTime, UNIX_EPOCH};

/// Hex-encode the first `n` bytes of `bytes` to a `2 * n`-char
/// lowercase hex string. Used by drift fingerprints, keystore short
/// fingerprints, and CLI pin outcomes. Truncation is intentional:
/// 16 bytes (128 bit) is the short-fingerprint length, 32 bytes
/// (256 bit) is the full BLAKE3 / SHA-256 digest length.
#[must_use]
pub fn hex_short(bytes: &[u8], n: usize) -> String {
    let mut out = String::with_capacity(n * 2);
    for b in bytes.iter().take(n) {
        let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{b:02x}"));
    }
    out
}

/// RFC-3339 UTC timestamp for "now", e.g. `2026-05-29T03:14:15Z`.
///
/// Chrono-free, civil-from-days based. Sub-second precision is
/// intentionally dropped — the drift / keystore / scan-history
/// pipelines lex-compare ISO strings, so fixed-width
/// `YYYY-MM-DDTHH:MM:SSZ` is the contract.
#[must_use]
pub fn now_iso() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    format_rfc3339_utc(secs)
}

/// Format a Unix timestamp (seconds since 1970-01-01 UTC) as an RFC-3339
/// UTC string. Pure-stdlib civil-from-days (Howard-Hinnant's algorithm
/// shifted to a 1970 epoch); proleptic Gregorian, valid 1970..9999.
/// No `chrono` dep, no sub-second precision.
///
/// `unix_secs < 0` is supported (clamped to 1970 if it underflows the
/// civil-from-days domain).
#[must_use]
pub fn format_rfc3339_utc(unix_secs: i64) -> String {
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
/// Howard-Hinnant's algorithm (proleptic Gregorian, correct for the full
/// 100/400 leap-year rule).
///
/// Reference: <https://howardhinnant.github.io/date_algorithms.html#civil_from_days>
///
/// `clippy::similar_names` is allowed here on purpose: `doe` (day-of-era)
/// and `doy` (day-of-year) are the canonical variable names from
/// Hinnant's published algorithm. Renaming would obscure the reference
/// implementation.
#[allow(clippy::similar_names)]
#[must_use]
pub fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = y + i64::from(u8::from(m <= 2));
    (year, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_unix_epoch() {
        assert_eq!(format_rfc3339_utc(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn rfc3339_known_date() {
        // 2026-05-03T12:34:56Z = day 20_576 since 1970-01-01.
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
        let secs: i64 = 20_576 * 86_400 + 12 * 3600;
        let ts = format_rfc3339_utc(secs);
        assert!(ts.as_str() > "2026-01-01T00:00:00Z");
        assert!(ts.as_str() < "2027-01-01T00:00:00Z");
    }

    #[test]
    fn now_iso_produces_canonical_shape() {
        let s = now_iso();
        assert_eq!(s.len(), 20, "got {s:?}");
        assert!(s.ends_with('Z'));
        assert_eq!(s.as_bytes()[4], b'-');
        assert_eq!(s.as_bytes()[10], b'T');
    }

    #[test]
    fn hex_short_truncates() {
        let bytes = [0xab_u8, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89];
        assert_eq!(hex_short(&bytes, 4), "abcdef01");
        assert_eq!(hex_short(&bytes, 8), "abcdef0123456789");
    }

    #[test]
    fn hex_short_zero_pads() {
        let bytes = [0x00_u8, 0x01, 0x02];
        assert_eq!(hex_short(&bytes, 3), "000102");
    }

    #[test]
    fn hex_short_n_greater_than_input_takes_all() {
        let bytes = [0xff_u8, 0xee];
        assert_eq!(hex_short(&bytes, 8), "ffee");
    }

    /// Civil-from-days bridges the leap-year edge.
    #[test]
    fn civil_from_days_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(31), (1970, 2, 1));
        assert_eq!(civil_from_days(59), (1970, 3, 1));
        assert_eq!(civil_from_days(365), (1971, 1, 1));
        // Leap year — 2024 has 366 days.
        assert_eq!(civil_from_days(19_722), (2023, 12, 31));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
    }
}
