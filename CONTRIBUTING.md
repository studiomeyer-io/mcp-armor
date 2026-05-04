# Contributing to mcp-armor

Thanks for considering a contribution. mcp-armor is a security tool;
we are deliberately conservative about scope and deliberately strict
about evidence. The bar for new code is "reproduces a real attack and
ships with a regression test".

## Quick Start

```sh
git clone https://github.com/studiomeyer-io/mcp-armor
cd mcp-armor
cargo fmt --check
cargo clippy --all-targets --features audit-db -- -D warnings
cargo test --features audit-db
cargo bench --bench scanner -- --quick   # optional
```

MSRV is **Rust 1.75**. CI tests both 1.75.0 and stable on Linux and
macOS — your patch needs to compile on the floor.

## What we accept

- **New CVE coverage.** A new entry in `cve-feed/` plus a real-world
  payload added to `tests/cve_simulation.rs`. Verdict must flip from
  `Allow` to `Block` for the test to count.
- **Scanner improvements.** New Unicode evasion classes, new pattern
  encodings, performance wins — all welcome, but each one needs a
  regression test that fails on `main` and passes with your patch.
- **Bug fixes.** A failing test in your PR description is the fastest
  path to merge.
- **Docs.** Typo fixes, clarifications, ecosystem links.

## What we are slow on

- New top-level features (e.g. OTLP gRPC, TOFU keystore, Sigstore
  bridge, rmcp migration). These are on the v0.2 roadmap and tracked
  in CHANGELOG "Known limitations". Please open an issue to discuss
  before opening a large PR.
- Adding runtime dependencies. Every crate added is a supply-chain
  surface for a security tool. We weigh `cargo audit` history and
  maintainership before accepting.
- Renaming/restructuring without a clear behavioural improvement.

## Pull Request Process

1. Open an issue or draft PR first for anything non-trivial. We do not
   want either of us to waste a weekend on a refactor we cannot ship.
2. One logical change per PR. Easier to review, easier to revert.
3. CI must be green: `fmt --check`, `clippy -- -D warnings`,
   `cargo test --features audit-db`, `cargo test --no-default-features`,
   plus the `sigstore-bridge stub still rejects` step.
4. CHANGELOG entry under `[Unreleased]` describing the user-visible
   change in plain English.
5. For security-impacting changes, see [SECURITY.md](SECURITY.md) —
   please email instead of opening a public PR.

## Coding Standards

- `#![deny(unsafe_code)]` is global. There are no exceptions in v0.1.
- No `unwrap()` / `expect()` in non-test code paths. The sidecar runs
  as a stdio proxy; a panic kills the whole connection. Use
  `unwrap_or_else(...)` with a sane fallback or propagate the error.
- Mutex locks recover on poison via `unwrap_or_else(PoisonError::into_inner)`.
  See `src/control/history.rs::lock_inner` for the helper.
- Clippy pedantic warnings are treated as errors in CI.
- `tracing` for logs. No `println!` / `eprintln!` outside binaries.

## Testing

- Unit tests live next to the code in `#[cfg(test)] mod tests`.
- Integration tests live in `tests/` (`integration_*.rs`,
  `cve_simulation.rs`).
- Benchmarks live in `benches/scanner.rs`. CI gates a 7 ms hard cliff
  on the p99 — don't accidentally regress past that.
- New CVE coverage requires a `cve_simulation` entry: same payload,
  must produce `Block` verdict, must reference the CVE in
  `result.cve_refs`.

## Releasing (maintainers)

- Version bump in `Cargo.toml` and the top of `CHANGELOG.md`.
- Tag `vX.Y.Z` on `main`.
- The publish workflow runs `cargo publish` and signs binaries with
  cosign keyless OIDC.
- After release, verify on crates.io and via
  `cargo install mcp-armor --version X.Y.Z --locked`.

## License

By contributing, you agree your work is licensed under the [MIT
License](LICENSE).

## Code of Conduct

Be kind. Assume good faith. We are a small project — do not bring
drama. Disagreement is fine, contempt is not.
