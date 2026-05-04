# Changelog

All notable changes to mcp-armor are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] — 2026-05-04

Cold cross-review hardening pass. Three substantive fixes plus four
repo-hygiene additions. No behavioural regressions, no API changes.

### Fixed

- **CI broken-by-design.** The previous `--all-features` invocation in
  `.github/workflows/ci.yml` activated the reserved `sigstore-bridge`
  feature flag, which intentionally fires `compile_error!`
  (`src/sigstore_bridge_stub.rs`). Result: every CI run on `main` was
  red since v0.1.0. Replaced with explicit `--features audit-db` plus a
  dedicated `cargo check --features sigstore-bridge` step that asserts
  the stub still rejects the build (defence against accidental
  un-stubbing).
- **Mutex-poisoning crash vector** in `src/control/history.rs`. The
  three `.lock().expect("history mutex")` sites would panic the entire
  sidecar if a writer panicked while holding the lock. Replaced with a
  shared `lock_inner` helper that recovers the inner `RingBuffer` via
  `PoisonError::into_inner()` — correct for an audit/observability ring
  buffer (worst case one entry was half-written). Regression test:
  `recovers_from_poisoned_mutex`.
- **Unicode evasion gap.** `src/scanner/unicode.rs` only stripped 7
  zero-width code points and no Bidi formatting. Added the four
  invisible math operators (U+2061–U+2064) plus all nine Bidi
  formatting code points (U+202A–U+202E, U+2066–U+2069). Closes the
  RTL-override / Trojan-Source bypass class. Regression tests:
  `strips_invisible_math_operators`, `strips_bidi_override`,
  `strips_all_bidi_formatting`, `strips_combined_evasion`.

### Added

- `SECURITY.md` with vulnerability disclosure policy (72 h ack, 30 d
  fix target, scope definition, coordinated disclosure).
- `CONTRIBUTING.md` with build/test workflow, MSRV pin, what we accept,
  what we are slow on, coding standards (no `unwrap()` in non-test
  paths, mutex poison-recovery helper, clippy-pedantic).
- README "Status" section listing v0.1 vs v0.2 backlog as a single
  table — no more spelunking through CHANGELOG to find the open items.

### Hardened

- `.gitignore` extended with `.env`, `.env.local`, `.env.*.local`,
  `*.log`, `coverage/`, `*.sqlite`, `*.sqlite3`, `*.db`,
  `*.sigstore.json`, `*.pem`. Prevents accidental commit of audit-db
  databases, sigstore bundles, or environment secrets.

## [0.1.0] — 2026-05-03

Initial release.

### Added

- `mcp-armor wrap` subcommand — stdio passthrough proxy around any upstream MCP server (MCP spec 2025-06-18)
- Three-stage scanner pipeline: Aho-Corasick prefilter → regex stage → NFKC + zero-width-strip + tag-unicode-strip + re-scan
- Ed25519 manifest verification with RFC-8785-flavoured canonical-JSON (stateless cryptographic verify only — TOFU keystore + Sigstore bridge are v0.2 backlog)
- 6 read-only control-plane MCP tools: `armor_scan_payload`, `armor_verify_manifest`, `armor_list_blocked`, `armor_get_policy`, `armor_check_cve`, `armor_simulate_attack`
- Policy loader: TOML-driven, `~/.config/mcp-armor/policy.toml` default with graceful fallback to defaults
- Stderr-only JSON tracing via `tracing` + `tracing-subscriber`. Full OTLP gRPC export is **v0.2 backlog** — when `OTEL_EXPORTER_OTLP_ENDPOINT` is set v0.1 logs a single warn-line recording the endpoint but does not ship spans to a collector
- Optional `audit-db` Cargo feature: SQLite-backed scan history (rusqlite bundled)
- Curated CVE feed (compiled in at build time via `include_str!`):
  - **CVE-2026-27124** detection — FastMCP shell-injection via unsanitized tool args (pattern: `shell_substitution`)
  - **CVE-2025-49596** detection — MCP Inspector unsanitized localhost callback (pattern: `localhost_callback`)
  - **CVE-2026-30615** detection — Windsurf zero-click RCE via auto_invoke tool (pattern: `auto_invoke_privileged`)
  - **CVE-2025-65720** detection — GPT Researcher prompt-injection via search-result markdown (pattern: `javascript_uri`)
  - **CVE-2026-22252** detection — LibreChat manifest-tampering via MITM (pattern: `instruction_override`)
  - **CVE-2026-30623** detection — LiteLLM tool-result injection (pattern: `tag_injection`)
  - **CVE-2026-22688** detection — Generic tool-output zero-width-char obfuscation (pattern: `zero_width_obfuscation`)
  - **CVE-2026-30888** detection — Marketplace mirror swaps tools/list response (pattern: `html_script_inject`)
  - **CVE-2026-31104** detection — Tag-Unicode evasion of pattern scanners (pattern: `tag_unicode_evasion`)
  - **CVE-2026-31312** detection — Fullwidth-Unicode evasion of pattern scanners (pattern: `fullwidth_evasion`)
- CI workflow with `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test --all-features`, `cargo bench` regression gate
- Publish workflow with cosign attestation on release binaries (Linux gnu + Linux musl + macOS aarch64)

### Known limitations

- Windows targets are not in v0.1 (v0.2 backlog) — Linux + macOS only
- Manifest verify is stateless cryptographic only. **No TOFU keystore** (planned for v0.2 at `~/.local/share/mcp-armor/keys.toml`) and **no Sigstore bridge** (the `sigstore-bridge` Cargo feature is a reserved no-op in v0.1)
- OTLP gRPC export not wired (stderr-json only) — v0.2 backlog
- The control-plane server is hand-rolled JSON-RPC; rmcp 1.6 migration is on the v0.2 backlog (PLAN.md R5 explicitly **REOPENED 2026-05-03**, see PLAN.md "Decisions" for the recorded deviation rationale)
- `armor_check_cve` matches by substring on `fixed_in`; an `affected_versions` semver range is on the v0.2 backlog

### Documentation

- README cross-links the [studiomeyer-io/ai-shield](https://github.com/studiomeyer-io/ai-shield) TypeScript sister project
- Test counts in README come from `cargo test` directly — no inflated claims
