# Changelog

All notable changes to mcp-armor are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
