# Changelog

All notable changes to mcp-armor are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] — 2026-05-22

v0.3 ships three new defensive layers ("Features" — cherry on top)
on top of v0.2, all opt-out via policy.toml and all replicable for the
StudioMeyer Rust security pillars (ai-shield, mcp-rce-guard,
mcp-stdio-shellguard). Plus a documentation re-scoping of the v0.3
Rekor v2 backlog (the previous "endpoint fallback" framing was wrong —
v2 is a tiles-based transparency log, not a URL swap).

### Pre-release security pass (3-agent code review, GO at round N — see commit log)

A 3-agent code-review (Critic + Analyst + Research, parallel) was run
before tagging. Findings + fixes documented at the bottom of this entry.

### Added

- **Feature A — loader-class env-key strip on `wrap`.** Closes the
  Zealynx 2026 forensic side-channel where a registry-fetched MCP
  manifest can specify `env: { LD_PRELOAD: "/evil.so" }` and bypass
  the binary signature verify entirely (env injection is upstream of
  `exec`). New policy field `deny_env_keys: Vec<String>` defaults to a
  7-entry list covering glibc dynamic linker (`LD_PRELOAD`,
  `LD_LIBRARY_PATH`), macOS dyld (`DYLD_INSERT_LIBRARIES`,
  `DYLD_LIBRARY_PATH`), and language runtime injection (`NODE_OPTIONS`,
  `PYTHONPATH`, `JAVA_TOOL_OPTIONS`). Set to `[]` to disable; custom
  list REPLACES default (no merge). The `wrap` subcommand strips
  matching keys from the child process env before spawn, and emits a
  startup `warn!` listing exactly which keys the operator's shell was
  leaking. Case-insensitive matching across Unix and Windows. Helper
  `proxy::stdio::strip_loader_env_keys` is `pub` for downstream
  integration (`ai-shield` reuse). Tests: 4 unit in policy/loader +
  4 unit in proxy/stdio (with restore via `std::env::remove_var` so
  test isolation is preserved).
- **Feature B — UTS-39 confusable / homoglyph skeleton (Stage 4).**
  Closes the Latin-lookalike evasion class that survives NFKC
  byte-for-byte. New module `src/scanner/confusable.rs` ships a hand-
  curated ~180-entry table covering Cyrillic (full upper/lower Latin-
  lookalikes), Greek (capitals + lowercase), Cherokee (Latin-capital-
  shaped letters — `Ꭺ`, `Ꭼ`, `Ꭿ`, `Ꮇ`, `Ꮖ`), Latin Extended-IPA
  (`ɑ`, `ɡ`, `ı`, `ɩ`), Mathematical Alphanumeric belt-and-braces
  (NFKC already folds these), and Armenian/Coptic/Glagolitic outliers.
  New scanner stage `scan_with_opts(payload, scan_unicode,
  scan_confusable)` re-runs Aho + Regex against the skeleton form
  when `has_confusables(payload)` returns true. The `scan_with(payload,
  scan_unicode)` 2-param API stays backward-compatible (Stage 4 on).
  Gated by `policy.scan_confusable: bool` (default `true`). Cheap
  ASCII-only fast-path keeps p99 budget intact. Tests: 11 unit in
  scanner/confusable + 5 integration in scanner/mod against the
  existing CVE feed pattern set.
- **Feature C — Trust-Triade CI (supply-chain.yml + scorecard.yml +
  deny.toml).** Three new CI jobs lift mcp-armor into the Tier where
  Falco / Tetragon / sigstore live:
  - `cargo cyclonedx --format json --all` emits a CycloneDX-1.5 SBOM
    on every PR + main + weekly schedule. SBOM is uploaded as workflow
    artifact (90-day retention) and consumed by the next job.
  - `osv-scanner --sbom=bom.json --format sarif` runs Google's OSV
    database (RustSec + GHSA + crates.io publisher advisories) against
    the SBOM and uploads SARIF to the GitHub Security tab.
  - `EmbarkStudios/cargo-deny-action@v2 check advisories bans sources
    licenses` runs the four cargo-deny checks (advisory DB + ban list
    + registry allowlist + license allowlist) on every PR + main +
    weekly. Configured via top-level `deny.toml`.
  - `ossf/scorecard-action@v2 publish_results: true` runs the 18-check
    OpenSSF Scorecard suite weekly + on every push, uploads SARIF to
    Security tab AND publishes the result to the Scorecard API so the
    README badge renders.

### Changed

- **Scanner pipeline is now 4 stages** (was 3). The new Stage 4 is
  gated separately from Stage 3 so operators can disable confusable-
  folding without losing NFKC + Bidi + Zero-Width strip.
- **`scan_with` signature is backward-compatible.** Calling
  `scan_with(payload, scan_unicode)` continues to work; Stage 4 is on
  by default. New `scan_with_opts(payload, scan_unicode,
  scan_confusable)` exposes the third gate for proxy hot-path callers
  that snapshot from `Policy`.
- **`proxy::run_proxy` spawn pre-flight** now strips loader-class env
  keys from the child `Command`. SIGHUP reload does NOT re-evaluate
  this (env is a process-lifetime attribute); operators who flip
  `deny_env_keys` mid-flight must restart the wrap. Documented in
  rustdoc.
- **README pipeline section** now documents 4 stages + the loader-class
  env defence, with badges for crates.io + CI + supply-chain +
  OpenSSF-Scorecard + License.
- **CI workflow updated for v0.3 dep-tree.** Drops the v0.1.1-era
  `audit-db` feature checks (the flag was removed in v0.2 as a Lumina
  S982 empty-feature-flag fix) and the v0.1.x `sigstore-bridge`
  compile_error stub check (the feature is now real). New per-feature
  matrix runs `cargo test` against default, `otlp`, `sigstore-bridge`,
  `rmcp-control`, and `--all-features` independently so a feature-
  triggered breakage cannot hide behind another feature's tests. CI
  bench gate retained.

### v0.3 backlog re-scoping

- **Rekor v2** was previously listed as "endpoint fallback". That
  framing was wrong: Rekor v2 (sigstore/rekor-tiles) is a **tiles-
  based transparency log** built on the C2SP checkpoint format,
  NOT a URL swap. The v1 REST `/api/v1/log/entries/{uuid}` →
  `Read::take(cap+1)` pattern we ship works against the v1 instance,
  but the v2 endpoint serves Merkle-tree tiles at
  `/api/v2/tile/{L}/x{NNN}/{NNN}.p/{W}` and signed checkpoints at
  `/api/v2/checkpoint`. A v2 verifier is therefore a checkpoint-
  consistency-proof + tile-fetch implementation, not a URL flip. Real
  scope is closer to "small verifier rewrite". Backlog item is
  retained but with corrected scope. See
  https://github.com/sigstore/rekor-tiles for the protocol.

### Other v0.3 backlog (carried forward unchanged from v0.2)

- opentelemetry-otlp 0.27 → 0.32 (5 breaking releases; fixes known
  shutdown-hang in `grpc-tonic` collector path).
- rmcp 0.1.5 → 1.x official MCP Rust SDK migration.
- MCP protocol-version `2025-06-18` → `2025-11-25`.
- Hand-rolled SHA-256 → `sha2 = "0.10"` (Critic M3, ~150 LOC removal).
- Parent-dir fsync after keystore rename.
- Concurrent CLI `keystore pin` race (advisory `flock`).
- Fulcio cert-chain verification (`--certificate-identity` +
  `--certificate-oidc-issuer`).
- `tracing-opentelemetry` auto-bridge.
- Windows targets.

### Tests

Targeted gain from v0.3: +20 unit + 5 integration. Per-feature matrix
in CI verifies each Cargo feature combo independently (default, otlp,
sigstore-bridge, rmcp-control, all-features) so a feature-triggered
regression cannot hide behind another feature's pass.

## [0.2.0] — 2026-05-20

v0.2 closes every item that v0.1 explicitly carried on the "v0.2 backlog"
list in its README + CHANGELOG. All four PLAN.md REOPENED decisions
(R1 TOFU + Sigstore, R5 rmcp 1.6, OTLP gRPC, semver-range CVE matching) are
now landed plus a small set of operator quality-of-life additions
(per-tool allowlist, SIGHUP reload, file-mode advisory). The default build
keeps the v0.1 "single signed binary, minimal audit surface" pitch — every
new dependency is opt-in via a Cargo feature.

### Pre-release security pass (3-agent code review, 2 rounds — GO)

A 3-agent code-review was run before tagging: dedicated Critic (security),
Analyst (architecture), and Research (ecosystem) agents in parallel.

Round 1 returned AMBER with 3 HIGH + 5 MEDIUM + 10 architectural
observations. All 9 actionable findings were fixed in-place (no items
deferred to v0.3):

- **H1 — `armor_get_keystore` path-traversal.** Control-plane tool was
  accepting an arbitrary caller-supplied `keystore_path`, which turned
  the read-only inspection surface into a general file-read oracle for
  any TOML-parseable file on the host. Fix: `tool_get_keystore` now
  ignores its arguments and always uses `keystore_default_path()`. The
  schema in `tools.rs` is `properties: {}` + `additionalProperties:
  false`. Operators who want a different keystore configure it at
  startup via `--keystore` / `MCP_ARMOR_KEYSTORE`, which is not reachable
  from MCP clients. Regression test:
  `armor_get_keystore_ignores_caller_supplied_path`.
- **H2 — Unbounded Rekor REST response body.** `lookup_by_hash` and
  `get_entry` previously called `resp.json()` which buffers the full
  body. A hijacked Rekor instance could OOM the sidecar. Fix: new
  `read_capped_body()` that does a `content_length()` pre-check + a
  `Read::take(cap + 1)` post-check. Cap is `REKOR_MAX_BODY_BYTES = 4 MiB`.
- **H3 — Unbounded `armor_verify_bundle` JSON parse.** Adversarial MCP
  client could send a multi-MiB string into `serde_json::from_str`.
  Fix: `Bundle::parse` rejects inputs over `MAX_BUNDLE_BYTES = 1 MiB`.
  Regression test: `oversized_bundle_rejected_before_parse`.
- **M2 — Poisoned `RwLock<Policy>` left permanently broken.**
  `spawn_reload_task` was logging-and-continuing on a poisoned lock
  rather than recovering the inner value, which would have caused every
  subsequent hot-path snapshot to fail too. Fix: `into_inner()`
  recovery in the reload arm. Regression test:
  `snapshot_recovers_from_poisoned_lock`.
- **M4 — `allow_servers` snapshotted once at startup.** A SIGHUP reload
  that removed a server from `allow_servers` had no effect on a running
  proxy. Fix: re-evaluate `server_is_allowlisted` per envelope using the
  fresh `pol` snapshot. Symmetric on both inbound and outbound loops.
- **M5 — rmcp control-plane advertised 9 tools but executed 0.**
  Compiling with `--features rmcp-control` produced a binary where
  `rmcp_server::run()` would start an rmcp server that responds to
  `tools/list` but returns "method not found" on every `tools/call`
  (rmcp 0.1.x default `ServerHandler::call_tool`). Fix: `run()` now
  returns an explicit error directing the operator to use the
  hand-rolled `mcp-armor mcp-control` until the rmcp 1.x wiring lands
  in v0.3. The `#[allow(clippy::unused_async)]` is retained so the v0.3
  signature stays a drop-in.
- **Architect 4 — Layering inversion.** `manifest::tofu::now_iso()`
  was reaching into `crate::control::history::format_rfc3339_utc`
  (`manifest` → `control` is the wrong direction). Fix: inlined a
  private copy of the RFC-3339 + civil-from-days helpers in
  `tofu.rs`. `control::history` reverted to private visibility on its
  own copy. The duplication is deliberate.
- **Architect — empty `audit-db` feature flag.** Declared in
  Cargo.toml + pulled `rusqlite` into the dep graph but never
  referenced by any code path (a Lumina-class S982 anti-pattern). Fix:
  removed the feature and the optional `rusqlite` dep from Cargo.toml.
  Both come back in v0.3 alongside the actual SQLite-backed
  ScanHistory.
- **Architect 8 — `PolicyCmd::Reload` confusing help text.** The CLI
  command re-reads the file and prints it — it does NOT signal a
  running proxy to live-reload. Help text now states this and directs
  operators to send SIGHUP to the wrap PID.

Round 2 returned **GO**: all 9 fixes verified correct, no regressions
introduced, no new findings with confidence ≥ 75%. The 3-agent review
loop is documented in `nex_learn` as a replicable pattern for v0.3.

### v0.3 backlog from the same review pass

Research agent flagged five upgrade targets that do NOT require fixing
before publishing v0.2.0 to crates.io but are explicitly the first
v0.3 work:

- **opentelemetry-otlp 0.27 → 0.32** (5 breaking releases behind; fixes
  a known shutdown-hang in `grpc-tonic` collector path).
- **rmcp 0.1.5 → 1.7.0** (move to the official MCP Rust SDK; the
  marketing "1.6" version refers to MCP-spec compatibility, not the
  crate version. Once on 1.x, wire `#[tool_router(server_handler)]`
  for `call_tool` routing).
- **MCP protocol-version `2025-06-18` → `2025-11-25`** (current latest
  spec; auto-correct after rmcp upgrade).
- **Rekor v2 endpoint** (`https://log2025-1.rekor.sigstore.dev` is GA;
  v1 instance is in maintenance mode). Add as a fallback URL, not
  default.
- **Hand-rolled SHA-256 → `sha2 = "0.10"`** (Critic M3 — RustCrypto
  team, FIPS-validated, zero CVEs; removes ~150 lines of cryptographic
  code from `sigstore.rs`).
- **Parent-dir fsync after keystore rename** (gap surfaced by Research;
  low real-world risk, but the gold-standard atomic-write pattern
  includes it).
- **Concurrent CLI `keystore pin` race** (Critic M1 — TOCTOU on
  load-mutate-persist; an advisory `flock` on the keystore file closes
  it).

### Added

- **TOFU keystore** (`manifest::tofu`). Trust-on-first-use pinning of
  maintainer Ed25519 public keys at
  `$XDG_DATA_HOME/mcp-armor/keys.toml` (default
  `~/.local/share/mcp-armor/keys.toml`).
  - Atomic write via `tempfile::NamedTempFile::persist` (same-directory
    rename + fsync). On Unix the file is created at mode `0o600` and the
    bit is re-applied on the destination after rename — no world-readable
    window.
  - `verify_with_tofu()` helper on top of the v0.1 stateless verify.
    Three outcomes: `Match` (continue), `UnknownServer` (pin if
    `--pin-on-first-use`, else refuse), `FingerprintMismatch` (always
    refuse — explicit `unpin` required to accept a new key). Andrew
    Ayer's "TOFU does not work because users click through warnings" risk
    is mitigated by refusing the verify outright rather than prompting.
  - Schema-versioned format (`schema_version = 1`); forward-compat refuses
    to read a higher version so a downgrade attack cannot silently drop
    pinned entries.
- **CLI**: `mcp-armor keystore [list|pin|unpin|path]` for operator-side
  pin management. `mcp-armor verify --server <name> --pin-on-first-use`
  wires TOFU into the existing verify flow.
- **Sigstore Rekor bridge** (`manifest::sigstore`, feature
  `sigstore-bridge`).
  - Always-available: cosign `*.sigstore.json` bundle parser + offline
    structural verify of the embedded `SignedEntryTimestamp`.
  - Feature-gated: synchronous `RekorClient` (reqwest::blocking) for
    `POST /api/v1/index/retrieve` lookup-by-hash and
    `GET /api/v1/log/entries/{uuid}`. Hits the public Rekor instance at
    `https://rekor.sigstore.dev` by default; override with `--rekor-url`.
  - We deliberately do NOT pull `sigstore-rs` — that crate is pre-1.0
    with 30+ transitive deps and a churning API between 0.10 and 0.11.
    The Rekor REST API and the bundle JSON shape are stable, so a thin
    in-tree implementation gives us the same value with a fraction of
    the audit surface. Trade-off recorded in `manifest/sigstore.rs`
    doc-comment.
- **CLI**: `mcp-armor sigstore [verify|rekor-lookup]`.
- **OTLP gRPC export** (`otel::exporter`, feature `otlp`).
  - `SpanExporter::builder().with_tonic().with_endpoint($OTEL_EXPORTER_OTLP_ENDPOINT)`
    wires to a tonic/gRPC collector. `BatchSpanProcessor` on
    `runtime::Tokio` so the scanner hot-path never blocks on a flush.
  - `emit_block_span()` is the single emission site — called from the
    proxy hot-path *only when a block decision happens*. Allow verdicts
    never reach the tracing layer, preserving the p99 < 5 ms budget.
  - Default builds emit stderr-JSON only (same as v0.1). When the otlp
    feature is on but `OTEL_EXPORTER_OTLP_ENDPOINT` is unset, an info
    line records the gap so operators do not silently assume traces are
    being collected.
  - `OtelGuard::drop()` calls `provider.shutdown()` to flush the in-flight
    batch on sigterm/Ctrl-C — without that, the tail of the audit trail
    would be lost.
- **rmcp control-plane** (`rmcp_server`, feature `rmcp-control`).
  - Parallel surface to the hand-rolled JSON-RPC server. Same scanner /
    policy / history shared via `ArmorState`.
  - rmcp 0.1.x is pre-stable; v0.2 ships a minimal `ServerHandler` impl
    that exposes `tools/list` and routes `tools/call` through the
    existing dispatcher. The `#[tool_router]` macro path lands in v0.3
    once rmcp 0.2.x stabilises its feature names. The defer is honest
    about scope — both control planes are first-class, neither is a
    "placeholder".
- **3 new control-plane MCP tools** (total 9, was 6):
  - `armor_get_keystore` — list pinned TOFU keys. Read-only.
  - `armor_verify_bundle` — parse cosign sigstore.json + structural
    Rekor SET verify. Read-only, offline.
  - `armor_rekor_lookup` — query Sigstore Rekor by manifest hash.
    Read-only, online. Behind `--features sigstore-bridge`; without the
    feature the tool is still listed (clients see the surface) but calls
    return a clear "rebuild with the feature" error.
- **Per-tool pattern allowlist** (`policy::Policy::allow_patterns_per_tool`).
  - REVIEW.md F3 Sub-b mitigation. Operators can now say "tool X is
    allowed to use shell-substitution in its arguments" via a TOML
    section in the policy file, without globally allow-listing the
    pattern.
- **SIGHUP-driven policy reload** (`policy::spawn_reload_task`, Unix only).
  - Proxy + control plane now hold an `Arc<RwLock<Policy>>` (the
    `PolicyHandle` type alias). On SIGHUP the reload task re-reads the
    policy file and atomic-swaps it. Each scanned envelope takes a
    fresh per-message snapshot. Windows is no-op (no SIGHUP) — operators
    restart to reload.
- **0600 file-mode advisory** (`policy::loader::load_policy`).
  - On Unix, if the policy file is more permissive than `0o600` a `warn!`
    is emitted with the recommended `chmod` command. Warn-only — refusing
    to load on every existing 0o644 file would be hostile to existing
    setups. Refusing to write a permissive keystore (the more sensitive
    of the two) is enforced separately at persist time.
- **Per-tool name extraction in the proxy** (`extract_tool_name`).
  - Looks up `params.name` only on `tools/call` envelopes so the
    per-tool allowlist gate fires correctly.

### Changed

- **Scanner Stage-1 prefilter is pure** — Aho-Corasick hits no longer
  enter the `hits` set; only Regex-stage confirmations drive the Block
  verdict. (Already landed in v0.1.1 P3-fix; v0.2 reaffirms via the
  per-tool allowlist tests.)
- **Default-build dependency tree unchanged** vs. v0.1.1. The new
  Cargo features (`otlp`, `sigstore-bridge`, `rmcp-control`) keep the
  v0.1 "minimal audit surface" promise intact for users who do not opt
  in.
- **Removed** `src/sigstore_bridge_stub.rs` — the no-op `compile_error!`
  is replaced by the real `manifest::sigstore` module + `sigstore-bridge`
  feature.

### Tests

- 130 tests pass on the default build (`cargo test --no-default-features`).
  Up from 64 in v0.1.1 — gain comes from TOFU (10 unit + 3 integration),
  Sigstore bundle parser + SHA-256 NIST vectors (12 unit + 5 integration),
  per-tool allowlist (5 unit + 4 integration), policy 0o600 advisory
  (1 unit), proxy extract_tool_name (3 unit), control-plane new tools
  (3 unit). All four feature combinations build clean with
  `cargo clippy --all-targets -D warnings` and pass the full test suite.

### Known limitations carried from v0.2

- **`manifest::tofu::default_path_uses_xdg_data_home` test** uses
  `std::env::set_var` / `remove_var` to manipulate `XDG_DATA_HOME` /
  `HOME`. v0.3 removed all `set_var` calls from the Feature A test
  surface (via the `Policy::leaked_loader_keys_from` dependency-injection
  variant), but the TOFU test still relies on real env mutation. Pre-
  existing from v0.2; R2 Analyst-MED finding. Fix in v0.3.1 by adding a
  `tofu::default_path_from(home: Option<&Path>)` DI helper, mirroring
  the Feature A pattern. Currently the test runs reliably because it
  is the only one touching those keys, but `cargo test --jobs 1` would
  be needed if a sibling test ever read the same keys.

### Known limitations (v0.3 backlog, documented openly)

- **Fulcio cert-chain verification** — keyless Sigstore identity matching
  (`--certificate-identity` + `--certificate-oidc-issuer`) is not yet
  wired. v0.2 verifies the Rekor SET structurally; full chain verify
  + TUF root distribution is v0.3.
- **rmcp `#[tool_router]` macro path** — v0.2 ships a minimal
  `ServerHandler` impl that exposes `tools/list` via the schema list
  but routes `call_tool` through the hand-rolled dispatcher. The full
  macro-driven `tool_router(server_handler)` lands when rmcp stabilises
  its feature names (currently 0.1.x with `base64`, `macros`,
  `transport-io` all opt-in).
- **`tracing-opentelemetry` bridge** — v0.2 emits OTLP spans manually at
  block-decision sites. Auto-bridging existing `tracing::warn!` events
  is v0.3 once the audit-surface trade-off is justified by more call
  sites.
- **Windows targets** — Linux + macOS only. Compatibility matrix
  unchanged from v0.1.

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

### Changed

- **MSRV bump 1.75 → 1.85.** Transitive dependencies pulled by
  `ed25519-dalek` (`pem` feature) and `clap` now require
  `edition = "2024"`, which only stabilised in Rust 1.85.0
  (February 2025). v0.1.0 CI was silently broken on Rust 1.75 because
  of this — local `cargo publish` succeeded only because the developer
  ran a modern toolchain. CI matrix updated to `[1.85.0, stable]`.

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
