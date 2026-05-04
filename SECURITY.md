# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

mcp-armor is in active early development. Only the latest 0.1.x patch
release receives security fixes. v0.2 will widen this to "latest minor".

## Reporting a Vulnerability

mcp-armor sits on the security-critical path between MCP clients and
servers. We take vulnerability reports seriously.

**Please do NOT open a public GitHub issue for security problems.**

Email **hi@studiomeyer.io** with:

1. A clear description of the issue and its impact.
2. Steps to reproduce (a failing test case is ideal).
3. Affected version(s) — `mcp-armor --version`.
4. Your platform and Rust toolchain (`rustc -V`).
5. Optional: a suggested fix or mitigation.

We will acknowledge your report within **72 hours**, share an initial
triage assessment within **7 days**, and aim to ship a fix or mitigation
within **30 days** for high/critical severity.

If you have not received a reply after 7 days, feel free to escalate
publicly via a generic GitHub issue ("awaiting response on private
report") — we will pick it up.

## Scope

In scope:

- Bypasses of the scanner pipeline (Aho-Corasick → regex → Unicode
  normalization). Includes any new evasion class — homoglyphs, novel
  invisible code points, bidi tricks, encoding round-trips, etc.
- Mishandling of `armor_verify_manifest` Ed25519 verification.
- Path-traversal, privilege-escalation, or RCE in the proxy/control-plane.
- Mutex-poisoning or deadlock vectors that crash the sidecar.
- Supply-chain issues in `Cargo.toml` deps that we missed in
  `cargo audit`.

Out of scope (still report them, but they are not security-tier):

- Performance regressions outside the p99 < 5 ms budget.
- README or documentation typos.
- v0.2-backlog gaps that are already documented (TOFU keystore, full
  Sigstore bridge, OTLP gRPC, Windows target).

## Coordinated Disclosure

We follow responsible coordinated disclosure. After a fix lands and a
patched release is published to crates.io, we will:

1. Issue a CHANGELOG entry referencing the CVE (if assigned) or a
   GitHub Security Advisory.
2. Credit the reporter (if they wish to be credited).
3. Optionally backfill a regression test against the now-patched payload.

If you would like a CVE assigned, we can request one via GitHub once the
fix is in `main`.

## PGP / Encrypted Email

We do not currently offer PGP. If you need encrypted transport, request
a one-time Signal handle via the email above and we will set it up.

## Acknowledgements

mcp-armor's threat model and pattern set are ports/derivations from
[studiomeyer-io/ai-shield](https://github.com/studiomeyer-io/ai-shield)
(Round 4 evasion work), with additional CVE references curated from the
[OX Security April 2026 advisory wave](https://www.ox.security/blog/).
Independent reviewers and the OX team have helped shape the v0.1 scope.
