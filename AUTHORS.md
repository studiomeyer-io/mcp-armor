# Authors

mcp-armor is built at [StudioMeyer](https://studiomeyer.io), a small studio
in Palma de Mallorca.

## Maintainer

- **Matthias Meyer** (StudioMeyer) — <hi@studiomeyer.io>

## AI co-authors

This project is developed in a human-in-the-loop workflow with Anthropic's
Claude models. Their contributions are credited here and in the
`Co-Authored-By` trailers of the commits they co-wrote.

- **Claude Fable 5** — v0.8 Layer 8 (tool-description / full-schema
  poisoning detection), the `path_traversal` scanner pattern, and the
  2026-07-03 CVE-feed refresh.
- **Claude Opus 4.8** — v0.1 through v0.7 (scanner pipeline, TOFU
  keystore, Sigstore bridge, OTLP export, Layer 7 drift detection, the
  rmcp 1.5 control-plane migration).

Every line ships behind a two-round adversarial code-review loop and the
full CI gate (tests + clippy `-D warnings` + fmt + cargo-deny + a release
p99 budget). The humans decide; the models draft, review, and harden.
