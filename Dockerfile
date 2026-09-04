# syntax=docker/dockerfile:1
#
# mcp-armor — OCI image for the Official MCP Registry (oci package type).
#
# The default command runs `mcp-armor mcp-control`: a stdio MCP server that
# exposes 11 read-only security tools (scan_payload, verify_manifest, check_cve,
# get_drift_history, rekor_lookup, ...). This is the surface the registry lists.
#
# To use mcp-armor as a wrapping sidecar instead (its primary mode), override
# the command:  docker run ghcr.io/studiomeyer-io/mcp-armor wrap -- <your-server>
#
# Reproducible: builds from source against the committed Cargo.lock.

FROM rust:bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922 AS builder
WORKDIR /build
COPY . .
RUN cargo build --release --locked --bin mcp-armor

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
# Ownership annotation for the Official MCP Registry — must match server.json "name".
LABEL io.modelcontextprotocol.server.name="io.studiomeyer/armor"
LABEL org.opencontainers.image.title="mcp-armor" \
      org.opencontainers.image.source="https://github.com/studiomeyer-io/mcp-armor" \
      org.opencontainers.image.description="Drop-in security sidecar for MCP servers — prompt-injection scanner, Ed25519 manifest verification, tools/list schema-drift detection. Control plane exposes 11 read-only MCP tools." \
      org.opencontainers.image.licenses="MIT"
COPY --from=builder /build/target/release/mcp-armor /usr/local/bin/mcp-armor
ENTRYPOINT ["/usr/local/bin/mcp-armor"]
CMD ["mcp-control"]
