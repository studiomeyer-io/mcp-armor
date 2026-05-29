# syntax=docker/dockerfile:1
#
# mcp-armor — OCI image for the Official MCP Registry (oci package type).
#
# The default command runs `mcp-armor mcp-control`: a stdio MCP server that
# exposes 10 read-only security tools (scan_payload, verify_manifest, check_cve,
# get_drift_history, rekor_lookup, ...). This is the surface the registry lists.
#
# To use mcp-armor as a wrapping sidecar instead (its primary mode), override
# the command:  docker run ghcr.io/studiomeyer-io/mcp-armor wrap -- <your-server>
#
# Reproducible: builds from source against the committed Cargo.lock.

FROM rust:bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --release --locked --bin mcp-armor

FROM gcr.io/distroless/cc-debian12:nonroot
# Ownership annotation for the Official MCP Registry — must match server.json "name".
LABEL io.modelcontextprotocol.server.name="io.studiomeyer/armor"
LABEL org.opencontainers.image.title="mcp-armor" \
      org.opencontainers.image.source="https://github.com/studiomeyer-io/mcp-armor" \
      org.opencontainers.image.description="Drop-in security sidecar for MCP servers — prompt-injection scanner, Ed25519 manifest verification, tools/list schema-drift detection. Control plane exposes 10 read-only MCP tools." \
      org.opencontainers.image.licenses="MIT"
COPY --from=builder /build/target/release/mcp-armor /usr/local/bin/mcp-armor
ENTRYPOINT ["/usr/local/bin/mcp-armor"]
CMD ["mcp-control"]
