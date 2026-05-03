//! Compile-time guard for the reserved `sigstore-bridge` feature flag.
//!
//! v0.1 ships this stub so the publicly documented feature name stays
//! reserved (CHANGELOG + README reference it), but enabling the flag now
//! triggers a clear error instead of a silent no-op build.
//!
//! Kills the Lumina-class anti-pattern "empty feature flag = vaporware"
//! (S982) while preserving the v0.2 interface contract.

#[cfg(feature = "sigstore-bridge")]
compile_error!(
    "feature `sigstore-bridge` is reserved for v0.2 and is a no-op in v0.1. \
     Track https://github.com/studiomeyer-io/mcp-armor/issues for the \
     sigstore-rs 0.10 wiring or pin to v0.1 without this feature."
);
