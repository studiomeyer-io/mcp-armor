//! Manifest verification: Ed25519-signed `tools/list` responses.
//!
//! Adresses the marketplace-poisoning class (CVE-2026-22252 LibreChat MITM).
//! TOFU-mode default in v0.1; Sigstore bridge is opt-in via `--sigstore`
//! flag (see PLAN.md R1).

pub mod canonical;
pub mod ed25519;

pub use canonical::canonicalize_json;
pub use ed25519::{verify, VerifyOutcome};
