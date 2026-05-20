//! Manifest verification: Ed25519-signed `tools/list` responses.
//!
//! v0.1 shipped stateless cryptographic verify only.
//! v0.2 adds two operator-facing layers on top:
//!
//! - [`tofu`] — Trust-On-First-Use keystore (`~/.local/share/mcp-armor/keys.toml`)
//!   that pins maintainer public keys after the first manual accept. Subsequent
//!   verifies cross-check the supplied key against the pinned fingerprint and
//!   refuse to validate on mismatch — closing the marketplace-mirror class
//!   where both manifest and pubkey are swapped together.
//!
//! - [`sigstore`] — cosign sigstore.json bundle parsing + Rekor transparency
//!   log lookup. Bundle parser and structural SET verify are always available;
//!   the online [`sigstore::RekorClient`] and [`sigstore::lookup_rekor_by_hash`]
//!   helpers are gated on `--features sigstore-bridge` because they bring
//!   `ureq` (rustls) as an extra dependency.
//!
//! Addresses CVE-2026-22252 LibreChat MITM and the broader marketplace-
//! poisoning class.

pub mod canonical;
pub mod ed25519;
pub mod sigstore;
pub mod tofu;

pub use canonical::canonicalize_json;
pub use ed25519::{verify, verify_with_tofu, TofuVerifyOutcome, VerifyOutcome};
pub use tofu::{Keystore, PinOutcome, PinnedKey, VerifyPin};
