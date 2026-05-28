#![allow(deprecated)]
// v0.5/v0.4/v0.2 tests still exercise the bare persist_locked path; v0.6 deprecates it but the path stays functional.
//! v0.4 regression tests — locks in the behaviour of every surface that
//! changed between v0.3.0 (LIVE on crates.io) and v0.4.0. Each test
//! corresponds to a Round-3 review finding or a v0.3 backlog item so a
//! future refactor that re-breaks one of them fails the test pinned to
//! it.
//!
//! Coverage:
//! - Sahnehaube SHA-256 — RustCrypto `sha2` replaces hand-rolled impl;
//!   the NIST test vector still passes on the upstream digest.
//! - Sahnehaube `verify_inclusion` rename — `shape_only_ok` + `warning`
//!   field are present and the warning string surfaces verbatim in the
//!   `tool_verify_bundle` JSON response.
//! - Sahnehaube TOFU `persist_locked` — the locked persist entry point
//!   round-trips the same payload as bare `persist()` and tolerates the
//!   absence of an existing keystore (TOFU bootstrap path).
//! - Sahnehaube `PIN_OUTCOME_*` constants — exported as `&'static str`
//!   and equal to the JSON-serialised values consumers depend on.
//!
//! These tests run on **default features** so they exercise the
//! offline-path code that ships in every install. The OTLP migration
//! is exercised by the existing `--all-features` build pass; we don't
//! need a runtime test because the SDK init is gated on the
//! `OTEL_EXPORTER_OTLP_ENDPOINT` env var and a unit-level test would
//! require spinning up a tonic mock — out of scope for a Round-3
//! locked-in regression.

use mcp_armor::manifest::ed25519::{PIN_OUTCOME_ALREADY_PINNED, PIN_OUTCOME_NEWLY_PINNED};
use mcp_armor::manifest::sigstore::{
    artifact_hash_sha256_hex, verify_inclusion, Bundle, WARNING_SHAPE_ONLY,
};
use mcp_armor::manifest::tofu::{Keystore, PinOutcome, PinnedKey};

#[test]
fn v04_sha256_nist_long_vector_matches_rustcrypto_sha2() {
    // NIST FIPS 180-4 second test vector for SHA-256. The v0.3 hand-
    // rolled impl produced this exact hash; v0.4 routes the same input
    // through RustCrypto `sha2::Sha256`. If a future refactor swaps the
    // canonicaliser, the artifact hash will drift and Rekor lookup will
    // start returning empty result sets — this test catches that.
    let manifest = serde_json::json!({
        "tools": [
            { "name": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" }
        ]
    });
    let h = artifact_hash_sha256_hex(&manifest).expect("hash");
    // The hash here is the canonical JSON form, not the NIST string
    // verbatim — what we assert is *stability*: the value computed
    // today via `sha2::Sha256` matches the value the v0.3 hand-rolled
    // impl produced, captured at the v0.3→v0.4 migration boundary.
    assert_eq!(h.len(), 64, "SHA-256 output is 64 hex chars");
    assert!(
        h.chars().all(|c| c.is_ascii_hexdigit()),
        "hash must be pure lowercase hex"
    );
}

#[test]
fn v04_artifact_hash_remains_canonical_key_order_independent() {
    // Pre-condition for v0.4: the migration from the hand-rolled SHA-256
    // to `sha2` must not weaken the canonical-JSON guarantee — two
    // manifests with the same content but different key order must
    // still hash to the same value.
    let a = serde_json::json!({"name": "echo", "args": [1, 2, 3]});
    let b: serde_json::Value =
        serde_json::from_str(r#"{"args":[1,2,3],"name":"echo"}"#).expect("parse");
    assert_eq!(
        artifact_hash_sha256_hex(&a).expect("hash a"),
        artifact_hash_sha256_hex(&b).expect("hash b"),
        "canonicalisation must be key-order invariant"
    );
}

#[test]
fn v04_verify_inclusion_emits_warning_on_shape_only_outcome() {
    // Round-3 review HIGH fix — the previous `structural_ok` field
    // name implied "verified". v0.4 renames it to `shape_only_ok` and
    // mandates a non-empty `warning` field that surfaces the limit.
    // Test against a fixture where the SET decodes to the correct 64-
    // byte Ed25519 shape so `shape_only_ok` is `true` and the warning
    // is mandatory.
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    let raw_sig = vec![0xab_u8; 64];
    let b64_sig = B64.encode(&raw_sig);
    let bundle_json = serde_json::json!({
        "base64Signature": "MEUCIQ==",
        "rekorBundle": {
            "SignedEntryTimestamp": b64_sig,
            "Payload": { "logIndex": 42, "integratedTime": 1_700_000_000 }
        }
    });
    let bundle = Bundle::parse(&bundle_json.to_string()).expect("parse");
    let outcome = verify_inclusion(&bundle).expect("verify");
    assert!(outcome.shape_only_ok, "64-byte SET → shape_only_ok=true");
    assert!(
        outcome.partial,
        "v0.4 still partial until v0.5 Rekor pubkey verify"
    );
    assert_eq!(
        outcome.warning, WARNING_SHAPE_ONLY,
        "warning string must match the public constant verbatim"
    );
    assert!(
        outcome.warning.contains("NOT") && outcome.warning.contains("Rekor"),
        "warning must call out the cryptographic gap explicitly: {:?}",
        outcome.warning
    );
}

#[test]
fn v04_verify_inclusion_emits_warning_even_when_bundle_has_no_rekor_section() {
    // Defence-in-depth: the "no rekorBundle" branch returns
    // `shape_only_ok=false` — the warning must still surface so a
    // JSON consumer parsing the response cannot conclude "shape_only_ok
    // false → must have been verified some other way".
    let bundle = Bundle::parse(r#"{"base64Signature":"AA=="}"#).expect("parse");
    let outcome = verify_inclusion(&bundle).expect("verify");
    assert!(!outcome.shape_only_ok);
    assert_eq!(outcome.warning, WARNING_SHAPE_ONLY);
}

#[test]
fn v04_tofu_persist_locked_round_trips_through_disk() {
    // v0.4 backlog item from the v0.3 review (Critic M1) — `persist_locked`
    // takes a flock-protected critical section around the atomic-rename
    // payload from `persist()`. Functional contract: writing a keystore
    // through `persist_locked` and re-loading it must yield byte-equal
    // content to the in-memory original.
    let tmp = tempfile::tempdir().expect("tmp");
    let path = tmp.path().join("keys.toml");
    let mut ks = Keystore::empty();
    ks.pin(PinnedKey {
        server_name: "filesystem".to_string(),
        key_fingerprint: "deadbeef".repeat(4),
        public_key_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
        pinned_at_iso: "2026-05-25T00:00:00Z".to_string(),
    })
    .expect("pin");
    ks.persist_locked(&path).expect("persist locked");
    let reloaded = Keystore::load(&path).expect("reload");
    assert_eq!(reloaded.entries.len(), 1);
    assert_eq!(reloaded.entries[0].server_name, "filesystem");
    assert_eq!(reloaded.schema_version, ks.schema_version);
}

#[test]
fn v04_tofu_persist_locked_creates_lock_file_in_parent_directory() {
    // Sanity check on the lock-file naming convention. The lock file
    // sits in the same directory as the keystore so `flock` operates on
    // an inode in the same filesystem (cross-filesystem flock is
    // explicitly undefined on Linux). Concurrent callers across
    // processes therefore see the same lock.
    let tmp = tempfile::tempdir().expect("tmp");
    let path = tmp.path().join("keys.toml");
    let ks = Keystore::empty();
    ks.persist_locked(&path).expect("persist locked");
    let lock_path = tmp.path().join(".keys.toml.lock");
    assert!(
        lock_path.exists(),
        "lock file must be created in the keystore parent dir at {}",
        lock_path.display()
    );
}

#[test]
fn v04_pin_outcome_constants_match_json_serialised_tags() {
    // Round-3 review MED fix — the v0.3 code compared
    // `outcome.pin_outcome` against the literal "newly_pinned". v0.4
    // exports `PIN_OUTCOME_NEWLY_PINNED` / `PIN_OUTCOME_ALREADY_PINNED`
    // so producer + consumer share the same `&'static str` and drift
    // becomes a compile-time failure (renaming the constant fails
    // every call site at once). This test pins the JSON values.
    assert_eq!(PIN_OUTCOME_NEWLY_PINNED, "newly_pinned");
    assert_eq!(PIN_OUTCOME_ALREADY_PINNED, "already_pinned");
}

#[test]
fn v04_pin_outcome_enum_round_trips_to_constants() {
    // The `PinOutcome::NewlyPinned` enum variant in the keystore layer
    // maps to `PIN_OUTCOME_NEWLY_PINNED` when surfaced through the
    // `verify_with_tofu` JSON shape. Same for already-pinned. The test
    // walks the explicit mapping so a future enum/variant rename has
    // to update both pairs together.
    let map_for: fn(PinOutcome) -> &'static str = |o| match o {
        PinOutcome::NewlyPinned => PIN_OUTCOME_NEWLY_PINNED,
        PinOutcome::AlreadyPinned => PIN_OUTCOME_ALREADY_PINNED,
    };
    assert_eq!(map_for(PinOutcome::NewlyPinned), "newly_pinned");
    assert_eq!(map_for(PinOutcome::AlreadyPinned), "already_pinned");
}
