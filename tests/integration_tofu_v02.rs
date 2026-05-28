#![allow(deprecated)]
// v0.5/v0.4/v0.2 tests still exercise the bare persist_locked path; v0.6 deprecates it but the path stays functional.
//! v0.2 integration: TOFU verify-then-pin roundtrip end-to-end.
//!
//! Mirrors the operator-facing flow:
//! 1. Empty keystore on disk.
//! 2. Generate Ed25519 key + sign a manifest.
//! 3. Call `verify_with_tofu(... pin_on_first_use=true)` → pins.
//! 4. Persist keystore atomically (0o600 on Unix).
//! 5. Re-load keystore, second call with same key succeeds.
//! 6. Third call with attacker's *valid* signature under same server_name
//!    is rejected by the TOFU mismatch — crypto_valid=true, valid=false.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use mcp_armor::manifest::{canonicalize_json, tofu::default_path, verify_with_tofu, Keystore};
use serde_json::json;
use tempfile::tempdir;

fn sign(manifest: &serde_json::Value, seed: [u8; 32]) -> (String, String) {
    let sk = SigningKey::from_bytes(&seed);
    let pk = B64.encode(sk.verifying_key().to_bytes());
    let canon = canonicalize_json(manifest).expect("canon");
    let sig = B64.encode(sk.sign(&canon).to_bytes());
    (pk, sig)
}

#[test]
fn tofu_pin_persist_reload_succeeds() {
    let dir = tempdir().expect("tmp");
    let path = dir.path().join("keys.toml");
    let manifest = json!({"tools": [{"name": "echo"}]});
    let (pk, sig) = sign(&manifest, [9u8; 32]);

    // First-use: pin.
    let mut ks = Keystore::load(&path).expect("load empty");
    let r1 = verify_with_tofu(&manifest, &pk, &sig, None, &mut ks, "fs", true).expect("ok");
    assert!(r1.valid);
    assert_eq!(r1.pin_outcome, Some("newly_pinned"));
    ks.persist(&path).expect("persist");

    // Reload from disk + second call with same key → success without re-pin.
    let mut ks2 = Keystore::load(&path).expect("load after persist");
    assert_eq!(ks2.len(), 1);
    let r2 = verify_with_tofu(&manifest, &pk, &sig, None, &mut ks2, "fs", false).expect("ok");
    assert!(r2.valid);
    assert_eq!(r2.pin_outcome, Some("already_pinned"));
}

#[test]
fn tofu_attacker_swap_under_known_server_rejected() {
    let dir = tempdir().expect("tmp");
    let path = dir.path().join("keys.toml");
    let manifest = json!({"tools": [{"name": "echo"}]});
    let (pk_legit, sig_legit) = sign(&manifest, [9u8; 32]);

    // Pin the legit key.
    let mut ks = Keystore::load(&path).expect("empty");
    let _ =
        verify_with_tofu(&manifest, &pk_legit, &sig_legit, None, &mut ks, "fs", true).expect("ok");
    ks.persist(&path).expect("persist");

    // Attacker signs their own manifest with a different key under the same
    // server_name. Crypto verify passes — TOFU is the only line of defence.
    let attacker_manifest = json!({"tools": [{"name": "evil"}]});
    let (pk_attacker, sig_attacker) = sign(&attacker_manifest, [42u8; 32]);
    let mut ks2 = Keystore::load(&path).expect("load");
    let r = verify_with_tofu(
        &attacker_manifest,
        &pk_attacker,
        &sig_attacker,
        None,
        &mut ks2,
        "fs",
        false,
    )
    .expect("ok");
    assert!(!r.valid, "TOFU must reject key swap");
    assert!(
        r.crypto_valid,
        "crypto verify of attacker's payload still passes"
    );
    assert!(
        r.error.as_deref().unwrap_or("").contains("mismatch"),
        "error must mention mismatch"
    );
}

/// Default path lives under $XDG_DATA_HOME or $HOME/.local/share/mcp-armor/.
/// Sanity-check the resolution falls back gracefully.
#[test]
fn default_path_falls_back_when_xdg_unset() {
    // Cannot mutate env in a parallel test suite without races; this test
    // just asserts the function returns *some* path, that's enough to catch
    // an accidental panic refactor.
    let p = default_path();
    assert!(!p.as_os_str().is_empty());
    assert!(p.to_string_lossy().ends_with("keys.toml"));
}
