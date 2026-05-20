use crate::error::ArmorError;
use crate::manifest::canonical::canonicalize_json;
use crate::manifest::tofu::{Keystore, PinOutcome, PinnedKey, VerifyPin};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use blake3::Hasher;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyOutcome {
    pub valid: bool,
    pub key_fingerprint: String,
    pub signed_at_iso: Option<String>,
    pub error: Option<String>,
}

/// v0.2 — outcome of [`verify_with_tofu`]. Adds the TOFU layer on top of the
/// stateless cryptographic verify so the caller can render the right operator
/// message and the audit trail can record what happened.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TofuVerifyOutcome {
    /// True iff (a) the cryptographic signature is valid AND (b) the
    /// fingerprint either matches the existing pin OR was newly pinned in
    /// this call (with `pin_on_first_use=true`).
    pub valid: bool,
    /// Short blake3-derived fingerprint of the supplied public key.
    pub key_fingerprint: String,
    /// `NewlyPinned` / `AlreadyPinned` / `null` if pinning was not attempted.
    pub pin_outcome: Option<&'static str>,
    /// Free-form reason when `valid=false` (e.g. fingerprint mismatch).
    pub error: Option<String>,
    /// `true` when the cryptographic Ed25519 verify itself succeeded.
    /// Distinguishes "signature was valid but key was not the pinned one"
    /// (still rejected) from "signature was bad".
    pub crypto_valid: bool,
    /// Pinned fingerprint at the time the call was made, if any. Surfaces
    /// the marketplace-mirror swap case to the audit log.
    pub previously_pinned_fingerprint: Option<String>,
}

/// Verify an Ed25519 signature over the canonical-JSON form of a
/// `tools/list` response. The signature and public key are passed as base64.
/// `signed_at_iso` is optional metadata from the manifest.
pub fn verify(
    tools_list_response: &Value,
    public_key_b64: &str,
    signature_b64: &str,
    signed_at_iso: Option<&str>,
) -> Result<VerifyOutcome, ArmorError> {
    let pk_bytes = B64.decode(public_key_b64).map_err(ArmorError::Base64)?;
    if pk_bytes.len() != 32 {
        return Err(ArmorError::MalformedKey(format!(
            "expected 32 bytes, got {}",
            pk_bytes.len()
        )));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let key = VerifyingKey::from_bytes(&pk_arr)?;

    let sig_bytes = B64.decode(signature_b64).map_err(ArmorError::Base64)?;
    if sig_bytes.len() != 64 {
        return Err(ArmorError::MalformedKey(format!(
            "expected 64-byte sig, got {}",
            sig_bytes.len()
        )));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);

    let canonical = canonicalize_json(tools_list_response)?;
    let valid = key.verify(&canonical, &sig).is_ok();

    let mut hasher = Hasher::new();
    hasher.update(&pk_arr);
    let fingerprint = hex_short(hasher.finalize().as_bytes(), 16);

    Ok(VerifyOutcome {
        valid,
        key_fingerprint: fingerprint,
        signed_at_iso: signed_at_iso.map(str::to_owned),
        error: if valid {
            None
        } else {
            Some("signature did not verify".into())
        },
    })
}

fn hex_short(bytes: &[u8], n: usize) -> String {
    let mut out = String::with_capacity(n * 2);
    for b in bytes.iter().take(n) {
        let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{b:02x}"));
    }
    out
}

/// v0.2 — verify with TOFU continuity check.
///
/// 1. Compute the cryptographic verify outcome (`verify()`).
/// 2. Look up the fingerprint in `keystore` under `server_name`.
/// 3. Three cases:
///    - **Match**: pinned fingerprint == supplied fingerprint → propagate
///      the crypto verdict.
///    - **UnknownServer**: no prior pin. If `pin_on_first_use=true`, pin
///      the supplied key and return `valid` matching the crypto verdict.
///      If `false`, return `valid=false` so the caller can prompt the
///      operator to pin manually.
///    - **FingerprintMismatch**: pinned key differs from supplied. *Always*
///      return `valid=false`, regardless of crypto verdict — this is the
///      marketplace-mirror signal. Operator must `unpin` to re-pin.
///
/// `keystore` is mutated when `pin_on_first_use=true` AND the server is
/// unknown AND the crypto verify passed (we never pin a bad signature).
/// Caller is responsible for persisting via `keystore.persist(path)` if
/// they want the pin to survive a restart.
pub fn verify_with_tofu(
    tools_list_response: &Value,
    public_key_b64: &str,
    signature_b64: &str,
    signed_at_iso: Option<&str>,
    keystore: &mut Keystore,
    server_name: &str,
    pin_on_first_use: bool,
) -> Result<TofuVerifyOutcome, ArmorError> {
    let crypto = verify(
        tools_list_response,
        public_key_b64,
        signature_b64,
        signed_at_iso,
    )?;
    let pinned_fp = keystore
        .find_by_server(server_name)
        .map(|p| p.key_fingerprint.clone());

    let pin_status = keystore.verify_pin(server_name, &crypto.key_fingerprint);

    let (valid, pin_outcome, error): (bool, Option<&'static str>, Option<String>) = match pin_status
    {
        VerifyPin::Match => (crypto.valid, Some("already_pinned"), crypto.error.clone()),
        VerifyPin::FingerprintMismatch { expected, found } => (
            false,
            None,
            Some(format!(
                "TOFU fingerprint mismatch for server={server_name}: \
                 pinned={expected}, presented={found}. Refusing verify. \
                 Run `mcp-armor keystore unpin {server_name}` to accept a \
                 new key (operator review required)."
            )),
        ),
        VerifyPin::UnknownServer if pin_on_first_use && crypto.valid => {
            // Only pin keys whose signature actually verified — pinning a
            // bad-signature key would persist garbage and trip every future
            // verify under the same server_name.
            let outcome = keystore.pin(PinnedKey {
                server_name: server_name.to_string(),
                key_fingerprint: crypto.key_fingerprint.clone(),
                public_key_b64: public_key_b64.to_string(),
                pinned_at_iso: crate::manifest::tofu::now_iso(),
            })?;
            let tag = match outcome {
                PinOutcome::NewlyPinned => "newly_pinned",
                PinOutcome::AlreadyPinned => "already_pinned",
            };
            (true, Some(tag), None)
        }
        VerifyPin::UnknownServer => (
            false,
            None,
            Some(format!(
                "TOFU: server={server_name} is not pinned. Re-run with \
                 `--pin-on-first-use` after manually verifying \
                 fingerprint={} out-of-band.",
                crypto.key_fingerprint
            )),
        ),
    };

    Ok(TofuVerifyOutcome {
        valid,
        key_fingerprint: crypto.key_fingerprint,
        pin_outcome,
        error,
        crypto_valid: crypto.valid,
        previously_pinned_fingerprint: pinned_fp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    fn make_pair() -> (String, SigningKey) {
        // Deterministic seed — fine for unit tests, never for production.
        let seed = [7u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let pk_b64 = B64.encode(sk.verifying_key().to_bytes());
        (pk_b64, sk)
    }

    #[test]
    fn happy_path_verifies() {
        let (pk, sk) = make_pair();
        let msg = json!({"tools": [{"name": "echo"}]});
        let canonical = canonicalize_json(&msg).expect("canon");
        let sig = sk.sign(&canonical);
        let sig_b64 = B64.encode(sig.to_bytes());
        let r = verify(&msg, &pk, &sig_b64, Some("2026-05-03T12:00:00Z")).expect("ok");
        assert!(r.valid, "{:?}", r.error);
        assert_eq!(r.signed_at_iso.as_deref(), Some("2026-05-03T12:00:00Z"));
        assert_eq!(r.key_fingerprint.len(), 32);
    }

    #[test]
    fn invalid_sig_fails_gracefully() {
        let (pk, sk) = make_pair();
        let msg = json!({"tools": [{"name": "echo"}]});
        let canonical = canonicalize_json(&msg).expect("canon");
        let sig = sk.sign(&canonical);
        let mut sig_bytes = sig.to_bytes();
        sig_bytes[0] ^= 0xff;
        let bad_sig_b64 = B64.encode(sig_bytes);
        let r = verify(&msg, &pk, &bad_sig_b64, None).expect("ok");
        assert!(!r.valid);
        assert!(r.error.is_some());
    }

    #[test]
    fn malformed_key_returns_err() {
        let bad_pk = B64.encode([1u8; 16]);
        let msg = json!({"tools": []});
        let r = verify(&msg, &bad_pk, &B64.encode([0u8; 64]), None);
        assert!(matches!(r, Err(ArmorError::MalformedKey(_))));
    }

    #[test]
    fn tampered_message_fails() {
        let (pk, sk) = make_pair();
        let msg = json!({"tools": [{"name": "echo"}]});
        let canonical = canonicalize_json(&msg).expect("canon");
        let sig = sk.sign(&canonical);
        let sig_b64 = B64.encode(sig.to_bytes());

        // Now modify the message after signing.
        let tampered = json!({"tools": [{"name": "echo-tampered"}]});
        let r = verify(&tampered, &pk, &sig_b64, None).expect("ok");
        assert!(!r.valid);
    }

    #[test]
    fn key_order_independent() {
        // Same logical content, different key order — must yield same canonical
        // form and verify.
        let (pk, sk) = make_pair();
        let msg_a = json!({"a": 1, "b": 2});
        let canon = canonicalize_json(&msg_a).expect("canon");
        let sig = sk.sign(&canon);
        let sig_b64 = B64.encode(sig.to_bytes());

        let msg_b: Value = serde_json::from_str(r#"{"b":2,"a":1}"#).expect("parse");
        let r = verify(&msg_b, &pk, &sig_b64, None).expect("ok");
        assert!(r.valid);
    }

    // ──── v0.2 TOFU verify tests ───────────────────────────────────────────

    fn signed_manifest() -> (String, String, Value) {
        let (pk, sk) = make_pair();
        let manifest = json!({"tools": [{"name": "echo"}]});
        let canon = canonicalize_json(&manifest).expect("canon");
        let sig = B64.encode(sk.sign(&canon).to_bytes());
        (pk, sig, manifest)
    }

    #[test]
    fn tofu_pin_on_first_use_succeeds_and_persists_fingerprint() {
        let (pk, sig, manifest) = signed_manifest();
        let mut ks = Keystore::empty();
        let r = verify_with_tofu(&manifest, &pk, &sig, None, &mut ks, "fs", true).expect("ok");
        assert!(r.valid, "first-use pin must accept good signature");
        assert!(r.crypto_valid);
        assert_eq!(r.pin_outcome, Some("newly_pinned"));
        assert_eq!(ks.len(), 1);
        let pinned = ks.find_by_server("fs").expect("pinned entry");
        assert_eq!(pinned.key_fingerprint, r.key_fingerprint);
    }

    #[test]
    fn tofu_unknown_server_without_pin_flag_refuses() {
        let (pk, sig, manifest) = signed_manifest();
        let mut ks = Keystore::empty();
        let r = verify_with_tofu(&manifest, &pk, &sig, None, &mut ks, "fs", false).expect("ok");
        assert!(
            !r.valid,
            "unknown server without pin_on_first_use must refuse"
        );
        assert!(r.crypto_valid, "crypto verify still passed");
        assert_eq!(ks.len(), 0, "no pin written when flag is false");
    }

    #[test]
    fn tofu_subsequent_call_with_matching_fingerprint_succeeds() {
        let (pk, sig, manifest) = signed_manifest();
        let mut ks = Keystore::empty();
        let _ = verify_with_tofu(&manifest, &pk, &sig, None, &mut ks, "fs", true).expect("first");
        // Second call — same key, same server — must succeed without re-pin.
        let r = verify_with_tofu(&manifest, &pk, &sig, None, &mut ks, "fs", false).expect("ok");
        assert!(r.valid);
        assert_eq!(r.pin_outcome, Some("already_pinned"));
    }

    #[test]
    fn tofu_fingerprint_mismatch_always_rejects() {
        // Pin server "fs" to key A. Now attacker presents valid signature
        // signed by key B for the same server_name — TOFU must reject even
        // though the signature is cryptographically valid.
        let (pk_a, sig_a, manifest_a) = signed_manifest();
        let mut ks = Keystore::empty();
        let _ =
            verify_with_tofu(&manifest_a, &pk_a, &sig_a, None, &mut ks, "fs", true).expect("pin");

        let seed_b = [42u8; 32];
        let sk_b = ed25519_dalek::SigningKey::from_bytes(&seed_b);
        let pk_b = B64.encode(sk_b.verifying_key().to_bytes());
        let manifest_b = json!({"tools": [{"name": "evil"}]});
        let canon_b = canonicalize_json(&manifest_b).expect("canon");
        let sig_b = B64.encode(sk_b.sign(&canon_b).to_bytes());

        let r =
            verify_with_tofu(&manifest_b, &pk_b, &sig_b, None, &mut ks, "fs", false).expect("ok");
        assert!(!r.valid, "mismatched key under known server must reject");
        assert!(
            r.crypto_valid,
            "crypto verify on the attacker's payload still passed — TOFU is the only guard"
        );
        assert!(r.error.is_some());
        assert!(r.previously_pinned_fingerprint.is_some());
    }

    #[test]
    fn tofu_does_not_pin_bad_signature() {
        let (pk, sk) = make_pair();
        let manifest = json!({"tools": [{"name": "echo"}]});
        let canon = canonicalize_json(&manifest).expect("canon");
        let sig = sk.sign(&canon);
        let mut sig_bytes = sig.to_bytes();
        sig_bytes[0] ^= 0xff;
        let bad_sig = B64.encode(sig_bytes);

        let mut ks = Keystore::empty();
        let r = verify_with_tofu(&manifest, &pk, &bad_sig, None, &mut ks, "fs", true).expect("ok");
        assert!(!r.valid);
        assert!(!r.crypto_valid);
        assert_eq!(
            ks.len(),
            0,
            "must never pin a key whose signature did not verify"
        );
    }
}
