use crate::error::ArmorError;
use crate::manifest::canonical::canonicalize_json;
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
}
