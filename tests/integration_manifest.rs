//! Roundtrip the Ed25519 manifest signing + verify path end-to-end.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use mcp_armor::manifest::{canonicalize_json, verify};
use serde_json::json;

fn make_pair() -> (String, SigningKey) {
    let seed = [13u8; 32];
    let sk = SigningKey::from_bytes(&seed);
    let pk = B64.encode(sk.verifying_key().to_bytes());
    (pk, sk)
}

#[test]
fn happy_roundtrip() {
    let (pk, sk) = make_pair();
    let manifest = json!({
        "tools": [
            {"name": "echo", "description": "echo back input"},
            {"name": "now", "description": "current iso timestamp"}
        ]
    });
    let canonical = canonicalize_json(&manifest).expect("canonical");
    let sig = sk.sign(&canonical);
    let sig_b64 = B64.encode(sig.to_bytes());
    let outcome = verify(&manifest, &pk, &sig_b64, None).expect("verify");
    assert!(outcome.valid);
}

#[test]
fn detects_tamper_post_signing() {
    let (pk, sk) = make_pair();
    let original = json!({"tools": [{"name": "calc"}]});
    let canonical = canonicalize_json(&original).expect("canonical");
    let sig = sk.sign(&canonical);
    let sig_b64 = B64.encode(sig.to_bytes());
    // Attacker swaps a tool description after signing.
    let tampered = json!({
        "tools": [{"name": "calc", "description": "<script>steal()</script>"}]
    });
    let outcome = verify(&tampered, &pk, &sig_b64, None).expect("verify call");
    assert!(!outcome.valid);
    assert!(outcome.error.is_some());
}

#[test]
fn key_order_independence() {
    let (pk, sk) = make_pair();
    let signed = json!({"a": 1, "b": 2, "c": 3});
    let canonical = canonicalize_json(&signed).expect("canon");
    let sig = sk.sign(&canonical);
    let sig_b64 = B64.encode(sig.to_bytes());

    // Same logical content, different key order in source JSON text.
    let reordered: serde_json::Value =
        serde_json::from_str(r#"{"c":3,"a":1,"b":2}"#).expect("parse");
    let outcome = verify(&reordered, &pk, &sig_b64, None).expect("verify");
    assert!(outcome.valid);
}
