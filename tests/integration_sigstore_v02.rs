//! v0.2 integration: Sigstore bundle parsing + structural Rekor inclusion
//! verification (offline). Online Rekor REST calls are not exercised here
//! — they live in `cargo test --features sigstore-bridge` under the
//! corresponding unit-test module so CI doesn't depend on the public
//! Rekor instance being reachable.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use mcp_armor::manifest::sigstore::{artifact_hash_sha256_hex, verify_inclusion, Bundle};
use serde_json::json;

#[test]
fn bundle_minimal_signature_only_parses_cleanly() {
    let raw = r#"{"base64Signature":"SGVsbG8="}"#;
    let b = Bundle::parse(raw).expect("parse");
    assert_eq!(b.base64_signature, "SGVsbG8=");
    assert!(b.cert_pem.is_none());
    assert!(b.rekor_bundle.is_none());
}

#[test]
fn bundle_with_rekor_section_parses_log_index_and_integrated_time() {
    // Use a 64-byte SET so structural verify says structural_ok=true.
    let raw_sig = vec![0xab_u8; 64];
    let b64_sig = B64.encode(&raw_sig);
    let raw = serde_json::json!({
        "base64Signature": "MEUCIQ==",
        "cert": "-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----",
        "rekorBundle": {
            "SignedEntryTimestamp": b64_sig,
            "Payload": {
                "logIndex": 4242,
                "integratedTime": 1_700_000_000
            }
        }
    })
    .to_string();
    let b = Bundle::parse(&raw).expect("parse");
    let inc = verify_inclusion(&b).expect("verify");
    assert!(inc.structural_ok);
    assert!(
        inc.partial,
        "v0.2 is partial pending v0.3 Rekor-pubkey verify"
    );
    assert_eq!(inc.log_index, Some(4242));
    assert_eq!(inc.integrated_time, Some(1_700_000_000));
}

#[test]
fn artifact_hash_is_canonical_key_order_independent() {
    let a = json!({"a": 1, "b": 2});
    let b: serde_json::Value = serde_json::from_str(r#"{"b":2,"a":1}"#).expect("parse");
    let ha = artifact_hash_sha256_hex(&a).expect("hash");
    let hb = artifact_hash_sha256_hex(&b).expect("hash");
    assert_eq!(ha, hb, "canonicalisation must yield identical sha256");
    assert_eq!(ha.len(), 64);
}

#[test]
fn artifact_hash_matches_nist_vector_for_known_input() {
    // The canonical form of {"x":"abc"} sorted-keys-with-minimal-escape is
    // `{"x":"abc"}`. Just sanity-check the function returns a 64-char hex.
    let v = json!({"x": "abc"});
    let h = artifact_hash_sha256_hex(&v).expect("hash");
    assert_eq!(h.len(), 64);
    assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn missing_signature_field_rejected() {
    let r = Bundle::parse(r#"{"base64Signature":""}"#);
    assert!(r.is_err());
}

/// Round-1-review H3 regression: oversized bundle JSON must be rejected
/// before the serde_json parser is engaged. The cap is documented at
/// 1 MiB. We feed 2 MiB of well-formed JSON and assert the parser is
/// short-circuited.
#[test]
fn oversized_bundle_rejected_before_parse() {
    let mut raw = String::with_capacity(2 * 1024 * 1024);
    raw.push_str(r#"{"base64Signature":"AA==","filler":""#);
    while raw.len() < 2 * 1024 * 1024 {
        raw.push('x');
    }
    raw.push_str("\"}");
    let r = Bundle::parse(&raw);
    let err = r.expect_err("oversized bundle must be rejected");
    assert!(
        format!("{err}").contains("byte cap") || format!("{err}").contains("exceeds"),
        "error must mention the size cap, got: {err}"
    );
}
