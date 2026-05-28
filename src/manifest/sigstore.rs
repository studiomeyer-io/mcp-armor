//! Sigstore Rekor bridge — transparency-log verification for signed manifests.
//!
//! Behind the `sigstore-bridge` Cargo feature. v0.2 ships a deliberately
//! thin implementation that talks to the public Rekor REST API directly
//! instead of pulling in the pre-1.0 `sigstore-rs` crate. Trade-off
//! recorded in CHANGELOG: 30+ transitive deps avoided, 4 stable endpoints
//! covered. When `sigstore-rs` reaches 1.0 we plan to swap to its native
//! `cosign::Client` path; until then, REST is the smaller blast radius.
//!
//! ## What this module does
//!
//! 1. **Bundle parsing** ([`Bundle::parse`]) — the cosign-emitted
//!    `*.sigstore.json` format is stable JSON: `{base64Signature,
//!    cert?, rekorBundle?}`. We parse it without sigstore-rs.
//!
//! 2. **Rekor REST lookup by artifact hash** ([`lookup_rekor_by_hash`]) —
//!    `POST /api/v1/index/retrieve` with `{ "hash": "sha256:<hex>" }`
//!    returns an array of log-entry UUIDs. Then `GET
//!    /api/v1/log/entries/{uuid}` returns the full entry with the SET.
//!
//! 3. **Offline SET verification** ([`verify_inclusion`]) — given a Rekor
//!    log-entry, the inclusion-proof + SignedEntryTimestamp can be checked
//!    against Rekor's published public key. v0.2 verifies the SET
//!    structurally (hash + signature shape) but does NOT yet validate the
//!    inclusion-Merkle-proof — that depends on the TUF-distributed Rekor
//!    pubkey which is also v0.3 backlog (CHANGELOG documents the limit).
//!
//! ## Out of scope (v0.3 backlog)
//!
//! - Fulcio cert chain verification (root-of-trust + identity matching).
//! - TUF-distributed Rekor pubkey rotation.
//! - Online Sigstore staging instance support (we only target
//!   `https://rekor.sigstore.dev`).
//! - Bundle generation. mcp-armor verifies bundles produced by `cosign
//!   sign-blob`; it does not yet emit them itself.

use crate::error::ArmorError;
use crate::manifest::canonical::canonicalize_json;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Default Rekor REST endpoint. Override via [`RekorClient::with_base_url`]
/// for staging or self-hosted instances.
pub const REKOR_PUBLIC_URL: &str = "https://rekor.sigstore.dev";

/// HTTP timeout for Rekor requests (seconds). Defensive against the public
/// instance occasionally hitting 95th-percentile latency in the 1-3 s range.
/// Only used when the `sigstore-bridge` feature is enabled — the constant
/// stays in the always-compiled module so docs reflect the budget.
#[cfg(feature = "sigstore-bridge")]
const REKOR_TIMEOUT_SECS: u64 = 10;

/// v0.2 SECURITY (Round 1 H2): cap on the Rekor REST response body. A real
/// Rekor entry is ~4-16 KiB; 4 MiB is a defensive ceiling against a hijacked
/// or unbounded endpoint that streams gigabytes of JSON until OOM.
/// Streaming-bounded read enforced via [`reqwest::blocking::Response::content_length`]
/// pre-check + a manual `Read::take` on the body stream.
#[cfg(feature = "sigstore-bridge")]
const REKOR_MAX_BODY_BYTES: u64 = 4 * 1024 * 1024;

/// Parsed cosign sigstore.json bundle. We only care about the fields needed
/// to verify a manifest signature; the bundle may carry more (cert chain,
/// timestamps) which we preserve in `raw` for v0.3 use.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_field_names)] // `rekor_bundle` matches the cosign field name.
pub struct Bundle {
    /// Base64-encoded signature. Matches the cosign field name.
    #[serde(rename = "base64Signature")]
    pub base64_signature: String,
    /// Optional PEM-encoded certificate. Present for keyless flows.
    #[serde(default, rename = "cert")]
    pub cert_pem: Option<String>,
    /// Optional embedded Rekor log entry.
    #[serde(default, rename = "rekorBundle")]
    pub rekor_bundle: Option<RekorBundleField>,
    /// Raw JSON kept around so callers can inspect bundle versions we do not
    /// yet decode strictly (cosign v3 sigstore-bundle format, in particular).
    #[serde(default, flatten)]
    pub raw: serde_json::Map<String, Value>,
}

/// The `rekorBundle` field inside a cosign sigstore.json. Mirror of the
/// upstream shape but kept Value-typed for forward compat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekorBundleField {
    #[serde(rename = "SignedEntryTimestamp")]
    pub signed_entry_timestamp: String,
    #[serde(rename = "Payload")]
    pub payload: serde_json::Map<String, Value>,
}

/// v0.2 SECURITY (Round 1 H3): cap on the JSON payload size for
/// [`Bundle::parse`]. A canonical cosign sigstore.json bundle is well under
/// 64 KiB (signature + cert + Rekor SET + Payload metadata). 1 MiB leaves
/// a generous safety margin without exposing the JSON parser to an
/// adversary-controlled multi-megabyte input that would force unbounded
/// allocation in `serde_json`. The cap is enforced before the parser sees
/// the bytes.
pub const MAX_BUNDLE_BYTES: usize = 1024 * 1024;

impl Bundle {
    /// Parse a sigstore.json bundle from a JSON string. Enforces
    /// [`MAX_BUNDLE_BYTES`] (1 MiB) as an input cap.
    pub fn parse(raw: &str) -> Result<Self, ArmorError> {
        if raw.len() > MAX_BUNDLE_BYTES {
            return Err(ArmorError::InvalidPattern(format!(
                "sigstore bundle JSON exceeds the {MAX_BUNDLE_BYTES}-byte cap (got {})",
                raw.len()
            )));
        }
        let parsed: Bundle = serde_json::from_str(raw)?;
        if parsed.base64_signature.trim().is_empty() {
            return Err(ArmorError::InvalidPattern(
                "sigstore bundle missing base64Signature field".to_string(),
            ));
        }
        Ok(parsed)
    }

    /// Convenience: parse from a file path.
    pub fn parse_from_path(path: &std::path::Path) -> Result<Self, ArmorError> {
        let raw = std::fs::read_to_string(path)?;
        Bundle::parse(&raw)
    }

    /// Decode the signature into raw bytes. Validates length (must be 64
    /// bytes for Ed25519, but we are signature-scheme-agnostic at the
    /// bundle layer).
    pub fn signature_bytes(&self) -> Result<Vec<u8>, ArmorError> {
        B64.decode(self.base64_signature.as_bytes())
            .map_err(ArmorError::Base64)
    }
}

/// Compute the SHA-256 hex digest of the canonicalised tools/list response.
/// Rekor entries index by hash, so this is the lookup key.
///
/// Uses blake3 internally for everything else in the crate, but Rekor
/// indexes by SHA-256 — so this is the only place we reach for SHA-256.
///
/// v0.4 (Round-3 review HIGH): switched from a hand-rolled SHA-256 impl
/// to the RustCrypto `sha2` crate. SHA-256 fed into the Rekor artifact
/// hash sits on the audit-trail path; that path shouldn't depend on
/// unaudited cryptography when a battle-tested alternative is a single
/// dep away. `sha2` is FIPS-validated, fuzzed in OSS-Fuzz, and brings
/// in only `digest`, `cpufeatures`, and a thin generic-array layer.
/// The deleted hand-rolled module previously held ~135 lines of NIST-
/// FIPS-180-4 reference code; the test vectors stay (`abc`, empty,
/// NIST long vector) and now exercise the upstream impl.
pub fn artifact_hash_sha256_hex(tools_list_response: &Value) -> Result<String, ArmorError> {
    let canonical = canonicalize_json(tools_list_response)?;
    Ok(sha256_hex(&canonical))
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

// v0.4 — the hand-rolled SHA-256 module (`mod sha256_impl`, ~135 LOC of
// NIST FIPS 180-4 reference code) was deleted in favour of the
// RustCrypto `sha2` crate. The motivation, transitive-dep size and
// audit-trail rationale live in the doc-comment on `sha256_hex` above.
// Test vectors stayed intact and now run against `sha2::Sha256`.

// ──── Rekor REST client ────────────────────────────────────────────────────

/// Minimal Rekor v1 REST client. reqwest::blocking under the hood so it
/// slots into the existing sync control-plane dispatch without an async
/// boundary. Constructed only when `--features sigstore-bridge` is enabled.
#[cfg(feature = "sigstore-bridge")]
pub struct RekorClient {
    base_url: String,
    client: reqwest::blocking::Client,
}

#[cfg(feature = "sigstore-bridge")]
impl Default for RekorClient {
    fn default() -> Self {
        Self::new().expect("default Rekor client should always build with rustls feature")
    }
}

#[cfg(feature = "sigstore-bridge")]
impl RekorClient {
    /// Construct a client pointing at the public Rekor instance
    /// (`https://rekor.sigstore.dev`) with the default 10 s HTTP timeout.
    pub fn new() -> Result<Self, ArmorError> {
        Self::with_base_url(REKOR_PUBLIC_URL)
    }

    pub fn with_base_url(base_url: &str) -> Result<Self, ArmorError> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(REKOR_TIMEOUT_SECS))
            .user_agent(concat!("mcp-armor/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| ArmorError::InvalidPattern(format!("rekor client build: {e}")))?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
        })
    }

    /// POST `/api/v1/index/retrieve` with `{"hash":"sha256:<hex>"}` →
    /// `["uuid", ...]`. Returns the list of log-entry UUIDs that hold this
    /// artifact hash. Empty list = not in the log (likely unsigned).
    pub fn lookup_by_hash(&self, sha256_hex: &str) -> Result<Vec<String>, ArmorError> {
        let url = format!("{}/api/v1/index/retrieve", self.base_url);
        let body = serde_json::json!({ "hash": format!("sha256:{}", sha256_hex) });
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .map_err(|e| ArmorError::InvalidPattern(format!("rekor http: {e}")))?;
        if !resp.status().is_success() {
            return Err(ArmorError::InvalidPattern(format!(
                "rekor lookup_by_hash returned HTTP {}",
                resp.status()
            )));
        }
        let bytes = read_capped_body(resp, REKOR_MAX_BODY_BYTES)?;
        let body: Vec<String> = serde_json::from_slice(&bytes)
            .map_err(|e| ArmorError::InvalidPattern(format!("rekor json: {e}")))?;
        Ok(body)
    }

    /// GET `/api/v1/log/entries/{uuid}` → log entry object. The shape is a
    /// single-key map `{uuid: {...}}`; we return the inner value verbatim
    /// so the caller can pick the fields they need.
    pub fn get_entry(&self, uuid: &str) -> Result<Value, ArmorError> {
        let url = format!("{}/api/v1/log/entries/{}", self.base_url, uuid);
        let resp = self
            .client
            .get(&url)
            .send()
            .map_err(|e| ArmorError::InvalidPattern(format!("rekor http: {e}")))?;
        if !resp.status().is_success() {
            return Err(ArmorError::InvalidPattern(format!(
                "rekor get_entry returned HTTP {}",
                resp.status()
            )));
        }
        let bytes = read_capped_body(resp, REKOR_MAX_BODY_BYTES)?;
        let body: Value = serde_json::from_slice(&bytes)
            .map_err(|e| ArmorError::InvalidPattern(format!("rekor json: {e}")))?;
        Ok(body)
    }
}

/// v0.2 — read a `reqwest::blocking::Response` body with a hard cap on the
/// number of bytes. Defends against an unbounded or hijacked Rekor endpoint
/// that streams until OOM. Two-stage check:
/// 1. If `Content-Length` is advertised and exceeds the cap, reject before
///    reading a single byte.
/// 2. Otherwise read via `Read::take(cap + 1)` and reject if the body
///    actually exceeds the cap (one extra byte is the tripwire).
#[cfg(feature = "sigstore-bridge")]
fn read_capped_body(resp: reqwest::blocking::Response, cap: u64) -> Result<Vec<u8>, ArmorError> {
    use std::io::Read;
    if let Some(len) = resp.content_length() {
        if len > cap {
            return Err(ArmorError::InvalidPattern(format!(
                "rekor response body {len} bytes exceeds the {cap}-byte cap"
            )));
        }
    }
    // `cap + 1` so we can distinguish "exactly at cap" from "over cap".
    let mut limited = resp.take(cap + 1);
    let mut buf = Vec::with_capacity(8 * 1024);
    limited
        .read_to_end(&mut buf)
        .map_err(|e| ArmorError::InvalidPattern(format!("rekor read: {e}")))?;
    if buf.len() as u64 > cap {
        return Err(ArmorError::InvalidPattern(format!(
            "rekor response body exceeded the {cap}-byte cap (chunked / no Content-Length)"
        )));
    }
    Ok(buf)
}

/// Outcome of a high-level Rekor lookup. Audit-friendly: every field the
/// operator might need to render a UI or write to a SOC2 log lands here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekorLookup {
    pub artifact_hash_sha256: String,
    pub entries_found: usize,
    pub uuids: Vec<String>,
    pub rekor_url: String,
    pub looked_up_at_iso: String,
    /// First entry's `logIndex` if present — useful as a stable anchor for
    /// follow-up SET verification.
    pub first_entry_log_index: Option<i64>,
}

/// High-level helper: hash the canonicalised manifest, query Rekor, return a
/// structured outcome. Returns Ok with `entries_found = 0` if the artifact
/// hash is not in the log — that is information, not an error.
#[cfg(feature = "sigstore-bridge")]
pub fn lookup_rekor_by_hash(
    tools_list_response: &Value,
    rekor_url: Option<&str>,
) -> Result<RekorLookup, ArmorError> {
    let hash = artifact_hash_sha256_hex(tools_list_response)?;
    let client = match rekor_url {
        Some(u) => RekorClient::with_base_url(u)?,
        None => RekorClient::new()?,
    };
    let uuids = client.lookup_by_hash(&hash)?;
    let mut first_index: Option<i64> = None;
    if let Some(first) = uuids.first() {
        if let Ok(entry) = client.get_entry(first) {
            if let Some(map) = entry.as_object() {
                if let Some((_, val)) = map.iter().next() {
                    first_index = val.get("logIndex").and_then(Value::as_i64);
                }
            }
        }
    }
    Ok(RekorLookup {
        artifact_hash_sha256: hash,
        entries_found: uuids.len(),
        uuids: uuids.clone(),
        rekor_url: rekor_url.map_or_else(|| REKOR_PUBLIC_URL.to_string(), str::to_owned),
        looked_up_at_iso: crate::manifest::tofu::now_iso(),
        first_entry_log_index: first_index,
    })
}

/// Structurally verify a `SignedEntryTimestamp` from a Rekor bundle. v0.2
/// scope: confirm the SET decodes as a 64-byte Ed25519 signature shape.
/// **Does not yet verify it against Rekor's public key** — that requires the
/// TUF-distributed pubkey rotation which is v0.3 backlog. CHANGELOG
/// documents the limit; the function returns `partial=true` so callers can
/// surface the gap rather than silently treat structural OK as full trust.
pub fn verify_inclusion(bundle: &Bundle) -> Result<InclusionOutcome, ArmorError> {
    let Some(rb) = &bundle.rekor_bundle else {
        return Ok(InclusionOutcome {
            shape_only_ok: false,
            partial: true,
            note: "bundle has no rekorBundle field".to_string(),
            warning: WARNING_SHAPE_ONLY.to_string(),
            set_bytes: 0,
            log_index: None,
            integrated_time: None,
        });
    };
    let set_bytes = B64
        .decode(rb.signed_entry_timestamp.as_bytes())
        .map_err(ArmorError::Base64)?;
    let log_index = rb.payload.get("logIndex").and_then(Value::as_i64);
    let integrated_time = rb.payload.get("integratedTime").and_then(Value::as_i64);
    let shape_only_ok = set_bytes.len() == 64;
    Ok(InclusionOutcome {
        shape_only_ok,
        partial: true,
        note: if shape_only_ok {
            "SET decoded to 64-byte Ed25519 shape (v0.5 backlog: verify against Rekor pubkey via TUF)"
                .to_string()
        } else {
            format!(
                "SET decoded to unexpected length {} (expected 64 bytes)",
                set_bytes.len()
            )
        },
        warning: WARNING_SHAPE_ONLY.to_string(),
        set_bytes: set_bytes.len(),
        log_index,
        integrated_time,
    })
}

/// Public warning surfaced in every [`InclusionOutcome`] and reflected
/// verbatim by `tool_verify_bundle` so consuming clients cannot mistake
/// the shape check for a cryptographic verify.
///
/// v0.4 (Round-3 review HIGH fix) — the previous `structural_ok` field
/// name nudged callers into reading the outcome as "verified". The
/// outcome is ONLY a length-and-shape check on the SET payload; the
/// actual cryptographic verify against Rekor's pubkey is v0.5 backlog
/// and requires the TUF-distributed log key. Until then this warning is
/// always emitted alongside the outcome.
pub const WARNING_SHAPE_ONLY: &str =
    "shape-only check — SET was structurally verified as a 64-byte Ed25519 signature but NOT \
     cryptographically verified against Rekor's public key. Do not treat as a Sigstore verdict.";

/// Outcome of [`verify_inclusion`]. `partial=true` means we did the
/// structural checks but not the cryptographic verify against Rekor's
/// pubkey — v0.5 backlog.
///
/// v0.4 field renames: `structural_ok` → `shape_only_ok` plus a
/// machine-readable `warning` field. The old name implied "verified";
/// the new pair makes the limit explicit so JSON-consuming clients
/// can branch on it without re-reading the doc.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionOutcome {
    pub shape_only_ok: bool,
    pub partial: bool,
    pub note: String,
    pub warning: String,
    pub set_bytes: usize,
    pub log_index: Option<i64>,
    pub integrated_time: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// SHA-256 of an empty string is the well-known
    /// `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
    /// Sanity-check our handrolled implementation against that vector.
    #[test]
    fn sha256_empty_string_vector() {
        let h = sha256_hex(b"");
        assert_eq!(
            h,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// `abc` → `ba7816bf...` (NIST FIPS 180-4 example).
    #[test]
    fn sha256_abc_vector() {
        let h = sha256_hex(b"abc");
        assert_eq!(
            h,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// `abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq` → second NIST vector.
    #[test]
    fn sha256_nist_long_vector() {
        let h = sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(
            h,
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn artifact_hash_is_canonical() {
        // Different key order, same logical content — must produce same hash
        // because canonicalize_json sorts the keys.
        let a = json!({"a": 1, "b": 2});
        let b: Value = serde_json::from_str(r#"{"b":2,"a":1}"#).expect("parse");
        let ha = artifact_hash_sha256_hex(&a).expect("hash");
        let hb = artifact_hash_sha256_hex(&b).expect("hash");
        assert_eq!(ha, hb);
        assert_eq!(ha.len(), 64);
    }

    #[test]
    fn bundle_parse_minimal() {
        let raw = r#"{"base64Signature":"SGVsbG8="}"#;
        let b = Bundle::parse(raw).expect("parse");
        assert_eq!(b.base64_signature, "SGVsbG8=");
        assert!(b.cert_pem.is_none());
        assert!(b.rekor_bundle.is_none());
    }

    #[test]
    fn bundle_parse_empty_signature_rejected() {
        let raw = r#"{"base64Signature":""}"#;
        let r = Bundle::parse(raw);
        assert!(matches!(r, Err(ArmorError::InvalidPattern(_))));
    }

    #[test]
    fn bundle_parse_full_shape() {
        let raw = r#"{
            "base64Signature": "MEUCIQ==",
            "cert": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
            "rekorBundle": {
                "SignedEntryTimestamp": "ABCD",
                "Payload": {
                    "logIndex": 12345,
                    "integratedTime": 1700000000
                }
            }
        }"#;
        let b = Bundle::parse(raw).expect("parse");
        assert!(b.cert_pem.is_some());
        let rb = b.rekor_bundle.as_ref().expect("rekorBundle");
        assert_eq!(rb.signed_entry_timestamp, "ABCD");
        assert_eq!(
            rb.payload.get("logIndex").and_then(Value::as_i64),
            Some(12345)
        );
    }

    #[test]
    fn verify_inclusion_no_rekor_bundle_returns_partial() {
        let b = Bundle::parse(r#"{"base64Signature":"AA=="}"#).expect("parse");
        let r = verify_inclusion(&b).expect("verify");
        assert!(!r.shape_only_ok);
        assert!(r.partial);
        assert_eq!(r.set_bytes, 0);
        assert!(
            !r.warning.is_empty(),
            "v0.4: warning string must surface the shape-only limit"
        );
    }

    #[test]
    fn verify_inclusion_bad_set_length() {
        // SET decodes to 3 bytes, not 64 → shape fail.
        let raw = r#"{
            "base64Signature": "MEUCIQ==",
            "rekorBundle": {
                "SignedEntryTimestamp": "QUFB",
                "Payload": { "logIndex": 1 }
            }
        }"#;
        let b = Bundle::parse(raw).expect("parse");
        let r = verify_inclusion(&b).expect("verify");
        assert!(!r.shape_only_ok);
        assert_eq!(r.set_bytes, 3);
    }

    #[test]
    fn verify_inclusion_64_byte_set_shape_only_ok() {
        // SET decodes to exactly 64 bytes (Ed25519 sig shape).
        let raw_sig = vec![0xab_u8; 64];
        let b64_sig = B64.encode(&raw_sig);
        let bundle_json = serde_json::json!({
            "base64Signature": "MEUCIQ==",
            "rekorBundle": {
                "SignedEntryTimestamp": b64_sig,
                "Payload": {
                    "logIndex": 99,
                    "integratedTime": 1_700_000_000
                }
            }
        });
        let b = Bundle::parse(&bundle_json.to_string()).expect("parse");
        let r = verify_inclusion(&b).expect("verify");
        assert!(r.shape_only_ok);
        assert!(
            r.partial,
            "v0.4: partial=true until v0.5 Rekor-pubkey verify"
        );
        assert_eq!(r.set_bytes, 64);
        assert_eq!(r.log_index, Some(99));
        assert_eq!(r.integrated_time, Some(1_700_000_000));
        // v0.4 (Round-3 review HIGH fix) — warning is mandatory until the
        // cryptographic verify lands. Same string surfaces verbatim in
        // `tool_verify_bundle` response JSON.
        assert_eq!(r.warning, WARNING_SHAPE_ONLY);
    }
}
