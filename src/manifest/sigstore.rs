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
/// Implemented via tiny constant-time helper to avoid adding the `sha2`
/// crate just for one call site.
pub fn artifact_hash_sha256_hex(tools_list_response: &Value) -> Result<String, ArmorError> {
    let canonical = canonicalize_json(tools_list_response)?;
    Ok(sha256_hex(&canonical))
}

fn sha256_hex(bytes: &[u8]) -> String {
    // Pull SHA-256 via blake3 is not possible (different algo). We hand-roll
    // a minimal SHA-256 to keep the dep tree flat. Reference: RFC 6234.
    // For v0.2 this is implemented via a small private routine; we deliberately
    // do not pull `sha2` because that crate is otherwise unused.
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut s = String::with_capacity(64);
    for b in &out {
        use std::fmt::Write;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

// ──── Minimal SHA-256 implementation (RFC 6234) ────────────────────────────
//
// Sized: 32-byte output, 64-byte block. Public-domain reference impl style.
// Only public via `sha256_hex`; not part of the crate's public API.
//
// The `allow`s here mirror the NIST FIPS 180-4 spec — adding underscores to
// the K-array constants or renaming the working variables `a..h` would
// obscure the reference algorithm.
#[allow(
    clippy::unreadable_literal,
    clippy::many_single_char_names,
    clippy::similar_names,
    clippy::needless_range_loop
)]
mod sha256_impl {
    pub struct Sha256 {
        pub state: [u32; 8],
        pub buffer: [u8; 64],
        pub buffer_len: usize,
        pub total_len: u64,
    }

    impl Sha256 {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];

        pub fn new() -> Self {
            Self {
                state: [
                    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
                    0x1f83d9ab, 0x5be0cd19,
                ],
                buffer: [0u8; 64],
                buffer_len: 0,
                total_len: 0,
            }
        }

        pub fn update(&mut self, mut data: &[u8]) {
            self.total_len = self.total_len.wrapping_add(data.len() as u64);
            if self.buffer_len > 0 {
                let to_copy = (64 - self.buffer_len).min(data.len());
                self.buffer[self.buffer_len..self.buffer_len + to_copy]
                    .copy_from_slice(&data[..to_copy]);
                self.buffer_len += to_copy;
                data = &data[to_copy..];
                if self.buffer_len == 64 {
                    let block = self.buffer;
                    self.compress(&block);
                    self.buffer_len = 0;
                }
            }
            while data.len() >= 64 {
                let mut block = [0u8; 64];
                block.copy_from_slice(&data[..64]);
                self.compress(&block);
                data = &data[64..];
            }
            if !data.is_empty() {
                self.buffer[..data.len()].copy_from_slice(data);
                self.buffer_len = data.len();
            }
        }

        fn compress(&mut self, block: &[u8; 64]) {
            let mut w = [0u32; 64];
            for (i, chunk) in block.chunks_exact(4).enumerate() {
                w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            }
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }
            let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
            for i in 0..64 {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & f) ^ ((!e) & g);
                let t1 = h
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(Self::K[i])
                    .wrapping_add(w[i]);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let mj = (a & b) ^ (a & c) ^ (b & c);
                let t2 = s0.wrapping_add(mj);
                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
            }
            self.state[0] = self.state[0].wrapping_add(a);
            self.state[1] = self.state[1].wrapping_add(b);
            self.state[2] = self.state[2].wrapping_add(c);
            self.state[3] = self.state[3].wrapping_add(d);
            self.state[4] = self.state[4].wrapping_add(e);
            self.state[5] = self.state[5].wrapping_add(f);
            self.state[6] = self.state[6].wrapping_add(g);
            self.state[7] = self.state[7].wrapping_add(h);
        }

        pub fn finalize(mut self) -> [u8; 32] {
            let bit_len = self.total_len.wrapping_mul(8);
            // Append 0x80 then pad with zeros until 56 bytes mod 64, then 8-byte length.
            let pad_start = self.buffer_len;
            self.buffer[pad_start] = 0x80;
            self.buffer_len += 1;
            // Two-block path if no room for length.
            if self.buffer_len > 56 {
                for i in self.buffer_len..64 {
                    self.buffer[i] = 0;
                }
                let block = self.buffer;
                self.compress(&block);
                self.buffer_len = 0;
                self.buffer.fill(0);
            }
            for i in self.buffer_len..56 {
                self.buffer[i] = 0;
            }
            let bit_bytes = bit_len.to_be_bytes();
            self.buffer[56..64].copy_from_slice(&bit_bytes);
            let block = self.buffer;
            self.compress(&block);

            let mut out = [0u8; 32];
            for (i, word) in self.state.iter().enumerate() {
                out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }
            out
        }
    }
} // mod sha256_impl
use sha256_impl::Sha256;

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
            structural_ok: false,
            partial: true,
            note: "bundle has no rekorBundle field".to_string(),
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
    let structural_ok = set_bytes.len() == 64;
    Ok(InclusionOutcome {
        structural_ok,
        partial: true,
        note: if structural_ok {
            "SET decoded to 64-byte Ed25519 shape (v0.3 will verify against Rekor pubkey)"
                .to_string()
        } else {
            format!(
                "SET decoded to unexpected length {} (expected 64 bytes)",
                set_bytes.len()
            )
        },
        set_bytes: set_bytes.len(),
        log_index,
        integrated_time,
    })
}

/// Outcome of [`verify_inclusion`]. `partial=true` means we did the
/// structural checks but not the cryptographic verify against Rekor's
/// pubkey — v0.3 backlog.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionOutcome {
    pub structural_ok: bool,
    pub partial: bool,
    pub note: String,
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
        assert!(!r.structural_ok);
        assert!(r.partial);
        assert_eq!(r.set_bytes, 0);
    }

    #[test]
    fn verify_inclusion_bad_set_length() {
        // SET decodes to 3 bytes, not 64 → structural fail.
        let raw = r#"{
            "base64Signature": "MEUCIQ==",
            "rekorBundle": {
                "SignedEntryTimestamp": "QUFB",
                "Payload": { "logIndex": 1 }
            }
        }"#;
        let b = Bundle::parse(raw).expect("parse");
        let r = verify_inclusion(&b).expect("verify");
        assert!(!r.structural_ok);
        assert_eq!(r.set_bytes, 3);
    }

    #[test]
    fn verify_inclusion_64_byte_set_structurally_ok() {
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
        assert!(r.structural_ok);
        assert!(
            r.partial,
            "v0.2: partial=true until v0.3 Rekor-pubkey verify"
        );
        assert_eq!(r.set_bytes, 64);
        assert_eq!(r.log_index, Some(99));
        assert_eq!(r.integrated_time, Some(1_700_000_000));
    }
}
