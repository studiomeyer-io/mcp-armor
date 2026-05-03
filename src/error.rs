use thiserror::Error;

/// Top-level error type for the `mcp_armor` library. All public constructors
/// return `Result<_, ArmorError>` — no panicking constructors (Lumina
/// anti-pattern S982).
#[derive(Debug, Error)]
pub enum ArmorError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("toml parse error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("regex compile error: {0}")]
    Regex(#[from] regex::Error),

    #[error("scanner: invalid pattern config: {0}")]
    InvalidPattern(String),

    #[error("manifest: invalid signature")]
    InvalidSignature,

    #[error("manifest: malformed key: {0}")]
    MalformedKey(String),

    #[error("manifest: canonical form failed: {0}")]
    CanonicalFailed(String),

    #[error("policy: missing field: {0}")]
    PolicyMissing(String),

    #[error("cve: unknown id: {0}")]
    UnknownCve(String),

    #[error("control: tool not found: {0}")]
    UnknownTool(String),

    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("ed25519 error: {0}")]
    Ed25519(String),
}

impl From<ed25519_dalek::SignatureError> for ArmorError {
    fn from(e: ed25519_dalek::SignatureError) -> Self {
        ArmorError::Ed25519(e.to_string())
    }
}
