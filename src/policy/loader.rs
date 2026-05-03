use crate::error::ArmorError;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FailMode {
    /// On scanner verdict==block: log & pass through (warn-and-pass).
    Open,
    /// On scanner verdict==block: drop the call, return -32603 to client.
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub fail_mode: FailMode,
    pub scan_unicode: bool,
    /// Pattern ids to never block (override scanner verdict to allow).
    #[serde(default)]
    pub allow_patterns: Vec<String>,
    /// Server names whose tool calls bypass the scanner entirely.
    #[serde(default)]
    pub allow_servers: Vec<String>,
    pub version: String,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            fail_mode: FailMode::Closed,
            scan_unicode: true,
            allow_patterns: Vec::new(),
            allow_servers: Vec::new(),
            version: "default".to_string(),
        }
    }
}

/// Resolve a policy from `path` if Some, else from
/// `$XDG_CONFIG_HOME/mcp-armor/policy.toml` (or `~/.config/...`), else default.
pub fn load_policy(path: Option<&Path>) -> Result<(Policy, PathBuf), ArmorError> {
    let resolved = match path {
        Some(p) => p.to_path_buf(),
        None => default_path(),
    };
    if !resolved.exists() {
        return Ok((Policy::default(), resolved));
    }
    let raw = std::fs::read_to_string(&resolved)?;
    let p: Policy = toml::from_str(&raw)?;
    Ok((p, resolved))
}

pub fn default_path() -> PathBuf {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        return PathBuf::from(xdg).join("mcp-armor").join("policy.toml");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home)
            .join(".config")
            .join("mcp-armor")
            .join("policy.toml");
    }
    PathBuf::from("policy.toml")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn missing_file_returns_default() {
        let dir = tempdir().expect("tmp");
        let p = dir.path().join("nope.toml");
        let (pol, _) = load_policy(Some(&p)).expect("ok");
        assert_eq!(pol.fail_mode, FailMode::Closed);
        assert!(pol.scan_unicode);
        assert_eq!(pol.version, "default");
    }

    #[test]
    fn parses_valid_toml() {
        let dir = tempdir().expect("tmp");
        let p = dir.path().join("policy.toml");
        std::fs::write(
            &p,
            r#"
fail_mode = "open"
scan_unicode = false
allow_patterns = ["javascript_uri"]
allow_servers = ["my-trusted-server"]
version = "test-1"
"#,
        )
        .expect("write");
        let (pol, _) = load_policy(Some(&p)).expect("ok");
        assert_eq!(pol.fail_mode, FailMode::Open);
        assert!(!pol.scan_unicode);
        assert_eq!(pol.allow_patterns, vec!["javascript_uri".to_string()]);
        assert_eq!(pol.version, "test-1");
    }

    #[test]
    fn invalid_toml_fails_gracefully() {
        let dir = tempdir().expect("tmp");
        let p = dir.path().join("bad.toml");
        std::fs::write(&p, "this is = not = toml ===").expect("write");
        let r = load_policy(Some(&p));
        assert!(matches!(r, Err(ArmorError::Toml(_))));
    }
}
