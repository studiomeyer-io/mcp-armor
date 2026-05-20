//! v0.2 integration: per-tool pattern allowlist suppresses Block verdict.
//!
//! Concretely covers REVIEW.md F3 Sub-b: an allowlisted tool name combined
//! with the matching pattern id must let a Block-verdict envelope through.
//! Verified at the policy layer (proxy hot-path layer is exercised in
//! `src/proxy/stdio.rs` unit tests).

use mcp_armor::policy::{FailMode, Policy};

fn policy_with(tool: &str, patterns: Vec<&str>) -> Policy {
    let mut p = Policy {
        fail_mode: FailMode::Closed,
        ..Default::default()
    };
    p.allow_patterns_per_tool.insert(
        tool.to_string(),
        patterns.into_iter().map(str::to_owned).collect(),
    );
    p
}

#[test]
fn code_interpreter_is_allowed_to_use_shell_substitution() {
    let p = policy_with("code-interpreter", vec!["shell_substitution"]);
    assert!(p.tool_allows_patterns("code-interpreter", &["shell_substitution".to_string()]));
}

#[test]
fn other_tool_not_allowed_when_listed_for_different_tool() {
    let p = policy_with("code-interpreter", vec!["shell_substitution"]);
    assert!(!p.tool_allows_patterns("web-fetch", &["shell_substitution".to_string()]));
}

#[test]
fn unlisted_pattern_not_covered() {
    let p = policy_with("code-interpreter", vec!["shell_substitution"]);
    assert!(!p.tool_allows_patterns("code-interpreter", &["javascript_uri".to_string()]));
}

#[test]
fn strict_subset_required_for_mixed_matches() {
    // The allowlist says "shell_substitution is OK", but the scanner
    // matched both shell_substitution AND javascript_uri. The per-tool
    // allowlist must NOT gate this call — javascript_uri is not allowed.
    let p = policy_with("code-interpreter", vec!["shell_substitution"]);
    assert!(!p.tool_allows_patterns(
        "code-interpreter",
        &[
            "shell_substitution".to_string(),
            "javascript_uri".to_string(),
        ]
    ));
}
