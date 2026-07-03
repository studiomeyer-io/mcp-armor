//! Provenance guard — the Official MCP Registry manifest (`server.json`)
//! must not drift from the crate it publishes. v0.8 shipped a stale
//! `server.json` (0.7.0 / "10 tools" / OCI tag :0.7.0) undetected because
//! CI never cross-checked it against `Cargo.toml`. This test closes that
//! class: it fails the build if the manifest version, the OCI image tag,
//! or the advertised tool count fall out of sync.

use serde_json::Value;

fn server_json() -> Value {
    let raw = include_str!("../server.json");
    serde_json::from_str(raw).expect("server.json is valid JSON")
}

#[test]
fn server_json_version_matches_crate() {
    let sj = server_json();
    assert_eq!(
        sj["version"].as_str().expect("version string"),
        env!("CARGO_PKG_VERSION"),
        "server.json version must equal Cargo.toml version — bump both together"
    );
}

#[test]
fn server_json_oci_tag_matches_crate() {
    let sj = server_json();
    let ident = sj["packages"][0]["identifier"]
        .as_str()
        .expect("oci identifier");
    let want = format!(
        "ghcr.io/studiomeyer-io/mcp-armor:{}",
        env!("CARGO_PKG_VERSION")
    );
    assert_eq!(
        ident, want,
        "server.json OCI tag must point at the current version's image"
    );
}

#[test]
fn server_json_advertises_current_tool_count() {
    // The registry description states the control-plane tool count.
    // Keep it truthful against the hand-rolled registry.
    let sj = server_json();
    let desc = sj["description"].as_str().expect("description");
    let tool_count = mcp_armor::control::tools::list()["tools"]
        .as_array()
        .expect("tools array")
        .len();
    // Leading space anchors the count so an 11→1 drift can't false-pass
    // ("1 read-only…" is a substring of "11 read-only…" without it).
    assert!(
        desc.contains(&format!(" {tool_count} read-only control-plane tools")),
        "server.json description must state the current tool count ({tool_count}); got: {desc}"
    );
}
