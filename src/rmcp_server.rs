//! Optional rmcp 0.1 control-plane server (feature `rmcp-control`).
//!
//! Parallel surface to the hand-rolled `control::run_control_plane`. The
//! same scanner / policy / history is shared via [`ArmorState`]; the rmcp
//! server simply translates MCP tool calls back into our existing
//! `dispatch_tool` path.
//!
//! Why two control planes? rmcp 0.1.x is pre-stable (the API churns
//! between every minor) and the StudioMeyer mcp-armor pitch is
//! "single-signed-binary, minimal audit surface". Default builds therefore
//! stay on the hand-rolled JSON-RPC server; operators who want native
//! `tool_router`/`schemars`-driven schemas + the upstream Spec
//! 2025-11-25 task-lifecycle pull this feature in.
//!
//! ## Lessons baked in
//!
//! - rmcp 0.1.5 requires the `base64` feature OR it fails with an
//!   unresolved `base64::engine` import in `prompt.rs`. The
//!   `rmcp-control` Cargo feature pulls it in transitively.
//! - The crate's tool-router macros are still in flux; v0.2 prefers
//!   explicit `ServerHandler::call_tool` impl over `#[tool_router]` so a
//!   minor rmcp release does not break the build. The macro-driven
//!   variant lands in v0.3 once rmcp 0.2.x stabilises.

#![cfg(feature = "rmcp-control")]

use crate::control::history::ScanHistory;
use crate::error::ArmorError;
use crate::policy::{snapshot, PolicyHandle};
use crate::scanner::Scanner;
use std::sync::Arc;

/// Shared sidecar state passed through the rmcp server context.
#[derive(Clone)]
pub struct ArmorState {
    pub scanner: Arc<Scanner>,
    pub policy: PolicyHandle,
    pub history: Arc<ScanHistory>,
}

impl ArmorState {
    pub fn new(scanner: Arc<Scanner>, policy: PolicyHandle, history: Arc<ScanHistory>) -> Self {
        Self {
            scanner,
            policy,
            history,
        }
    }
}

/// Dispatch a tool call by routing through the existing hand-rolled
/// dispatcher. Keeps a single source of truth for the 9 tool semantics.
///
/// Returns the same `result.structuredContent` JSON value the JSON-RPC
/// control plane emits. rmcp wraps it as a CallToolResult downstream.
pub fn dispatch_via_handle_request(
    state: &ArmorState,
    tool_name: &str,
    arguments: serde_json::Value,
) -> Result<serde_json::Value, ArmorError> {
    let req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": tool_name, "arguments": arguments }
    });
    let snap = snapshot(&state.policy);
    let resp = crate::control::handle_request(&req, &state.scanner, &snap, &state.history);
    if resp["result"]["isError"].as_bool().unwrap_or(false) {
        let msg = resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or("tool error")
            .to_string();
        return Err(ArmorError::InvalidPattern(msg));
    }
    Ok(resp["result"]["structuredContent"].clone())
}

/// Spawn an rmcp stdio server using the existing scanner/policy/history.
///
/// **v0.2 STATUS — INCOMPLETE WIRING (Round 1 review finding M5).**
///
/// rmcp 0.1.x's `ServerHandler::call_tool` default impl returns
/// "method not found" for every tool call. v0.2 ships [`get_info`] +
/// `tools/list` via the hand-rolled schema (9 tools) but does NOT yet
/// route `tools/call` through [`dispatch_via_handle_request`] — the
/// trait surface in rmcp 0.1.5 makes that wiring risky to land without
/// a 0.2/1.x upgrade.
///
/// Calling this function therefore advertises 9 tools to an MCP client
/// but executes 0 of them. To avoid a silent-misuse trap we refuse to
/// run and instruct the operator to use the hand-rolled control plane
/// (`mcp-armor mcp-control`) until the rmcp wiring lands in v0.3.
// `async` retained so the v0.3 wiring (which will call rmcp's async
// `serve_server(...).await`) can be a drop-in replacement without changing
// the function signature.
#[allow(clippy::unused_async)]
pub async fn run(_state: ArmorState) -> Result<(), ArmorError> {
    Err(ArmorError::InvalidPattern(
        "rmcp control-plane is compiled in (--features rmcp-control) but \
         tools/call routing is not yet wired in v0.2. Use the hand-rolled \
         control plane via `mcp-armor mcp-control` until v0.3 lands the \
         rmcp 1.x #[tool_router] migration. See CHANGELOG v0.2.0 for the \
         v0.3 backlog entry."
            .to_string(),
    ))
}

/// Minimal rmcp `ServerHandler` impl. We deliberately avoid the
/// `#[tool_router]` macro path so the build stays robust against rmcp
/// 0.1.x macro renames.
#[derive(Clone)]
#[allow(dead_code)] // `state` is held for the v0.3 call_tool wiring; rmcp 0.1.x
                    // trait surface intentionally only uses get_info() in v0.2.
struct ArmorRmcpHandler {
    state: ArmorState,
}

impl rmcp::ServerHandler for ArmorRmcpHandler {
    fn get_info(&self) -> rmcp::model::ServerInfo {
        rmcp::model::ServerInfo {
            protocol_version: rmcp::model::ProtocolVersion::default(),
            capabilities: rmcp::model::ServerCapabilities::builder()
                .enable_tools()
                .build(),
            server_info: rmcp::model::Implementation {
                name: "mcp-armor-control".to_string(),
                version: crate::VERSION.to_string(),
            },
            instructions: Some(
                "mcp-armor read-only control plane (rmcp variant). \
                 Same 9 tools as the JSON-RPC control plane."
                    .to_string(),
            ),
        }
    }
}
