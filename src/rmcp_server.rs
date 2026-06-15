//! Optional rmcp 1.5 control-plane server (feature `rmcp-control`).
//!
//! Parallel surface to the hand-rolled [`crate::control::run_control_plane`].
//! Both share the same [`Scanner`], [`PolicyHandle`], and [`ScanHistory`]
//! state via [`ArmorState`]; the rmcp control plane translates MCP `tools/call`
//! requests into the existing [`crate::control::handle_request`] dispatcher
//! so the 10-tool surface (6 v0.1 + 3 v0.2 + 1 v0.5 drift) stays a Single
//! Source of Truth across both control planes.
//!
//! # Why two control planes (still)?
//!
//! The hand-rolled JSON-RPC plane is the DEFAULT because it is
//! bench-verified (under 5ms p99 measured against the scanner hot path),
//! audit-minimal (one source file, zero extra crate deps), and identical
//! in semantics to the rmcp plane.
//!
//! The rmcp 1.5 plane is for operators who want the official Anthropic
//! MCP Rust SDK on the wire, the upstream SDK's `RequestContext<RoleServer>`
//! cancellation semantics, and first-class compatibility with new spec
//! features (SEP-1319 task lifecycle, structured outputs, `_meta` namespace)
//! without waiting on the hand-rolled plane to catch up.
//!
//! # v0.7 migration notes (rmcp 0.1.5 → 1.5)
//!
//! v0.7 is the long-promised follow-through on the rmcp 0.1 to 1.x
//! migration that v0.2 deferred to a tag of its own. The migration closes
//! CVE-2026-42559 transitively (rmcp 1.4.0 added Host-header validation
//! to the Streamable HTTP server transport — we don't use that transport
//! so the CVE was never exploitable in mcp-armor, but the transitive dep
//! bump means downstream `cargo audit` runs stop flagging us once the
//! rustsec advisory-db propagates). v0.7 also wires `tools/call` through
//! [`dispatch_via_handle_request`] (v0.2 advertised the 9 (now 10) tools
//! via `get_info()` but refused every call with a "v0.3 backlog" error;
//! v0.7 routes calls through the same dispatcher the hand-rolled plane
//! uses — both planes are behaviourally identical from the client's
//! perspective), uses manual `impl ServerHandler` instead of the
//! `#[tool_router]` plus `#[tool_handler]` macro pair (the macro path
//! requires every tool to be a `#[tool]`-annotated function with a
//! `Parameters<T>` derive plus a `schemars::JsonSchema` derive on the
//! input type; our 10 tools share a hand-rolled JSON schema set in
//! [`crate::control::tools::list`] that is also the SSOT for the
//! hand-rolled JSON-RPC plane, and reusing that source via
//! `serde_json::from_value::<rmcp::model::Tool>` keeps the dispatcher
//! as the single source of truth for tool semantics and avoids schema
//! drift between the rmcp surface and the JSON-RPC surface — the same
//! drift class the v0.5 Layer 7 detector catches in upstream servers),
//! and bumps the protocol version to `2025-11-25` (matches the
//! hand-rolled plane via [`crate::control::handle_request`]'s
//! `initialize_result`).
//!
//! # v0.8 backlog (intentionally deferred)
//!
//! The `#[tool_router(server_handler)]` macro path: revisit once we ship
//! the structured-output `_meta` injection (SEP-2659) on the hand-rolled
//! plane and want a single derive site for the schemas. The
//! `transport-streamable-http` with `StreamableHttpService::with_allowed_hosts`
//! (the v0.7 CVE-2026-42559 fix) only lands if/when an operator asks for
//! HTTP-served control-plane (stdio is sufficient for the StudioMeyer
//! dogfood loop). The `auth` feature for OAuth-protected control-plane
//! is deferred until a non-StudioMeyer operator surfaces the demand.
//!
//! Note: this module is feature-gated at its `mod` declaration in `lib.rs`
//! (`#[cfg(feature = "rmcp-control")] pub mod rmcp_server;`). A second inner
//! `#![cfg(...)]` here would be redundant — and is rejected as a duplicated
//! attribute by some rustc versions (e.g. 1.88) — so it is intentionally absent.

use crate::control::history::ScanHistory;
use crate::error::ArmorError;
use crate::policy::{snapshot, PolicyHandle};
use crate::scanner::Scanner;

use std::sync::Arc;

use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, Content, Implementation, InitializeRequestParams,
    InitializeResult, ListToolsResult, PaginatedRequestParams, ProtocolVersion, ServerCapabilities,
    ServerInfo, Tool,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::transport::stdio;
use rmcp::ErrorData as McpError;
use rmcp::ServiceExt;

/// Shared sidecar state passed through the rmcp server.
///
/// `Clone` is cheap — every field is already `Arc`-wrapped or a small
/// handle. The clone count rises with every concurrent `tools/call`
/// (rmcp 1.5 hands the handler `&self` per request, so we never need
/// `Arc<Self>` for the handler itself — the inner state arcs do the
/// sharing).
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
/// dispatcher. This is the SSOT for the 10-tool semantics — both control
/// planes (hand-rolled + rmcp 1.5) call into this function so a fix in
/// the dispatcher lands in both surfaces without further wiring.
///
/// Returns the same `result.structuredContent` JSON value the JSON-RPC
/// control plane emits. The rmcp wrapper packages it as a
/// [`CallToolResult`] with both a textual `Content::text(...)` mirror
/// and a `structured_content: Some(value)` payload so MCP clients that
/// only render text and clients that parse structured outputs both work.
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
        // v0.7 R2 Critic Finding 2: tool-layer errors now flow through
        // `ArmorError::Rmcp(...)` instead of overloading `InvalidPattern`
        // (which is documented as "scanner: invalid pattern config").
        // The Rmcp variant is the rmcp-plane error catch-all — transport
        // init/loop failures from `run()` and tool-dispatch failures here
        // share the variant because both surface to operators as
        // "the rmcp control plane could not complete this operation".
        // Scanner-config errors stay distinct in `InvalidPattern`.
        return Err(ArmorError::Rmcp(format!("tool dispatch: {msg}")));
    }
    Ok(resp["result"]["structuredContent"].clone())
}

/// Build the rmcp `Tool` list by deserialising the hand-rolled
/// JSON-Schema set from [`crate::control::tools::list`]. Keeping a
/// single tool-schema source avoids the schema-drift class the v0.5
/// Layer 7 detector catches in upstream MCP servers — if we maintained
/// two parallel tool-schema sources here, an operator inspecting the
/// hand-rolled plane and the rmcp plane could see different
/// `inputSchema`s for the same tool name. That would be an own-goal.
///
/// v0.7 — R1 Critic finding M2: every drop is logged with `tracing::warn!`
/// so a future rmcp release that renames a `Tool` field (e.g.
/// `inputSchema` → `input_schema`) surfaces loudly in the operator log
/// instead of silently truncating the advertised toolset. The count
/// tests in this module catch the all-drops case; the warn line catches
/// the partial-drift case where only some tools fail the round-trip.
fn build_tools() -> Vec<Tool> {
    let v = crate::control::tools::list();
    let arr = v["tools"].as_array().cloned().unwrap_or_default();
    arr.into_iter()
        .filter_map(|t| {
            let name = t
                .get("name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("<unnamed>")
                .to_string();
            match serde_json::from_value::<Tool>(t) {
                Ok(tool) => Some(tool),
                Err(e) => {
                    tracing::warn!(
                        tool = %name,
                        error = %e,
                        "rmcp_server::build_tools: dropping tool schema that failed to deserialise to rmcp::model::Tool — check rmcp crate version against control::tools::list schema",
                    );
                    None
                }
            }
        })
        .collect()
}

/// rmcp 1.5 `ServerHandler` impl for the mcp-armor control plane.
///
/// `Clone` because rmcp's tower-style trait surface clones the handler
/// per concurrent request. The inner [`ArmorState`] is already
/// `Arc`-shared so the clone cost is one atomic refcount bump per
/// request.
#[derive(Clone)]
pub struct ArmorRmcpHandler {
    state: ArmorState,
}

impl ArmorRmcpHandler {
    pub fn new(state: ArmorState) -> Self {
        Self { state }
    }
}

impl ServerHandler for ArmorRmcpHandler {
    fn get_info(&self) -> ServerInfo {
        // rmcp 1.5 `ServerInfo` (`= InitializeResult`) and `Implementation`
        // are `#[non_exhaustive]` — future-spec field additions (SEP-1319
        // task lifecycle, _meta namespace) must not be a SemVer break for
        // downstream consumers. Non-exhaustive structs cannot be
        // constructed with struct-expression syntax in external crates
        // (E0639), so we go through:
        //   - `Implementation::new(name, version)` — the documented
        //     public constructor.
        //   - `ServerInfo::default()` + field assignment for the
        //     `InitializeResult` alias which has no public ctor for
        //     the four fields we care about.
        let mut info = ServerInfo::default();
        info.protocol_version = ProtocolVersion::default();
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.server_info =
            Implementation::new("mcp-armor-control".to_string(), crate::VERSION.to_string());
        info.instructions = Some(
            "mcp-armor read-only control plane (rmcp 1.5 variant). \
             10 tools: armor_scan_payload, armor_verify_manifest, \
             armor_list_blocked, armor_get_policy, armor_check_cve, \
             armor_simulate_attack, armor_get_keystore, \
             armor_verify_bundle, armor_rekor_lookup, \
             armor_get_drift_history. All read-only, all non-destructive. \
             Identical semantics to the hand-rolled JSON-RPC plane \
             (`mcp-armor mcp-control`) — both planes share one dispatcher."
                .to_string(),
        );
        info
    }

    // The `manual_async_fn` clippy lint normally prefers `async fn` here,
    // but the trait's default method signature returns
    // `impl Future + MaybeSendFuture + '_` and we want to mirror that
    // shape verbatim so the bounds stay obvious to a reader scanning the
    // module. Suppress just this lint for the three async-trait methods
    // instead of crate-wide — that keeps the lint live for other code
    // that might write a future-returning fn by accident.
    #[allow(clippy::manual_async_fn)]
    fn initialize(
        &self,
        _request: InitializeRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<InitializeResult, McpError>>
           + rmcp::service::MaybeSendFuture
           + '_ {
        async move { Ok(self.get_info()) }
    }

    #[allow(clippy::manual_async_fn)]
    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<ListToolsResult, McpError>>
           + rmcp::service::MaybeSendFuture
           + '_ {
        async move {
            Ok(ListToolsResult {
                meta: None,
                next_cursor: None,
                tools: build_tools(),
            })
        }
    }

    #[allow(clippy::manual_async_fn)]
    fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<CallToolResult, McpError>>
           + rmcp::service::MaybeSendFuture
           + '_ {
        let state = self.state.clone();
        async move {
            let name = request.name.to_string();
            let arguments = request.arguments.map_or_else(
                || serde_json::Value::Object(serde_json::Map::new()),
                serde_json::Value::Object,
            );
            match dispatch_via_handle_request(&state, &name, arguments) {
                Ok(structured) => {
                    let text = serde_json::to_string(&structured).unwrap_or_default();
                    // CallToolResult is `#[non_exhaustive]` — must go
                    // through the public constructors. `success(content)`
                    // sets is_error=Some(false) + content=...; we then
                    // mutate the public `structured_content` field so
                    // MCP clients that parse SEP-1319 structured outputs
                    // and clients that only render text both see the
                    // payload.
                    let mut result = CallToolResult::success(vec![Content::text(text)]);
                    result.structured_content = Some(structured);
                    Ok(result)
                }
                Err(e) => Ok(CallToolResult::error(vec![Content::text(format!(
                    "error: {e}"
                ))])),
            }
        }
    }
}

/// Spawn an rmcp 1.5 stdio server using the existing scanner / policy /
/// history. Runs until stdin is closed by the upstream MCP client.
///
/// v0.7 — fully wired. v0.2 / v0.5 / v0.6 shipped an [`ArmorRmcpHandler`]
/// that returned a "not yet implemented" error from `run()`; the trait
/// surface has since stabilised (rmcp 1.5) and the `tools/call` routing
/// now goes through [`dispatch_via_handle_request`].
pub async fn run(state: ArmorState) -> Result<(), ArmorError> {
    let handler = ArmorRmcpHandler::new(state);
    let transport = stdio();
    // v0.7 — R1 Critic finding M1/L2: transport + serve-loop failures
    // surface as `ArmorError::Rmcp(...)` so callers can match on the
    // dedicated variant. Pre-v0.7 these collapsed into
    // `InvalidPattern(...)` which is reserved for scanner-config errors;
    // confusing the two variants meant a caller that wrote
    // `match err { ArmorError::InvalidPattern(_) => fix_policy() ... }`
    // would try to "fix the policy" when stdin EOF'd.
    let service = handler
        .serve(transport)
        .await
        .map_err(|e| ArmorError::Rmcp(format!("serve init: {e}")))?;
    service
        .waiting()
        .await
        .map_err(|e| ArmorError::Rmcp(format!("serve loop: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{into_handle, Policy};

    fn make_state() -> ArmorState {
        let scanner = Arc::new(Scanner::new().expect("scanner"));
        let handle = into_handle(Policy::default());
        let history = Arc::new(ScanHistory::new(100));
        ArmorState::new(scanner, handle, history)
    }

    /// v0.7 — the rmcp plane MUST surface the same 10 tools the
    /// hand-rolled JSON plane advertises. `build_tools` round-trips
    /// the hand-rolled JSON-Schema set through `serde_json::from_value`
    /// — a non-zero count proves the rmcp `Tool` struct shape still
    /// accepts our schema set across rmcp 1.5 patch releases.
    #[test]
    fn build_tools_returns_ten_entries() {
        let tools = build_tools();
        assert_eq!(
            tools.len(),
            10,
            "v0.7 rmcp plane expects 10 control-plane tools (same set as hand-rolled plane: 6 v0.1 + 3 v0.2 + 1 v0.5 drift)"
        );
    }

    /// v0.7 — every advertised tool MUST round-trip through the
    /// `serde_json::from_value::<Tool>` step. If a future rmcp release
    /// renames a field on `Tool` (e.g. `inputSchema` → `input_schema`)
    /// the filter_map in `build_tools` would silently drop entries
    /// instead of failing loudly. This test catches that regression.
    #[test]
    fn build_tools_matches_hand_rolled_list_length() {
        let hand_rolled = crate::control::tools::list();
        let hand_rolled_count = hand_rolled["tools"].as_array().map_or(0, Vec::len);
        assert_eq!(
            build_tools().len(),
            hand_rolled_count,
            "rmcp plane lost tools during serde round-trip — check rmcp::model::Tool field names against control::tools::list"
        );
    }

    /// v0.7 — `dispatch_via_handle_request` is the SSOT that both
    /// control planes route through. Calling `armor_get_policy` (no
    /// args) should return a JSON object with at least `fail_mode`.
    /// If this regresses both control planes break simultaneously,
    /// so a fast unit check here is worth its weight.
    #[test]
    fn dispatch_via_handle_request_returns_policy() {
        let state = make_state();
        let result = dispatch_via_handle_request(&state, "armor_get_policy", serde_json::json!({}))
            .expect("armor_get_policy should succeed");
        assert!(
            result.get("fail_mode").is_some(),
            "armor_get_policy must return a `fail_mode` field"
        );
    }

    /// v0.7 — unknown tools must produce an `ArmorError`, not a panic
    /// and not a silent success. The error message must mention the
    /// tool name so an operator can identify the typo from the rmcp
    /// surface without dumping the dispatcher source. We accept the
    /// canonical "tool not found: NAME" emitted by
    /// [`crate::control::handle_request`] plus the older "unknown tool"
    /// prefix some test fixtures still produce.
    #[test]
    fn dispatch_via_handle_request_unknown_tool_errors() {
        let state = make_state();
        let err = dispatch_via_handle_request(&state, "armor_nonexistent", serde_json::json!({}))
            .expect_err("unknown tool must error");
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("not found") || msg.contains("unknown"),
            "tool-routing error must mention the missing tool: got {msg}"
        );
        assert!(
            msg.contains("armor_nonexistent"),
            "tool-routing error must include the tool name: got {msg}"
        );
    }

    /// v0.7 — the rmcp plane's `get_info()` must report the same
    /// server_info.name as the hand-rolled plane (`mcp-armor-control`)
    /// so MCP clients toggling between planes see the same identity.
    #[test]
    fn handler_get_info_reports_canonical_name() {
        let handler = ArmorRmcpHandler::new(make_state());
        let info = handler.get_info();
        assert_eq!(info.server_info.name, "mcp-armor-control");
        assert_eq!(info.server_info.version, crate::VERSION);
    }

    /// v0.7 R1 Critic finding H1 + Analyst Concern-1 (R2 Critic Finding 3
    /// hardening): the rmcp plane uses `ProtocolVersion::default()` (an
    /// rmcp-controlled value) while the hand-rolled plane uses our own
    /// `const MCP_PROTOCOL_VERSION` constant. If a future rmcp release
    /// changes its default to a version newer or older than ours, the
    /// two planes would advertise different `protocolVersion` strings
    /// to clients — a subtle identity-drift bug that violates the
    /// documented SSOT contract ("both planes are behaviourally
    /// identical from the client's perspective"). R2 strengthened the
    /// assertion: instead of a hard-coded `"2025-11-25"` literal we
    /// now compare directly against `crate::control::MCP_PROTOCOL_VERSION`,
    /// so the test fails BOTH when rmcp's default drifts away from
    /// our constant AND when our constant drifts away from rmcp's
    /// default — true cross-plane parity rather than a one-sided
    /// string check. A failure here means EITHER bump
    /// `MCP_PROTOCOL_VERSION` in `src/control/mod.rs` OR pin the
    /// rmcp default via an explicit constant (e.g.
    /// `ProtocolVersion::V_2025_11_25` if rmcp exposes one).
    #[test]
    fn handler_protocol_version_matches_hand_rolled_plane() {
        let handler = ArmorRmcpHandler::new(make_state());
        let info = handler.get_info();
        let pv_json = serde_json::to_value(&info.protocol_version)
            .expect("rmcp ProtocolVersion serialises via serde");
        let pv_str = pv_json
            .as_str()
            .expect("rmcp ProtocolVersion serialises as a JSON string");
        assert_eq!(
            pv_str,
            crate::control::MCP_PROTOCOL_VERSION,
            "rmcp plane protocolVersion ({pv_str}) drifted from hand-rolled \
             plane (MCP_PROTOCOL_VERSION={}). Audit: either bump \
             MCP_PROTOCOL_VERSION in src/control/mod.rs OR pin the rmcp \
             default via an explicit constant — see v0.7 R1 Critic H1 + \
             Analyst Concern-1 + R2 Critic Finding 3 in CHANGELOG.",
            crate::control::MCP_PROTOCOL_VERSION
        );
    }
}
