//! Policy loader. Reads `~/.config/mcp-armor/policy.toml` (override via
//! `--policy <path>` flag). On missing file the default policy is returned.
//!
//! v0.2 additions:
//! - Per-tool pattern allowlist ([`Policy::allow_patterns_per_tool`]).
//! - File mode advisory (0o600 warn-only on Unix).
//! - SIGHUP-driven runtime reload ([`reload::spawn_reload_task`]).
//! - [`PolicyHandle`] — `Arc<RwLock<Policy>>` shared across proxy hot-path,
//!   control-plane, and the reload task.

use std::sync::{Arc, RwLock};

pub mod loader;
pub mod reload;

pub use loader::{default_path, load_policy, FailMode, Policy};
pub use reload::spawn_reload_task;

/// Shared, mutable, thread-safe handle to the active policy. Held by the
/// proxy + control-plane + SIGHUP reload task. Reads are cheap (uncontended
/// RwLock) and never block writers for long. v0.2 introduction.
pub type PolicyHandle = Arc<RwLock<Policy>>;

/// Convenience constructor: wrap a `Policy` into a fresh [`PolicyHandle`].
pub fn into_handle(policy: Policy) -> PolicyHandle {
    Arc::new(RwLock::new(policy))
}

/// Snapshot the policy. Recovers from a poisoned lock (the audit-grade
/// fallback we already use for `ScanHistory`) — losing a writer to a panic
/// must not crash the side-car.
pub fn snapshot(handle: &PolicyHandle) -> Policy {
    match handle.read() {
        Ok(g) => g.clone(),
        Err(poison) => poison.into_inner().clone(),
    }
}
