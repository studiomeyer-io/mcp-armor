//! Policy loader. Reads `~/.config/mcp-armor/policy.toml` (override via
//! `--policy <path>` flag). On missing file the default policy is returned.

pub mod loader;

pub use loader::{load_policy, FailMode, Policy};
