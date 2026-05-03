//! mcp-armor — drop-in stdio sidecar that scans MCP traffic for prompt
//! injection, validates Ed25519 manifest signatures, and blocks
//! marketplace-poisoning vectors.
//!
//! See `README.md` for usage. The crate exposes the building blocks so the
//! `mcp-armor` binary and external integrators (tests, benches) share one
//! implementation.

#![deny(unsafe_code)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::module_name_repetitions,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::doc_markdown,
    clippy::single_match_else,
    clippy::manual_let_else,
    clippy::needless_pass_by_value,
    clippy::too_many_lines,
    clippy::iter_cloned_collect,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::match_same_arms,
    clippy::unnecessary_wraps
)]

pub mod control;
pub mod cve;
pub mod error;
pub mod manifest;
pub mod otel;
pub mod policy;
pub mod proxy;
pub mod scanner;
mod sigstore_bridge_stub;

pub use control::history::ScanHistory;
pub use error::ArmorError;
pub use scanner::{ScanResult, ScanVerdict, Scanner};

/// Crate version, sourced from `Cargo.toml` at build time. Avoids the
/// hardcoded-version drift class.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
