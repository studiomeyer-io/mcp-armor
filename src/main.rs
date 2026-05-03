//! `mcp-armor` CLI binary. Subcommands:
//! - `wrap`         — start the stdio proxy around an upstream MCP server
//! - `verify`       — verify an Ed25519 manifest signature
//! - `scan`         — run the scanner against a payload from CLI/stdin
//! - `policy`       — show or reload policy
//! - `mcp-control`  — start the read-only control-plane MCP server
//! - `version`      — print the crate version

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use mcp_armor::{ScanHistory, Scanner, VERSION};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Parser)]
#[command(
    name = "mcp-armor",
    version = VERSION,
    about = "Drop-in Rust sidecar that armors any MCP server.",
    long_about = "Wraps any stdio MCP server with prompt-injection scanning, Ed25519 manifest verification, and a curated CVE block-list."
)]
struct Cli {
    /// Override the policy file path.
    #[arg(long, env = "MCP_ARMOR_POLICY", global = true)]
    policy: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Wrap an upstream MCP server with the scanner+proxy.
    Wrap {
        /// Upstream program (e.g. `npx`, `python`, an absolute path).
        program: String,
        /// Arguments forwarded to the upstream program.
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
    /// Verify an Ed25519 manifest signature against a JSON file.
    Verify {
        /// Path to the JSON file containing the `tools/list` response.
        manifest: PathBuf,
        /// Base64-encoded 32-byte Ed25519 public key.
        public_key_b64: String,
        /// Base64-encoded 64-byte Ed25519 signature.
        signature_b64: String,
        /// Optional ISO-8601 timestamp recorded with the signature.
        #[arg(long)]
        signed_at_iso: Option<String>,
    },
    /// Scan a payload (positional arg) or stdin if no payload given.
    Scan {
        /// Inline payload to scan.
        payload: Option<String>,
        /// Direction (inbound|outbound).
        #[arg(long, default_value = "inbound")]
        direction: String,
    },
    /// Inspect the active policy.
    Policy {
        #[command(subcommand)]
        action: PolicyCmd,
    },
    /// Start the read-only control-plane stdio MCP server.
    #[command(name = "mcp-control")]
    McpControl,
    /// Print the version and exit.
    Version,
}

#[derive(Debug, Subcommand)]
enum PolicyCmd {
    /// Show the resolved policy as JSON.
    Show,
    /// Reload from disk and show.
    Reload,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let _otel = mcp_armor::otel::init().context("init telemetry")?;
    let cli = Cli::parse();

    match cli.cmd {
        Cmd::Version => {
            println!("{VERSION}");
            Ok(())
        }
        Cmd::Wrap { program, args } => {
            let scanner = Arc::new(Scanner::new().context("build scanner")?);
            let (policy, _path) =
                mcp_armor::policy::load_policy(cli.policy.as_deref()).context("load policy")?;
            let policy = Arc::new(policy);
            let history = Arc::new(ScanHistory::new(10_000));
            mcp_armor::proxy::run_proxy(&program, &args, scanner, policy, history)
                .await
                .context("proxy run")?;
            Ok(())
        }
        Cmd::Verify {
            manifest,
            public_key_b64,
            signature_b64,
            signed_at_iso,
        } => {
            let raw = std::fs::read_to_string(&manifest)
                .with_context(|| format!("read {}", manifest.display()))?;
            let value: serde_json::Value =
                serde_json::from_str(&raw).context("parse manifest json")?;
            let outcome = mcp_armor::manifest::verify(
                &value,
                &public_key_b64,
                &signature_b64,
                signed_at_iso.as_deref(),
            )
            .context("verify")?;
            println!("{}", serde_json::to_string_pretty(&outcome)?);
            if outcome.valid {
                Ok(())
            } else {
                std::process::exit(2);
            }
        }
        Cmd::Scan { payload, direction } => {
            let scanner = Scanner::new().context("build scanner")?;
            let payload = match payload {
                Some(p) => p,
                None => {
                    use std::io::Read;
                    let mut buf = String::new();
                    std::io::stdin()
                        .read_to_string(&mut buf)
                        .context("read stdin")?;
                    buf
                }
            };
            let result = scanner.scan(&payload);
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "direction": direction,
                    "verdict": result.verdict,
                    "matched_patterns": result.matched_patterns,
                    "cve_refs": result.cve_refs,
                    "latency_us": result.latency_us
                }))?
            );
            if matches!(result.verdict, mcp_armor::ScanVerdict::Block) {
                std::process::exit(3);
            }
            Ok(())
        }
        Cmd::Policy { action } => {
            let (policy, path) =
                mcp_armor::policy::load_policy(cli.policy.as_deref()).context("load policy")?;
            match action {
                PolicyCmd::Show | PolicyCmd::Reload => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "policy_path": path.display().to_string(),
                            "policy": policy
                        }))?
                    );
                }
            }
            Ok(())
        }
        Cmd::McpControl => {
            let scanner = Arc::new(Scanner::new().context("build scanner")?);
            let (policy, _) =
                mcp_armor::policy::load_policy(cli.policy.as_deref()).context("load policy")?;
            let policy = Arc::new(policy);
            let history = Arc::new(ScanHistory::new(10_000));
            mcp_armor::control::run_control_plane(scanner, policy, history)
                .await
                .context("control-plane run")?;
            Ok(())
        }
    }
}
