//! `mcp-armor` CLI binary. Subcommands:
//! - `wrap`          — start the stdio proxy around an upstream MCP server
//! - `verify`        — verify an Ed25519 manifest signature (stateless or TOFU)
//! - `scan`          — run the scanner against a payload from CLI/stdin
//! - `policy`        — show or reload policy
//! - `mcp-control`   — start the read-only control-plane MCP server
//! - `keystore`      — list / pin / unpin TOFU maintainer keys (v0.2)
//! - `sigstore`      — verify cosign bundles + lookup Rekor inclusion (v0.2)
//! - `version`       — print the crate version

use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use clap::{Parser, Subcommand};
use mcp_armor::manifest::{verify_with_tofu, Keystore};
use mcp_armor::{ScanHistory, Scanner, VERSION};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Parser)]
#[command(
    name = "mcp-armor",
    version = VERSION,
    about = "Drop-in Rust sidecar that armors any MCP server.",
    long_about = "Wraps any stdio MCP server with prompt-injection scanning, Ed25519 manifest verification (TOFU + Sigstore), OTLP telemetry, and a curated CVE block-list."
)]
struct Cli {
    /// Override the policy file path.
    #[arg(long, env = "MCP_ARMOR_POLICY", global = true)]
    policy: Option<PathBuf>,

    /// Override the TOFU keystore path (v0.2).
    #[arg(long, env = "MCP_ARMOR_KEYSTORE", global = true)]
    keystore: Option<PathBuf>,

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
        /// v0.2 — when set, also cross-check against the TOFU keystore for
        /// this server name. Pin on first use if `--pin-on-first-use` is also
        /// supplied; otherwise refuse to validate unknown servers.
        #[arg(long)]
        server: Option<String>,
        /// v0.2 — pin the key into the keystore if the server is unknown.
        /// No-op when `--server` is not supplied.
        #[arg(long)]
        pin_on_first_use: bool,
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
    /// v0.2 — Manage the TOFU keystore (list / pin / unpin).
    Keystore {
        #[command(subcommand)]
        action: KeystoreCmd,
    },
    /// v0.2 — Sigstore Rekor bridge: verify bundles + lookup inclusion.
    Sigstore {
        #[command(subcommand)]
        action: SigstoreCmd,
    },
    /// Print the version and exit.
    Version,
}

#[derive(Debug, Subcommand)]
enum PolicyCmd {
    /// Show the resolved policy as JSON.
    Show,
    /// Re-read the file from disk and print it. Identical to `show` —
    /// this subcommand operates on a freshly-loaded copy and does NOT
    /// signal a running proxy. To apply a live reload to an in-flight
    /// `mcp-armor wrap` process, send `SIGHUP` to the wrap PID on Unix.
    Reload,
}

#[derive(Debug, Subcommand)]
enum KeystoreCmd {
    /// List all pinned maintainer keys.
    List,
    /// Pin a key for a server name. Reads the public key from --pubkey-b64.
    Pin {
        /// Display name of the upstream server (e.g. `filesystem`).
        server_name: String,
        /// Base64-encoded 32-byte Ed25519 verifying key.
        #[arg(long)]
        pubkey_b64: String,
    },
    /// Remove a pinned key by server name.
    Unpin {
        /// Display name of the upstream server.
        server_name: String,
    },
    /// Print the resolved keystore path (default or `--keystore`).
    Path,
}

#[derive(Debug, Subcommand)]
enum SigstoreCmd {
    /// Parse a cosign sigstore.json bundle and structurally verify the
    /// Rekor SignedEntryTimestamp shape. Offline.
    Verify {
        /// Path to the cosign sigstore.json bundle.
        bundle: PathBuf,
    },
    /// Compute the SHA-256 hash of a manifest JSON file and look it up in
    /// the Rekor transparency log.
    ///
    /// Requires this build to have been compiled with
    /// `--features sigstore-bridge`.
    RekorLookup {
        /// Path to the JSON file containing the `tools/list` response.
        manifest: PathBuf,
        /// Override the Rekor endpoint (defaults to https://rekor.sigstore.dev).
        #[arg(long)]
        rekor_url: Option<String>,
    },
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
            let (policy, policy_path) =
                mcp_armor::policy::load_policy(cli.policy.as_deref()).context("load policy")?;

            // v0.3 Sahnehaube A — startup advisory: surface to the operator
            // exactly which loader-class env keys the current shell is
            // leaking into the proxy process. The proxy itself will
            // env_remove these from the *child* before spawn (defence
            // applies regardless of this warning), but printing the leaks
            // here gives the operator the chance to scrub their shell init
            // so the keys never reach mcp-armor in the first place.
            //
            // R1-fix (Architect MED): use the public `Policy` method so
            // the binary doesn't reach into crate-internal helpers.
            let leaked = policy.leaked_loader_keys();
            if !leaked.is_empty() {
                tracing::warn!(
                    leaked = ?leaked,
                    "v0.3 Sahnehaube A: loader-class env keys present in operator shell — these will be stripped from the child but consider clearing them upstream"
                );
            }

            let handle = mcp_armor::policy::into_handle(policy);
            // v0.2 — install SIGHUP reload (Unix). Windows is a no-op.
            mcp_armor::policy::spawn_reload_task(handle.clone(), policy_path)
                .context("spawn policy reload")?;
            let history = Arc::new(ScanHistory::new(10_000));
            mcp_armor::proxy::run_proxy(&program, &args, scanner, handle, history)
                .await
                .context("proxy run")?;
            Ok(())
        }
        Cmd::Verify {
            manifest,
            public_key_b64,
            signature_b64,
            signed_at_iso,
            server,
            pin_on_first_use,
        } => {
            let raw = std::fs::read_to_string(&manifest)
                .with_context(|| format!("read {}", manifest.display()))?;
            let value: serde_json::Value =
                serde_json::from_str(&raw).context("parse manifest json")?;

            if let Some(server_name) = server {
                // v0.2 — TOFU-aware verify.
                let keystore_path = cli
                    .keystore
                    .clone()
                    .unwrap_or_else(mcp_armor::manifest::tofu::default_path);
                let mut ks = Keystore::load(&keystore_path).context("load TOFU keystore")?;
                let outcome = verify_with_tofu(
                    &value,
                    &public_key_b64,
                    &signature_b64,
                    signed_at_iso.as_deref(),
                    &mut ks,
                    &server_name,
                    pin_on_first_use,
                )
                .context("tofu verify")?;
                if matches!(outcome.pin_outcome, Some("newly_pinned")) {
                    ks.persist(&keystore_path).context("persist keystore")?;
                }
                println!("{}", serde_json::to_string_pretty(&outcome)?);
                if outcome.valid {
                    Ok(())
                } else {
                    std::process::exit(2);
                }
            } else {
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
            let (policy, policy_path) =
                mcp_armor::policy::load_policy(cli.policy.as_deref()).context("load policy")?;
            let handle = mcp_armor::policy::into_handle(policy);
            mcp_armor::policy::spawn_reload_task(handle.clone(), policy_path)
                .context("spawn policy reload")?;
            let history = Arc::new(ScanHistory::new(10_000));
            mcp_armor::control::run_control_plane(scanner, handle, history)
                .await
                .context("control-plane run")?;
            Ok(())
        }
        Cmd::Keystore { action } => {
            let path = cli
                .keystore
                .clone()
                .unwrap_or_else(mcp_armor::manifest::tofu::default_path);
            match action {
                KeystoreCmd::Path => {
                    println!("{}", path.display());
                    Ok(())
                }
                KeystoreCmd::List => {
                    let ks = Keystore::load(&path).context("load keystore")?;
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "keystore_path": path.display().to_string(),
                            "schema_version": ks.schema_version,
                            "count": ks.len(),
                            "pinned_entries": ks.entries
                        }))?
                    );
                    Ok(())
                }
                KeystoreCmd::Pin {
                    server_name,
                    pubkey_b64,
                } => {
                    let raw = B64
                        .decode(pubkey_b64.as_bytes())
                        .context("decode pubkey_b64")?;
                    if raw.len() != 32 {
                        anyhow::bail!("pubkey must decode to exactly 32 bytes, got {}", raw.len());
                    }
                    let mut hasher = blake3::Hasher::new();
                    hasher.update(&raw);
                    let fingerprint = hex_short(hasher.finalize().as_bytes(), 16);
                    let mut ks = Keystore::load(&path).context("load keystore")?;
                    let outcome = ks
                        .pin(mcp_armor::manifest::PinnedKey {
                            server_name: server_name.clone(),
                            key_fingerprint: fingerprint.clone(),
                            public_key_b64: pubkey_b64.clone(),
                            pinned_at_iso: mcp_armor::manifest::tofu::now_iso(),
                        })
                        .context("pin")?;
                    ks.persist(&path).context("persist keystore")?;
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "outcome": match outcome {
                                mcp_armor::manifest::PinOutcome::NewlyPinned => "newly_pinned",
                                mcp_armor::manifest::PinOutcome::AlreadyPinned => "already_pinned",
                            },
                            "server_name": server_name,
                            "key_fingerprint": fingerprint,
                            "keystore_path": path.display().to_string()
                        }))?
                    );
                    Ok(())
                }
                KeystoreCmd::Unpin { server_name } => {
                    let mut ks = Keystore::load(&path).context("load keystore")?;
                    let removed = ks.unpin(&server_name);
                    if removed {
                        ks.persist(&path).context("persist keystore")?;
                    }
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "removed": removed,
                            "server_name": server_name,
                            "keystore_path": path.display().to_string()
                        }))?
                    );
                    Ok(())
                }
            }
        }
        Cmd::Sigstore { action } => match action {
            SigstoreCmd::Verify { bundle } => {
                let b = mcp_armor::manifest::sigstore::Bundle::parse_from_path(&bundle)
                    .context("parse sigstore bundle")?;
                let inclusion = mcp_armor::manifest::sigstore::verify_inclusion(&b)
                    .context("verify inclusion")?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "bundle_path": bundle.display().to_string(),
                        "has_cert": b.cert_pem.is_some(),
                        "has_rekor_bundle": b.rekor_bundle.is_some(),
                        "inclusion": inclusion
                    }))?
                );
                Ok(())
            }
            #[cfg(feature = "sigstore-bridge")]
            SigstoreCmd::RekorLookup {
                manifest,
                rekor_url,
            } => {
                let raw = std::fs::read_to_string(&manifest)
                    .with_context(|| format!("read {}", manifest.display()))?;
                let value: serde_json::Value =
                    serde_json::from_str(&raw).context("parse manifest json")?;
                let lookup = mcp_armor::manifest::sigstore::lookup_rekor_by_hash(
                    &value,
                    rekor_url.as_deref(),
                )
                .context("rekor lookup")?;
                println!("{}", serde_json::to_string_pretty(&lookup)?);
                Ok(())
            }
            #[cfg(not(feature = "sigstore-bridge"))]
            SigstoreCmd::RekorLookup { .. } => {
                anyhow::bail!(
                    "sigstore rekor-lookup requires building with `--features sigstore-bridge`. \
                     Rebuild via `cargo install mcp-armor --features sigstore-bridge`."
                )
            }
        },
    }
}

fn hex_short(bytes: &[u8], n: usize) -> String {
    let mut out = String::with_capacity(n * 2);
    for b in bytes.iter().take(n) {
        let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{b:02x}"));
    }
    out
}
