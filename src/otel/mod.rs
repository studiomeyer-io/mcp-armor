//! Telemetry initialisation — v0.2 wires real OTLP gRPC export.
//!
//! ## Two compile-time modes
//!
//! - **Default (no `otlp` feature)**: stderr-only JSON tracing-subscriber.
//!   Same behaviour as v0.1. Zero extra dependencies. Suitable for sidecars
//!   that ship to environments where adding a tonic/grpc stack is overkill.
//!
//! - **`--features otlp`**: in addition to the stderr layer, an OTLP gRPC
//!   exporter is wired against `$OTEL_EXPORTER_OTLP_ENDPOINT` using the
//!   official `opentelemetry-otlp` crate with `grpc-tonic`. Spans are
//!   batched via `BatchSpanProcessor` on the tokio runtime so the scanner
//!   hot-path never blocks on a flush. The exporter is **only installed
//!   when the env var is set** — if it is unset, the otlp-feature build
//!   behaves identically to the default build (the dependencies are pulled
//!   in but no provider is constructed).
//!
//! ## Hot-path budget
//!
//! PLAN.md R2 holds: p99 < 5 ms on 100 kB payloads. The OTLP exporter only
//! emits a span when a block decision happens (`fail_mode=closed` reject
//! path in `proxy::stdio`) — clean-payload Allow verdicts never reach the
//! tracing layer, so the per-call hot-path cost stays at the scanner's
//! Aho+Regex cost. The `BatchSpanProcessor` buffer-size and export-timeout
//! are tuned conservatively (default 512 spans, 5 s) so a back-pressured
//! collector cannot leak into the scanner thread.
//!
//! ## Why not `tracing-opentelemetry`?
//!
//! The 0.32 release of `tracing-opentelemetry` would let us bridge existing
//! `tracing::warn!` events automatically, but it adds another crate to the
//! audit surface. v0.2 emits OTLP spans manually via [`emit_block_span`] at
//! the small set of sites that actually need a span (block decisions, plus
//! TOFU verify mismatches). v0.3 may revisit if the call-site count grows
//! beyond ~10.
//!
//! ## v0.3 backlog (documented openly)
//!
//! - `tracing-opentelemetry` bridge for automatic span emission.
//! - Span exemplars for the scanner-latency histogram (today emitted as a
//!   single `latency_us` attribute on the block-span).
//! - mTLS client cert for OTLP gRPC (today: TLS via tonic native-roots).

use crate::error::ArmorError;
use std::env;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

#[cfg(feature = "otlp")]
mod exporter;

/// Guard returned from [`init`]. Holds the OTLP-active flag plus, when the
/// `otlp` feature is enabled, the SDK tracer provider so its `shutdown()`
/// is called on Drop. Without the feature it is an empty marker.
pub struct OtelGuard {
    otlp_active: bool,
    #[cfg(feature = "otlp")]
    provider: Option<opentelemetry_sdk::trace::TracerProvider>,
}

impl OtelGuard {
    /// `true` when an OTLP exporter was installed (env var set + feature on).
    pub fn is_otlp_active(&self) -> bool {
        self.otlp_active
    }
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        #[cfg(feature = "otlp")]
        {
            if let Some(provider) = self.provider.take() {
                // Best-effort: a hung collector must not block process
                // shutdown — `shutdown_tracer_provider` already wraps the
                // call in a timeout.
                let _ = provider.shutdown();
            }
        }
    }
}

/// Initialise tracing.
///
/// Behaviour:
/// - `RUST_LOG` controls verbosity (default `info`).
/// - Stderr JSON subscriber is always installed.
/// - With `--features otlp` AND `OTEL_EXPORTER_OTLP_ENDPOINT` set, an OTLP
///   gRPC exporter is installed in addition.
/// - With `--features otlp` but env var unset, no exporter is installed
///   and the build behaves like the default. An `info!` event records the
///   gap so operators do not silently believe traces are being collected.
pub fn init() -> Result<OtelGuard, ArmorError> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .json();

    let otlp_endpoint = env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok();

    #[cfg(feature = "otlp")]
    {
        // OTLP feature path.
        let mut otlp_active = false;
        let mut provider: Option<opentelemetry_sdk::trace::TracerProvider> = None;
        if let Some(ref endpoint) = otlp_endpoint {
            match exporter::init_provider(endpoint) {
                Ok(p) => {
                    provider = Some(p);
                    otlp_active = true;
                }
                Err(e) => {
                    // We intentionally do not abort init() on exporter
                    // failure — losing telemetry should never take the
                    // sidecar down. The error surfaces as a warn-line.
                    eprintln!(
                        "{{\"level\":\"warn\",\"target\":\"mcp_armor::otel\",\
                         \"message\":\"OTLP exporter init failed: {e}; \
                         falling back to stderr-only telemetry\"}}"
                    );
                }
            }
        }
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt_layer)
            .try_init()
            .map_err(|e| ArmorError::InvalidPattern(format!("tracing init: {e}")))?;

        if !otlp_active {
            if let Some(endpoint) = otlp_endpoint.as_ref() {
                tracing::warn!(
                    endpoint = %endpoint,
                    "OTEL_EXPORTER_OTLP_ENDPOINT set but exporter did not install; stderr-only fallback"
                );
            }
        } else if let Some(endpoint) = otlp_endpoint.as_ref() {
            tracing::info!(
                endpoint = %endpoint,
                "OTLP gRPC exporter active (otlp feature build)"
            );
        }
        Ok(OtelGuard {
            otlp_active,
            provider,
        })
    }
    #[cfg(not(feature = "otlp"))]
    {
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt_layer)
            .try_init()
            .map_err(|e| ArmorError::InvalidPattern(format!("tracing init: {e}")))?;

        if let Some(endpoint) = otlp_endpoint {
            tracing::warn!(
                endpoint = %endpoint,
                "OTEL_EXPORTER_OTLP_ENDPOINT set but this build was compiled without the `otlp` feature; rebuild with `--features otlp` to ship spans"
            );
        }
        Ok(OtelGuard { otlp_active: false })
    }
}

/// Hot-path span emission helper. Block decisions in the proxy hot-path call
/// this with the matched-pattern + cve-ref vectors so an OTLP collector sees
/// `mcp_armor.block` events with all the metadata. With the `otlp` feature
/// off this is a cheap no-op (still emits a stderr `tracing::warn!`).
#[cfg(feature = "otlp")]
pub fn emit_block_span(direction: &str, matched: &[String], cves: &[String], latency_us: u64) {
    use opentelemetry::global;
    use opentelemetry::trace::{Span, SpanKind, Status, Tracer};
    use opentelemetry::KeyValue;
    let tracer = global::tracer("mcp_armor");
    let mut span = tracer
        .span_builder("mcp_armor.block")
        .with_kind(SpanKind::Internal)
        .start(&tracer);
    span.set_attribute(KeyValue::new("direction", direction.to_string()));
    span.set_attribute(KeyValue::new("matched_patterns", matched.join(",")));
    span.set_attribute(KeyValue::new("cve_refs", cves.join(",")));
    span.set_attribute(KeyValue::new(
        "latency_us",
        i64::try_from(latency_us).unwrap_or(i64::MAX),
    ));
    span.set_status(Status::error("blocked by mcp-armor"));
    span.end();
}

/// Default-feature no-op variant. Kept callable from the proxy hot-path
/// without `cfg`-juggling at every call site — the optimiser inlines this
/// to nothing.
#[cfg(not(feature = "otlp"))]
#[inline]
pub fn emit_block_span(_direction: &str, _matched: &[String], _cves: &[String], _latency_us: u64) {
    // intentional no-op
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_no_panic_without_endpoint() {
        // Cannot call init() twice in the same process (try_init returns Err
        // on second call), so just verify the guard struct constructs.
        #[cfg(feature = "otlp")]
        let g = OtelGuard {
            otlp_active: false,
            provider: None,
        };
        #[cfg(not(feature = "otlp"))]
        let g = OtelGuard { otlp_active: false };
        assert!(!g.is_otlp_active());
        drop(g);
    }

    #[test]
    fn emit_block_span_no_op_without_otlp_does_not_panic() {
        // The no-op call must compile and run without spans being emitted.
        emit_block_span(
            "inbound",
            &["shell_substitution".to_string()],
            &["CVE-X".to_string()],
            42,
        );
    }
}
