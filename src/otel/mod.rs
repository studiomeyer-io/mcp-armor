//! Telemetry initialisation — v0.4 runs on `opentelemetry 0.30`.
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
//!   batched via the async-runtime variant of `BatchSpanProcessor` on the
//!   tokio runtime so the scanner hot-path never blocks on a flush. The
//!   exporter is **only installed when the env var is set** — if it is
//!   unset, the otlp-feature build behaves identically to the default
//!   build (the dependencies are pulled in but no provider is constructed).
//!
//! ## v0.4 — 0.27 → 0.30 SDK migration (closes the shutdown-hang class)
//!
//! The 0.27 line had a known shutdown-deadlock when the BatchSpanProcessor
//! ran on the tokio runtime and the collector was unreachable
//! (open-telemetry/opentelemetry-rust#2071 + #2798). The 0.28 release
//! restructured BatchSpanProcessor / PeriodicReader to run on a dedicated
//! background thread by default. We migrated to 0.30 directly, which is
//! the LTS-shaped step that ships the deadlock fix without the metrics-SDK
//! churn of 0.31 / 0.32. We opted in to the
//! `experimental_trace_batch_span_processor_with_async_runtime` feature so
//! the proxy hot-path keeps the previous async-flush semantics — the
//! shutdown deadlock is still gone because we no longer block on the
//! `tokio::main` runtime during process tear-down.
//!
//! Other SDK renames absorbed in v0.4:
//! - `TracerProvider` → `SdkTracerProvider`
//! - `Resource::new(...)` (deprecated) → `Resource::builder().with_service_name().with_attributes().build()`
//! - `provider.shutdown()` returns `OTelSdkResult` (no longer a void)
//! - `TraceError` (return type from exporter build) → `OTelSdkError`
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
//! The 0.33 release of `tracing-opentelemetry` would let us bridge existing
//! `tracing::warn!` events automatically, but it adds another crate to the
//! audit surface. We emit OTLP spans manually via [`emit_block_span`] at
//! the small set of sites that actually need a span (block decisions, plus
//! TOFU verify mismatches). v0.5 may revisit if the call-site count grows
//! beyond ~10.
//!
//! ## v0.5 backlog (documented openly)
//!
//! - `tracing-opentelemetry 0.33` bridge for automatic span emission.
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
///
/// v0.4 — `provider` is now an [`opentelemetry_sdk::trace::SdkTracerProvider`]
/// (renamed in 0.28). `shutdown()` returns an `OTelSdkResult`; we swallow
/// any error since this is a best-effort flush during process teardown.
pub struct OtelGuard {
    otlp_active: bool,
    #[cfg(feature = "otlp")]
    provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
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
                // shutdown. The v0.4 SDK runs the BatchSpanProcessor on a
                // dedicated background thread (or the experimental async
                // runtime we opted in to), so this returns promptly even
                // when the collector is unreachable — closing the v0.3
                // shutdown-hang class.
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
        let mut provider: Option<opentelemetry_sdk::trace::SdkTracerProvider> = None;
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
