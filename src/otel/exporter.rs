//! OTLP gRPC exporter wiring (feature `otlp`).
//!
//! v0.4 — migrated from `opentelemetry-otlp 0.27` to `0.30`. The
//! BatchSpanProcessor API in 0.28 was rewritten to run on a dedicated
//! background thread instead of a tokio runtime, which closes the
//! shutdown-hang class that bit the 0.27 line
//! (open-telemetry/opentelemetry-rust#2071 + #2798). We kept the
//! tokio-runtime variant available via the
//! `experimental_trace_batch_span_processor_with_async_runtime` feature
//! flag so the proxy hot-path keeps its async-flush semantics, but the
//! new constructor signature drops the redundant runtime parameter and
//! handles SDK shutdown deterministically.
//!
//! Build path:
//! 1. `SpanExporter::builder().with_tonic().with_endpoint(...).build()`
//! 2. `BatchSpanProcessor::builder(exporter, runtime::Tokio).build()`
//!    (async-runtime variant — feature-gated, matches v0.3 semantics)
//! 3. `SdkTracerProvider::builder().with_span_processor(...)
//!    .with_resource(Resource::new(...)).build()`
//! 4. `global::set_tracer_provider(provider.clone())`
//!
//! The provider clone is returned to the caller (held in `OtelGuard`) so
//! `Drop` can call `.shutdown()` and flush any in-flight batches at process
//! exit. Without that step a sigterm during a tool-call would drop the
//! tail of the audit trail.
//!
//! Tonic transport selection follows the `OTEL_EXPORTER_OTLP_PROTOCOL`
//! convention: gRPC default. HTTPS endpoints get tls-native-roots through
//! the opentelemetry-otlp feature flag (selected at Cargo.toml).
//!
//! ## What we do NOT do here
//!
//! - mTLS client certs — v0.5 backlog.
//! - Custom propagators (W3C TraceContext default is fine for a side-car).
//! - Metrics / logs exporters — scanner emits spans only.

use opentelemetry::KeyValue;
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::runtime::Tokio;
use opentelemetry_sdk::trace::{
    span_processor_with_async_runtime::BatchSpanProcessor, SdkTracerProvider,
};
use opentelemetry_sdk::Resource;

/// Build an OTLP-aware `SdkTracerProvider`, install it as the global, and
/// return the cloned provider so the caller can shut it down on Drop.
///
/// `endpoint` is the value of `OTEL_EXPORTER_OTLP_ENDPOINT`. Pass-through
/// to the tonic exporter — the SDK accepts both http:// and grpc:// URLs.
///
/// v0.4 — the 0.30 SDK renamed `TracerProvider` → `SdkTracerProvider` to
/// disambiguate from the `opentelemetry::trace::TracerProvider` trait.
/// `Resource::new(...)` was deprecated in favour of `Resource::builder()`
/// with explicit `service_name` shortcut; we use the new builder so a
/// future SDK release that drops the deprecated free-function constructor
/// won't break us. The exporter constructor uses
/// `OtlpExporterBuilderTrait` style which is also stable since 0.28.
pub fn init_provider(
    endpoint: &str,
) -> Result<SdkTracerProvider, opentelemetry_sdk::error::OTelSdkError> {
    let exporter = SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint.to_string())
        .build()
        .map_err(|e| {
            opentelemetry_sdk::error::OTelSdkError::InternalFailure(format!(
                "otlp exporter build: {e}"
            ))
        })?;

    // v0.4 — keep the async-runtime path via the
    // `experimental_trace_batch_span_processor_with_async_runtime` feature
    // because the proxy hot-path emits block spans from the tokio runtime
    // and we want non-blocking flush behaviour identical to v0.3.
    let processor = BatchSpanProcessor::builder(exporter, Tokio).build();

    // We hardcode the service.name + sdk metadata as plain strings rather
    // than pull the opentelemetry-semantic-conventions crate. The keys are
    // stable in the W3C / OTel spec; this avoids a 4-MB dep tree to look
    // up two constants.
    let resource = Resource::builder()
        .with_service_name("mcp-armor")
        .with_attributes(vec![
            KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
            KeyValue::new("telemetry.sdk.name", "opentelemetry"),
            KeyValue::new("telemetry.sdk.language", "rust"),
        ])
        .build();

    let provider = SdkTracerProvider::builder()
        .with_span_processor(processor)
        .with_resource(resource)
        .build();

    opentelemetry::global::set_tracer_provider(provider.clone());
    Ok(provider)
}
