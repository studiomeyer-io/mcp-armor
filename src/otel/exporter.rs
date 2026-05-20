//! OTLP gRPC exporter wiring (feature `otlp`).
//!
//! Build path:
//! 1. `SpanExporter::builder().with_tonic().with_endpoint(...).build()`
//! 2. `BatchSpanProcessor::builder(exporter, runtime::Tokio).build()`
//! 3. `TracerProvider::builder().with_span_processor(...)
//!    .with_resource(Resource::new([service.name = "mcp-armor"])).build()`
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
//! - mTLS client certs — v0.3 backlog.
//! - Custom propagators (W3C TraceContext default is fine for a side-car).
//! - Metrics / logs exporters — scanner emits spans only.

use opentelemetry::KeyValue;
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::runtime::Tokio;
use opentelemetry_sdk::trace::{BatchSpanProcessor, TracerProvider};
use opentelemetry_sdk::Resource;

/// Build an OTLP-aware `TracerProvider`, install it as the global, and
/// return the cloned provider so the caller can shut it down on Drop.
///
/// `endpoint` is the value of `OTEL_EXPORTER_OTLP_ENDPOINT`. Pass-through
/// to the tonic exporter — the SDK accepts both http:// and grpc:// URLs.
pub fn init_provider(endpoint: &str) -> Result<TracerProvider, opentelemetry::trace::TraceError> {
    let exporter = SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint.to_string())
        .build()?;

    let processor = BatchSpanProcessor::builder(exporter, Tokio).build();

    // We hardcode the service.name + sdk metadata as plain strings rather
    // than pull the opentelemetry-semantic-conventions crate. The keys are
    // stable in the W3C / OTel spec; this avoids a 4-MB dep tree to look
    // up two constants.
    let resource = Resource::new([
        KeyValue::new("service.name", "mcp-armor"),
        KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
        KeyValue::new("telemetry.sdk.name", "opentelemetry"),
        KeyValue::new("telemetry.sdk.language", "rust"),
    ]);

    let provider = TracerProvider::builder()
        .with_span_processor(processor)
        .with_resource(resource)
        .build();

    opentelemetry::global::set_tracer_provider(provider.clone());
    Ok(provider)
}
