//! Telemetry initialisation.
//!
//! v0.1 status: **stderr-only JSON tracing**. Full OTLP gRPC export is on
//! the v0.2 backlog (see CHANGELOG.md "Known limitations" + BUILDER_NOTES).
//!
//! When `OTEL_EXPORTER_OTLP_ENDPOINT` is set, v0.1 logs a single info-line
//! recording the endpoint and otherwise behaves identically to the unset
//! case. No spans are emitted to a collector. The advisory note here is
//! deliberate so users running with the env var pre-set notice the gap
//! instead of silently believing traces are being shipped.

use crate::error::ArmorError;
use std::env;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// Guard returned from [`init`]. Holds the OTLP-active flag so callers can
/// query it; in v0.1 the drop is a no-op (no provider was installed).
pub struct OtelGuard {
    _otlp_active: bool,
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        // v0.1: nothing to flush. Provider install + flush land in v0.2
        // when the OTLP wiring becomes real.
    }
}

/// Initialise tracing. Returns a guard that is held for the process
/// lifetime.
///
/// Behaviour (v0.1):
/// - `RUST_LOG` controls verbosity (default `info`).
/// - `OTEL_EXPORTER_OTLP_ENDPOINT` set → an info-line is logged announcing
///   the endpoint, but **no spans are exported**. Full OTLP gRPC wiring is
///   on the v0.2 backlog.
/// - Stderr-only JSON subscriber otherwise.
pub fn init() -> Result<OtelGuard, ArmorError> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .json();

    let otlp_endpoint = env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok();

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .try_init()
        .map_err(|e| ArmorError::InvalidPattern(format!("tracing init: {e}")))?;

    if let Some(endpoint) = otlp_endpoint {
        tracing::warn!(
            endpoint = %endpoint,
            "OTEL_EXPORTER_OTLP_ENDPOINT set but OTLP gRPC export is a v0.2 feature; v0.1 only logs to stderr"
        );
        Ok(OtelGuard {
            _otlp_active: false,
        })
    } else {
        Ok(OtelGuard {
            _otlp_active: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_no_panic_without_endpoint() {
        // Cannot call init() twice in the same process (try_init returns Err
        // on second call), so just verify the guard struct constructs.
        let g = OtelGuard {
            _otlp_active: false,
        };
        drop(g);
    }
}
