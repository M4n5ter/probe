use std::path::PathBuf;

use probe_config::{CaptureBackend, TlsMaterialKind};
use probe_core::{CapabilityKind, CapabilityState, RuntimeMode};
use runtime::{CaptureProviderBuilder, CaptureProviderDescriptor, ExportTlsMaterialPlan};

pub(super) fn capture_provider(
    backend: CaptureBackend,
    builder: CaptureProviderBuilder,
    mode: RuntimeMode,
) -> CaptureProviderDescriptor {
    match mode {
        RuntimeMode::Available => CaptureProviderDescriptor::available(backend, builder),
        RuntimeMode::Degraded => CaptureProviderDescriptor::degraded(backend, builder, "degraded"),
        RuntimeMode::Unavailable => {
            CaptureProviderDescriptor::unavailable(backend, builder, "unavailable")
        }
    }
}

pub(super) fn test_platform_capabilities() -> Vec<CapabilityState> {
    vec![
        CapabilityState::available(CapabilityKind::Http1),
        CapabilityState::available(CapabilityKind::Sse),
        CapabilityState::available(CapabilityKind::WebSocketHandoff),
        CapabilityState::available(CapabilityKind::WebSocketFrame),
        CapabilityState::unavailable(CapabilityKind::LibsslUprobe, "not built"),
        CapabilityState::available(CapabilityKind::DryRunEnforcement),
        CapabilityState::unavailable(CapabilityKind::ConnectionEnforcement, "not built"),
    ]
}

pub(super) fn test_platform_capabilities_with_libssl(mode: RuntimeMode) -> Vec<CapabilityState> {
    test_platform_capabilities()
        .into_iter()
        .map(|state| {
            if state.kind == CapabilityKind::LibsslUprobe {
                match mode {
                    RuntimeMode::Available => {
                        CapabilityState::available(CapabilityKind::LibsslUprobe)
                    }
                    RuntimeMode::Degraded => {
                        CapabilityState::degraded(CapabilityKind::LibsslUprobe, "degraded")
                    }
                    RuntimeMode::Unavailable => {
                        CapabilityState::unavailable(CapabilityKind::LibsslUprobe, "unavailable")
                    }
                }
            } else {
                state
            }
        })
        .collect()
}

pub(super) fn test_platform_capabilities_with_connection_enforcement(
    mode: RuntimeMode,
) -> Vec<CapabilityState> {
    test_platform_capabilities()
        .into_iter()
        .map(|state| {
            if state.kind == CapabilityKind::ConnectionEnforcement {
                match mode {
                    RuntimeMode::Available => {
                        CapabilityState::available(CapabilityKind::ConnectionEnforcement)
                    }
                    RuntimeMode::Degraded => {
                        CapabilityState::degraded(CapabilityKind::ConnectionEnforcement, "degraded")
                    }
                    RuntimeMode::Unavailable => CapabilityState::unavailable(
                        CapabilityKind::ConnectionEnforcement,
                        "unavailable",
                    ),
                }
            } else {
                state
            }
        })
        .collect()
}

pub(super) fn export_tls_material(
    id: &str,
    kind: TlsMaterialKind,
    path: impl Into<PathBuf>,
) -> ExportTlsMaterialPlan {
    ExportTlsMaterialPlan {
        id: id.to_string(),
        kind,
        path: path.into(),
    }
}
