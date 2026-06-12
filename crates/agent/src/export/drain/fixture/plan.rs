use std::{collections::BTreeMap, num::NonZeroU64, path::PathBuf};

use probe_config::{AgentConfig, CompressionCodecName, ExporterTransport, TlsMaterialKind};
use probe_core::{CapabilityKind, CapabilityState};
use runtime::{
    self, ExportPlan, ExportSinkPlan, ExportSinkTlsPlan, ExportSinkWorkerPlan,
    ExportTlsMaterialPlan, ExportWorkerPlan, ProviderRegistry, RuntimePlan,
};

pub(in crate::export::drain) fn export_plan_with_trust_anchor(path: PathBuf) -> ExportPlan {
    ExportPlan {
        worker: ExportWorkerPlan::Disabled {
            reason: "test".to_string(),
        },
        sinks: vec![ExportSinkPlan {
            id: "secure".to_string(),
            transport: ExporterTransport::Webhook,
            endpoint: "https://collector.example/batches".to_string(),
            codec: CompressionCodecName::None,
            headers: BTreeMap::new(),
            tls: ExportSinkTlsPlan {
                trust_anchors: vec![tls_material(
                    "collector-ca",
                    TlsMaterialKind::TrustAnchor,
                    path,
                )],
                ..Default::default()
            },
            worker: inherited_worker_quota(1),
        }],
    }
}

pub(in crate::export::drain) fn inherited_worker_quota(
    effective_batches_per_tick: u64,
) -> ExportSinkWorkerPlan {
    ExportSinkWorkerPlan {
        batches_per_tick_override: None,
        effective_batches_per_tick: NonZeroU64::new(effective_batches_per_tick)
            .expect("positive batch quota"),
    }
}

pub(in crate::export::drain) fn overridden_worker_quota(
    effective_batches_per_tick: u64,
) -> ExportSinkWorkerPlan {
    ExportSinkWorkerPlan {
        batches_per_tick_override: Some(effective_batches_per_tick),
        effective_batches_per_tick: NonZeroU64::new(effective_batches_per_tick)
            .expect("positive batch quota"),
    }
}

pub(in crate::export::drain) fn tls_material(
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

pub(in crate::export::drain) fn runtime_plan(
    config: AgentConfig,
) -> Result<RuntimePlan, runtime::RuntimeError> {
    RuntimePlan::build(
        config,
        &ProviderRegistry::new(Vec::new(), test_capabilities()),
    )
}

fn test_capabilities() -> Vec<CapabilityState> {
    vec![
        CapabilityState::available(CapabilityKind::Http1),
        CapabilityState::available(CapabilityKind::Sse),
        CapabilityState::available(CapabilityKind::WebSocketHandoff),
        CapabilityState::available(CapabilityKind::WebSocketFrame),
        CapabilityState::unavailable(CapabilityKind::LibsslUprobe, "not built"),
        CapabilityState::available(CapabilityKind::DryRunEnforcement),
    ]
}
