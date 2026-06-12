use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use probe_config::{
    AgentConfig, CaptureBackend, CaptureSelection, CompressionCodecName, ExporterConfig,
    ExporterTransport,
};
use probe_core::CapabilityState;
use runtime::{CaptureProviderBuilder, CaptureProviderDescriptor, ProviderRegistry, RuntimePlan};

pub(in crate::status) fn runtime_plan_from_config(
    config: AgentConfig,
    capabilities: Vec<CapabilityState>,
) -> Result<RuntimePlan, runtime::RuntimeError> {
    let registry = ProviderRegistry::new(
        vec![
            CaptureProviderDescriptor::available(
                CaptureBackend::Replay,
                CaptureProviderBuilder::Replay,
            ),
            CaptureProviderDescriptor::available(
                CaptureBackend::Libpcap,
                CaptureProviderBuilder::Libpcap,
            ),
        ],
        capabilities,
    );
    RuntimePlan::build(config, &registry)
}

pub(in crate::status) fn config_with_storage_path(storage_path: PathBuf) -> AgentConfig {
    AgentConfig {
        agent_id: "agent-1".to_string(),
        capture: probe_config::CaptureConfig {
            selection: CaptureSelection::Replay,
            ..Default::default()
        },
        storage: probe_config::StorageConfig {
            path: storage_path,
            ..Default::default()
        },
        exporters: vec![ExporterConfig {
            id: "primary".to_string(),
            transport: ExporterTransport::Webhook,
            endpoint: "https://collector.example/batches".to_string(),
            codec: CompressionCodecName::None,
            headers: BTreeMap::new(),
            tls: Default::default(),
            worker: Default::default(),
        }],
        ..AgentConfig::default()
    }
}

pub(in crate::status) fn test_dir(name: &str) -> Result<PathBuf, std::io::Error> {
    let path = std::env::temp_dir().join(format!("{name}-{}", current_unix_time_ns()));
    if Path::new(&path).exists() {
        fs::remove_dir_all(&path)?;
    }
    fs::create_dir_all(&path)?;
    Ok(path)
}

fn current_unix_time_ns() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    u64::try_from(nanos).unwrap_or(u64::MAX)
}
