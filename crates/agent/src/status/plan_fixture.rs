use std::{
    collections::BTreeMap,
    ops::Deref,
    path::{Path, PathBuf},
};

use probe_config::{
    AgentConfig, CaptureBackend, CaptureSelection, CompressionCodecName, ExporterConfig,
    ExporterTransportConfig,
};
use probe_core::CapabilityState;
use runtime::{CaptureProviderBuilder, CaptureProviderDescriptor, ProviderRegistry, RuntimePlan};

#[derive(Debug)]
pub(in crate::status) struct TestDir(tempfile::TempDir);

impl Deref for TestDir {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.0.path()
    }
}

impl AsRef<Path> for TestDir {
    fn as_ref(&self) -> &Path {
        self.0.path()
    }
}

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
            transport: ExporterTransportConfig::Webhook {
                endpoint: "https://collector.example/batches".to_string(),
                headers: BTreeMap::new(),
                tls: Default::default(),
            },
            codec: CompressionCodecName::None,
            worker: Default::default(),
        }],
        ..AgentConfig::default()
    }
}

pub(in crate::status) fn test_dir(name: &str) -> Result<TestDir, std::io::Error> {
    tempfile::Builder::new()
        .prefix(&format!("{name}-"))
        .tempdir()
        .map(TestDir)
}
