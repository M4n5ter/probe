use capture::{CaptureProvider, EbpfProcessObservationProbeConfig, EbpfProcessObservationProvider};
use runtime::RuntimePlan;

use super::{
    OpenedLiveCaptureBackend, procfs_resolver::ProcfsTcpProcessResolver,
    runtime::CaptureProviderRuntimeDetailsSnapshot,
};
use crate::error::AgentError;

pub(super) fn build_ebpf_capture_provider(
    plan: &RuntimePlan,
) -> Result<OpenedLiveCaptureBackend, AgentError> {
    let object_path = plan
        .config
        .capture
        .ebpf
        .object_path
        .clone()
        .ok_or_else(|| {
            AgentError::UnsupportedRunConfig(
                "ebpf capture requires capture.ebpf.object_path".to_string(),
            )
        })?;
    let deep_observe_selector = plan
        .config
        .capture
        .deep_observe_selector
        .as_ref()
        .map(|selector| {
            selector
                .compile_with_registry(&plan.config.selectors)
                .map_err(|source| {
                    AgentError::UnsupportedRunConfig(format!(
                        "invalid capture.deep_observe_selector: {source}"
                    ))
                })
        })
        .transpose()?;
    let provider = EbpfProcessObservationProvider::open(
        EbpfProcessObservationProbeConfig::new(object_path),
        Box::<ProcfsTcpProcessResolver>::default(),
        deep_observe_selector,
    )?;
    let provider_details = Some(
        CaptureProviderRuntimeDetailsSnapshot::ebpf_process_observation(provider.probe_snapshot()),
    );
    Ok(OpenedLiveCaptureBackend {
        provider: Box::new(provider) as Box<dyn CaptureProvider>,
        provider_details,
    })
}
