use capture::{CaptureProvider, EbpfProcessObservationProbeConfig, EbpfProcessObservationProvider};
use probe_core::{CancellationToken, CompiledSelector, ProcessSelector, Selector};
use runtime::RuntimePlan;

use super::{
    OpenedLiveCaptureBackend, procfs_resolver::ProcfsTcpProcessResolver,
    runtime::CaptureProviderRuntimeDetailsSnapshot,
};
use crate::error::AgentError;

pub(super) fn build_ebpf_capture_provider(
    plan: &RuntimePlan,
    cancellation: CancellationToken,
) -> Result<OpenedLiveCaptureBackend, AgentError> {
    let object_path = plan
        .effective_config
        .capture
        .ebpf
        .object_path
        .clone()
        .ok_or_else(|| {
            AgentError::UnsupportedRunConfig(
                "ebpf capture requires capture.ebpf.object_path".to_string(),
            )
        })?;
    let (deep_observe_selector, process_payload_selector) = deep_observe_selector_plan(plan)?;
    let provider = EbpfProcessObservationProvider::open_with_cancellation(
        EbpfProcessObservationProbeConfig::new(object_path),
        Box::<ProcfsTcpProcessResolver>::default(),
        deep_observe_selector.clone(),
        process_payload_selector.clone(),
        cancellation,
    )?;
    let provider_details = Some(
        CaptureProviderRuntimeDetailsSnapshot::ebpf_process_observation(provider.probe_snapshot()),
    );
    Ok(OpenedLiveCaptureBackend {
        provider: Box::new(provider) as Box<dyn CaptureProvider>,
        provider_details,
    })
}

fn deep_observe_selector_plan(
    plan: &RuntimePlan,
) -> Result<(Option<CompiledSelector>, Option<CompiledSelector>), AgentError> {
    let Some(selector) = plan.effective_config.capture.deep_observe_selector.as_ref() else {
        return Ok((None, None));
    };
    let resolved = selector
        .resolve_refs_with_registry(&plan.effective_config.selectors)
        .map_err(|source| {
            AgentError::UnsupportedRunConfig(format!(
                "invalid capture.deep_observe_selector: {source}"
            ))
        })?;
    let compiled = resolved.as_selector().compile().map_err(|source| {
        AgentError::UnsupportedRunConfig(format!("invalid capture.deep_observe_selector: {source}"))
    })?;
    let process_payload_selector =
        selector_requires_process_constraint_on_all_paths(resolved.as_selector())
            .then_some(compiled.clone());
    Ok((Some(compiled), process_payload_selector))
}

fn selector_requires_process_constraint_on_all_paths(selector: &Selector) -> bool {
    match selector {
        Selector::Match { term } => term.process != ProcessSelector::default(),
        Selector::All { selectors } => selectors
            .iter()
            .any(selector_requires_process_constraint_on_all_paths),
        Selector::Any { selectors } => selectors
            .iter()
            .all(selector_requires_process_constraint_on_all_paths),
        Selector::Not { .. } | Selector::Ref { .. } => false,
    }
}

#[cfg(test)]
mod tests {
    use probe_core::{Direction, TrafficSelector};

    use super::*;

    #[test]
    fn process_gate_requires_a_positive_process_constraint_on_all_paths() {
        assert!(selector_requires_process_constraint_on_all_paths(
            &process_selector()
        ));
        assert!(selector_requires_process_constraint_on_all_paths(
            &Selector::All {
                selectors: vec![traffic_selector(), process_selector()],
            }
        ));
        assert!(selector_requires_process_constraint_on_all_paths(
            &Selector::Any {
                selectors: vec![process_selector(), named_process_selector("worker")],
            }
        ));

        assert!(!selector_requires_process_constraint_on_all_paths(
            &traffic_selector()
        ));
        assert!(!selector_requires_process_constraint_on_all_paths(
            &Selector::Any {
                selectors: vec![process_selector(), traffic_selector()],
            }
        ));
        assert!(!selector_requires_process_constraint_on_all_paths(
            &Selector::Not {
                selector: Box::new(process_selector()),
            }
        ));
    }

    fn process_selector() -> Selector {
        named_process_selector("fixture-backend")
    }

    fn named_process_selector(name: &str) -> Selector {
        Selector::term(
            ProcessSelector {
                names: vec![name.to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector::default(),
        )
    }

    fn traffic_selector() -> Selector {
        Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                remote_ports: vec![443],
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
        )
    }
}
