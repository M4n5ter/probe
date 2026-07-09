use probe_core::{CompiledSelector, ProcessContext};

use crate::CaptureError;

use super::super::{
    EbpfObservedProcess, EbpfProcessHint, EbpfSocketFlowResolver,
    bridge::{process_context_from_observed, process_hint_from_observed},
    flow_start::PendingEbpfFlowStart,
    observation_source::EbpfObservationSource,
    payload_authorization::ProcessPayloadSampleAuthorization,
    types::EbpfProcessPayloadAllowanceDiagnostics,
};

pub(super) fn process_payload_authorization_for_observed_process(
    resolver: &mut dyn EbpfSocketFlowResolver,
    process: &EbpfObservedProcess,
    selector: &CompiledSelector,
) -> Option<ProcessPayloadSampleAuthorization> {
    direct_process_payload_authorization(resolver, process, selector)
        .or_else(|| observed_process_payload_authorization(process, selector))
}

pub(super) fn sync_process_payload_allowance_for_flow_start(
    resolver: &mut dyn EbpfSocketFlowResolver,
    observations: &mut dyn EbpfObservationSource,
    flow_start: &PendingEbpfFlowStart,
    selector: Option<&CompiledSelector>,
) -> Result<(), CaptureError> {
    let Some(selector) = selector else {
        return Ok(());
    };
    if let Some(authorization) = process_payload_authorization_for_observed_process(
        resolver,
        flow_start.observed_process(),
        selector,
    ) {
        observations.allow_process_payload_sample(authorization)?;
    }
    Ok(())
}

pub(super) fn sync_current_process_payload_allowance(
    resolver: &mut dyn EbpfSocketFlowResolver,
    observations: &mut dyn EbpfObservationSource,
    selector: Option<&CompiledSelector>,
) -> Result<EbpfProcessPayloadAllowanceDiagnostics, CaptureError> {
    let mut diagnostics = EbpfProcessPayloadAllowanceDiagnostics::default();
    let Some(selector) = selector else {
        return Ok(diagnostics);
    };
    diagnostics.selector_configured = true;
    let processes = resolver.resolve_processes()?;
    diagnostics.scanned_processes = processes.len() as u64;
    for process in processes {
        if let Some(authorization) =
            ProcessPayloadSampleAuthorization::from_process_prefilter_selector(
                process.identity.tgid,
                &process,
                selector,
            )
        {
            diagnostics.matched_processes = diagnostics.matched_processes.saturating_add(1);
            observations.allow_process_payload_sample(authorization)?;
            diagnostics.allowed_processes = diagnostics.allowed_processes.saturating_add(1);
        }
    }
    Ok(diagnostics)
}

fn direct_process_payload_authorization(
    resolver: &mut dyn EbpfSocketFlowResolver,
    process: &EbpfObservedProcess,
    selector: &CompiledSelector,
) -> Option<ProcessPayloadSampleAuthorization> {
    let resolved_process = resolver.resolve_process(process.tgid).ok()??;
    let hint = process_hint_from_observed(process);
    if hint
        .as_ref()
        .is_some_and(|hint| !process_matches_hint(&resolved_process, hint))
    {
        return None;
    }
    ProcessPayloadSampleAuthorization::from_process_prefilter_selector(
        process.tgid,
        &resolved_process,
        selector,
    )
}

fn observed_process_payload_authorization(
    process: &EbpfObservedProcess,
    selector: &CompiledSelector,
) -> Option<ProcessPayloadSampleAuthorization> {
    ProcessPayloadSampleAuthorization::from_observed_process_prefilter_selector(
        process.tgid,
        &process_context_from_observed(process),
        selector,
    )
}

fn process_matches_hint(process: &ProcessContext, hint: &EbpfProcessHint) -> bool {
    process.name == hint.name
        && process.identity.uid == hint.uid
        && process.identity.gid == hint.gid
}
