use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use probe_core::{
    CancellationToken, CapabilityKind, CapabilityState, CaptureSource, CompiledSelector,
    FlowContext, ProcessContext, Timestamp,
};

use crate::output_loss::OutputLossTracker;
use crate::{
    CaptureError, CaptureEvent, CapturePoll, CaptureProvider, CaptureProviderRuntimeDiagnostics,
    EbpfProcessObservationActiveTracepointLiveness, EbpfProcessObservationRuntimeDiagnostics,
    EbpfProcessObservationTracepointDiagnostics, EbpfProcessObservationTracepointFiring,
};

use super::super::{
    EbpfCloseRangeTracepointObservation, EbpfCloseTracepointObservation, EbpfObservedProcess,
    EbpfProcessLifecycleKind, EbpfProcessLifecycleObservation, EbpfProcessObservation,
    EbpfProcessObservationProbe, EbpfProcessObservationProbeConfig,
    EbpfProcessObservationProbeSnapshot, EbpfSocketFlowResolver,
    active_liveness::{
        active_tracepoint_liveness_from_firings, trigger_safe_active_tracepoint_liveness_probe,
    },
    bridge::{output_loss_event, process_hint_from_observed},
    clock::EbpfObservationClock,
    flow_start::{PendingEbpfFlowResolution, PendingEbpfFlowStart},
    observation_source::{EbpfObservationSource, ProbeObservationSource},
    payload_authorization::{ProcessPayloadSampleAuthorization, SocketPayloadSampleAuthorization},
    payload_bridge::{
        output_loss_gap_events, process_lifecycle_gap_events, read_events,
        tracked_flow_displacement_gap_events, tracked_flow_handoff_boundary_gap_events,
        write_events,
    },
    payload_direction::PayloadDirections,
    tracked_flow::{TrackedEbpfFlow, TrackedEbpfFlows},
};

const DEFAULT_RESOLUTION_RETRIES: u32 = 20;
const DEFAULT_RESOLUTION_RETRY_SLEEP: Duration = Duration::from_millis(5);
const DEFAULT_RUNTIME_DIAGNOSTICS_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const MAX_TRACKED_EBPF_FLOWS: usize = 8192;
const MAX_PENDING_EBPF_FLOW_RESOLUTIONS: usize = 8192;

#[derive(Debug, Clone, Copy)]
enum PendingFlowRetryDelay {
    Respect,
    Ignore,
}

pub struct EbpfProcessObservationProvider {
    observations: Box<dyn EbpfObservationSource>,
    resolver: Box<dyn EbpfSocketFlowResolver>,
    clock: EbpfObservationClock,
    resolution_retries: u32,
    resolution_retry_sleep: Duration,
    stop_when_idle: bool,
    deep_observe_selector: Option<CompiledSelector>,
    process_payload_selector: Option<CompiledSelector>,
    tracked_flows: TrackedEbpfFlows,
    pending_flows: VecDeque<PendingEbpfFlowResolution>,
    pending_events: VecDeque<CaptureEvent>,
    handoff_boundary_emitted: bool,
    output_loss: OutputLossTracker,
    probe_snapshot: EbpfProcessObservationProbeSnapshot,
    runtime_diagnostics: EbpfProcessObservationRuntimeDiagnosticsCache,
}

impl EbpfProcessObservationProvider {
    pub fn open(
        config: EbpfProcessObservationProbeConfig,
        resolver: Box<dyn EbpfSocketFlowResolver>,
        deep_observe_selector: Option<CompiledSelector>,
        process_payload_selector: Option<CompiledSelector>,
    ) -> Result<Self, CaptureError> {
        Self::open_with_cancellation(
            config,
            resolver,
            deep_observe_selector,
            process_payload_selector,
            CancellationToken::default(),
        )
    }

    pub fn open_with_cancellation(
        config: EbpfProcessObservationProbeConfig,
        resolver: Box<dyn EbpfSocketFlowResolver>,
        deep_observe_selector: Option<CompiledSelector>,
        process_payload_selector: Option<CompiledSelector>,
        cancellation: CancellationToken,
    ) -> Result<Self, CaptureError> {
        let probe = EbpfProcessObservationProbe::load_with_cancellation(config, cancellation)
            .map_err(|error| CaptureError::provider("ebpf", error.to_string()))?;
        let probe_snapshot = probe.probe_snapshot();
        let observations: Box<dyn EbpfObservationSource> =
            Box::new(ProbeObservationSource { probe });
        Ok(Self {
            observations,
            resolver,
            clock: EbpfObservationClock::default(),
            resolution_retries: DEFAULT_RESOLUTION_RETRIES,
            resolution_retry_sleep: DEFAULT_RESOLUTION_RETRY_SLEEP,
            stop_when_idle: false,
            deep_observe_selector,
            process_payload_selector,
            tracked_flows: TrackedEbpfFlows::bounded(MAX_TRACKED_EBPF_FLOWS),
            pending_flows: VecDeque::new(),
            pending_events: VecDeque::new(),
            handoff_boundary_emitted: false,
            output_loss: OutputLossTracker::default(),
            probe_snapshot,
            runtime_diagnostics: EbpfProcessObservationRuntimeDiagnosticsCache::default(),
        })
    }

    pub fn probe_snapshot(&self) -> EbpfProcessObservationProbeSnapshot {
        self.probe_snapshot.clone()
    }

    pub fn allow_process_payload_sample(
        &mut self,
        authorization: ProcessPayloadSampleAuthorization,
    ) -> Result<(), CaptureError> {
        self.observations
            .allow_process_payload_sample(authorization)
    }

    pub fn revoke_process_payload_sample(&mut self, tgid: u32) -> Result<(), CaptureError> {
        self.observations.revoke_process_payload_sample(tgid)
    }

    fn poll_event(&mut self) -> Result<CapturePoll, CaptureError> {
        if let Some(event) = self.pending_events.pop_front() {
            return Ok(CapturePoll::event(event));
        }
        if self.output_loss.should_check_during_drain()
            && let Some(event) = self.output_loss_events()?
        {
            return Ok(CapturePoll::event(event));
        }
        if !self.pending_flows.is_empty() {
            return self.poll_pending_flow_resolution();
        }
        if let Some(observation) = self.observations.next_observation()? {
            self.output_loss.record_observation();
            return self.poll_observation(observation);
        }
        if let Some(event) = self.output_loss_events()? {
            return Ok(CapturePoll::event(event));
        }
        Ok(if self.stop_when_idle {
            CapturePoll::Finished
        } else {
            CapturePoll::Idle
        })
    }

    fn poll_observation(
        &mut self,
        observation: EbpfProcessObservation,
    ) -> Result<CapturePoll, CaptureError> {
        match observation {
            EbpfProcessObservation::Connect(connect) => {
                self.begin_flow_resolution(PendingEbpfFlowStart::Connect(connect))
            }
            EbpfProcessObservation::Accept(accept) => {
                self.begin_flow_resolution(PendingEbpfFlowStart::Accept(accept))
            }
            EbpfProcessObservation::Close(close) => Ok(self
                .close_event(&close)
                .map(CapturePoll::event)
                .unwrap_or(CapturePoll::Progress)),
            EbpfProcessObservation::CloseRange(close_range) => {
                let events = self.close_range_events(&close_range);
                Ok(self.queue_events(events))
            }
            EbpfProcessObservation::ProcessLifecycle(lifecycle) => {
                self.sync_process_payload_allowance_for_lifecycle(&lifecycle)?;
                let events = self.process_lifecycle_events(&lifecycle);
                Ok(self.queue_events(events))
            }
            EbpfProcessObservation::Write(write) => {
                let timestamp = self.clock.next_timestamp();
                let events = write_events(&mut self.tracked_flows, &write, timestamp);
                Ok(self.queue_events(events))
            }
            EbpfProcessObservation::Read(read) => {
                let timestamp = self.clock.next_timestamp();
                let events = read_events(&mut self.tracked_flows, &read, timestamp);
                Ok(self.queue_events(events))
            }
        }
    }

    fn queue_events(&mut self, events: impl IntoIterator<Item = CaptureEvent>) -> CapturePoll {
        self.pending_events.extend(events);
        self.pending_events
            .pop_front()
            .map(CapturePoll::event)
            .unwrap_or(CapturePoll::Progress)
    }

    fn begin_flow_resolution(
        &mut self,
        flow_start: PendingEbpfFlowStart,
    ) -> Result<CapturePoll, CaptureError> {
        let timestamp = self.clock.next_timestamp();
        if flow_start.descriptor_lease().is_none() {
            return Ok(CapturePoll::event(
                flow_start.invalid_descriptor_lease_gap(timestamp, self.resolver.as_mut()),
            ));
        }
        self.poll_pending_flow_resolution_attempt(PendingEbpfFlowResolution::new(
            flow_start, timestamp,
        ))
    }

    fn poll_pending_flow_resolution(&mut self) -> Result<CapturePoll, CaptureError> {
        let pending_count = self.pending_flows.len();
        for _ in 0..pending_count {
            let Some(pending) = self.pending_flows.pop_front() else {
                return Ok(CapturePoll::Idle);
            };
            if pending
                .retry_at
                .is_some_and(|retry_at| Instant::now() < retry_at)
            {
                self.pending_flows.push_back(pending);
                continue;
            }
            return self.poll_pending_flow_resolution_attempt(pending);
        }
        Ok(CapturePoll::Idle)
    }

    fn poll_pending_flow_resolution_attempt(
        &mut self,
        pending: PendingEbpfFlowResolution,
    ) -> Result<CapturePoll, CaptureError> {
        self.poll_pending_flow_resolution_attempt_with_retry_delay(
            pending,
            PendingFlowRetryDelay::Respect,
        )
    }

    fn drain_pending_flow_resolution_before_handoff(
        &mut self,
    ) -> Result<CapturePoll, CaptureError> {
        let Some(pending) = self.pending_flows.pop_front() else {
            return Ok(CapturePoll::Idle);
        };
        self.poll_pending_flow_resolution_attempt_with_retry_delay(
            pending,
            PendingFlowRetryDelay::Ignore,
        )
    }

    fn poll_pending_flow_resolution_attempt_with_retry_delay(
        &mut self,
        mut pending: PendingEbpfFlowResolution,
        retry_delay: PendingFlowRetryDelay,
    ) -> Result<CapturePoll, CaptureError> {
        if matches!(retry_delay, PendingFlowRetryDelay::Respect)
            && let Some(retry_at) = pending.retry_at
            && Instant::now() < retry_at
        {
            return Ok(self.queue_pending_flow_resolution(pending));
        }
        if let Some(event) = pending
            .flow_start
            .opened_event(pending.timestamp, self.resolver.as_mut())?
        {
            self.track_flow_start_event(&pending.flow_start, &event)?;
            return Ok(CapturePoll::event(event));
        }
        if pending.attempts_completed < self.resolution_retries {
            pending.attempts_completed = pending.attempts_completed.saturating_add(1);
            pending.retry_at = Some(Instant::now() + self.resolution_retry_sleep);
            self.resolver.invalidate_cached_resolution();
            return Ok(self.queue_pending_flow_resolution(pending));
        }
        if let Some(event) = pending
            .flow_start
            .observed_opened_event(pending.timestamp, self.resolver.as_mut())
        {
            self.track_flow_start_event(&pending.flow_start, &event)?;
            Ok(CapturePoll::event(event))
        } else {
            let reason = pending
                .flow_start
                .unresolved_reason(self.resolution_retries.saturating_add(1));
            Ok(CapturePoll::event(pending.flow_start.unresolved_gap(
                pending.timestamp,
                reason,
                self.resolver.as_mut(),
            )))
        }
    }

    fn queue_pending_flow_resolution(&mut self, pending: PendingEbpfFlowResolution) -> CapturePoll {
        if self.pending_flows.len() < MAX_PENDING_EBPF_FLOW_RESOLUTIONS {
            self.pending_flows.push_back(pending);
            return CapturePoll::Progress;
        }
        let reason = format!(
            "{}; pending flow resolution queue is full",
            pending
                .flow_start
                .unresolved_reason(pending.attempts_completed)
        );
        CapturePoll::event(pending.flow_start.unresolved_gap(
            pending.timestamp,
            reason,
            self.resolver.as_mut(),
        ))
    }

    fn track_flow_start_event(
        &mut self,
        flow_start: &PendingEbpfFlowStart,
        event: &CaptureEvent,
    ) -> Result<(), CaptureError> {
        if let CaptureEvent::ConnectionOpened {
            timestamp, flow, ..
        } = &event
        {
            let Some(lease) = flow_start.descriptor_lease() else {
                return Ok(());
            };
            let authorization = SocketPayloadSampleAuthorization::from_selector(
                lease,
                flow,
                self.deep_observe_selector.as_ref(),
            );
            let payload_directions = authorization
                .as_ref()
                .map(|authorization| authorization.payload_directions())
                .unwrap_or_else(PayloadDirections::empty);
            if let Some(authorization) = authorization {
                self.observations
                    .allow_socket_payload_sample(authorization)?;
            }
            if let Some(displacement) =
                self.tracked_flows
                    .insert_flow(lease, flow.clone(), payload_directions)
            {
                let displaced_key = displacement.key();
                let retained_payload_allowance = self
                    .tracked_flows
                    .has_payload_allowance_for_allow_map_key(displaced_key);
                if displacement.should_revoke_allow_map_key(retained_payload_allowance) {
                    self.observations
                        .revoke_socket_payload_sample(displaced_key)?;
                }
                self.pending_events
                    .extend(tracked_flow_displacement_gap_events(
                        displacement,
                        *timestamp,
                    ));
            }
        }
        Ok(())
    }

    fn output_loss_events(&mut self) -> Result<Option<CaptureEvent>, CaptureError> {
        let count = self.observations.process_output_loss_count()?;
        let Some(lost_events) = self.output_loss.checkpoint(count) else {
            return Ok(None);
        };
        let timestamp = self.clock.next_timestamp();
        self.pending_events
            .push_back(output_loss_event(timestamp, lost_events));
        self.pending_events.extend(output_loss_gap_events(
            &self.tracked_flows,
            timestamp,
            lost_events,
        ));
        Ok(self.pending_events.pop_front())
    }

    fn handoff_boundary_events(&mut self) -> Option<CaptureEvent> {
        if self.handoff_boundary_emitted {
            return None;
        }
        self.handoff_boundary_emitted = true;
        if !self.tracked_flows.has_active_payload_gap_targets() {
            return None;
        }
        let timestamp = self.clock.next_timestamp();
        self.pending_events
            .extend(tracked_flow_handoff_boundary_gap_events(
                &self.tracked_flows,
                timestamp,
            ));
        self.pending_events.pop_front()
    }

    fn close_event(&mut self, close: &EbpfCloseTracepointObservation) -> Option<CaptureEvent> {
        let flow = self.tracked_flows.remove_close(close)?.flow;
        Some(connection_closed_event(self.clock.next_timestamp(), flow))
    }

    fn close_range_events(
        &mut self,
        close_range: &EbpfCloseRangeTracepointObservation,
    ) -> Vec<CaptureEvent> {
        let removed = self.tracked_flows.remove_close_range(close_range);
        self.connection_closed_events(removed)
    }

    fn process_lifecycle_events(
        &mut self,
        lifecycle: &EbpfProcessLifecycleObservation,
    ) -> Vec<CaptureEvent> {
        let has_pending = self.has_pending_flow_resolutions_for_tgid(lifecycle.process.tgid);
        let active_payload_targets = self
            .tracked_flows
            .active_payload_gap_targets_for_tgid(lifecycle.process.tgid);
        if !has_pending && active_payload_targets.is_empty() {
            return Vec::new();
        }
        let timestamp = self.clock.next_timestamp();
        let active_payload_events = process_lifecycle_gap_events(
            active_payload_targets,
            timestamp,
            lifecycle.process.tgid,
            lifecycle.kind,
        );
        let mut events = self.cancel_pending_flow_resolutions_for_lifecycle(lifecycle, timestamp);
        events.extend(active_payload_events);
        events
    }

    fn sync_process_payload_allowance_for_lifecycle(
        &mut self,
        lifecycle: &EbpfProcessLifecycleObservation,
    ) -> Result<(), CaptureError> {
        let Some(selector) = self.process_payload_selector.clone() else {
            return Ok(());
        };
        match lifecycle.kind {
            EbpfProcessLifecycleKind::Exit => self
                .observations
                .revoke_process_payload_sample(lifecycle.process.tgid),
            EbpfProcessLifecycleKind::Exec => {
                let authorization = self.process_payload_authorization_for_observed_process(
                    &lifecycle.process,
                    &selector,
                );
                match authorization {
                    Some(authorization) => self
                        .observations
                        .allow_process_payload_sample(authorization),
                    None => self
                        .observations
                        .revoke_process_payload_sample(lifecycle.process.tgid),
                }
            }
        }
    }

    fn process_payload_authorization_for_observed_process(
        &mut self,
        process: &EbpfObservedProcess,
        selector: &CompiledSelector,
    ) -> Option<ProcessPayloadSampleAuthorization> {
        if let Some(hint) = process_hint_from_observed(process) {
            let candidates = self.resolver.resolve_processes_by_hint(hint).ok()?;
            return unique_process_payload_authorization(process.tgid, candidates, selector);
        }

        match self.resolver.resolve_process(process.tgid) {
            Ok(Some(resolved_process)) => {
                ProcessPayloadSampleAuthorization::from_unattributed_selector(
                    process.tgid,
                    &resolved_process,
                    selector,
                )
            }
            Ok(None) | Err(_) => None,
        }
    }

    fn has_pending_flow_resolutions_for_tgid(&self, tgid: u32) -> bool {
        self.pending_flows
            .iter()
            .any(|pending| pending.flow_start.tgid() == tgid)
    }

    fn cancel_pending_flow_resolutions_for_lifecycle(
        &mut self,
        lifecycle: &EbpfProcessLifecycleObservation,
        timestamp: Timestamp,
    ) -> Vec<CaptureEvent> {
        let mut retained = VecDeque::with_capacity(self.pending_flows.len());
        let mut events = Vec::new();
        while let Some(pending) = self.pending_flows.pop_front() {
            if pending.flow_start.tgid() == lifecycle.process.tgid {
                events.push(pending.flow_start.lifecycle_boundary_gap(
                    timestamp,
                    lifecycle.kind,
                    self.resolver.as_mut(),
                ));
            } else {
                retained.push_back(pending);
            }
        }
        self.pending_flows = retained;
        events
    }

    fn connection_closed_events(&mut self, removed: Vec<TrackedEbpfFlow>) -> Vec<CaptureEvent> {
        if removed.is_empty() {
            return Vec::new();
        }
        let timestamp = self.clock.next_timestamp();
        removed
            .into_iter()
            .map(|tracked| connection_closed_event(timestamp, tracked.flow))
            .collect()
    }
}

struct EbpfProcessObservationRuntimeDiagnosticsCache {
    refresh_interval: Duration,
    last_refresh: Option<Instant>,
    snapshot: EbpfProcessObservationRuntimeDiagnostics,
    active_liveness: Option<EbpfProcessObservationActiveTracepointLiveness>,
}

impl Default for EbpfProcessObservationRuntimeDiagnosticsCache {
    fn default() -> Self {
        Self {
            refresh_interval: DEFAULT_RUNTIME_DIAGNOSTICS_REFRESH_INTERVAL,
            last_refresh: None,
            snapshot: EbpfProcessObservationRuntimeDiagnostics {
                tracepoints: Err(
                    "process tracepoint diagnostics have not been read yet".to_string()
                ),
            },
            active_liveness: None,
        }
    }
}

impl EbpfProcessObservationRuntimeDiagnosticsCache {
    fn snapshot(
        &mut self,
        observations: &mut dyn EbpfObservationSource,
    ) -> EbpfProcessObservationRuntimeDiagnostics {
        let now = Instant::now();
        if self
            .last_refresh
            .is_some_and(|last_refresh| now.duration_since(last_refresh) < self.refresh_interval)
        {
            return self.snapshot.clone();
        }
        self.last_refresh = Some(now);
        self.snapshot = match observations.process_tracepoint_firings() {
            Ok(Some(tracepoint_firings)) => {
                self.snapshot_from_available_tracepoint_firings(observations, tracepoint_firings)
            }
            Ok(None) => EbpfProcessObservationRuntimeDiagnostics {
                tracepoints: Err(
                    "process tracepoint firing diagnostics are not available for this observation source"
                        .to_string(),
                ),
            },
            Err(error) => EbpfProcessObservationRuntimeDiagnostics {
                tracepoints: Err(error.to_string()),
            },
        };
        self.snapshot.clone()
    }

    fn snapshot_from_available_tracepoint_firings(
        &mut self,
        observations: &mut dyn EbpfObservationSource,
        before_firings: Vec<EbpfProcessObservationTracepointFiring>,
    ) -> EbpfProcessObservationRuntimeDiagnostics {
        let Some(active_liveness) = &self.active_liveness else {
            let (tracepoint_firings, active_liveness) =
                run_active_liveness_probe(observations, before_firings);
            if let Ok(active_liveness) = &active_liveness {
                self.active_liveness = Some(active_liveness.clone());
            }
            return EbpfProcessObservationRuntimeDiagnostics {
                tracepoints: Ok(EbpfProcessObservationTracepointDiagnostics {
                    firings: tracepoint_firings,
                    active_liveness,
                }),
            };
        };
        EbpfProcessObservationRuntimeDiagnostics {
            tracepoints: Ok(EbpfProcessObservationTracepointDiagnostics {
                firings: before_firings,
                active_liveness: Ok(active_liveness.clone()),
            }),
        }
    }
}

fn run_active_liveness_probe(
    observations: &mut dyn EbpfObservationSource,
    before_firings: Vec<EbpfProcessObservationTracepointFiring>,
) -> (
    Vec<EbpfProcessObservationTracepointFiring>,
    Result<EbpfProcessObservationActiveTracepointLiveness, String>,
) {
    let _probe_guard = match trigger_safe_active_tracepoint_liveness_probe() {
        Ok(probe_guard) => probe_guard,
        Err(error) => {
            return (
                before_firings,
                Err(format!(
                    "safe active process eBPF tracepoint liveness probe failed: {error}"
                )),
            );
        }
    };
    match observations.process_tracepoint_firings() {
        Ok(Some(after_firings)) => {
            let active_liveness =
                active_tracepoint_liveness_from_firings(&before_firings, &after_firings);
            (after_firings, Ok(active_liveness))
        }
        Ok(None) => (
            before_firings,
            Err(
                "process tracepoint firing diagnostics became unavailable after active liveness probe"
                    .to_string(),
            ),
        ),
        Err(error) => (
            before_firings,
            Err(format!(
                "process tracepoint firing diagnostics failed after active liveness probe: {error}"
            )),
        ),
    }
}

fn unique_process_payload_authorization(
    observed_tgid: u32,
    candidates: impl IntoIterator<Item = ProcessContext>,
    selector: &CompiledSelector,
) -> Option<ProcessPayloadSampleAuthorization> {
    let mut candidates = candidates.into_iter();
    let process = candidates.next()?;
    if candidates.next().is_some() {
        return None;
    }
    ProcessPayloadSampleAuthorization::from_unattributed_selector(observed_tgid, &process, selector)
}

fn connection_closed_event(timestamp: Timestamp, flow: FlowContext) -> CaptureEvent {
    CaptureEvent::ConnectionClosed {
        timestamp,
        flow,
        origin: probe_core::CaptureOrigin::from_source(CaptureSource::EbpfSyscall),
    }
}

impl CaptureProvider for EbpfProcessObservationProvider {
    fn name(&self) -> &'static str {
        "ebpf"
    }

    fn capabilities(&self) -> Vec<CapabilityState> {
        vec![CapabilityState::degraded(
            CapabilityKind::Ebpf,
            "eBPF provider emits connect and accept/accept4 flow-start observations with descriptor leases, \
             prefers procfs-resolved socket metadata when available, falls back to degraded observed flows when \
             kernel tracepoints provide a remote endpoint before procfs resolution succeeds, uses direct TGID or \
             unique process-hint procfs matches for process lifecycle payload allowance when observed kernel TGIDs \
             are hidden from host procfs or collide with unrelated host PIDs, binds flow-start payload capture through \
             descriptor/socket allow maps, emits selector-authorized always-degraded outbound single-buffer and \
             bounded multi-iovec prefix syscall argument samples, outbound available sendfile family kernel-transfer \
             byte-count gaps, inbound single-buffer and bounded multi-iovec prefix syscall result samples bound to \
             descriptor generation, descriptor-generation close/plain \
             close_range lifecycle events, TGID-level process exit/exec cancellation of pending flow resolution plus \
             lifecycle boundary gaps for active payload-tracked flows, userspace tracked-flow displacement as \
             event-local terminal provider-state boundary gaps, output ring-buffer failure conversion to degraded \
             capture_loss events, conservative unknown-offset gap fan-out to active tracked payload flows, \
             per-tracepoint kernel firing counters, and safe active pipe read/write tracepoint liveness diagnostics; \
             payload beyond the bounded multi-iovec scan/sample or fixed verifier-friendly append slots, \
             kernel-transfer payload bytes, partial-write retry semantics, precise flow-specific lost-event \
             reconstruction, and kernel socket-object lifetime are not implemented",
        )]
    }

    fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
        self.handoff_boundary_emitted = false;
        self.poll_event()
    }

    fn drain_before_handoff(&mut self) -> Result<CapturePoll, CaptureError> {
        if let Some(event) = self.pending_events.pop_front() {
            return Ok(CapturePoll::event(event));
        }
        if self.output_loss.should_check_during_drain()
            && let Some(event) = self.output_loss_events()?
        {
            return Ok(CapturePoll::event(event));
        }
        if !self.pending_flows.is_empty() {
            return self.drain_pending_flow_resolution_before_handoff();
        }
        if let Some(event) = self.output_loss_events()? {
            return Ok(CapturePoll::event(event));
        }
        if let Some(event) = self.handoff_boundary_events() {
            return Ok(CapturePoll::event(event));
        }
        Ok(CapturePoll::Idle)
    }

    fn runtime_diagnostics(&mut self) -> CaptureProviderRuntimeDiagnostics {
        CaptureProviderRuntimeDiagnostics::from_ebpf_process_observation(
            self.runtime_diagnostics
                .snapshot(self.observations.as_mut()),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::Ipv4Addr,
        sync::{Arc, Mutex},
    };

    use crate::{
        CaptureProviderKind, EbpfProcessObservationActiveTracepointLiveness,
        EbpfProcessObservationActiveTracepointLivenessProgram,
        EbpfProcessObservationActiveTracepointLivenessState,
        EbpfProcessObservationTracepointFiring, EnforcementEvidencePropagation,
    };

    use ebpf_abi::EbpfProcessTracepointRole;
    use probe_core::{
        Direction, ObservationOnlyReason, ProcessContext, ProcessIdentity, ProcessSelector,
        Selector, TcpConnection, TcpEndpoint, TrafficSelector,
    };

    use crate::ebpf::{
        EbpfAcceptTracepointObservation, EbpfCloseRangeTracepointObservation,
        EbpfCloseTracepointObservation, EbpfConnectTracepointObservation, EbpfObservedProcess,
        EbpfProcessHint, EbpfResolvedSocketFlow, EbpfSocketEndpoint, EbpfSocketFlowLookup,
        EbpfSocketReadObservation, EbpfSocketWriteObservation,
    };

    use super::super::super::{EbpfProcessLifecycleKind, descriptor_lease::DescriptorLeaseKey};

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    impl EbpfProcessObservationProvider {
        fn from_observations_for_test(
            observations: impl IntoIterator<Item = EbpfProcessObservation> + 'static,
            resolver: Box<dyn EbpfSocketFlowResolver>,
        ) -> Self {
            Self::from_source_for_test(source_from_observations(observations), resolver, None)
        }

        fn from_source_for_test(
            observations: impl EbpfObservationSource + 'static,
            resolver: Box<dyn EbpfSocketFlowResolver>,
            deep_observe_selector: Option<CompiledSelector>,
        ) -> Self {
            Self {
                observations: Box::new(observations),
                resolver,
                clock: EbpfObservationClock::default(),
                resolution_retries: 0,
                resolution_retry_sleep: Duration::ZERO,
                stop_when_idle: true,
                process_payload_selector: deep_observe_selector.clone(),
                deep_observe_selector,
                tracked_flows: TrackedEbpfFlows::bounded(MAX_TRACKED_EBPF_FLOWS),
                pending_flows: VecDeque::new(),
                pending_events: VecDeque::new(),
                handoff_boundary_emitted: false,
                output_loss: OutputLossTracker::default(),
                probe_snapshot: EbpfProcessObservationProbeSnapshot::unreported(),
                runtime_diagnostics: EbpfProcessObservationRuntimeDiagnosticsCache::default(),
            }
        }

        fn with_output_loss_check_interval_for_test(mut self, interval: u32) -> Self {
            self.output_loss = OutputLossTracker::new(interval);
            self
        }

        fn with_runtime_diagnostics_refresh_interval_for_test(
            mut self,
            refresh_interval: Duration,
        ) -> Self {
            self.runtime_diagnostics.refresh_interval = refresh_interval;
            self
        }

        fn with_max_tracked_flows_for_test(mut self, max_tracked_flows: usize) -> Self {
            self.tracked_flows = TrackedEbpfFlows::bounded(max_tracked_flows);
            self
        }
    }

    struct VecObservationSource {
        observations: VecDeque<EbpfProcessObservation>,
    }

    impl EbpfObservationSource for VecObservationSource {
        fn next_observation(&mut self) -> Result<Option<EbpfProcessObservation>, CaptureError> {
            Ok(self.observations.pop_front())
        }

        fn allow_socket_payload_sample(
            &mut self,
            _authorization: SocketPayloadSampleAuthorization,
        ) -> Result<(), CaptureError> {
            Ok(())
        }

        fn allow_process_payload_sample(
            &mut self,
            _authorization: ProcessPayloadSampleAuthorization,
        ) -> Result<(), CaptureError> {
            Ok(())
        }

        fn revoke_process_payload_sample(&mut self, _tgid: u32) -> Result<(), CaptureError> {
            Ok(())
        }
    }

    struct RecordingObservationSource {
        observations: VecDeque<EbpfProcessObservation>,
        allowed: Arc<Mutex<Vec<DescriptorLeaseKey>>>,
        revoked: Arc<Mutex<Vec<DescriptorLeaseKey>>>,
    }

    impl EbpfObservationSource for RecordingObservationSource {
        fn next_observation(&mut self) -> Result<Option<EbpfProcessObservation>, CaptureError> {
            Ok(self.observations.pop_front())
        }

        fn allow_socket_payload_sample(
            &mut self,
            authorization: SocketPayloadSampleAuthorization,
        ) -> Result<(), CaptureError> {
            self.allowed.lock().expect("allowed lock poisoned").push(
                DescriptorLeaseKey::from_observed(
                    authorization.tgid(),
                    authorization.fd(),
                    authorization.fd_generation(),
                )
                .expect("authorization carries a valid descriptor lease"),
            );
            Ok(())
        }

        fn allow_process_payload_sample(
            &mut self,
            _authorization: ProcessPayloadSampleAuthorization,
        ) -> Result<(), CaptureError> {
            Ok(())
        }

        fn revoke_process_payload_sample(&mut self, _tgid: u32) -> Result<(), CaptureError> {
            Ok(())
        }

        fn revoke_socket_payload_sample(
            &mut self,
            key: DescriptorLeaseKey,
        ) -> Result<(), CaptureError> {
            self.revoked
                .lock()
                .expect("revoked lock poisoned")
                .push(key);
            Ok(())
        }
    }

    struct ProcessRecordingObservationSource {
        observations: VecDeque<EbpfProcessObservation>,
        allowed: Arc<Mutex<Vec<u32>>>,
        revoked: Arc<Mutex<Vec<u32>>>,
    }

    impl EbpfObservationSource for ProcessRecordingObservationSource {
        fn next_observation(&mut self) -> Result<Option<EbpfProcessObservation>, CaptureError> {
            Ok(self.observations.pop_front())
        }

        fn allow_socket_payload_sample(
            &mut self,
            _authorization: SocketPayloadSampleAuthorization,
        ) -> Result<(), CaptureError> {
            Ok(())
        }

        fn revoke_socket_payload_sample(
            &mut self,
            _key: DescriptorLeaseKey,
        ) -> Result<(), CaptureError> {
            Ok(())
        }

        fn allow_process_payload_sample(
            &mut self,
            authorization: ProcessPayloadSampleAuthorization,
        ) -> Result<(), CaptureError> {
            self.allowed
                .lock()
                .expect("allowed process lock poisoned")
                .push(authorization.tgid());
            Ok(())
        }

        fn revoke_process_payload_sample(&mut self, tgid: u32) -> Result<(), CaptureError> {
            self.revoked
                .lock()
                .expect("revoked process lock poisoned")
                .push(tgid);
            Ok(())
        }
    }

    #[test]
    fn emits_connection_opened_events() -> TestResult {
        let (local, remote) = outbound_loopback();
        let mut provider = provider_from_observations(
            [connect_observation(observed_process(101, 100), 7, remote)],
            local,
            remote,
        );

        let (timestamp, flow) = expect_connection_opened(&mut provider)?;
        assert_eq!(timestamp.monotonic_ns, 1);
        assert_eq!(flow.local.port, 50_000);
        assert_eq!(flow.remote.port, 443);
        assert_eq!(flow.attribution_confidence, 90);
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn emits_accepted_connection_opened_events() -> TestResult {
        let (local, remote) = inbound_loopback();
        let mut provider = provider_from_observations(
            [accept_observation(observed_process(101, 100), 9, 3, remote)],
            local,
            remote,
        );

        let (timestamp, flow) = expect_connection_opened(&mut provider)?;
        assert_eq!(timestamp.monotonic_ns, 1);
        assert_eq!(flow.local.port, 443);
        assert_eq!(flow.remote.port, 50_000);
        assert_eq!(flow.attribution_confidence, 90);
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn emits_inbound_read_bytes() -> TestResult {
        let (local, remote) = outbound_loopback();
        let process = observed_process(101, 100);
        let observations = [
            connect_observation(process.clone(), 7, remote),
            EbpfProcessObservation::Read(EbpfSocketReadObservation {
                process,
                fd: 7,
                fd_generation: 10,
                original_len: 5,
                buffer: b"HTTP/".to_vec(),
                truncated: false,
                read_failed: false,
            }),
        ];
        let selector = Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                remote_ports: vec![443],
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        )
        .compile()?;
        let mut provider = EbpfProcessObservationProvider::from_source_for_test(
            source_from_observations(observations),
            static_resolver(local, remote),
            Some(selector),
        );

        expect_connection_opened(&mut provider)?;
        let bytes = expect_bytes(&mut provider)?;

        assert_eq!(bytes.origin.source(), CaptureSource::EbpfSyscall);
        assert_eq!(bytes.origin.provider(), CaptureProviderKind::Ebpf);
        assert_eq!(bytes.direction, Direction::Inbound);
        assert_eq!(bytes.stream_offset, 0);
        assert_eq!(bytes.bytes.as_ref(), b"HTTP/");
        assert!(bytes.degraded);
        let degradation_reason = bytes
            .degradation_reason
            .as_deref()
            .expect("inbound eBPF bytes must include degradation reason");
        assert!(degradation_reason.contains("inbound syscall sample"));
        assert!(degradation_reason.contains("after the kernel returns"));
        assert!(degradation_reason.contains("best-effort"));
        Ok(())
    }

    #[test]
    fn emits_inbound_read_bytes_for_accepted_flow() -> TestResult {
        let (local, remote) = inbound_loopback();
        let process = observed_process(101, 100);
        let observations = [
            accept_observation(process.clone(), 9, 3, remote),
            EbpfProcessObservation::Read(EbpfSocketReadObservation {
                process,
                fd: 9,
                fd_generation: 10,
                original_len: 5,
                buffer: b"GET /".to_vec(),
                truncated: false,
                read_failed: false,
            }),
        ];
        let selector = Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                local_ports: vec![443],
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        )
        .compile()?;
        let mut provider = EbpfProcessObservationProvider::from_source_for_test(
            source_from_observations(observations),
            static_resolver(local, remote),
            Some(selector),
        );

        expect_connection_opened(&mut provider)?;
        let bytes = expect_bytes(&mut provider)?;

        assert_eq!(bytes.direction, Direction::Inbound);
        assert_eq!(bytes.flow.local.port, 443);
        assert_eq!(bytes.flow.remote.port, 50_000);
        assert_eq!(bytes.bytes.as_ref(), b"GET /");
        assert!(bytes.degraded);
        Ok(())
    }

    #[test]
    fn pending_flow_resolution_precedes_later_payload_observations() -> TestResult {
        let (local, remote) = inbound_loopback();
        let process = observed_process(101, 100);
        let observations = [
            missing_accept_observation(process.clone(), 9, 3),
            EbpfProcessObservation::Read(EbpfSocketReadObservation {
                process,
                fd: 9,
                fd_generation: 10,
                original_len: 5,
                buffer: b"GET /".to_vec(),
                truncated: false,
                read_failed: false,
            }),
        ];
        let selector = Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                local_ports: vec![443],
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        )
        .compile()?;
        let resolver = Box::new(RetryResolver {
            calls: 0,
            resolved: EbpfResolvedSocketFlow {
                process: demo_process(),
                confidence: 90,
                connection: TcpConnection::new(local, remote),
                socket_cookie: None,
            },
        });
        let mut provider = EbpfProcessObservationProvider::from_source_for_test(
            source_from_observations(observations),
            resolver,
            Some(selector),
        );
        provider.resolution_retries = 1;
        provider.resolution_retry_sleep = Duration::ZERO;

        let (_, opened) = expect_connection_opened(&mut provider)?;
        let bytes = expect_bytes(&mut provider)?;

        assert_eq!(opened.local.port, 443);
        assert_eq!(opened.remote.port, 50_000);
        assert_eq!(bytes.direction, Direction::Inbound);
        assert_eq!(bytes.flow.local.port, 443);
        assert_eq!(bytes.flow.remote.port, 50_000);
        assert_eq!(bytes.bytes.as_ref(), b"GET /");
        Ok(())
    }

    #[test]
    fn emits_connection_closed_events() -> TestResult {
        let (local, remote) = outbound_loopback();
        let process = observed_process(101, 100);
        let observations = [
            connect_observation(process.clone(), 7, remote),
            close_observation(process, 7),
        ];
        let mut provider = provider_from_observations(observations, local, remote);

        let (_, opened_flow) = expect_connection_opened(&mut provider)?;
        assert_eq!(opened_flow.local.port, 50_000);
        assert_eq!(opened_flow.remote.port, 443);

        let (timestamp, flow) = expect_connection_closed(&mut provider)?;
        assert_eq!(timestamp.monotonic_ns, 2);
        assert_eq!(flow.id, opened_flow.id);
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn closes_same_process_fd_from_sibling_thread() -> TestResult {
        let (local, remote) = outbound_loopback();
        let observations = [
            connect_observation(observed_process(101, 100), 7, remote),
            close_observation(observed_process(102, 100), 7),
        ];
        let mut provider = provider_from_observations(observations, local, remote);

        let (_, opened) = expect_connection_opened(&mut provider)?;
        let opened_flow_id = opened.id.clone();
        assert_eq!(opened.local.port, 50_000);
        let (_, flow) = expect_connection_closed(&mut provider)?;
        assert_eq!(flow.id, opened_flow_id);
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn closes_tracked_close_range() -> TestResult {
        let (local, remote) = outbound_loopback();
        let process = observed_process(101, 100);
        let observations = [
            connect_observation(process.clone(), 7, remote),
            connect_observation(process.clone(), 10, remote),
            close_range_observation(process, 7, 10),
        ];
        let mut provider = provider_from_observations(observations, local, remote);

        let (_, first_opened) = expect_connection_opened(&mut provider)?;
        let first_flow_id = first_opened.id.clone();
        let (_, second_opened) = expect_connection_opened(&mut provider)?;
        let second_flow_id = second_opened.id.clone();

        let (timestamp, flow) = expect_connection_closed(&mut provider)?;
        assert_eq!(timestamp.monotonic_ns, 3);
        assert_eq!(flow.id, first_flow_id);

        let (timestamp, flow) = expect_connection_closed(&mut provider)?;
        assert_eq!(timestamp.monotonic_ns, 3);
        assert_eq!(flow.id, second_flow_id);
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn emits_process_lifecycle_gaps_on_exit() -> TestResult {
        let (local, remote) = outbound_loopback();
        let process = observed_process(101, 100);
        let observations = [
            connect_observation(process.clone(), 7, remote),
            process_exit_observation(process),
        ];
        let selector = deep_observe_selector([443], [Direction::Inbound, Direction::Outbound])?;
        let mut provider = EbpfProcessObservationProvider::from_source_for_test(
            source_from_observations(observations),
            static_resolver(local, remote),
            Some(selector),
        );

        let (_, opened) = expect_connection_opened(&mut provider)?;
        let outbound = expect_gap(&mut provider)?;
        let inbound = expect_gap(&mut provider)?;
        let gaps = [outbound, inbound];

        assert!(gaps.iter().all(|gap| gap.timestamp.monotonic_ns == 2));
        assert!(gaps.iter().all(|gap| gap.flow.id == opened.id));
        assert!(gaps.iter().all(|gap| gap.gap.next_offset.is_none()));
        assert!(
            gaps.iter()
                .all(|gap| gap.gap.reason.contains("TGID leader exit"))
        );
        assert!(gaps.iter().all(|gap| gap.enforcement_evidence
            == probe_core::EnforcementEvidence::observation_only_with_detail(
                ObservationOnlyReason::EbpfProcessLifecycleBoundary,
                gap.gap.reason.clone()
            )));
        assert!(
            gaps.iter()
                .any(|gap| gap.gap.direction == Direction::Outbound)
        );
        assert!(
            gaps.iter()
                .any(|gap| gap.gap.direction == Direction::Inbound)
        );
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn emits_process_lifecycle_gap_on_exec() -> TestResult {
        let (local, remote) = outbound_loopback();
        let process = observed_process(101, 100);
        let observations = [
            connect_observation(process.clone(), 7, remote),
            process_exec_observation(process),
        ];
        let selector = deep_observe_selector([443], [Direction::Outbound])?;
        let mut provider = EbpfProcessObservationProvider::from_source_for_test(
            source_from_observations(observations),
            static_resolver(local, remote),
            Some(selector),
        );

        let (_, opened) = expect_connection_opened(&mut provider)?;
        let gap = expect_gap(&mut provider)?;

        assert_eq!(gap.timestamp.monotonic_ns, 2);
        assert_eq!(gap.flow.id, opened.id);
        assert_eq!(gap.gap.direction, Direction::Outbound);
        assert_eq!(gap.gap.expected_offset, 0);
        assert_eq!(gap.gap.next_offset, None);
        assert!(gap.gap.reason.contains("process exec"));
        assert_eq!(
            gap.enforcement_evidence,
            probe_core::EnforcementEvidence::observation_only_with_detail(
                ObservationOnlyReason::EbpfProcessLifecycleBoundary,
                gap.gap.reason.clone()
            )
        );
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn process_exec_authorizes_matching_process_payload() -> TestResult {
        let process = observed_process(101, 100);
        let allowed = Arc::new(Mutex::new(Vec::new()));
        let revoked = Arc::new(Mutex::new(Vec::new()));
        let source = ProcessRecordingObservationSource {
            observations: VecDeque::from([process_exec_observation(process)]),
            allowed: Arc::clone(&allowed),
            revoked: Arc::clone(&revoked),
        };
        let mut provider = EbpfProcessObservationProvider::from_source_for_test(
            source,
            Box::new(ProcessIdentityResolver {
                process: Some(demo_process()),
            }),
            Some(process_selector([100])?),
        );

        assert!(matches!(provider.poll_next()?, CapturePoll::Progress));
        assert_eq!(
            allowed
                .lock()
                .expect("allowed process lock poisoned")
                .as_slice(),
            &[100]
        );
        assert!(
            revoked
                .lock()
                .expect("revoked process lock poisoned")
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn flow_start_does_not_grant_process_payload_allowance_from_hint_candidate() -> TestResult {
        let (_, remote) = inbound_loopback();
        let process = observed_process_named(101, 4_271, "curl");
        let allowed = Arc::new(Mutex::new(Vec::new()));
        let revoked = Arc::new(Mutex::new(Vec::new()));
        let source = ProcessRecordingObservationSource {
            observations: VecDeque::from([accept_observation(process, 9, 3, remote)]),
            allowed: Arc::clone(&allowed),
            revoked: Arc::clone(&revoked),
        };
        let mut provider = EbpfProcessObservationProvider::from_source_for_test(
            source,
            Box::new(HintProcessResolver {
                direct_process: None,
                hinted_processes: vec![demo_process()],
            }),
            Some(process_selector([100])?),
        );

        let _ = provider.poll_next()?;

        assert!(
            allowed
                .lock()
                .expect("allowed process lock poisoned")
                .is_empty()
        );
        assert!(
            revoked
                .lock()
                .expect("revoked process lock poisoned")
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn observed_flow_start_prefers_unique_hint_candidate_over_colliding_direct_tgid() -> TestResult
    {
        let (_, remote) = inbound_loopback();
        let observed_tgid = 4_271;
        let process = observed_process_named(101, observed_tgid, "curl");
        let mut colliding = demo_process();
        colliding.identity.pid = observed_tgid;
        colliding.identity.tgid = observed_tgid;
        colliding.name = "unrelated".to_string();
        colliding.cmdline = vec!["unrelated".to_string()];
        let mut provider = EbpfProcessObservationProvider::from_source_for_test(
            source_from_observations([accept_observation(process, 9, 3, remote)]),
            Box::new(HintProcessResolver {
                direct_process: Some(colliding),
                hinted_processes: vec![demo_process()],
            }),
            None,
        );

        let (_, flow) = expect_connection_opened(&mut provider)?;

        assert_eq!(flow.process.identity.pid, 100);
        assert_eq!(flow.process.identity.tgid, 100);
        assert_eq!(flow.process.name, "curl");
        assert_eq!(flow.attribution_confidence, 0);
        Ok(())
    }

    #[test]
    fn process_exec_authorizes_observed_tgid_from_unique_hint_candidate() -> TestResult {
        let observed_tgid = 4_271;
        let process = observed_process_named(101, observed_tgid, "curl");
        let allowed = Arc::new(Mutex::new(Vec::new()));
        let revoked = Arc::new(Mutex::new(Vec::new()));
        let source = ProcessRecordingObservationSource {
            observations: VecDeque::from([process_exec_observation(process)]),
            allowed: Arc::clone(&allowed),
            revoked: Arc::clone(&revoked),
        };
        let mut provider = EbpfProcessObservationProvider::from_source_for_test(
            source,
            Box::new(HintProcessResolver {
                direct_process: None,
                hinted_processes: vec![demo_process()],
            }),
            Some(process_selector([100])?),
        );

        assert!(matches!(provider.poll_next()?, CapturePoll::Progress));

        assert_eq!(
            allowed
                .lock()
                .expect("allowed process lock poisoned")
                .as_slice(),
            &[observed_tgid]
        );
        assert!(
            revoked
                .lock()
                .expect("revoked process lock poisoned")
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn process_exec_skips_hint_authorization_when_candidates_are_ambiguous() -> TestResult {
        let process = observed_process_named(101, 4_271, "curl");
        let allowed = Arc::new(Mutex::new(Vec::new()));
        let revoked = Arc::new(Mutex::new(Vec::new()));
        let source = ProcessRecordingObservationSource {
            observations: VecDeque::from([process_exec_observation(process)]),
            allowed: Arc::clone(&allowed),
            revoked: Arc::clone(&revoked),
        };
        let mut other = demo_process();
        other.identity.pid = 101;
        other.identity.tgid = 101;
        let mut provider = EbpfProcessObservationProvider::from_source_for_test(
            source,
            Box::new(HintProcessResolver {
                direct_process: None,
                hinted_processes: vec![demo_process(), other],
            }),
            Some(process_selector([100, 101])?),
        );

        assert!(matches!(provider.poll_next()?, CapturePoll::Progress));

        assert!(
            allowed
                .lock()
                .expect("allowed process lock poisoned")
                .is_empty()
        );
        assert_eq!(
            revoked
                .lock()
                .expect("revoked process lock poisoned")
                .as_slice(),
            &[4_271]
        );
        Ok(())
    }

    #[test]
    fn process_exec_rejects_colliding_direct_tgid_without_unique_hint_candidate() -> TestResult {
        let observed_tgid = 4_271;
        let process = observed_process_named(101, observed_tgid, "curl");
        let allowed = Arc::new(Mutex::new(Vec::new()));
        let revoked = Arc::new(Mutex::new(Vec::new()));
        let source = ProcessRecordingObservationSource {
            observations: VecDeque::from([process_exec_observation(process)]),
            allowed: Arc::clone(&allowed),
            revoked: Arc::clone(&revoked),
        };
        let mut colliding = demo_process();
        colliding.identity.pid = observed_tgid;
        colliding.identity.tgid = observed_tgid;
        let mut provider = EbpfProcessObservationProvider::from_source_for_test(
            source,
            Box::new(HintProcessResolver {
                direct_process: Some(colliding),
                hinted_processes: Vec::new(),
            }),
            Some(process_selector([100])?),
        );

        assert!(matches!(provider.poll_next()?, CapturePoll::Progress));

        assert!(
            allowed
                .lock()
                .expect("allowed process lock poisoned")
                .is_empty()
        );
        assert_eq!(
            revoked
                .lock()
                .expect("revoked process lock poisoned")
                .as_slice(),
            &[observed_tgid]
        );
        Ok(())
    }

    #[test]
    fn process_exec_rejects_flow_dependent_process_payload_selector() -> TestResult {
        let process = observed_process(101, 100);
        let allowed = Arc::new(Mutex::new(Vec::new()));
        let revoked = Arc::new(Mutex::new(Vec::new()));
        let source = ProcessRecordingObservationSource {
            observations: VecDeque::from([process_exec_observation(process)]),
            allowed: Arc::clone(&allowed),
            revoked: Arc::clone(&revoked),
        };
        let mut provider = EbpfProcessObservationProvider::from_source_for_test(
            source,
            Box::new(ProcessIdentityResolver {
                process: Some(demo_process()),
            }),
            Some(process_remote_port_selector([100], [443])?),
        );

        assert!(matches!(provider.poll_next()?, CapturePoll::Progress));
        assert!(
            allowed
                .lock()
                .expect("allowed process lock poisoned")
                .is_empty()
        );
        assert_eq!(
            revoked
                .lock()
                .expect("revoked process lock poisoned")
                .as_slice(),
            &[100]
        );
        Ok(())
    }

    #[test]
    fn process_exec_revokes_payload_allowance_when_process_resolution_fails() -> TestResult {
        let process = observed_process(101, 100);
        let allowed = Arc::new(Mutex::new(Vec::new()));
        let revoked = Arc::new(Mutex::new(Vec::new()));
        let source = ProcessRecordingObservationSource {
            observations: VecDeque::from([process_exec_observation(process)]),
            allowed: Arc::clone(&allowed),
            revoked: Arc::clone(&revoked),
        };
        let mut provider = EbpfProcessObservationProvider::from_source_for_test(
            source,
            Box::new(FailingProcessIdentityResolver),
            Some(process_selector([100])?),
        );

        assert!(matches!(provider.poll_next()?, CapturePoll::Progress));
        assert!(
            allowed
                .lock()
                .expect("allowed process lock poisoned")
                .is_empty()
        );
        assert_eq!(
            revoked
                .lock()
                .expect("revoked process lock poisoned")
                .as_slice(),
            &[100]
        );
        Ok(())
    }

    #[test]
    fn process_exit_revokes_process_payload_allowance() -> TestResult {
        let process = observed_process(101, 100);
        let allowed = Arc::new(Mutex::new(Vec::new()));
        let revoked = Arc::new(Mutex::new(Vec::new()));
        let source = ProcessRecordingObservationSource {
            observations: VecDeque::from([process_exit_observation(process)]),
            allowed: Arc::clone(&allowed),
            revoked: Arc::clone(&revoked),
        };
        let mut provider = EbpfProcessObservationProvider::from_source_for_test(
            source,
            Box::new(ProcessIdentityResolver { process: None }),
            Some(process_selector([100])?),
        );

        assert!(matches!(provider.poll_next()?, CapturePoll::Progress));
        assert!(
            allowed
                .lock()
                .expect("allowed process lock poisoned")
                .is_empty()
        );
        assert_eq!(
            revoked
                .lock()
                .expect("revoked process lock poisoned")
                .as_slice(),
            &[100]
        );
        Ok(())
    }

    #[test]
    fn process_lifecycle_does_not_remove_tracked_flow() -> TestResult {
        let (local, remote) = outbound_loopback();
        let process = observed_process(101, 100);
        let observations = [
            connect_observation(process.clone(), 7, remote),
            process_exit_observation(process.clone()),
            close_observation(process, 7),
        ];
        let selector = deep_observe_selector([443], [Direction::Outbound])?;
        let mut provider = EbpfProcessObservationProvider::from_source_for_test(
            source_from_observations(observations),
            static_resolver(local, remote),
            Some(selector),
        );

        let (_, opened) = expect_connection_opened(&mut provider)?;
        let gap = expect_gap(&mut provider)?;
        assert_eq!(gap.flow.id, opened.id);

        let (timestamp, flow) = expect_connection_closed(&mut provider)?;
        assert_eq!(timestamp.monotonic_ns, 3);
        assert_eq!(flow.id, opened.id);
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn process_lifecycle_does_not_gap_or_close_other_tgid_flows() -> TestResult {
        let (local, remote) = outbound_loopback();
        let owner = observed_process(101, 100);
        let other = observed_process(201, 200);
        let observations = [
            connect_observation(owner.clone(), 7, remote),
            connect_observation(other.clone(), 8, remote),
            process_exit_observation(owner),
            close_observation(other, 8),
        ];
        let selector = deep_observe_selector([40_007, 40_008], [Direction::Outbound])?;
        let mut provider = EbpfProcessObservationProvider::from_source_for_test(
            source_from_observations(observations),
            fd_distinct_resolver(local),
            Some(selector),
        );

        let (_, first_opened) = expect_connection_opened(&mut provider)?;
        let first_flow_id = first_opened.id.clone();
        let (_, second_opened) = expect_connection_opened(&mut provider)?;
        let second_flow_id = second_opened.id.clone();

        let gap = expect_gap(&mut provider)?;
        assert_eq!(gap.flow.id, first_flow_id);

        let (_, closed) = expect_connection_closed(&mut provider)?;
        assert_eq!(closed.id, second_flow_id);
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn tracked_flow_capacity_eviction_emits_provider_state_boundary_gaps() -> TestResult {
        let (local, remote) = outbound_loopback();
        let process = observed_process(101, 100);
        let selector =
            deep_observe_selector([40_007, 40_008], [Direction::Inbound, Direction::Outbound])?;
        let observations = [
            connect_observation(process.clone(), 7, remote),
            EbpfProcessObservation::Write(EbpfSocketWriteObservation {
                process: process.clone(),
                fd: 7,
                fd_generation: 10,
                original_len: 5,
                buffer: b"GET /".to_vec(),
                truncated: false,
                read_failed: false,
                kernel_transfer: false,
            }),
            connect_observation(process.clone(), 8, remote),
            close_observation(process, 7),
        ];
        let mut provider = EbpfProcessObservationProvider::from_source_for_test(
            source_from_observations(observations),
            fd_distinct_resolver(local),
            Some(selector),
        )
        .with_max_tracked_flows_for_test(1);

        let (_, first_opened) = expect_connection_opened(&mut provider)?;
        let bytes = expect_bytes(&mut provider)?;
        assert_eq!(bytes.flow.id, first_opened.id);
        assert_eq!(bytes.stream_offset, 0);
        assert_eq!(bytes.bytes.as_ref(), b"GET /");

        let (second_timestamp, second_opened) = expect_connection_opened(&mut provider)?;
        assert_ne!(second_opened.id, first_opened.id);

        let first_gap = expect_gap(&mut provider)?;
        let second_gap = expect_gap(&mut provider)?;
        let gaps = [first_gap, second_gap];
        assert!(
            gaps.iter()
                .all(|gap| gap.timestamp == second_timestamp && gap.flow.id == first_opened.id)
        );
        assert!(gaps.iter().all(|gap| gap.gap.next_offset.is_none()));
        assert!(gaps.iter().all(|gap| {
            gap.gap
                .reason
                .contains("tracked-flow capacity was exceeded")
        }));
        assert!(gaps.iter().all(|gap| gap.enforcement_evidence
            == probe_core::EnforcementEvidence::observation_only_with_detail(
                ObservationOnlyReason::ProviderStateBoundary,
                gap.gap.reason.clone()
            )));
        assert!(gaps.iter().all(|gap| {
            gap.enforcement_evidence_propagation == EnforcementEvidencePropagation::Event
        }));
        assert!(gaps.iter().any(|gap| {
            gap.gap.direction == Direction::Outbound && gap.gap.expected_offset == 5
        }));
        assert!(
            gaps.iter()
                .any(|gap| gap.gap.direction == Direction::Inbound && gap.gap.expected_offset == 0)
        );
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn tracked_flow_capacity_eviction_revokes_displaced_payload_allowance() -> TestResult {
        let (local, remote) = outbound_loopback();
        let process = observed_process(101, 100);
        let selector =
            deep_observe_selector([40_007, 40_008], [Direction::Inbound, Direction::Outbound])?;
        let observations = [
            connect_observation(process.clone(), 7, remote),
            connect_observation(process, 8, remote),
        ];
        let allowed = Arc::new(Mutex::new(Vec::new()));
        let revoked = Arc::new(Mutex::new(Vec::new()));
        let source = RecordingObservationSource {
            observations: observations.into_iter().collect(),
            allowed: Arc::clone(&allowed),
            revoked: Arc::clone(&revoked),
        };
        let mut provider = EbpfProcessObservationProvider::from_source_for_test(
            source,
            fd_distinct_resolver(local),
            Some(selector),
        )
        .with_max_tracked_flows_for_test(1);

        expect_connection_opened(&mut provider)?;
        expect_connection_opened(&mut provider)?;

        let first_key =
            DescriptorLeaseKey::from_observed(100, 7, 10).expect("valid test descriptor key");
        let second_key =
            DescriptorLeaseKey::from_observed(100, 8, 10).expect("valid test descriptor key");
        assert_eq!(
            allowed.lock().expect("allowed lock poisoned").as_slice(),
            &[first_key, second_key]
        );
        assert_eq!(
            revoked.lock().expect("revoked lock poisoned").as_slice(),
            &[first_key]
        );
        Ok(())
    }

    #[test]
    fn same_fd_replacement_keeps_new_payload_allowance() -> TestResult {
        let (local, remote) = outbound_loopback();
        let process = observed_process(101, 100);
        let selector = deep_observe_selector([40_007], [Direction::Inbound, Direction::Outbound])?;
        let observations = [
            connect_observation_with_lease(process.clone(), 7, remote, 9, 10),
            connect_observation_with_lease(process, 7, remote, 9, 11),
        ];
        let allowed = Arc::new(Mutex::new(Vec::new()));
        let revoked = Arc::new(Mutex::new(Vec::new()));
        let source = RecordingObservationSource {
            observations: observations.into_iter().collect(),
            allowed: Arc::clone(&allowed),
            revoked: Arc::clone(&revoked),
        };
        let mut provider = EbpfProcessObservationProvider::from_source_for_test(
            source,
            fd_distinct_resolver(local),
            Some(selector),
        )
        .with_max_tracked_flows_for_test(1);

        expect_connection_opened(&mut provider)?;
        expect_connection_opened(&mut provider)?;

        let first_key =
            DescriptorLeaseKey::from_observed(100, 7, 10).expect("valid test descriptor key");
        let second_key =
            DescriptorLeaseKey::from_observed(100, 7, 11).expect("valid test descriptor key");
        assert_eq!(
            allowed.lock().expect("allowed lock poisoned").as_slice(),
            &[first_key, second_key]
        );
        assert!(revoked.lock().expect("revoked lock poisoned").is_empty());
        Ok(())
    }

    #[test]
    fn retained_same_fd_generation_prevents_stale_allowance_revoke() -> TestResult {
        let (local, remote) = outbound_loopback();
        let process = observed_process(101, 100);
        let selector = deep_observe_selector([40_007], [Direction::Inbound, Direction::Outbound])?;
        let observations = [
            connect_observation_with_lease(process.clone(), 7, remote, 9, 10),
            connect_observation_with_lease(process.clone(), 7, remote, 9, 11),
            connect_observation(process, 8, remote),
        ];
        let allowed = Arc::new(Mutex::new(Vec::new()));
        let revoked = Arc::new(Mutex::new(Vec::new()));
        let source = RecordingObservationSource {
            observations: observations.into_iter().collect(),
            allowed: Arc::clone(&allowed),
            revoked: Arc::clone(&revoked),
        };
        let mut provider = EbpfProcessObservationProvider::from_source_for_test(
            source,
            fd_distinct_resolver(local),
            Some(selector),
        )
        .with_max_tracked_flows_for_test(2);

        expect_connection_opened(&mut provider)?;
        expect_connection_opened(&mut provider)?;
        expect_connection_opened(&mut provider)?;

        let first_key =
            DescriptorLeaseKey::from_observed(100, 7, 10).expect("valid test descriptor key");
        let second_key =
            DescriptorLeaseKey::from_observed(100, 7, 11).expect("valid test descriptor key");
        assert_eq!(
            allowed.lock().expect("allowed lock poisoned").as_slice(),
            &[first_key, second_key]
        );
        assert!(revoked.lock().expect("revoked lock poisoned").is_empty());
        Ok(())
    }

    #[test]
    fn does_not_close_different_fd_from_same_process() -> TestResult {
        let (local, remote) = outbound_loopback();
        let process = observed_process(101, 100);
        let observations = [
            connect_observation(process.clone(), 7, remote),
            close_observation(process, 8),
        ];
        let mut provider = provider_from_observations(observations, local, remote);

        let (_, opened) = expect_connection_opened(&mut provider)?;
        assert_eq!(opened.local.port, 50_000);
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn does_not_track_when_payload_authorization_fails() -> TestResult {
        let (local, remote) = outbound_loopback();
        let process = observed_process(101, 100);
        let observations = [
            connect_observation(process.clone(), 7, remote),
            close_observation(process, 7),
        ];
        let source = FailingAllowObservationSource {
            observations: observations.into_iter().collect(),
        };
        let resolver = static_resolver(local, remote);
        let selector = Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                remote_ports: vec![443],
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
        )
        .compile()?;
        let mut provider =
            EbpfProcessObservationProvider::from_source_for_test(source, resolver, Some(selector));

        let error = provider
            .next()
            .expect_err("matching deep observation authorization should fail");
        assert!(error.to_string().contains("allow map unavailable"));
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn ignores_untracked_close_and_keeps_polling() -> TestResult {
        let (local, remote) = outbound_loopback();
        let observations = [
            close_observation(observed_process(101, 100), 7),
            connect_observation(observed_process(101, 100), 8, remote),
        ];
        let mut provider = provider_from_observations(observations, local, remote);

        let (timestamp, flow) = expect_connection_opened(&mut provider)?;
        assert_eq!(timestamp.monotonic_ns, 1);
        assert_eq!(flow.local.port, 50_000);
        assert_eq!(flow.remote.port, 443);
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn keeps_fd_reuse_as_distinct_connect_events() -> TestResult {
        let (local, remote) = outbound_loopback();
        let process = observed_process(101, 100);
        let observations = [
            connect_observation(process.clone(), 7, remote),
            close_observation(process.clone(), 7),
            connect_observation(process, 7, remote),
        ];
        let mut provider = provider_from_observations(observations, local, remote);

        let (timestamp, flow) = expect_connection_opened(&mut provider)?;
        let first_flow_id = flow.id.clone();
        assert_eq!(timestamp.monotonic_ns, 1);

        let (timestamp, flow) = expect_connection_closed(&mut provider)?;
        assert_eq!(timestamp.monotonic_ns, 2);
        assert_eq!(flow.id, first_flow_id);

        let (timestamp, flow) = expect_connection_opened(&mut provider)?;
        assert_eq!(timestamp.monotonic_ns, 3);
        assert_ne!(flow.id, first_flow_id);
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn emits_gap_for_unresolved_observations() -> TestResult {
        let observation = missing_connect_observation(observed_process(101, 100), 7);
        let resolver = Box::new(StaticResolver { resolved: None });
        let mut provider =
            EbpfProcessObservationProvider::from_observations_for_test([observation], resolver);

        let Some(CaptureEvent::Gap(gap)) = provider.next()? else {
            panic!("expected degraded gap event");
        };

        assert_eq!(gap.origin.source(), CaptureSource::EbpfSyscall);
        assert_eq!(gap.origin.provider(), CaptureProviderKind::Ebpf);
        assert_eq!(gap.gap.direction, Direction::Outbound);
        assert_eq!(gap.gap.expected_offset, 0);
        assert_eq!(gap.gap.next_offset, None);
        assert_eq!(gap.flow.process.identity.pid, 100);
        assert_eq!(gap.flow.attribution_confidence, 0);
        assert!(gap.gap.reason.contains("could not be resolved"));
        assert!(gap.gap.reason.contains("thread_pid=101"));
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn degraded_observed_flow_keeps_resolved_process_identity() -> TestResult {
        let (_, remote) = inbound_loopback();
        let observation = accept_observation(observed_process(101, 100), 9, 3, remote);
        let resolver = Box::new(ProcessOnlyResolver {
            process: demo_process(),
        });
        let mut provider =
            EbpfProcessObservationProvider::from_observations_for_test([observation], resolver);

        let (_, flow) = expect_connection_opened(&mut provider)?;

        assert_eq!(flow.attribution_confidence, 0);
        assert_eq!(flow.local.port, 0);
        assert_eq!(flow.remote.port, 50_000);
        assert_eq!(flow.process.identity.pid, 100);
        assert_eq!(flow.process.identity.exe_path, "/usr/bin/curl");
        let selector = Selector::term(
            ProcessSelector {
                exe_path_globs: vec!["/usr/bin/curl".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector {
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        )
        .compile()?;
        assert!(selector.matches_flow(&flow, Direction::Inbound));
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn flow_start_retries_procfs_before_observed_endpoint_fallback() -> TestResult {
        let (local, remote) = inbound_loopback();
        let observation = accept_observation(observed_process(101, 100), 9, 3, remote);
        let resolver = Box::new(RetryResolver {
            calls: 0,
            resolved: EbpfResolvedSocketFlow {
                process: demo_process(),
                confidence: 90,
                connection: TcpConnection::new(local, remote),
                socket_cookie: None,
            },
        });
        let mut provider =
            EbpfProcessObservationProvider::from_observations_for_test([observation], resolver);
        provider.resolution_retries = 1;
        provider.resolution_retry_sleep = Duration::ZERO;

        let (_, flow) = expect_connection_opened(&mut provider)?;

        assert_eq!(flow.attribution_confidence, 90);
        assert_eq!(flow.local.port, 443);
        assert_eq!(flow.remote.port, 50_000);
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn degraded_observed_flow_tracks_authorized_payload() -> TestResult {
        let (_, remote) = inbound_loopback();
        let process = observed_process(101, 100);
        let payload = b"HTTP/1.1 401 Unauthorized\r\ncontent-length: 0\r\n\r\n";
        let observations = [
            accept_observation(process.clone(), 9, 3, remote),
            EbpfProcessObservation::Write(EbpfSocketWriteObservation {
                process,
                fd: 9,
                fd_generation: 10,
                original_len: payload.len() as u32,
                buffer: payload.to_vec(),
                truncated: false,
                read_failed: false,
                kernel_transfer: false,
            }),
        ];
        let selector = Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
        )
        .compile()?;
        let mut provider = EbpfProcessObservationProvider::from_source_for_test(
            source_from_observations(observations),
            Box::new(StaticResolver { resolved: None }),
            Some(selector),
        );

        let (_, flow) = expect_connection_opened(&mut provider)?;
        let bytes = expect_bytes(&mut provider)?;

        assert_eq!(flow.attribution_confidence, 0);
        assert_eq!(bytes.flow.id, flow.id);
        assert_eq!(bytes.direction, Direction::Outbound);
        assert_eq!(bytes.bytes.as_ref(), payload);
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn emits_gap_instead_of_unclosable_flow_for_invalid_descriptor_lease() -> TestResult {
        let (_, remote) = outbound_loopback();
        let observation =
            connect_observation_with_lease(observed_process(101, 100), 7, remote, 9, 0);
        let mut provider = provider_from_observations(
            [
                observation,
                close_observation(observed_process(101, 100), 7),
            ],
            loopback_endpoint(50_000),
            remote,
        );

        let Some(CaptureEvent::Gap(gap)) = provider.next()? else {
            panic!("expected degraded gap event");
        };

        assert_eq!(gap.origin.source(), CaptureSource::EbpfSyscall);
        assert!(gap.gap.reason.contains("valid descriptor lease"));
        assert!(gap.gap.reason.contains("fd_generation=0"));
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn retries_fd_resolution() -> TestResult {
        let (local, remote) = outbound_loopback();
        let observation = missing_connect_observation(observed_process(101, 100), 7);
        let resolver = Box::new(RetryResolver {
            calls: 0,
            resolved: EbpfResolvedSocketFlow {
                process: demo_process(),
                confidence: 90,
                connection: TcpConnection::new(local, remote),
                socket_cookie: None,
            },
        });
        let mut provider =
            EbpfProcessObservationProvider::from_observations_for_test([observation], resolver);
        provider.resolution_retries = 1;

        let (_, flow) = expect_connection_opened(&mut provider)?;
        assert_eq!(flow.local.port, 50_000);
        Ok(())
    }

    #[test]
    fn process_lifecycle_waits_for_pending_flow_resolution() -> TestResult {
        let (local, remote) = outbound_loopback();
        let process = observed_process(101, 100);
        let observations = [
            missing_connect_observation(process.clone(), 7),
            process_exec_observation(process),
        ];
        let resolver = Box::new(RetryResolver {
            calls: 0,
            resolved: EbpfResolvedSocketFlow {
                process: demo_process(),
                confidence: 90,
                connection: TcpConnection::new(local, remote),
                socket_cookie: None,
            },
        });
        let mut provider =
            EbpfProcessObservationProvider::from_observations_for_test(observations, resolver);
        provider.resolution_retries = 1;
        provider.resolution_retry_sleep = Duration::ZERO;

        let (_, flow) = expect_connection_opened(&mut provider)?;

        assert_eq!(flow.local.port, 50_000);
        assert_eq!(flow.remote.port, 443);
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn unresolved_flow_resolution_emits_gap_before_later_flow_start() -> TestResult {
        let (local, remote) = outbound_loopback();
        let process = observed_process(101, 100);
        let observations = [
            missing_connect_observation(process.clone(), 7),
            connect_observation(process, 8, remote),
        ];
        let resolver = Box::new(FdSelectiveResolver {
            unresolved_fd: 7,
            resolved: EbpfResolvedSocketFlow {
                process: demo_process(),
                confidence: 90,
                connection: TcpConnection::new(local, remote),
                socket_cookie: None,
            },
        });
        let mut provider =
            EbpfProcessObservationProvider::from_observations_for_test(observations, resolver);
        provider.resolution_retries = 1;

        let Some(CaptureEvent::Gap(gap)) = provider.next()? else {
            panic!("expected unresolved flow gap before later flow start");
        };
        assert!(gap.gap.reason.contains("fd=7"));

        let (_, flow) = expect_connection_opened(&mut provider)?;
        assert_eq!(flow.local.port, 50_000);
        assert_eq!(flow.remote.port, 443);
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn full_pending_flow_resolution_queue_emits_gap() -> TestResult {
        let (_, remote) = outbound_loopback();
        let process = observed_process(101, 100);
        let mut provider = EbpfProcessObservationProvider::from_observations_for_test(
            [],
            Box::new(StaticResolver { resolved: None }),
        );
        provider.resolution_retries = 1;
        for fd in 0..MAX_PENDING_EBPF_FLOW_RESOLUTIONS {
            provider.pending_flows.push_back(pending_connect_resolution(
                process.clone(),
                1000 + fd as i32,
                remote,
            ));
        }

        let CapturePoll::Event(event) = provider
            .queue_pending_flow_resolution(pending_missing_connect_resolution(process.clone(), 7))
        else {
            panic!("expected degraded gap when pending flow queue is full");
        };
        let CaptureEvent::Gap(gap) = *event else {
            panic!("expected degraded gap when pending flow queue is full");
        };
        assert!(
            gap.gap
                .reason
                .contains("pending flow resolution queue is full")
        );
        assert!(gap.gap.reason.contains("fd=7"));
        Ok(())
    }

    #[test]
    fn emits_output_loss_delta_through_poll() -> TestResult {
        let source = OutputLossObservationSource {
            observations: VecDeque::new(),
            counts: VecDeque::from([2, 2, 5]),
        };
        let resolver = Box::new(StaticResolver { resolved: None });
        let mut provider =
            EbpfProcessObservationProvider::from_source_for_test(source, resolver, None);
        provider.stop_when_idle = false;

        let first = expect_output_loss(provider.poll_next()?);
        assert_eq!(first.origin.source(), CaptureSource::EbpfSyscall);
        assert_eq!(first.origin.provider(), CaptureProviderKind::Ebpf);
        assert_eq!(first.loss.lost_events, 2);
        assert!(
            first
                .loss
                .reason
                .contains("output ring buffer could not accept 2 event(s)")
        );

        assert!(matches!(provider.poll_next()?, CapturePoll::Idle));
        let second = expect_output_loss(provider.poll_next()?);
        assert_eq!(second.loss.lost_events, 3);
        assert!(matches!(provider.poll_next()?, CapturePoll::Idle));
        Ok(())
    }

    #[test]
    fn runtime_diagnostics_reads_tracepoint_firing_counts() {
        let source = TracepointFiringObservationSource {
            firings: vec![
                EbpfProcessObservationTracepointFiring {
                    program_name: "connect_enter",
                    category: "syscalls",
                    tracepoint_name: "sys_enter_connect",
                    firing_count: 2,
                },
                EbpfProcessObservationTracepointFiring {
                    program_name: "connect_exit",
                    category: "syscalls",
                    tracepoint_name: "sys_exit_connect",
                    firing_count: 1,
                },
            ],
        };
        let resolver = Box::new(StaticResolver { resolved: None });
        let mut provider =
            EbpfProcessObservationProvider::from_source_for_test(source, resolver, None)
                .with_runtime_diagnostics_refresh_interval_for_test(Duration::ZERO);

        let diagnostics = provider
            .runtime_diagnostics()
            .into_ebpf_process_observation()
            .expect("expected eBPF process observation diagnostics");

        let tracepoints = diagnostics
            .tracepoints
            .expect("tracepoint diagnostics should be available");
        let firings = tracepoints.firings;
        assert_eq!(firings.len(), 2);
        assert_eq!(firings[0].program_name, "connect_enter");
        assert_eq!(firings[0].category, "syscalls");
        assert_eq!(firings[0].tracepoint_name, "sys_enter_connect");
        assert_eq!(firings[0].firing_count, 2);
        assert_eq!(firings[1].program_name, "connect_exit");
        assert_eq!(firings[1].category, "syscalls");
        assert_eq!(firings[1].tracepoint_name, "sys_exit_connect");
        assert_eq!(firings[1].firing_count, 1);
    }

    #[test]
    fn runtime_diagnostics_reports_active_tracepoint_liveness() {
        let source = QueuedTracepointFiringObservationSource {
            firings: VecDeque::from([
                vec![tracepoint_firing(EbpfProcessTracepointRole::WriteEnter, 10)],
                vec![tracepoint_firing(EbpfProcessTracepointRole::WriteEnter, 11)],
            ]),
        };
        let resolver = Box::new(StaticResolver { resolved: None });
        let mut provider =
            EbpfProcessObservationProvider::from_source_for_test(source, resolver, None)
                .with_runtime_diagnostics_refresh_interval_for_test(Duration::ZERO);

        let diagnostics = provider
            .runtime_diagnostics()
            .into_ebpf_process_observation()
            .expect("expected eBPF process observation diagnostics");

        let tracepoints = diagnostics
            .tracepoints
            .expect("tracepoint diagnostics should be available");
        let firings = &tracepoints.firings;
        assert_eq!(
            firings[0].program_name,
            EbpfProcessTracepointRole::WriteEnter.spec().program_name
        );
        assert_eq!(firings[0].firing_count, 11);

        let liveness = tracepoints
            .active_liveness
            .expect("active tracepoint liveness should be available");
        let write_enter = active_liveness_program(&liveness, EbpfProcessTracepointRole::WriteEnter);
        assert_eq!(
            write_enter.state,
            EbpfProcessObservationActiveTracepointLivenessState::Advanced
        );
        assert_eq!(write_enter.before_firing_count, 10);
        assert_eq!(write_enter.after_firing_count, 11);

        let connect_enter =
            active_liveness_program(&liveness, EbpfProcessTracepointRole::ConnectEnter);
        assert_eq!(
            connect_enter.state,
            EbpfProcessObservationActiveTracepointLivenessState::Unsupported
        );
    }

    #[test]
    fn output_loss_fans_out_unknown_gaps_to_active_payload_flows() -> TestResult {
        let (local, remote) = outbound_loopback();
        let process = observed_process(101, 100);
        let source = OutputLossObservationSource {
            observations: VecDeque::from([connect_observation(process, 7, remote)]),
            counts: VecDeque::from([2, 2]),
        };
        let selector = Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                remote_ports: vec![443],
                directions: vec![Direction::Inbound, Direction::Outbound],
                ..TrafficSelector::default()
            },
        )
        .compile()?;
        let mut provider = EbpfProcessObservationProvider::from_source_for_test(
            source,
            static_resolver(local, remote),
            Some(selector),
        );

        let (_, opened_flow) = expect_connection_opened(&mut provider)?;
        let loss = expect_output_loss(provider.poll_next()?);
        assert_eq!(loss.loss.lost_events, 2);

        let first_gap = expect_gap_event(provider.poll_next()?);
        let second_gap = expect_gap_event(provider.poll_next()?);
        let gaps = [first_gap, second_gap];

        assert!(gaps.iter().all(|gap| gap.flow.id == opened_flow.id));
        assert!(gaps.iter().all(|gap| gap.gap.next_offset.is_none()));
        assert!(
            gaps.iter()
                .all(|gap| gap.gap.reason.contains("affected flow, time, bytes"))
        );
        assert!(
            gaps.iter()
                .any(|gap| gap.gap.direction == Direction::Inbound)
        );
        assert!(
            gaps.iter()
                .any(|gap| gap.gap.direction == Direction::Outbound)
        );
        Ok(())
    }

    #[test]
    fn interleaves_output_loss_during_observation_drain() -> TestResult {
        let process = observed_process(101, 100);
        let source = OutputLossObservationSource {
            observations: VecDeque::from([
                EbpfProcessObservation::Close(EbpfCloseTracepointObservation {
                    process: process.clone(),
                    fd: 70,
                    fd_generation: 10,
                }),
                EbpfProcessObservation::Close(EbpfCloseTracepointObservation {
                    process: process.clone(),
                    fd: 71,
                    fd_generation: 10,
                }),
                EbpfProcessObservation::Close(EbpfCloseTracepointObservation {
                    process,
                    fd: 72,
                    fd_generation: 10,
                }),
            ]),
            counts: VecDeque::from([4]),
        };
        let resolver = Box::new(StaticResolver { resolved: None });
        let mut provider =
            EbpfProcessObservationProvider::from_source_for_test(source, resolver, None)
                .with_output_loss_check_interval_for_test(2);

        assert!(matches!(provider.poll_next()?, CapturePoll::Progress));
        assert!(matches!(provider.poll_next()?, CapturePoll::Progress));
        let loss = expect_output_loss(provider.poll_next()?);
        assert_eq!(loss.loss.lost_events, 4);
        assert!(matches!(provider.poll_next()?, CapturePoll::Progress));
        Ok(())
    }

    #[test]
    fn handoff_drain_emits_pending_payload_events_without_polling_new_observations() -> TestResult {
        let (local, remote) = outbound_loopback();
        let process = observed_process(101, 100);
        let observations = [
            connect_observation(process.clone(), 7, remote),
            EbpfProcessObservation::Read(EbpfSocketReadObservation {
                process: process.clone(),
                fd: 7,
                fd_generation: 10,
                original_len: 9,
                buffer: b"HTTP/".to_vec(),
                truncated: true,
                read_failed: false,
            }),
            connect_observation(process, 8, remote),
        ];
        let selector = Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                remote_ports: vec![443],
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        )
        .compile()?;
        let mut provider = EbpfProcessObservationProvider::from_source_for_test(
            source_from_observations(observations),
            static_resolver(local, remote),
            Some(selector),
        );

        expect_connection_opened(&mut provider)?;
        let bytes = expect_bytes(&mut provider)?;
        assert_eq!(bytes.bytes.as_ref(), b"HTTP/");

        let gap = expect_gap_event(provider.drain_before_handoff()?);
        assert_eq!(gap.gap.direction, Direction::Inbound);
        assert_eq!(gap.gap.expected_offset, 5);
        assert_eq!(gap.gap.next_offset, Some(9));
        assert!(gap.gap.reason.contains("truncated payload"));
        let gap = expect_gap_event(provider.drain_before_handoff()?);
        assert_eq!(gap.gap.direction, Direction::Inbound);
        assert_eq!(gap.gap.expected_offset, 9);
        assert!(gap.gap.reason.contains("runtime generation handoff"));
        assert!(matches!(
            provider.drain_before_handoff()?,
            CapturePoll::Idle
        ));

        let (timestamp, _) = expect_connection_opened(&mut provider)?;
        assert_eq!(timestamp.monotonic_ns, 4);
        Ok(())
    }

    #[test]
    fn handoff_drain_retries_pending_flow_resolution_until_safe_point() -> TestResult {
        let (local, remote) = outbound_loopback();
        let process = observed_process(101, 100);
        let resolver = Box::new(RetryResolver {
            calls: 0,
            resolved: EbpfResolvedSocketFlow {
                process: demo_process(),
                confidence: 90,
                connection: TcpConnection::new(local, remote),
                socket_cookie: None,
            },
        });
        let mut provider = EbpfProcessObservationProvider::from_observations_for_test([], resolver);
        provider.resolution_retries = 1;
        provider.resolution_retry_sleep = Duration::from_secs(60);
        provider
            .pending_flows
            .push_back(pending_missing_connect_resolution(process, 7));

        assert!(matches!(
            provider.drain_before_handoff()?,
            CapturePoll::Progress
        ));
        assert_eq!(provider.pending_flows.len(), 1);

        let CapturePoll::Event(event) = provider.drain_before_handoff()? else {
            panic!("expected pending flow resolution event before handoff safe point");
        };
        let CaptureEvent::ConnectionOpened { flow, .. } = *event else {
            panic!("expected connection opened event, got {event:?}");
        };
        assert_eq!(flow.local.port, 50_000);
        assert_eq!(flow.remote.port, 443);
        assert!(matches!(
            provider.drain_before_handoff()?,
            CapturePoll::Idle
        ));
        Ok(())
    }

    #[test]
    fn handoff_drain_does_not_consume_live_observations() -> TestResult {
        let (local, remote) = outbound_loopback();
        let process = observed_process(101, 100);
        let mut provider =
            provider_from_observations([connect_observation(process, 7, remote)], local, remote);

        assert!(matches!(
            provider.drain_before_handoff()?,
            CapturePoll::Idle
        ));
        let (timestamp, flow) = expect_connection_opened(&mut provider)?;
        assert_eq!(timestamp.monotonic_ns, 1);
        assert_eq!(flow.remote.port, 443);
        Ok(())
    }

    #[test]
    fn handoff_drain_emits_boundary_gap_without_discarding_tracked_flow() -> TestResult {
        let (local, remote) = outbound_loopback();
        let process = observed_process(101, 100);
        let payload = b"GET /".to_vec();
        let observations = [
            connect_observation(process.clone(), 7, remote),
            EbpfProcessObservation::Write(EbpfSocketWriteObservation {
                process,
                fd: 7,
                fd_generation: 10,
                original_len: payload.len() as u32,
                buffer: payload.clone(),
                truncated: false,
                read_failed: false,
                kernel_transfer: false,
            }),
        ];
        let selector = Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                remote_ports: vec![443],
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
        )
        .compile()?;
        let mut provider = EbpfProcessObservationProvider::from_source_for_test(
            source_from_observations(observations),
            static_resolver(local, remote),
            Some(selector),
        );

        expect_connection_opened(&mut provider)?;
        let gap = expect_gap_event(provider.drain_before_handoff()?);
        assert_eq!(gap.gap.direction, Direction::Outbound);
        assert_eq!(gap.gap.expected_offset, 0);
        assert!(gap.gap.next_offset.is_none());
        assert!(gap.gap.reason.contains("runtime generation handoff"));
        assert!(matches!(
            provider.drain_before_handoff()?,
            CapturePoll::Idle
        ));

        let bytes = expect_bytes(&mut provider)?;
        assert_eq!(bytes.bytes.as_ref(), payload.as_slice());

        let gap = expect_gap_event(provider.drain_before_handoff()?);
        assert_eq!(gap.gap.expected_offset, payload.len() as u64);
        assert!(matches!(
            provider.drain_before_handoff()?,
            CapturePoll::Idle
        ));
        Ok(())
    }

    struct StaticResolver {
        resolved: Option<EbpfResolvedSocketFlow>,
    }

    impl EbpfSocketFlowResolver for StaticResolver {
        fn resolve_socket_flow(
            &mut self,
            _lookup: EbpfSocketFlowLookup,
        ) -> Result<Option<EbpfResolvedSocketFlow>, CaptureError> {
            Ok(self.resolved.clone())
        }
    }

    struct ProcessIdentityResolver {
        process: Option<ProcessContext>,
    }

    impl EbpfSocketFlowResolver for ProcessIdentityResolver {
        fn resolve_socket_flow(
            &mut self,
            _lookup: EbpfSocketFlowLookup,
        ) -> Result<Option<EbpfResolvedSocketFlow>, CaptureError> {
            Ok(None)
        }

        fn resolve_process(&mut self, _tgid: u32) -> Result<Option<ProcessContext>, CaptureError> {
            Ok(self.process.clone())
        }
    }

    struct ProcessOnlyResolver {
        process: ProcessContext,
    }

    impl EbpfSocketFlowResolver for ProcessOnlyResolver {
        fn resolve_socket_flow(
            &mut self,
            _lookup: EbpfSocketFlowLookup,
        ) -> Result<Option<EbpfResolvedSocketFlow>, CaptureError> {
            Ok(None)
        }

        fn resolve_process(&mut self, _tgid: u32) -> Result<Option<ProcessContext>, CaptureError> {
            Ok(Some(self.process.clone()))
        }
    }

    struct HintProcessResolver {
        direct_process: Option<ProcessContext>,
        hinted_processes: Vec<ProcessContext>,
    }

    impl EbpfSocketFlowResolver for HintProcessResolver {
        fn resolve_socket_flow(
            &mut self,
            _lookup: EbpfSocketFlowLookup,
        ) -> Result<Option<EbpfResolvedSocketFlow>, CaptureError> {
            Ok(None)
        }

        fn resolve_process(&mut self, _tgid: u32) -> Result<Option<ProcessContext>, CaptureError> {
            Ok(self.direct_process.clone())
        }

        fn resolve_processes_by_hint(
            &mut self,
            hint: EbpfProcessHint,
        ) -> Result<Vec<ProcessContext>, CaptureError> {
            Ok(self
                .hinted_processes
                .iter()
                .filter(|process| {
                    process.name == hint.name
                        && process.identity.uid == hint.uid
                        && process.identity.gid == hint.gid
                })
                .cloned()
                .collect())
        }
    }

    struct FailingProcessIdentityResolver;

    impl EbpfSocketFlowResolver for FailingProcessIdentityResolver {
        fn resolve_socket_flow(
            &mut self,
            _lookup: EbpfSocketFlowLookup,
        ) -> Result<Option<EbpfResolvedSocketFlow>, CaptureError> {
            Ok(None)
        }

        fn resolve_process(&mut self, _tgid: u32) -> Result<Option<ProcessContext>, CaptureError> {
            Err(CaptureError::provider(
                "procfs",
                "process table unavailable",
            ))
        }
    }

    struct FdDistinctResolver {
        local: TcpEndpoint,
    }

    impl EbpfSocketFlowResolver for FdDistinctResolver {
        fn resolve_socket_flow(
            &mut self,
            lookup: EbpfSocketFlowLookup,
        ) -> Result<Option<EbpfResolvedSocketFlow>, CaptureError> {
            let Ok(fd) = u16::try_from(lookup.fd) else {
                return Ok(None);
            };
            Ok(Some(EbpfResolvedSocketFlow {
                process: demo_process(),
                confidence: 90,
                connection: TcpConnection::new(
                    self.local,
                    loopback_endpoint(40_000_u16.saturating_add(fd)),
                ),
                socket_cookie: Some(u64::from(fd)),
            }))
        }
    }

    struct RetryResolver {
        calls: u32,
        resolved: EbpfResolvedSocketFlow,
    }

    impl EbpfSocketFlowResolver for RetryResolver {
        fn resolve_socket_flow(
            &mut self,
            _lookup: EbpfSocketFlowLookup,
        ) -> Result<Option<EbpfResolvedSocketFlow>, CaptureError> {
            self.calls = self.calls.saturating_add(1);
            if self.calls == 1 {
                return Ok(None);
            }
            Ok(Some(self.resolved.clone()))
        }
    }

    struct FdSelectiveResolver {
        unresolved_fd: i32,
        resolved: EbpfResolvedSocketFlow,
    }

    impl EbpfSocketFlowResolver for FdSelectiveResolver {
        fn resolve_socket_flow(
            &mut self,
            lookup: EbpfSocketFlowLookup,
        ) -> Result<Option<EbpfResolvedSocketFlow>, CaptureError> {
            if lookup.fd == self.unresolved_fd {
                return Ok(None);
            }
            Ok(Some(self.resolved.clone()))
        }
    }

    struct FailingAllowObservationSource {
        observations: VecDeque<EbpfProcessObservation>,
    }

    impl EbpfObservationSource for FailingAllowObservationSource {
        fn next_observation(&mut self) -> Result<Option<EbpfProcessObservation>, CaptureError> {
            Ok(self.observations.pop_front())
        }

        fn allow_socket_payload_sample(
            &mut self,
            _authorization: SocketPayloadSampleAuthorization,
        ) -> Result<(), CaptureError> {
            Err(CaptureError::provider("ebpf", "allow map unavailable"))
        }

        fn allow_process_payload_sample(
            &mut self,
            _authorization: ProcessPayloadSampleAuthorization,
        ) -> Result<(), CaptureError> {
            Ok(())
        }

        fn revoke_process_payload_sample(&mut self, _tgid: u32) -> Result<(), CaptureError> {
            Ok(())
        }
    }

    struct OutputLossObservationSource {
        observations: VecDeque<EbpfProcessObservation>,
        counts: VecDeque<u64>,
    }

    impl EbpfObservationSource for OutputLossObservationSource {
        fn next_observation(&mut self) -> Result<Option<EbpfProcessObservation>, CaptureError> {
            Ok(self.observations.pop_front())
        }

        fn allow_socket_payload_sample(
            &mut self,
            _authorization: SocketPayloadSampleAuthorization,
        ) -> Result<(), CaptureError> {
            Ok(())
        }

        fn allow_process_payload_sample(
            &mut self,
            _authorization: ProcessPayloadSampleAuthorization,
        ) -> Result<(), CaptureError> {
            Ok(())
        }

        fn revoke_process_payload_sample(&mut self, _tgid: u32) -> Result<(), CaptureError> {
            Ok(())
        }

        fn process_output_loss_count(&mut self) -> Result<u64, CaptureError> {
            Ok(self.counts.pop_front().unwrap_or(5))
        }
    }

    struct TracepointFiringObservationSource {
        firings: Vec<EbpfProcessObservationTracepointFiring>,
    }

    impl EbpfObservationSource for TracepointFiringObservationSource {
        fn next_observation(&mut self) -> Result<Option<EbpfProcessObservation>, CaptureError> {
            Ok(None)
        }

        fn allow_socket_payload_sample(
            &mut self,
            _authorization: SocketPayloadSampleAuthorization,
        ) -> Result<(), CaptureError> {
            Ok(())
        }

        fn allow_process_payload_sample(
            &mut self,
            _authorization: ProcessPayloadSampleAuthorization,
        ) -> Result<(), CaptureError> {
            Ok(())
        }

        fn revoke_process_payload_sample(&mut self, _tgid: u32) -> Result<(), CaptureError> {
            Ok(())
        }

        fn process_tracepoint_firings(
            &mut self,
        ) -> Result<Option<Vec<EbpfProcessObservationTracepointFiring>>, CaptureError> {
            Ok(Some(self.firings.clone()))
        }
    }

    struct QueuedTracepointFiringObservationSource {
        firings: VecDeque<Vec<EbpfProcessObservationTracepointFiring>>,
    }

    impl EbpfObservationSource for QueuedTracepointFiringObservationSource {
        fn next_observation(&mut self) -> Result<Option<EbpfProcessObservation>, CaptureError> {
            Ok(None)
        }

        fn allow_socket_payload_sample(
            &mut self,
            _authorization: SocketPayloadSampleAuthorization,
        ) -> Result<(), CaptureError> {
            Ok(())
        }

        fn allow_process_payload_sample(
            &mut self,
            _authorization: ProcessPayloadSampleAuthorization,
        ) -> Result<(), CaptureError> {
            Ok(())
        }

        fn revoke_process_payload_sample(&mut self, _tgid: u32) -> Result<(), CaptureError> {
            Ok(())
        }

        fn process_tracepoint_firings(
            &mut self,
        ) -> Result<Option<Vec<EbpfProcessObservationTracepointFiring>>, CaptureError> {
            Ok(Some(self.firings.pop_front().unwrap_or_default()))
        }
    }

    fn active_liveness_program(
        liveness: &EbpfProcessObservationActiveTracepointLiveness,
        role: EbpfProcessTracepointRole,
    ) -> &EbpfProcessObservationActiveTracepointLivenessProgram {
        let spec = role.spec();
        liveness
            .programs
            .iter()
            .find(|program| {
                program.program_name == spec.program_name
                    && program.category == spec.category
                    && program.tracepoint_name == spec.tracepoint_name
            })
            .expect("role should have active liveness diagnostics")
    }

    fn tracepoint_firing(
        role: EbpfProcessTracepointRole,
        firing_count: u64,
    ) -> EbpfProcessObservationTracepointFiring {
        let spec = role.spec();
        EbpfProcessObservationTracepointFiring {
            program_name: spec.program_name,
            category: spec.category,
            tracepoint_name: spec.tracepoint_name,
            firing_count,
        }
    }

    fn expect_output_loss(poll: CapturePoll) -> crate::CapturedLoss {
        let CapturePoll::Event(event) = poll else {
            panic!("expected output loss event, got {poll:?}");
        };
        let CaptureEvent::Loss(loss) = *event else {
            panic!("expected output loss event, got {event:?}");
        };
        loss
    }

    fn expect_gap_event(poll: CapturePoll) -> crate::CapturedGap {
        let CapturePoll::Event(event) = poll else {
            panic!("expected gap event, got {poll:?}");
        };
        let CaptureEvent::Gap(gap) = *event else {
            panic!("expected gap event, got {event:?}");
        };
        gap
    }

    fn provider_from_observations(
        observations: impl IntoIterator<Item = EbpfProcessObservation> + 'static,
        local: TcpEndpoint,
        remote: TcpEndpoint,
    ) -> EbpfProcessObservationProvider {
        EbpfProcessObservationProvider::from_observations_for_test(
            observations,
            static_resolver(local, remote),
        )
    }

    fn source_from_observations(
        observations: impl IntoIterator<Item = EbpfProcessObservation>,
    ) -> VecObservationSource {
        VecObservationSource {
            observations: observations.into_iter().collect(),
        }
    }

    fn outbound_loopback() -> (TcpEndpoint, TcpEndpoint) {
        (loopback_endpoint(50_000), loopback_endpoint(443))
    }

    fn inbound_loopback() -> (TcpEndpoint, TcpEndpoint) {
        (loopback_endpoint(443), loopback_endpoint(50_000))
    }

    fn loopback_endpoint(port: u16) -> TcpEndpoint {
        TcpEndpoint::new(Ipv4Addr::LOCALHOST.into(), port)
    }

    fn expect_connection_opened(
        provider: &mut EbpfProcessObservationProvider,
    ) -> Result<(Timestamp, FlowContext), CaptureError> {
        match provider.next()? {
            Some(CaptureEvent::ConnectionOpened {
                timestamp,
                flow,
                origin,
            }) => {
                assert_eq!(
                    (origin.source(), origin.provider()),
                    (CaptureSource::EbpfSyscall, CaptureProviderKind::Ebpf)
                );
                Ok((timestamp, flow))
            }
            event => panic!("expected connection opened event, got {event:?}"),
        }
    }

    fn expect_connection_closed(
        provider: &mut EbpfProcessObservationProvider,
    ) -> Result<(Timestamp, FlowContext), CaptureError> {
        match provider.next()? {
            Some(CaptureEvent::ConnectionClosed {
                timestamp,
                flow,
                origin,
            }) => {
                assert_eq!(
                    (origin.source(), origin.provider()),
                    (CaptureSource::EbpfSyscall, CaptureProviderKind::Ebpf)
                );
                Ok((timestamp, flow))
            }
            event => panic!("expected connection closed event, got {event:?}"),
        }
    }

    fn expect_bytes(
        provider: &mut EbpfProcessObservationProvider,
    ) -> Result<crate::CapturedBytes, CaptureError> {
        match provider.next()? {
            Some(CaptureEvent::Bytes(bytes)) => Ok(bytes),
            event => panic!("expected bytes event, got {event:?}"),
        }
    }

    fn expect_gap(
        provider: &mut EbpfProcessObservationProvider,
    ) -> Result<crate::CapturedGap, CaptureError> {
        match provider.next()? {
            Some(CaptureEvent::Gap(gap)) => Ok(gap),
            event => panic!("expected gap event, got {event:?}"),
        }
    }

    fn static_resolver(local: TcpEndpoint, remote: TcpEndpoint) -> Box<StaticResolver> {
        Box::new(StaticResolver {
            resolved: Some(EbpfResolvedSocketFlow {
                process: demo_process(),
                confidence: 90,
                connection: TcpConnection::new(local, remote),
                socket_cookie: None,
            }),
        })
    }

    fn fd_distinct_resolver(local: TcpEndpoint) -> Box<FdDistinctResolver> {
        Box::new(FdDistinctResolver { local })
    }

    fn deep_observe_selector(
        remote_ports: impl IntoIterator<Item = u16>,
        directions: impl IntoIterator<Item = Direction>,
    ) -> Result<CompiledSelector, probe_core::SelectorError> {
        Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                remote_ports: remote_ports.into_iter().collect(),
                directions: directions.into_iter().collect(),
                ..TrafficSelector::default()
            },
        )
        .compile()
    }

    fn process_selector(
        pids: impl IntoIterator<Item = u32>,
    ) -> Result<CompiledSelector, probe_core::SelectorError> {
        Selector::term(
            ProcessSelector {
                pids: pids.into_iter().collect(),
                ..ProcessSelector::default()
            },
            TrafficSelector::default(),
        )
        .compile()
    }

    fn process_remote_port_selector(
        pids: impl IntoIterator<Item = u32>,
        remote_ports: impl IntoIterator<Item = u16>,
    ) -> Result<CompiledSelector, probe_core::SelectorError> {
        Selector::All {
            selectors: vec![
                Selector::term(
                    ProcessSelector {
                        pids: pids.into_iter().collect(),
                        ..ProcessSelector::default()
                    },
                    TrafficSelector::default(),
                ),
                Selector::term(
                    ProcessSelector::default(),
                    TrafficSelector {
                        remote_ports: remote_ports.into_iter().collect(),
                        ..TrafficSelector::default()
                    },
                ),
            ],
        }
        .compile()
    }

    fn connect_observation(
        process: EbpfObservedProcess,
        fd: i32,
        remote: TcpEndpoint,
    ) -> EbpfProcessObservation {
        connect_observation_with_lease(process, fd, remote, 9, 10)
    }

    fn pending_connect_resolution(
        process: EbpfObservedProcess,
        fd: i32,
        remote: TcpEndpoint,
    ) -> PendingEbpfFlowResolution {
        let EbpfProcessObservation::Connect(connect) = connect_observation(process, fd, remote)
        else {
            unreachable!("connect_observation always creates a connect observation");
        };
        PendingEbpfFlowResolution::new(
            PendingEbpfFlowStart::Connect(connect),
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
        )
    }

    fn pending_missing_connect_resolution(
        process: EbpfObservedProcess,
        fd: i32,
    ) -> PendingEbpfFlowResolution {
        let EbpfProcessObservation::Connect(connect) = missing_connect_observation(process, fd)
        else {
            unreachable!("missing_connect_observation always creates a connect observation");
        };
        PendingEbpfFlowResolution::new(
            PendingEbpfFlowStart::Connect(connect),
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
        )
    }

    fn connect_observation_with_lease(
        process: EbpfObservedProcess,
        fd: i32,
        remote: TcpEndpoint,
        fd_table_epoch: u64,
        fd_generation: u64,
    ) -> EbpfProcessObservation {
        EbpfProcessObservation::Connect(EbpfConnectTracepointObservation {
            process,
            fd,
            addrlen: 16,
            fd_table_epoch,
            fd_generation,
            endpoint: EbpfSocketEndpoint::Remote(remote),
        })
    }

    fn missing_connect_observation(
        process: EbpfObservedProcess,
        fd: i32,
    ) -> EbpfProcessObservation {
        EbpfProcessObservation::Connect(EbpfConnectTracepointObservation {
            process,
            fd,
            addrlen: 0,
            fd_table_epoch: 9,
            fd_generation: 10,
            endpoint: EbpfSocketEndpoint::Missing,
        })
    }

    fn accept_observation(
        process: EbpfObservedProcess,
        fd: i32,
        listen_fd: i32,
        remote: TcpEndpoint,
    ) -> EbpfProcessObservation {
        EbpfProcessObservation::Accept(EbpfAcceptTracepointObservation {
            process,
            fd,
            listen_fd,
            addrlen: 16,
            fd_table_epoch: 9,
            fd_generation: 10,
            endpoint: EbpfSocketEndpoint::Remote(remote),
        })
    }

    fn missing_accept_observation(
        process: EbpfObservedProcess,
        fd: i32,
        listen_fd: i32,
    ) -> EbpfProcessObservation {
        EbpfProcessObservation::Accept(EbpfAcceptTracepointObservation {
            process,
            fd,
            listen_fd,
            addrlen: 0,
            fd_table_epoch: 9,
            fd_generation: 10,
            endpoint: EbpfSocketEndpoint::Missing,
        })
    }

    fn close_observation(process: EbpfObservedProcess, fd: i32) -> EbpfProcessObservation {
        EbpfProcessObservation::Close(EbpfCloseTracepointObservation {
            process,
            fd,
            fd_generation: 10,
        })
    }

    fn close_range_observation(
        process: EbpfObservedProcess,
        first_fd: u32,
        last_fd: u32,
    ) -> EbpfProcessObservation {
        EbpfProcessObservation::CloseRange(EbpfCloseRangeTracepointObservation {
            process,
            first_fd,
            last_fd,
        })
    }

    fn process_exit_observation(process: EbpfObservedProcess) -> EbpfProcessObservation {
        EbpfProcessObservation::ProcessLifecycle(EbpfProcessLifecycleObservation {
            process,
            kind: EbpfProcessLifecycleKind::Exit,
        })
    }

    fn process_exec_observation(process: EbpfObservedProcess) -> EbpfProcessObservation {
        EbpfProcessObservation::ProcessLifecycle(EbpfProcessLifecycleObservation {
            process,
            kind: EbpfProcessLifecycleKind::Exec,
        })
    }

    fn observed_process(pid: u32, tgid: u32) -> EbpfObservedProcess {
        EbpfObservedProcess {
            pid,
            tgid,
            uid: 1000,
            gid: 1000,
            command: [0; 16],
        }
    }

    fn observed_process_named(pid: u32, tgid: u32, name: &str) -> EbpfObservedProcess {
        let mut process = observed_process(pid, tgid);
        for (slot, byte) in process.command.iter_mut().zip(name.bytes()) {
            *slot = byte;
        }
        process
    }

    fn demo_process() -> ProcessContext {
        ProcessContext {
            identity: ProcessIdentity {
                pid: 100,
                tgid: 100,
                start_time_ticks: 1234,
                boot_id: "boot".to_string(),
                exe_path: "/usr/bin/curl".to_string(),
                cmdline_hash: "cmd".to_string(),
                uid: 1000,
                gid: 1000,
                cgroup: None,
                systemd_service: None,
                container_id: None,
                runtime_hint: None,
            },
            name: "curl".to_string(),
            cmdline: vec!["curl".to_string()],
        }
    }
}
