use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use probe_core::{
    CapabilityKind, CapabilityState, CaptureSource, CompiledSelector, FlowContext, Timestamp,
};

use crate::output_loss::OutputLossTracker;
use crate::{CaptureError, CaptureEvent, CapturePoll, CaptureProvider};

use super::super::{
    EbpfCloseRangeTracepointObservation, EbpfCloseTracepointObservation, EbpfProcessObservation,
    EbpfProcessObservationLinkOwnershipSnapshot, EbpfProcessObservationProbe,
    EbpfProcessObservationProbeConfig, EbpfSocketFlowResolver,
    bridge::output_loss_event,
    clock::EbpfObservationClock,
    flow_start::{PendingEbpfFlowResolution, PendingEbpfFlowStart},
    observation_source::{EbpfObservationSource, ProbeObservationSource},
    payload_authorization::SocketPayloadSampleAuthorization,
    payload_bridge::{output_loss_gap_events, read_events, write_events},
    payload_direction::PayloadDirections,
    tracked_flow::TrackedEbpfFlows,
};

const DEFAULT_RESOLUTION_RETRIES: u32 = 20;
const DEFAULT_RESOLUTION_RETRY_SLEEP: Duration = Duration::from_millis(5);
const MAX_TRACKED_EBPF_FLOWS: usize = 8192;
const MAX_PENDING_EBPF_FLOW_RESOLUTIONS: usize = 8192;

pub struct EbpfProcessObservationProvider {
    observations: Box<dyn EbpfObservationSource>,
    resolver: Box<dyn EbpfSocketFlowResolver>,
    clock: EbpfObservationClock,
    resolution_retries: u32,
    resolution_retry_sleep: Duration,
    stop_when_idle: bool,
    deep_observe_selector: Option<CompiledSelector>,
    tracked_flows: TrackedEbpfFlows,
    pending_flows: VecDeque<PendingEbpfFlowResolution>,
    pending_events: VecDeque<CaptureEvent>,
    output_loss: OutputLossTracker,
    link_ownership: EbpfProcessObservationLinkOwnershipSnapshot,
}

impl EbpfProcessObservationProvider {
    pub fn open(
        config: EbpfProcessObservationProbeConfig,
        resolver: Box<dyn EbpfSocketFlowResolver>,
        deep_observe_selector: Option<CompiledSelector>,
    ) -> Result<Self, CaptureError> {
        let probe = EbpfProcessObservationProbe::load(config)
            .map_err(|error| CaptureError::provider("ebpf", error.to_string()))?;
        let link_ownership = probe.link_ownership();
        Ok(Self {
            observations: Box::new(ProbeObservationSource { probe }),
            resolver,
            clock: EbpfObservationClock::default(),
            resolution_retries: DEFAULT_RESOLUTION_RETRIES,
            resolution_retry_sleep: DEFAULT_RESOLUTION_RETRY_SLEEP,
            stop_when_idle: false,
            deep_observe_selector,
            tracked_flows: TrackedEbpfFlows::bounded(MAX_TRACKED_EBPF_FLOWS),
            pending_flows: VecDeque::new(),
            pending_events: VecDeque::new(),
            output_loss: OutputLossTracker::default(),
            link_ownership,
        })
    }

    pub fn link_ownership(&self) -> EbpfProcessObservationLinkOwnershipSnapshot {
        self.link_ownership.clone()
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
        if let Some(observation) = self.observations.next_observation()? {
            self.output_loss.record_observation();
            return self.poll_observation(observation);
        }
        if let Some(event) = self.output_loss_events()? {
            return Ok(CapturePoll::event(event));
        }
        if !self.pending_flows.is_empty() {
            return self.poll_pending_flow_resolution();
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
                self.pending_events.extend(events);
                Ok(self
                    .pending_events
                    .pop_front()
                    .map(CapturePoll::event)
                    .unwrap_or(CapturePoll::Progress))
            }
            EbpfProcessObservation::Write(write) => {
                let timestamp = self.clock.next_timestamp();
                let events = write_events(&mut self.tracked_flows, &write, timestamp);
                self.pending_events.extend(events);
                Ok(self
                    .pending_events
                    .pop_front()
                    .map(CapturePoll::event)
                    .unwrap_or(CapturePoll::Progress))
            }
            EbpfProcessObservation::Read(read) => {
                let timestamp = self.clock.next_timestamp();
                let events = read_events(&mut self.tracked_flows, &read, timestamp);
                self.pending_events.extend(events);
                Ok(self
                    .pending_events
                    .pop_front()
                    .map(CapturePoll::event)
                    .unwrap_or(CapturePoll::Progress))
            }
        }
    }

    fn begin_flow_resolution(
        &mut self,
        flow_start: PendingEbpfFlowStart,
    ) -> Result<CapturePoll, CaptureError> {
        let timestamp = self.clock.next_timestamp();
        if flow_start.descriptor_lease().is_none() {
            return Ok(CapturePoll::event(
                flow_start.invalid_descriptor_lease_gap(timestamp),
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
        mut pending: PendingEbpfFlowResolution,
    ) -> Result<CapturePoll, CaptureError> {
        if let Some(retry_at) = pending.retry_at
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
        if pending.attempts_completed >= self.resolution_retries {
            let reason = pending
                .flow_start
                .unresolved_reason(self.resolution_retries.saturating_add(1));
            return Ok(CapturePoll::event(
                pending.flow_start.unresolved_gap(pending.timestamp, reason),
            ));
        }
        pending.attempts_completed = pending.attempts_completed.saturating_add(1);
        pending.retry_at = Some(Instant::now() + self.resolution_retry_sleep);
        self.resolver.invalidate_cached_resolution();
        Ok(self.queue_pending_flow_resolution(pending))
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
        CapturePoll::event(pending.flow_start.unresolved_gap(pending.timestamp, reason))
    }

    fn track_flow_start_event(
        &mut self,
        flow_start: &PendingEbpfFlowStart,
        event: &CaptureEvent,
    ) -> Result<(), CaptureError> {
        if let CaptureEvent::ConnectionOpened { flow, .. } = &event {
            let Some(lease) = flow_start.descriptor_lease() else {
                return Ok(());
            };
            let authorization = SocketPayloadSampleAuthorization::from_selector(
                lease,
                flow,
                self.deep_observe_selector.as_ref(),
            );
            let payload_directions = authorization
                .map(|authorization| authorization.payload_directions())
                .unwrap_or_else(PayloadDirections::empty);
            if let Some(authorization) = authorization {
                self.observations
                    .allow_socket_payload_sample(authorization)?;
            }
            self.tracked_flows
                .insert_flow(lease, flow.clone(), payload_directions);
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

    fn close_event(&mut self, close: &EbpfCloseTracepointObservation) -> Option<CaptureEvent> {
        let flow = self.tracked_flows.remove_close(close)?.flow;
        Some(connection_closed_event(self.clock.next_timestamp(), flow))
    }

    fn close_range_events(
        &mut self,
        close_range: &EbpfCloseRangeTracepointObservation,
    ) -> Vec<CaptureEvent> {
        let removed = self.tracked_flows.remove_close_range(close_range);
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
            "eBPF provider emits result-gated connect and accept/accept4 flow-start observations with descriptor leases, selector-authorized always-degraded outbound single-buffer and bounded first-readable-iovec syscall argument samples plus inbound single-buffer and bounded first-readable-iovec syscall result samples bound to descriptor generation, descriptor-generation close/plain close_range lifecycle events, output ring-buffer failure conversion to degraded capture_loss events, and conservative unknown-offset gap fan-out to active tracked payload flows; payload beyond the first readable iovec segment, bounded scan window, or sample buffer, partial-write retry semantics, precise flow-specific lost-event reconstruction, and kernel socket-object lifetime are not implemented",
        )]
    }

    fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
        self.poll_event()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::CaptureProviderKind;

    use probe_core::{
        Direction, ProcessContext, ProcessIdentity, ProcessSelector, Selector, TcpConnection,
        TcpEndpoint, TrafficSelector,
    };

    use crate::ebpf::{
        EbpfAcceptTracepointObservation, EbpfCloseRangeTracepointObservation,
        EbpfCloseTracepointObservation, EbpfConnectTracepointObservation, EbpfObservedProcess,
        EbpfResolvedSocketFlow, EbpfSocketEndpoint, EbpfSocketFlowLookup,
        EbpfSocketReadObservation,
    };

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
                deep_observe_selector,
                tracked_flows: TrackedEbpfFlows::bounded(MAX_TRACKED_EBPF_FLOWS),
                pending_flows: VecDeque::new(),
                pending_events: VecDeque::new(),
                output_loss: OutputLossTracker::default(),
                link_ownership: EbpfProcessObservationLinkOwnershipSnapshot::unreported(),
            }
        }

        fn with_output_loss_check_interval_for_test(mut self, interval: u32) -> Self {
            self.output_loss = OutputLossTracker::new(interval);
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
        let observation = connect_observation(observed_process(101, 100), 7, remote);
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
    fn unresolved_flow_resolution_does_not_block_later_flow_start() -> TestResult {
        let (local, remote) = outbound_loopback();
        let process = observed_process(101, 100);
        let observations = [
            connect_observation(process.clone(), 7, remote),
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

        let (_, flow) = expect_connection_opened(&mut provider)?;
        assert_eq!(flow.local.port, 50_000);
        assert_eq!(flow.remote.port, 443);

        let Some(CaptureEvent::Gap(gap)) = provider.next()? else {
            panic!("expected unresolved flow gap after later flow start");
        };
        assert!(gap.gap.reason.contains("fd=7"));
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn full_pending_flow_resolution_queue_emits_gap() -> TestResult {
        let (_, remote) = outbound_loopback();
        let process = observed_process(101, 100);
        let observation = connect_observation(process.clone(), 7, remote);
        let mut provider = EbpfProcessObservationProvider::from_observations_for_test(
            [observation],
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

        let Some(CaptureEvent::Gap(gap)) = provider.next()? else {
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

        fn process_output_loss_count(&mut self) -> Result<u64, CaptureError> {
            Ok(self.counts.pop_front().unwrap_or(5))
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

    fn observed_process(pid: u32, tgid: u32) -> EbpfObservedProcess {
        EbpfObservedProcess {
            pid,
            tgid,
            uid: 1000,
            gid: 1000,
            command: [0; 16],
        }
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
