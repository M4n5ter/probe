use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use probe_core::{CapabilityKind, CapabilityState, CaptureSource, CompiledSelector};

use crate::{CaptureError, CaptureEvent, CapturePoll, CaptureProvider, CaptureProviderKind};

use super::{
    EbpfCloseTracepointObservation, EbpfProcessObservation, EbpfProcessObservationProbe,
    EbpfProcessObservationProbeConfig, EbpfSocketFlowResolver,
    bridge::output_loss_event,
    clock::EbpfObservationClock,
    flow_start::{PendingEbpfFlowResolution, PendingEbpfFlowStart},
    observation_source::{EbpfObservationSource, ProbeObservationSource},
    output_loss::OutputLossTracker,
    payload_authorization::SocketPayloadSampleAuthorization,
    payload_bridge::{read_events, write_events},
    payload_direction::PayloadDirections,
    tracked_flow::TrackedEbpfFlows,
};

const DEFAULT_RESOLUTION_RETRIES: u32 = 20;
const DEFAULT_RESOLUTION_RETRY_SLEEP: Duration = Duration::from_millis(5);
const MAX_TRACKED_EBPF_FLOWS: usize = 8192;

pub struct EbpfProcessObservationProvider {
    observations: Box<dyn EbpfObservationSource>,
    resolver: Box<dyn EbpfSocketFlowResolver>,
    clock: EbpfObservationClock,
    resolution_retries: u32,
    resolution_retry_sleep: Duration,
    stop_when_idle: bool,
    deep_observe_selector: Option<CompiledSelector>,
    tracked_flows: TrackedEbpfFlows,
    pending_flow: Option<PendingEbpfFlowResolution>,
    pending_events: VecDeque<CaptureEvent>,
    output_loss: OutputLossTracker,
}

impl EbpfProcessObservationProvider {
    pub fn open(
        config: EbpfProcessObservationProbeConfig,
        resolver: Box<dyn EbpfSocketFlowResolver>,
        deep_observe_selector: Option<CompiledSelector>,
    ) -> Result<Self, CaptureError> {
        let probe = EbpfProcessObservationProbe::load(config)
            .map_err(|error| CaptureError::provider("ebpf", error.to_string()))?;
        Ok(Self {
            observations: Box::new(ProbeObservationSource { probe }),
            resolver,
            clock: EbpfObservationClock::default(),
            resolution_retries: DEFAULT_RESOLUTION_RETRIES,
            resolution_retry_sleep: DEFAULT_RESOLUTION_RETRY_SLEEP,
            stop_when_idle: false,
            deep_observe_selector,
            tracked_flows: TrackedEbpfFlows::bounded(MAX_TRACKED_EBPF_FLOWS),
            pending_flow: None,
            pending_events: VecDeque::new(),
            output_loss: OutputLossTracker::default(),
        })
    }

    fn poll_event(&mut self) -> Result<CapturePoll, CaptureError> {
        if let Some(event) = self.pending_events.pop_front() {
            return Ok(CapturePoll::event(event));
        }
        if self.pending_flow.is_some() {
            return self.poll_pending_flow_resolution();
        }
        if self.output_loss.should_check_during_drain()
            && let Some(event) = self.output_loss_event()?
        {
            return Ok(CapturePoll::event(event));
        }
        if let Some(observation) = self.observations.next_observation()? {
            self.output_loss.record_observation();
            return self.poll_observation(observation);
        }
        if let Some(event) = self.output_loss_event()? {
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
                self.pending_flow = Some(PendingEbpfFlowResolution::new(
                    PendingEbpfFlowStart::Connect(connect),
                    self.clock.next_timestamp(),
                ));
                self.poll_pending_flow_resolution()
            }
            EbpfProcessObservation::Accept(accept) => {
                self.pending_flow = Some(PendingEbpfFlowResolution::new(
                    PendingEbpfFlowStart::Accept(accept),
                    self.clock.next_timestamp(),
                ));
                self.poll_pending_flow_resolution()
            }
            EbpfProcessObservation::Close(close) => Ok(self
                .close_event(&close)
                .map(CapturePoll::event)
                .unwrap_or(CapturePoll::Progress)),
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

    fn poll_pending_flow_resolution(&mut self) -> Result<CapturePoll, CaptureError> {
        let Some(mut pending) = self.pending_flow.take() else {
            return Ok(CapturePoll::Idle);
        };
        if let Some(retry_at) = pending.retry_at
            && Instant::now() < retry_at
        {
            self.pending_flow = Some(pending);
            return Ok(CapturePoll::Idle);
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
        self.pending_flow = Some(pending);
        Ok(CapturePoll::Progress)
    }

    fn track_flow_start_event(
        &mut self,
        flow_start: &PendingEbpfFlowStart,
        event: &CaptureEvent,
    ) -> Result<(), CaptureError> {
        if let CaptureEvent::ConnectionOpened { flow, .. } = &event {
            let authorization = SocketPayloadSampleAuthorization::from_selector(
                flow_start.payload_source(),
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
            self.tracked_flows.insert_flow(
                flow_start.tgid(),
                flow_start.fd(),
                flow.clone(),
                payload_directions,
            );
        }
        Ok(())
    }

    fn output_loss_event(&mut self) -> Result<Option<CaptureEvent>, CaptureError> {
        let count = self.observations.process_output_loss_count()?;
        Ok(self
            .output_loss
            .checkpoint(count)
            .map(|lost_events| output_loss_event(self.clock.next_timestamp(), lost_events)))
    }

    fn close_event(&mut self, close: &EbpfCloseTracepointObservation) -> Option<CaptureEvent> {
        let flow = self.tracked_flows.remove_close(close)?.flow;
        Some(CaptureEvent::ConnectionClosed {
            timestamp: self.clock.next_timestamp(),
            flow,
            source: CaptureSource::EbpfSyscall,
            provider: CaptureProviderKind::Ebpf,
        })
    }
}

impl CaptureProvider for EbpfProcessObservationProvider {
    fn name(&self) -> &'static str {
        "ebpf"
    }

    fn kind(&self) -> CaptureProviderKind {
        CaptureProviderKind::Ebpf
    }

    fn capabilities(&self) -> Vec<CapabilityState> {
        vec![CapabilityState::degraded(
            CapabilityKind::Ebpf,
            "eBPF provider emits connect and accept/accept4 flow-start observations, selector-authorized always-degraded outbound single-buffer and bounded first-non-empty-iovec syscall argument samples plus inbound single-buffer and bounded first-non-empty-iovec syscall result samples, best-effort descriptor-close lifecycle events, and output ring-buffer failure conversion to degraded capture_loss events; payload beyond the first sampled iovec segment, bounded iovec scan, or sample buffer, partial-write retry semantics, and flow-specific lost-event reconstruction are not implemented",
        )]
    }

    fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
        self.poll_event()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use probe_core::{
        Direction, ProcessContext, ProcessIdentity, ProcessSelector, Selector, TcpConnection,
        TcpEndpoint, TrafficSelector,
    };

    use crate::ebpf::{
        EbpfAcceptTracepointObservation, EbpfCloseTracepointObservation,
        EbpfConnectTracepointObservation, EbpfObservedProcess, EbpfResolvedSocketFlow,
        EbpfSocketEndpoint, EbpfSocketFlowLookup, EbpfSocketReadObservation,
    };

    use super::*;

    impl EbpfProcessObservationProvider {
        fn from_observations_for_test(
            observations: impl IntoIterator<Item = EbpfProcessObservation> + 'static,
            resolver: Box<dyn EbpfSocketFlowResolver>,
        ) -> Self {
            Self {
                observations: Box::new(VecObservationSource {
                    observations: observations.into_iter().collect(),
                }),
                resolver,
                clock: EbpfObservationClock::default(),
                resolution_retries: 0,
                resolution_retry_sleep: Duration::ZERO,
                stop_when_idle: true,
                deep_observe_selector: None,
                tracked_flows: TrackedEbpfFlows::bounded(MAX_TRACKED_EBPF_FLOWS),
                pending_flow: None,
                pending_events: VecDeque::new(),
                output_loss: OutputLossTracker::default(),
            }
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
                pending_flow: None,
                pending_events: VecDeque::new(),
                output_loss: OutputLossTracker::default(),
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
    fn ebpf_process_observation_provider_emits_connection_opened_events()
    -> Result<(), Box<dyn std::error::Error>> {
        let remote = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 443);
        let local = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 50_000);
        let observation = connect_observation(observed_process(101, 100), 7, remote);
        let resolver = static_resolver(local, remote);
        let mut provider =
            EbpfProcessObservationProvider::from_observations_for_test([observation], resolver);

        let Some(CaptureEvent::ConnectionOpened {
            timestamp,
            flow,
            source,
            provider: provider_kind,
        }) = provider.next()?
        else {
            panic!("expected connection opened event");
        };

        assert_eq!(timestamp.monotonic_ns, 1);
        assert_eq!(source, CaptureSource::EbpfSyscall);
        assert_eq!(provider_kind, CaptureProviderKind::Ebpf);
        assert_eq!(flow.local.port, 50_000);
        assert_eq!(flow.remote.port, 443);
        assert_eq!(flow.attribution_confidence, 90);
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn ebpf_process_observation_provider_emits_accepted_connection_opened_events()
    -> Result<(), Box<dyn std::error::Error>> {
        let remote = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 50_000);
        let local = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 443);
        let observation = accept_observation(observed_process(101, 100), 9, 3, remote);
        let resolver = static_resolver(local, remote);
        let mut provider =
            EbpfProcessObservationProvider::from_observations_for_test([observation], resolver);

        let Some(CaptureEvent::ConnectionOpened {
            timestamp,
            flow,
            source,
            provider: provider_kind,
        }) = provider.next()?
        else {
            panic!("expected accepted connection opened event");
        };

        assert_eq!(timestamp.monotonic_ns, 1);
        assert_eq!(source, CaptureSource::EbpfSyscall);
        assert_eq!(provider_kind, CaptureProviderKind::Ebpf);
        assert_eq!(flow.local.port, 443);
        assert_eq!(flow.remote.port, 50_000);
        assert_eq!(flow.attribution_confidence, 90);
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn ebpf_process_observation_provider_emits_inbound_read_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let remote = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 443);
        let local = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 50_000);
        let process = observed_process(101, 100);
        let observations = [
            connect_observation(process.clone(), 7, remote),
            EbpfProcessObservation::Read(EbpfSocketReadObservation {
                process,
                fd: 7,
                original_len: 5,
                buffer: b"HTTP/".to_vec(),
                truncated: false,
                read_failed: false,
            }),
        ];
        let resolver = static_resolver(local, remote);
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
            VecObservationSource {
                observations: observations.into_iter().collect(),
            },
            resolver,
            Some(selector),
        );

        let Some(CaptureEvent::ConnectionOpened { .. }) = provider.next()? else {
            panic!("expected connection opened event");
        };
        let Some(CaptureEvent::Bytes(bytes)) = provider.next()? else {
            panic!("expected inbound read bytes");
        };

        assert_eq!(bytes.source, CaptureSource::EbpfSyscall);
        assert_eq!(bytes.provider, CaptureProviderKind::Ebpf);
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
    fn ebpf_process_observation_provider_emits_inbound_read_bytes_for_accepted_flow()
    -> Result<(), Box<dyn std::error::Error>> {
        let remote = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 50_000);
        let local = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 443);
        let process = observed_process(101, 100);
        let observations = [
            accept_observation(process.clone(), 9, 3, remote),
            EbpfProcessObservation::Read(EbpfSocketReadObservation {
                process,
                fd: 9,
                original_len: 5,
                buffer: b"GET /".to_vec(),
                truncated: false,
                read_failed: false,
            }),
        ];
        let resolver = static_resolver(local, remote);
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
            VecObservationSource {
                observations: observations.into_iter().collect(),
            },
            resolver,
            Some(selector),
        );

        let Some(CaptureEvent::ConnectionOpened { .. }) = provider.next()? else {
            panic!("expected accepted connection opened event");
        };
        let Some(CaptureEvent::Bytes(bytes)) = provider.next()? else {
            panic!("expected accepted inbound read bytes");
        };

        assert_eq!(bytes.direction, Direction::Inbound);
        assert_eq!(bytes.flow.local.port, 443);
        assert_eq!(bytes.flow.remote.port, 50_000);
        assert_eq!(bytes.bytes.as_ref(), b"GET /");
        assert!(bytes.degraded);
        Ok(())
    }

    #[test]
    fn ebpf_process_observation_provider_emits_connection_closed_events()
    -> Result<(), Box<dyn std::error::Error>> {
        let remote = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 443);
        let local = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 50_000);
        let process = observed_process(101, 100);
        let observations = [
            connect_observation(process.clone(), 7, remote),
            close_observation(process, 7),
        ];
        let resolver = static_resolver(local, remote);
        let mut provider =
            EbpfProcessObservationProvider::from_observations_for_test(observations, resolver);

        let Some(CaptureEvent::ConnectionOpened { flow, .. }) = provider.next()? else {
            panic!("expected connection opened event");
        };

        let opened_flow = flow.clone();
        assert_eq!(flow.local.port, 50_000);
        assert_eq!(flow.remote.port, 443);

        let Some(CaptureEvent::ConnectionClosed {
            timestamp,
            flow,
            source,
            provider: provider_kind,
        }) = provider.next()?
        else {
            panic!("expected connection closed event");
        };

        assert_eq!(timestamp.monotonic_ns, 2);
        assert_eq!(source, CaptureSource::EbpfSyscall);
        assert_eq!(provider_kind, CaptureProviderKind::Ebpf);
        assert_eq!(flow.id, opened_flow.id);
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn ebpf_process_observation_provider_closes_same_process_fd_from_sibling_thread()
    -> Result<(), Box<dyn std::error::Error>> {
        let remote = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 443);
        let local = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 50_000);
        let observations = [
            connect_observation(observed_process(101, 100), 7, remote),
            close_observation(observed_process(102, 100), 7),
        ];
        let resolver = static_resolver(local, remote);
        let mut provider =
            EbpfProcessObservationProvider::from_observations_for_test(observations, resolver);

        let Some(CaptureEvent::ConnectionOpened { flow: opened, .. }) = provider.next()? else {
            panic!("expected connection opened event");
        };
        let opened_flow_id = opened.id.clone();
        assert_eq!(opened.local.port, 50_000);
        let Some(CaptureEvent::ConnectionClosed { flow, .. }) = provider.next()? else {
            panic!("expected sibling-thread close to close the process fd flow");
        };
        assert_eq!(flow.id, opened_flow_id);
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn ebpf_process_observation_provider_does_not_close_different_fd_from_same_process()
    -> Result<(), Box<dyn std::error::Error>> {
        let remote = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 443);
        let local = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 50_000);
        let process = observed_process(101, 100);
        let observations = [
            connect_observation(process.clone(), 7, remote),
            close_observation(process, 8),
        ];
        let resolver = static_resolver(local, remote);
        let mut provider =
            EbpfProcessObservationProvider::from_observations_for_test(observations, resolver);

        let Some(CaptureEvent::ConnectionOpened { flow: opened, .. }) = provider.next()? else {
            panic!("expected connection opened event");
        };
        assert_eq!(opened.local.port, 50_000);
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn ebpf_process_observation_provider_does_not_track_when_payload_authorization_fails()
    -> Result<(), Box<dyn std::error::Error>> {
        let remote = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 443);
        let local = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 50_000);
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
    fn ebpf_process_observation_provider_ignores_untracked_close_and_keeps_polling()
    -> Result<(), Box<dyn std::error::Error>> {
        let remote = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 443);
        let local = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 50_000);
        let observations = [
            close_observation(observed_process(101, 100), 7),
            connect_observation(observed_process(101, 100), 8, remote),
        ];
        let resolver = static_resolver(local, remote);
        let mut provider =
            EbpfProcessObservationProvider::from_observations_for_test(observations, resolver);

        let Some(CaptureEvent::ConnectionOpened {
            timestamp, flow, ..
        }) = provider.next()?
        else {
            panic!("expected provider to continue after an untracked close");
        };

        assert_eq!(timestamp.monotonic_ns, 1);
        assert_eq!(flow.local.port, 50_000);
        assert_eq!(flow.remote.port, 443);
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn ebpf_process_observation_provider_keeps_fd_reuse_as_distinct_connect_events()
    -> Result<(), Box<dyn std::error::Error>> {
        let remote = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 443);
        let local = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 50_000);
        let process = observed_process(101, 100);
        let observations = [
            connect_observation(process.clone(), 7, remote),
            close_observation(process.clone(), 7),
            connect_observation(process, 7, remote),
        ];
        let resolver = static_resolver(local, remote);
        let mut provider =
            EbpfProcessObservationProvider::from_observations_for_test(observations, resolver);

        let Some(CaptureEvent::ConnectionOpened {
            timestamp, flow, ..
        }) = provider.next()?
        else {
            panic!("expected first connection opened event");
        };
        let first_flow_id = flow.id.clone();
        assert_eq!(timestamp.monotonic_ns, 1);

        let Some(CaptureEvent::ConnectionClosed {
            timestamp, flow, ..
        }) = provider.next()?
        else {
            panic!("expected first connection closed event");
        };
        assert_eq!(timestamp.monotonic_ns, 2);
        assert_eq!(flow.id, first_flow_id);

        let Some(CaptureEvent::ConnectionOpened {
            timestamp, flow, ..
        }) = provider.next()?
        else {
            panic!("expected reused fd connection opened event");
        };
        assert_eq!(timestamp.monotonic_ns, 3);
        assert_ne!(flow.id, first_flow_id);
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn ebpf_process_observation_provider_emits_gap_for_unresolved_observations()
    -> Result<(), Box<dyn std::error::Error>> {
        let observation = missing_connect_observation(observed_process(101, 100), 7);
        let resolver = Box::new(StaticResolver { resolved: None });
        let mut provider =
            EbpfProcessObservationProvider::from_observations_for_test([observation], resolver);

        let Some(CaptureEvent::Gap(gap)) = provider.next()? else {
            panic!("expected degraded gap event");
        };

        assert_eq!(gap.source, CaptureSource::EbpfSyscall);
        assert_eq!(gap.provider, CaptureProviderKind::Ebpf);
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
    fn ebpf_process_observation_provider_retries_fd_resolution()
    -> Result<(), Box<dyn std::error::Error>> {
        let remote = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 443);
        let local = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 50_000);
        let observation = connect_observation(observed_process(101, 100), 7, remote);
        let resolver = Box::new(RetryResolver {
            calls: 0,
            resolved: EbpfResolvedSocketFlow {
                process: demo_process(),
                confidence: 90,
                connection: TcpConnection::new(local, remote),
            },
        });
        let mut provider =
            EbpfProcessObservationProvider::from_observations_for_test([observation], resolver);
        provider.resolution_retries = 1;

        let Some(CaptureEvent::ConnectionOpened { flow, .. }) = provider.next()? else {
            panic!("expected connection opened event after retry");
        };

        assert_eq!(flow.local.port, 50_000);
        Ok(())
    }

    #[test]
    fn ebpf_process_observation_provider_emits_output_loss_delta_through_poll()
    -> Result<(), Box<dyn std::error::Error>> {
        let source = OutputLossObservationSource {
            observations: VecDeque::new(),
            counts: VecDeque::from([2, 2, 5]),
        };
        let resolver = Box::new(StaticResolver { resolved: None });
        let mut provider =
            EbpfProcessObservationProvider::from_source_for_test(source, resolver, None);
        provider.stop_when_idle = false;

        let first = expect_output_loss(provider.poll_next()?);
        assert_eq!(first.source, CaptureSource::EbpfSyscall);
        assert_eq!(first.provider, CaptureProviderKind::Ebpf);
        assert_eq!(first.flow.attribution_confidence, 0);
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
    fn ebpf_process_observation_provider_interleaves_output_loss_during_observation_drain()
    -> Result<(), Box<dyn std::error::Error>> {
        let process = observed_process(101, 100);
        let source = OutputLossObservationSource {
            observations: VecDeque::from([
                EbpfProcessObservation::Close(EbpfCloseTracepointObservation {
                    process: process.clone(),
                    fd: 70,
                }),
                EbpfProcessObservation::Close(EbpfCloseTracepointObservation {
                    process: process.clone(),
                    fd: 71,
                }),
                EbpfProcessObservation::Close(EbpfCloseTracepointObservation { process, fd: 72 }),
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

    struct FailingAllowObservationSource {
        observations: std::collections::VecDeque<EbpfProcessObservation>,
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

    fn static_resolver(local: TcpEndpoint, remote: TcpEndpoint) -> Box<StaticResolver> {
        Box::new(StaticResolver {
            resolved: Some(EbpfResolvedSocketFlow {
                process: demo_process(),
                confidence: 90,
                connection: TcpConnection::new(local, remote),
            }),
        })
    }

    fn connect_observation(
        process: EbpfObservedProcess,
        fd: i32,
        remote: TcpEndpoint,
    ) -> EbpfProcessObservation {
        EbpfProcessObservation::Connect(EbpfConnectTracepointObservation {
            process,
            fd,
            addrlen: 16,
            fd_table_epoch: 9,
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
            endpoint: EbpfSocketEndpoint::Remote(remote),
        })
    }

    fn close_observation(process: EbpfObservedProcess, fd: i32) -> EbpfProcessObservation {
        EbpfProcessObservation::Close(EbpfCloseTracepointObservation { process, fd })
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
