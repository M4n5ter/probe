use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use probe_core::{CapabilityKind, CapabilityState, CaptureSource, FlowContext, Timestamp};

use crate::{CaptureError, CaptureEvent, CapturePoll, CaptureProvider, CaptureProviderKind};

use super::{
    EbpfCloseTracepointObservation, EbpfConnectFlowResolver, EbpfConnectTracepointObservation,
    EbpfProcessObservation, EbpfProcessObservationProbe, EbpfProcessObservationProbeConfig,
    connect_opened_event_from_observation, unresolved_connect_gap_from_observation,
};

const DEFAULT_RESOLUTION_RETRIES: u32 = 20;
const DEFAULT_RESOLUTION_RETRY_SLEEP: Duration = Duration::from_millis(5);
const MAX_TRACKED_EBPF_FLOWS: usize = 8192;

pub struct EbpfProcessObservationProvider {
    observations: Box<dyn EbpfObservationSource>,
    resolver: Box<dyn EbpfConnectFlowResolver>,
    clock: EbpfObservationClock,
    resolution_retries: u32,
    resolution_retry_sleep: Duration,
    stop_when_idle: bool,
    tracked_flows: TrackedEbpfFlows,
    pending_connect: Option<PendingEbpfConnectResolution>,
}

impl EbpfProcessObservationProvider {
    pub fn open(
        config: EbpfProcessObservationProbeConfig,
        resolver: Box<dyn EbpfConnectFlowResolver>,
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
            tracked_flows: TrackedEbpfFlows::bounded(MAX_TRACKED_EBPF_FLOWS),
            pending_connect: None,
        })
    }

    #[cfg(test)]
    fn from_observations_for_test(
        observations: impl IntoIterator<Item = EbpfProcessObservation> + 'static,
        resolver: Box<dyn EbpfConnectFlowResolver>,
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
            tracked_flows: TrackedEbpfFlows::bounded(MAX_TRACKED_EBPF_FLOWS),
            pending_connect: None,
        }
    }

    #[cfg(test)]
    fn with_tracked_flow_capacity_for_test(mut self, max_tracked_flows: usize) -> Self {
        self.tracked_flows = TrackedEbpfFlows::bounded(max_tracked_flows);
        self
    }

    fn poll_event(&mut self) -> Result<CapturePoll, CaptureError> {
        if self.pending_connect.is_some() {
            return self.poll_pending_connect_resolution();
        }
        let Some(observation) = self.observations.next_observation()? else {
            return Ok(if self.stop_when_idle {
                CapturePoll::Finished
            } else {
                CapturePoll::Idle
            });
        };
        self.poll_observation(observation)
    }

    fn poll_observation(
        &mut self,
        observation: EbpfProcessObservation,
    ) -> Result<CapturePoll, CaptureError> {
        match observation {
            EbpfProcessObservation::Connect(connect) => {
                self.pending_connect = Some(PendingEbpfConnectResolution::new(
                    connect,
                    self.clock.next_timestamp(),
                ));
                self.poll_pending_connect_resolution()
            }
            EbpfProcessObservation::Close(close) => Ok(self
                .close_event(&close)
                .map(CapturePoll::event)
                .unwrap_or(CapturePoll::Progress)),
        }
    }

    fn poll_pending_connect_resolution(&mut self) -> Result<CapturePoll, CaptureError> {
        let Some(mut pending) = self.pending_connect.take() else {
            return Ok(CapturePoll::Idle);
        };
        if let Some(retry_at) = pending.retry_at
            && Instant::now() < retry_at
        {
            self.pending_connect = Some(pending);
            return Ok(CapturePoll::Idle);
        }
        if let Some(event) = connect_opened_event_from_observation(
            &pending.connect,
            pending.timestamp,
            self.resolver.as_mut(),
        )? {
            self.track_connect_event(&pending.connect, &event);
            return Ok(CapturePoll::event(event));
        }
        if pending.attempts_completed >= self.resolution_retries {
            return Ok(CapturePoll::event(unresolved_connect_gap_from_observation(
                &pending.connect,
                pending.timestamp,
                self.unresolved_connect_reason(&pending.connect),
            )));
        }
        pending.attempts_completed = pending.attempts_completed.saturating_add(1);
        pending.retry_at = Some(Instant::now() + self.resolution_retry_sleep);
        self.resolver.invalidate_cached_resolution();
        self.pending_connect = Some(pending);
        Ok(CapturePoll::Progress)
    }

    fn track_connect_event(
        &mut self,
        connect: &EbpfConnectTracepointObservation,
        event: &CaptureEvent,
    ) {
        if let CaptureEvent::ConnectionOpened { flow, .. } = &event {
            self.tracked_flows
                .insert(EbpfDescriptorKey::from_connect(connect), flow.clone());
        }
    }

    fn close_event(&mut self, close: &EbpfCloseTracepointObservation) -> Option<CaptureEvent> {
        let flow = self
            .tracked_flows
            .remove(EbpfDescriptorKey::from_close(close))?;
        Some(CaptureEvent::ConnectionClosed {
            timestamp: self.clock.next_timestamp(),
            flow,
            source: CaptureSource::EbpfSyscall,
            provider: CaptureProviderKind::Ebpf,
        })
    }

    fn unresolved_connect_reason(&self, connect: &EbpfConnectTracepointObservation) -> String {
        format!(
            "eBPF connect observation could not be resolved to a procfs socket after {} attempt(s); tgid={}, thread_pid={}, fd={}",
            self.resolution_retries.saturating_add(1),
            connect.process.tgid,
            connect.process.pid,
            connect.fd
        )
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
            "eBPF provider emits connect observations and best-effort tracked descriptor-close lifecycle events; payload and lost-event capture are not implemented",
        )]
    }

    fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
        self.poll_event()
    }
}

struct PendingEbpfConnectResolution {
    connect: EbpfConnectTracepointObservation,
    timestamp: Timestamp,
    attempts_completed: u32,
    retry_at: Option<Instant>,
}

impl PendingEbpfConnectResolution {
    fn new(connect: EbpfConnectTracepointObservation, timestamp: Timestamp) -> Self {
        Self {
            connect,
            timestamp,
            attempts_completed: 0,
            retry_at: None,
        }
    }
}

trait EbpfObservationSource {
    fn next_observation(&mut self) -> Result<Option<EbpfProcessObservation>, CaptureError>;
}

struct ProbeObservationSource {
    probe: EbpfProcessObservationProbe,
}

impl EbpfObservationSource for ProbeObservationSource {
    fn next_observation(&mut self) -> Result<Option<EbpfProcessObservation>, CaptureError> {
        self.probe
            .next_observation()
            .map_err(|error| CaptureError::provider("ebpf", error.to_string()))
    }
}

struct TrackedEbpfFlows {
    by_descriptor: HashMap<EbpfDescriptorKey, FlowContext>,
    recency_order: VecDeque<EbpfDescriptorKey>,
    max_tracked_flows: usize,
}

impl TrackedEbpfFlows {
    fn bounded(max_tracked_flows: usize) -> Self {
        Self {
            by_descriptor: HashMap::new(),
            recency_order: VecDeque::new(),
            max_tracked_flows,
        }
    }

    fn insert(&mut self, key: EbpfDescriptorKey, flow: FlowContext) {
        if self.max_tracked_flows == 0 {
            return;
        }
        if self.by_descriptor.contains_key(&key) {
            self.recency_order.retain(|tracked_key| *tracked_key != key);
        } else {
            self.evict_until_available();
        }
        self.recency_order.push_back(key);
        self.by_descriptor.insert(key, flow);
    }

    fn remove(&mut self, key: EbpfDescriptorKey) -> Option<FlowContext> {
        let flow = self.by_descriptor.remove(&key)?;
        self.recency_order.retain(|tracked_key| *tracked_key != key);
        Some(flow)
    }

    fn evict_until_available(&mut self) {
        while self.by_descriptor.len() >= self.max_tracked_flows {
            let Some(evicted) = self.recency_order.pop_front() else {
                self.by_descriptor.clear();
                break;
            };
            if self.by_descriptor.remove(&evicted).is_some() {
                break;
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct EbpfDescriptorKey {
    tgid: u32,
    fd: i32,
}

impl EbpfDescriptorKey {
    fn from_connect(connect: &EbpfConnectTracepointObservation) -> Self {
        Self {
            tgid: connect.process.tgid,
            fd: connect.fd,
        }
    }

    fn from_close(close: &EbpfCloseTracepointObservation) -> Self {
        Self {
            tgid: close.process.tgid,
            fd: close.fd,
        }
    }
}

#[cfg(test)]
struct VecObservationSource {
    observations: std::collections::VecDeque<EbpfProcessObservation>,
}

#[cfg(test)]
impl EbpfObservationSource for VecObservationSource {
    fn next_observation(&mut self) -> Result<Option<EbpfProcessObservation>, CaptureError> {
        Ok(self.observations.pop_front())
    }
}

#[derive(Default)]
struct EbpfObservationClock {
    monotonic_sequence: u64,
}

impl EbpfObservationClock {
    fn next_timestamp(&mut self) -> Timestamp {
        self.monotonic_sequence = self.monotonic_sequence.saturating_add(1);
        Timestamp {
            monotonic_ns: self.monotonic_sequence,
            wall_time_unix_ns: current_wall_time_unix_ns(),
        }
    }
}

fn current_wall_time_unix_ns() -> i64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    nanos.min(i64::MAX as u128) as i64
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use probe_core::{Direction, ProcessContext, ProcessIdentity, TcpConnection, TcpEndpoint};

    use crate::ebpf::{
        EbpfCloseTracepointObservation, EbpfConnectEndpoint, EbpfConnectFlowLookup,
        EbpfConnectTracepointObservation, EbpfObservedProcess, EbpfResolvedConnectFlow,
    };

    use super::*;

    #[test]
    fn ebpf_process_observation_provider_emits_connection_opened_events()
    -> Result<(), Box<dyn std::error::Error>> {
        let remote = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 443);
        let local = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 50_000);
        let observation = EbpfProcessObservation::Connect(EbpfConnectTracepointObservation {
            process: EbpfObservedProcess {
                pid: 101,
                tgid: 100,
                uid: 1000,
                gid: 1000,
                command: [0; 16],
            },
            fd: 7,
            addrlen: 16,
            endpoint: EbpfConnectEndpoint::Remote(remote),
        });
        let resolver = Box::new(StaticResolver {
            resolved: Some(EbpfResolvedConnectFlow {
                process: demo_process(),
                confidence: 90,
                connection: TcpConnection::new(local, remote),
            }),
        });
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
    fn ebpf_process_observation_provider_emits_connection_closed_events()
    -> Result<(), Box<dyn std::error::Error>> {
        let remote = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 443);
        let local = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 50_000);
        let observations = [
            EbpfProcessObservation::Connect(EbpfConnectTracepointObservation {
                process: EbpfObservedProcess {
                    pid: 101,
                    tgid: 100,
                    uid: 1000,
                    gid: 1000,
                    command: [0; 16],
                },
                fd: 7,
                addrlen: 16,
                endpoint: EbpfConnectEndpoint::Remote(remote),
            }),
            EbpfProcessObservation::Close(EbpfCloseTracepointObservation {
                process: EbpfObservedProcess {
                    pid: 101,
                    tgid: 100,
                    uid: 1000,
                    gid: 1000,
                    command: [0; 16],
                },
                fd: 7,
            }),
        ];
        let resolver = Box::new(StaticResolver {
            resolved: Some(EbpfResolvedConnectFlow {
                process: demo_process(),
                confidence: 90,
                connection: TcpConnection::new(local, remote),
            }),
        });
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
    fn ebpf_process_observation_provider_closes_fd_from_sibling_thread()
    -> Result<(), Box<dyn std::error::Error>> {
        let remote = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 443);
        let local = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 50_000);
        let observations = [
            EbpfProcessObservation::Connect(EbpfConnectTracepointObservation {
                process: EbpfObservedProcess {
                    pid: 101,
                    tgid: 100,
                    uid: 1000,
                    gid: 1000,
                    command: [0; 16],
                },
                fd: 7,
                addrlen: 16,
                endpoint: EbpfConnectEndpoint::Remote(remote),
            }),
            EbpfProcessObservation::Close(EbpfCloseTracepointObservation {
                process: EbpfObservedProcess {
                    pid: 102,
                    tgid: 100,
                    uid: 1000,
                    gid: 1000,
                    command: [0; 16],
                },
                fd: 7,
            }),
        ];
        let resolver = Box::new(StaticResolver {
            resolved: Some(EbpfResolvedConnectFlow {
                process: demo_process(),
                confidence: 90,
                connection: TcpConnection::new(local, remote),
            }),
        });
        let mut provider =
            EbpfProcessObservationProvider::from_observations_for_test(observations, resolver);

        let Some(CaptureEvent::ConnectionOpened { flow: opened, .. }) = provider.next()? else {
            panic!("expected connection opened event");
        };
        let Some(CaptureEvent::ConnectionClosed { flow: closed, .. }) = provider.next()? else {
            panic!("expected connection closed event from sibling thread close");
        };

        assert_eq!(closed.id, opened.id);
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn ebpf_process_observation_provider_ignores_untracked_close_and_keeps_polling()
    -> Result<(), Box<dyn std::error::Error>> {
        let remote = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 443);
        let local = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 50_000);
        let observations = [
            EbpfProcessObservation::Close(EbpfCloseTracepointObservation {
                process: EbpfObservedProcess {
                    pid: 101,
                    tgid: 100,
                    uid: 1000,
                    gid: 1000,
                    command: [0; 16],
                },
                fd: 7,
            }),
            EbpfProcessObservation::Connect(EbpfConnectTracepointObservation {
                process: EbpfObservedProcess {
                    pid: 101,
                    tgid: 100,
                    uid: 1000,
                    gid: 1000,
                    command: [0; 16],
                },
                fd: 8,
                addrlen: 16,
                endpoint: EbpfConnectEndpoint::Remote(remote),
            }),
        ];
        let resolver = Box::new(StaticResolver {
            resolved: Some(EbpfResolvedConnectFlow {
                process: demo_process(),
                confidence: 90,
                connection: TcpConnection::new(local, remote),
            }),
        });
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
        let process = EbpfObservedProcess {
            pid: 101,
            tgid: 100,
            uid: 1000,
            gid: 1000,
            command: [0; 16],
        };
        let observations = [
            EbpfProcessObservation::Connect(EbpfConnectTracepointObservation {
                process: process.clone(),
                fd: 7,
                addrlen: 16,
                endpoint: EbpfConnectEndpoint::Remote(remote),
            }),
            EbpfProcessObservation::Close(EbpfCloseTracepointObservation {
                process: process.clone(),
                fd: 7,
            }),
            EbpfProcessObservation::Connect(EbpfConnectTracepointObservation {
                process,
                fd: 7,
                addrlen: 16,
                endpoint: EbpfConnectEndpoint::Remote(remote),
            }),
        ];
        let resolver = Box::new(StaticResolver {
            resolved: Some(EbpfResolvedConnectFlow {
                process: demo_process(),
                confidence: 90,
                connection: TcpConnection::new(local, remote),
            }),
        });
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
    fn ebpf_process_observation_provider_bounds_tracked_flow_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let remote = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 443);
        let local = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 50_000);
        let process = EbpfObservedProcess {
            pid: 101,
            tgid: 100,
            uid: 1000,
            gid: 1000,
            command: [0; 16],
        };
        let observations = [
            EbpfProcessObservation::Connect(EbpfConnectTracepointObservation {
                process: process.clone(),
                fd: 7,
                addrlen: 16,
                endpoint: EbpfConnectEndpoint::Remote(remote),
            }),
            EbpfProcessObservation::Connect(EbpfConnectTracepointObservation {
                process: process.clone(),
                fd: 8,
                addrlen: 16,
                endpoint: EbpfConnectEndpoint::Remote(remote),
            }),
            EbpfProcessObservation::Close(EbpfCloseTracepointObservation {
                process: process.clone(),
                fd: 7,
            }),
            EbpfProcessObservation::Close(EbpfCloseTracepointObservation { process, fd: 8 }),
        ];
        let resolver = Box::new(StaticResolver {
            resolved: Some(EbpfResolvedConnectFlow {
                process: demo_process(),
                confidence: 90,
                connection: TcpConnection::new(local, remote),
            }),
        });
        let mut provider =
            EbpfProcessObservationProvider::from_observations_for_test(observations, resolver)
                .with_tracked_flow_capacity_for_test(1);

        let Some(CaptureEvent::ConnectionOpened { flow: first, .. }) = provider.next()? else {
            panic!("expected first connection opened event");
        };
        let Some(CaptureEvent::ConnectionOpened { flow: second, .. }) = provider.next()? else {
            panic!("expected second connection opened event");
        };
        assert_ne!(first.id, second.id);

        let Some(CaptureEvent::ConnectionClosed { flow, .. }) = provider.next()? else {
            panic!("expected only the non-evicted connection to close");
        };
        assert_eq!(flow.id, second.id);
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn ebpf_process_observation_provider_refreshes_descriptor_age_on_reuse()
    -> Result<(), Box<dyn std::error::Error>> {
        let remote = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 443);
        let local = TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 50_000);
        let process = EbpfObservedProcess {
            pid: 101,
            tgid: 100,
            uid: 1000,
            gid: 1000,
            command: [0; 16],
        };
        let observations = [
            EbpfProcessObservation::Connect(EbpfConnectTracepointObservation {
                process: process.clone(),
                fd: 7,
                addrlen: 16,
                endpoint: EbpfConnectEndpoint::Remote(remote),
            }),
            EbpfProcessObservation::Connect(EbpfConnectTracepointObservation {
                process: process.clone(),
                fd: 8,
                addrlen: 16,
                endpoint: EbpfConnectEndpoint::Remote(remote),
            }),
            EbpfProcessObservation::Connect(EbpfConnectTracepointObservation {
                process: process.clone(),
                fd: 7,
                addrlen: 16,
                endpoint: EbpfConnectEndpoint::Remote(remote),
            }),
            EbpfProcessObservation::Connect(EbpfConnectTracepointObservation {
                process: process.clone(),
                fd: 9,
                addrlen: 16,
                endpoint: EbpfConnectEndpoint::Remote(remote),
            }),
            EbpfProcessObservation::Close(EbpfCloseTracepointObservation {
                process: process.clone(),
                fd: 8,
            }),
            EbpfProcessObservation::Close(EbpfCloseTracepointObservation {
                process: process.clone(),
                fd: 7,
            }),
            EbpfProcessObservation::Close(EbpfCloseTracepointObservation { process, fd: 9 }),
        ];
        let resolver = Box::new(StaticResolver {
            resolved: Some(EbpfResolvedConnectFlow {
                process: demo_process(),
                confidence: 90,
                connection: TcpConnection::new(local, remote),
            }),
        });
        let mut provider =
            EbpfProcessObservationProvider::from_observations_for_test(observations, resolver)
                .with_tracked_flow_capacity_for_test(2);

        let Some(CaptureEvent::ConnectionOpened {
            flow: first_fd7, ..
        }) = provider.next()?
        else {
            panic!("expected first fd 7 connection opened event");
        };
        let Some(CaptureEvent::ConnectionOpened { flow: fd8, .. }) = provider.next()? else {
            panic!("expected fd 8 connection opened event");
        };
        let Some(CaptureEvent::ConnectionOpened {
            flow: second_fd7, ..
        }) = provider.next()?
        else {
            panic!("expected refreshed fd 7 connection opened event");
        };
        let Some(CaptureEvent::ConnectionOpened { flow: fd9, .. }) = provider.next()? else {
            panic!("expected fd 9 connection opened event");
        };

        assert_ne!(first_fd7.id, second_fd7.id);
        assert_ne!(fd8.id, fd9.id);

        let Some(CaptureEvent::ConnectionClosed { flow, .. }) = provider.next()? else {
            panic!("expected refreshed fd 7 connection to survive capacity eviction");
        };
        assert_eq!(flow.id, second_fd7.id);

        let Some(CaptureEvent::ConnectionClosed { flow, .. }) = provider.next()? else {
            panic!("expected fd 9 connection to close");
        };
        assert_eq!(flow.id, fd9.id);
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn ebpf_process_observation_provider_emits_gap_for_unresolved_observations()
    -> Result<(), Box<dyn std::error::Error>> {
        let observation = EbpfProcessObservation::Connect(EbpfConnectTracepointObservation {
            process: EbpfObservedProcess {
                pid: 101,
                tgid: 100,
                uid: 1000,
                gid: 1000,
                command: [0; 16],
            },
            fd: 7,
            addrlen: 0,
            endpoint: EbpfConnectEndpoint::Missing,
        });
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
        let observation = EbpfProcessObservation::Connect(EbpfConnectTracepointObservation {
            process: EbpfObservedProcess {
                pid: 101,
                tgid: 100,
                uid: 1000,
                gid: 1000,
                command: [0; 16],
            },
            fd: 7,
            addrlen: 16,
            endpoint: EbpfConnectEndpoint::Remote(remote),
        });
        let resolver = Box::new(RetryResolver {
            calls: 0,
            resolved: EbpfResolvedConnectFlow {
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

    struct StaticResolver {
        resolved: Option<EbpfResolvedConnectFlow>,
    }

    impl EbpfConnectFlowResolver for StaticResolver {
        fn resolve_connect_flow(
            &mut self,
            _lookup: EbpfConnectFlowLookup,
        ) -> Result<Option<EbpfResolvedConnectFlow>, CaptureError> {
            Ok(self.resolved.clone())
        }
    }

    struct RetryResolver {
        calls: u32,
        resolved: EbpfResolvedConnectFlow,
    }

    impl EbpfConnectFlowResolver for RetryResolver {
        fn resolve_connect_flow(
            &mut self,
            _lookup: EbpfConnectFlowLookup,
        ) -> Result<Option<EbpfResolvedConnectFlow>, CaptureError> {
            self.calls = self.calls.saturating_add(1);
            if self.calls == 1 {
                return Ok(None);
            }
            Ok(Some(self.resolved.clone()))
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
