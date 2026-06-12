use std::{
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use probe_core::{CapabilityKind, CapabilityState, CaptureSource, Timestamp};

use crate::{CaptureError, CaptureEvent, CaptureProvider, CaptureProviderKind};

use super::{
    EbpfConnectFlowResolver, EbpfConnectTracepointObservation, EbpfProcessObservation,
    EbpfProcessObservationProbe, EbpfProcessObservationProbeConfig,
    connect_opened_event_from_observation, unresolved_connect_gap_from_observation,
};

const DEFAULT_IDLE_SLEEP: Duration = Duration::from_millis(10);
const DEFAULT_RESOLUTION_RETRIES: u32 = 20;
const DEFAULT_RESOLUTION_RETRY_SLEEP: Duration = Duration::from_millis(5);

pub struct EbpfProcessObservationProvider {
    observations: Box<dyn EbpfObservationSource>,
    resolver: Box<dyn EbpfConnectFlowResolver>,
    clock: EbpfObservationClock,
    idle_sleep: Duration,
    resolution_retries: u32,
    resolution_retry_sleep: Duration,
    stop_when_idle: bool,
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
            idle_sleep: DEFAULT_IDLE_SLEEP,
            resolution_retries: DEFAULT_RESOLUTION_RETRIES,
            resolution_retry_sleep: DEFAULT_RESOLUTION_RETRY_SLEEP,
            stop_when_idle: false,
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
            idle_sleep: Duration::ZERO,
            resolution_retries: 0,
            resolution_retry_sleep: Duration::ZERO,
            stop_when_idle: true,
        }
    }

    fn next_event(&mut self) -> Result<Option<CaptureEvent>, CaptureError> {
        loop {
            let Some(observation) = self.observations.next_observation()? else {
                if self.stop_when_idle {
                    return Ok(None);
                }
                thread::sleep(self.idle_sleep);
                continue;
            };
            if let Some(event) = self.event_from_observation(observation)? {
                return Ok(Some(event));
            }
        }
    }

    fn event_from_observation(
        &mut self,
        observation: EbpfProcessObservation,
    ) -> Result<Option<CaptureEvent>, CaptureError> {
        match observation {
            EbpfProcessObservation::Connect(connect) => {
                self.connect_event_with_retry(&connect).map(Some)
            }
            EbpfProcessObservation::Close(_) => Ok(None),
        }
    }

    fn connect_event_with_retry(
        &mut self,
        connect: &EbpfConnectTracepointObservation,
    ) -> Result<CaptureEvent, CaptureError> {
        let timestamp = self.clock.next_timestamp();
        for attempt in 0..=self.resolution_retries {
            if let Some(event) =
                connect_opened_event_from_observation(connect, timestamp, self.resolver.as_mut())?
            {
                return Ok(event);
            }
            if attempt == self.resolution_retries {
                return Ok(unresolved_connect_gap_from_observation(
                    connect,
                    timestamp,
                    self.unresolved_connect_reason(connect),
                ));
            }
            self.resolver.invalidate_cached_resolution();
            thread::sleep(self.resolution_retry_sleep);
        }
        Ok(unresolved_connect_gap_from_observation(
            connect,
            timestamp,
            self.unresolved_connect_reason(connect),
        ))
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

    fn source(&self) -> CaptureSource {
        CaptureSource::EbpfSyscall
    }

    fn capabilities(&self) -> Vec<CapabilityState> {
        vec![CapabilityState::degraded(
            CapabilityKind::Ebpf,
            "eBPF provider emits connect observations and decodes descriptor close observations; payload, lost-event capture, and socket-lifetime close events are not implemented",
        )]
    }

    fn next(&mut self) -> Result<Option<CaptureEvent>, CaptureError> {
        self.next_event()
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
    fn ebpf_process_observation_provider_does_not_turn_descriptor_close_into_connection_close()
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

        assert_eq!(flow.local.port, 50_000);
        assert_eq!(flow.remote.port, 443);
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

        let Some(CaptureEvent::ConnectionOpened {
            timestamp, flow, ..
        }) = provider.next()?
        else {
            panic!("expected reused fd connection opened event");
        };
        assert_eq!(timestamp.monotonic_ns, 2);
        assert_ne!(flow.id, first_flow_id);
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
