use std::{
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use capture::{
    CaptureError, CaptureEvent, CapturePoll, CaptureProvider, CaptureProviderRuntimeDiagnostics,
};
use probe_core::{CapabilityState, CaptureProviderKind, CaptureSource};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CaptureInputActivityRuntimeSnapshot {
    pub(crate) polls: CaptureInputPollActivityRuntimeSnapshot,
    pub(crate) capture_events: u64,
    pub(crate) output_loss_events: u64,
    pub(crate) lost_events: u64,
    pub(crate) providers: Vec<CaptureInputProviderActivityRuntimeSnapshot>,
    pub(crate) last_signal: Option<CaptureInputSignalRuntimeSnapshot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CaptureInputProviderActivityRuntimeSnapshot {
    pub(crate) provider: CaptureProviderKind,
    pub(crate) capture_events: u64,
    pub(crate) output_loss_events: u64,
    pub(crate) lost_events: u64,
}

impl CaptureInputActivityRuntimeSnapshot {
    pub(crate) fn provider_activity(
        &self,
        provider: CaptureProviderKind,
    ) -> Option<&CaptureInputProviderActivityRuntimeSnapshot> {
        self.providers
            .iter()
            .find(|activity| activity.provider == provider)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CaptureInputPollActivityRuntimeSnapshot {
    pub(crate) total: u64,
    pub(crate) events: u64,
    pub(crate) progress: u64,
    pub(crate) idle: u64,
    pub(crate) finished: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub(crate) enum CaptureInputSignalRuntimeSnapshot {
    Event {
        sequence: u64,
        observed_unix_ns: u64,
        source: CaptureSource,
        provider: CaptureProviderKind,
        event_wall_time_unix_ns: i64,
    },
    OutputLoss {
        sequence: u64,
        observed_unix_ns: u64,
        source: CaptureSource,
        provider: CaptureProviderKind,
        event_wall_time_unix_ns: i64,
        lost_events: u64,
    },
    Progress {
        sequence: u64,
        observed_unix_ns: u64,
    },
    Idle {
        sequence: u64,
        observed_unix_ns: u64,
    },
    Finished {
        sequence: u64,
        observed_unix_ns: u64,
    },
}

impl CaptureInputSignalRuntimeSnapshot {
    pub(crate) const KINDS: [&'static str; 5] =
        ["event", "output_loss", "progress", "idle", "finished"];

    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::Event { .. } => "event",
            Self::OutputLoss { .. } => "output_loss",
            Self::Progress { .. } => "progress",
            Self::Idle { .. } => "idle",
            Self::Finished { .. } => "finished",
        }
    }

    pub(crate) fn sequence(&self) -> u64 {
        match self {
            Self::Event { sequence, .. }
            | Self::OutputLoss { sequence, .. }
            | Self::Progress { sequence, .. }
            | Self::Idle { sequence, .. }
            | Self::Finished { sequence, .. } => *sequence,
        }
    }

    pub(crate) fn observed_unix_ns(&self) -> u64 {
        match self {
            Self::Event {
                observed_unix_ns, ..
            }
            | Self::OutputLoss {
                observed_unix_ns, ..
            }
            | Self::Progress {
                observed_unix_ns, ..
            }
            | Self::Idle {
                observed_unix_ns, ..
            }
            | Self::Finished {
                observed_unix_ns, ..
            } => *observed_unix_ns,
        }
    }
}

#[derive(Clone, Default)]
pub(crate) struct CaptureInputActivityRuntimeState {
    inner: Arc<CaptureInputActivityRuntimeInner>,
}

#[derive(Default)]
struct CaptureInputActivityRuntimeInner {
    sequence: AtomicCounter,
    poll_events: AtomicCounter,
    poll_progress: AtomicCounter,
    poll_idle: AtomicCounter,
    poll_finished: AtomicCounter,
    providers: CaptureInputProviderActivityCounters,
    last_signal: RwLock<Option<CaptureInputSignalRuntimeSnapshot>>,
}

impl CaptureInputActivityRuntimeState {
    pub(crate) fn reset(&self) {
        self.inner.sequence.reset();
        self.inner.poll_events.reset();
        self.inner.poll_progress.reset();
        self.inner.poll_idle.reset();
        self.inner.poll_finished.reset();
        self.inner.providers.reset();
        *self
            .inner
            .last_signal
            .write()
            .expect("capture input activity lock poisoned") = None;
    }

    pub(crate) fn record_poll(&self, poll: &CapturePoll) {
        self.record_poll_at(poll, current_unix_time_ns());
    }

    fn record_poll_at(&self, poll: &CapturePoll, observed_unix_ns: u64) {
        let sequence = self.inner.sequence.increment();
        let signal = match poll {
            CapturePoll::Event(event) => {
                self.inner.poll_events.increment();
                self.record_event(event, sequence, observed_unix_ns)
            }
            CapturePoll::Progress => {
                self.inner.poll_progress.increment();
                CaptureInputSignalRuntimeSnapshot::Progress {
                    sequence,
                    observed_unix_ns,
                }
            }
            CapturePoll::Idle => {
                self.inner.poll_idle.increment();
                CaptureInputSignalRuntimeSnapshot::Idle {
                    sequence,
                    observed_unix_ns,
                }
            }
            CapturePoll::Finished => {
                self.inner.poll_finished.increment();
                CaptureInputSignalRuntimeSnapshot::Finished {
                    sequence,
                    observed_unix_ns,
                }
            }
        };
        *self
            .inner
            .last_signal
            .write()
            .expect("capture input activity lock poisoned") = Some(signal);
    }

    pub(crate) fn snapshot(&self) -> CaptureInputActivityRuntimeSnapshot {
        let events = self.inner.poll_events.load();
        let progress = self.inner.poll_progress.load();
        let idle = self.inner.poll_idle.load();
        let finished = self.inner.poll_finished.load();
        let providers = self.inner.providers.snapshot();
        let (capture_events, output_loss_events, lost_events) =
            capture_event_totals_from_providers(&providers);
        CaptureInputActivityRuntimeSnapshot {
            polls: CaptureInputPollActivityRuntimeSnapshot {
                total: [events, progress, idle, finished]
                    .into_iter()
                    .fold(0_u64, u64::saturating_add),
                events,
                progress,
                idle,
                finished,
            },
            capture_events,
            output_loss_events,
            lost_events,
            providers,
            last_signal: self
                .inner
                .last_signal
                .read()
                .expect("capture input activity lock poisoned")
                .clone(),
        }
    }

    fn record_event(
        &self,
        event: &CaptureEvent,
        sequence: u64,
        observed_unix_ns: u64,
    ) -> CaptureInputSignalRuntimeSnapshot {
        match event {
            CaptureEvent::Loss(loss) => {
                self.inner
                    .providers
                    .record_output_loss(loss.origin.provider(), loss.loss.lost_events);
                CaptureInputSignalRuntimeSnapshot::OutputLoss {
                    sequence,
                    observed_unix_ns,
                    source: loss.origin.source(),
                    provider: loss.origin.provider(),
                    event_wall_time_unix_ns: loss.timestamp.wall_time_unix_ns,
                    lost_events: loss.loss.lost_events,
                }
            }
            CaptureEvent::Bytes(bytes) => self.event_signal(
                sequence,
                observed_unix_ns,
                bytes.origin.source(),
                bytes.origin.provider(),
                bytes.timestamp.wall_time_unix_ns,
            ),
            CaptureEvent::Gap(gap) => self.event_signal(
                sequence,
                observed_unix_ns,
                gap.origin.source(),
                gap.origin.provider(),
                gap.timestamp.wall_time_unix_ns,
            ),
            CaptureEvent::ConnectionOpened {
                timestamp, origin, ..
            }
            | CaptureEvent::ConnectionClosed {
                timestamp, origin, ..
            } => self.event_signal(
                sequence,
                observed_unix_ns,
                origin.source(),
                origin.provider(),
                timestamp.wall_time_unix_ns,
            ),
        }
    }

    fn event_signal(
        &self,
        sequence: u64,
        observed_unix_ns: u64,
        source: CaptureSource,
        provider: CaptureProviderKind,
        event_wall_time_unix_ns: i64,
    ) -> CaptureInputSignalRuntimeSnapshot {
        self.inner.providers.record_capture_event(provider);
        CaptureInputSignalRuntimeSnapshot::Event {
            sequence,
            observed_unix_ns,
            source,
            provider,
            event_wall_time_unix_ns,
        }
    }
}

fn current_unix_time_ns() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    u64::try_from(nanos).unwrap_or(u64::MAX)
}

pub(crate) struct ActivityObservedCaptureInput {
    inner: Box<dyn CaptureProvider>,
    activity: CaptureInputActivityRuntimeState,
}

impl ActivityObservedCaptureInput {
    pub(crate) fn new(
        inner: Box<dyn CaptureProvider>,
        activity: CaptureInputActivityRuntimeState,
    ) -> Self {
        Self { inner, activity }
    }
}

impl CaptureProvider for ActivityObservedCaptureInput {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn capabilities(&self) -> Vec<CapabilityState> {
        self.inner.capabilities()
    }

    fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
        let poll = self.inner.poll_next()?;
        self.activity.record_poll(&poll);
        Ok(poll)
    }

    fn drain_before_handoff(&mut self) -> Result<CapturePoll, CaptureError> {
        let poll = self.inner.drain_before_handoff()?;
        self.activity.record_poll(&poll);
        Ok(poll)
    }

    fn runtime_diagnostics(&mut self) -> CaptureProviderRuntimeDiagnostics {
        self.inner.runtime_diagnostics()
    }
}

fn capture_event_totals_from_providers(
    providers: &[CaptureInputProviderActivityRuntimeSnapshot],
) -> (u64, u64, u64) {
    providers
        .iter()
        .fold((0_u64, 0_u64, 0_u64), |totals, provider| {
            (
                totals.0.saturating_add(provider.capture_events),
                totals.1.saturating_add(provider.output_loss_events),
                totals.2.saturating_add(provider.lost_events),
            )
        })
}

#[derive(Debug, Default)]
struct CaptureInputProviderActivityCounters {
    replay: CaptureInputProviderCounters,
    ebpf: CaptureInputProviderCounters,
    libpcap: CaptureInputProviderCounters,
    plaintext: CaptureInputProviderCounters,
    interception: CaptureInputProviderCounters,
}

impl CaptureInputProviderActivityCounters {
    fn reset(&self) {
        for (_, counters) in self.all_provider_counters() {
            counters.reset();
        }
    }

    fn record_capture_event(&self, provider: CaptureProviderKind) {
        self.for_provider(provider).capture_events.increment();
    }

    fn record_output_loss(&self, provider: CaptureProviderKind, lost_events: u64) {
        let counters = self.for_provider(provider);
        counters.output_loss_events.increment();
        counters.lost_events.add(lost_events);
    }

    fn snapshot(&self) -> Vec<CaptureInputProviderActivityRuntimeSnapshot> {
        self.all_provider_counters()
            .into_iter()
            .filter_map(|(provider, counters)| counters.snapshot(provider))
            .collect()
    }

    fn for_provider(&self, provider: CaptureProviderKind) -> &CaptureInputProviderCounters {
        match provider {
            CaptureProviderKind::Replay => &self.replay,
            CaptureProviderKind::Ebpf => &self.ebpf,
            CaptureProviderKind::Libpcap => &self.libpcap,
            CaptureProviderKind::Plaintext => &self.plaintext,
            CaptureProviderKind::Interception => &self.interception,
        }
    }

    fn all_provider_counters(&self) -> [(CaptureProviderKind, &CaptureInputProviderCounters); 5] {
        CaptureProviderKind::ALL.map(|provider| (provider, self.for_provider(provider)))
    }
}

#[derive(Debug, Default)]
struct CaptureInputProviderCounters {
    capture_events: AtomicCounter,
    output_loss_events: AtomicCounter,
    lost_events: AtomicCounter,
}

impl CaptureInputProviderCounters {
    fn reset(&self) {
        self.capture_events.reset();
        self.output_loss_events.reset();
        self.lost_events.reset();
    }

    fn snapshot(
        &self,
        provider: CaptureProviderKind,
    ) -> Option<CaptureInputProviderActivityRuntimeSnapshot> {
        let capture_events = self.capture_events.load();
        let output_loss_events = self.output_loss_events.load();
        let lost_events = self.lost_events.load();
        (capture_events > 0 || output_loss_events > 0 || lost_events > 0).then_some(
            CaptureInputProviderActivityRuntimeSnapshot {
                provider,
                capture_events,
                output_loss_events,
                lost_events,
            },
        )
    }
}

#[derive(Debug, Default)]
struct AtomicCounter(AtomicU64);

impl AtomicCounter {
    fn reset(&self) {
        self.0.store(0, Ordering::Relaxed);
    }

    fn increment(&self) -> u64 {
        self.add(1)
    }

    fn add(&self, delta: u64) -> u64 {
        let previous = self
            .0
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.saturating_add(delta))
            })
            .unwrap_or_else(|value| value);
        previous.saturating_add(delta)
    }

    fn load(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use probe_core::{
        AddressPort, CaptureLoss, CaptureOrigin, EnforcementEvidence, FlowContext, FlowIdentity,
        ObservationOnlyReason, ProcessContext, ProcessIdentity, Timestamp, TransportProtocol,
    };

    use super::*;

    #[test]
    fn observed_input_records_poll_event_and_loss_activity()
    -> Result<(), Box<dyn std::error::Error>> {
        let activity = CaptureInputActivityRuntimeState::default();
        let event = CaptureEvent::ConnectionOpened {
            timestamp: timestamp(11),
            flow: flow(),
            origin: CaptureOrigin::from_source(CaptureSource::Libpcap),
        };
        let loss = CaptureEvent::Loss(capture::CapturedLoss {
            timestamp: timestamp(17),
            origin: CaptureOrigin::from_source(CaptureSource::EbpfSyscall),
            enforcement_evidence: EnforcementEvidence::observation_only(
                ObservationOnlyReason::ProviderCaptureLoss,
            ),
            loss: CaptureLoss {
                lost_events: 3,
                reason: "ringbuf reserve failed".to_string(),
            },
        });
        let mut provider = ActivityObservedCaptureInput::new(
            Box::new(FakeProvider::new([
                CapturePoll::event(event.clone()),
                CapturePoll::Progress,
                CapturePoll::event(loss.clone()),
                CapturePoll::Idle,
                CapturePoll::Finished,
            ])),
            activity.clone(),
        );

        assert_eq!(provider.poll_next()?, CapturePoll::event(event));
        assert_eq!(provider.poll_next()?, CapturePoll::Progress);
        assert_eq!(provider.poll_next()?, CapturePoll::event(loss));
        assert_eq!(provider.poll_next()?, CapturePoll::Idle);
        assert_eq!(provider.poll_next()?, CapturePoll::Finished);

        let snapshot = activity.snapshot();
        assert_eq!(snapshot.polls.total, 5);
        assert_eq!(snapshot.polls.events, 2);
        assert_eq!(snapshot.polls.progress, 1);
        assert_eq!(snapshot.polls.idle, 1);
        assert_eq!(snapshot.polls.finished, 1);
        assert_eq!(snapshot.capture_events, 1);
        assert_eq!(snapshot.output_loss_events, 1);
        assert_eq!(snapshot.lost_events, 3);
        let libpcap = snapshot
            .provider_activity(CaptureProviderKind::Libpcap)
            .expect("libpcap provider activity");
        assert_eq!(libpcap.capture_events, 1);
        assert_eq!(libpcap.output_loss_events, 0);
        assert_eq!(libpcap.lost_events, 0);
        let ebpf = snapshot
            .provider_activity(CaptureProviderKind::Ebpf)
            .expect("eBPF provider activity");
        assert_eq!(ebpf.capture_events, 0);
        assert_eq!(ebpf.output_loss_events, 1);
        assert_eq!(ebpf.lost_events, 3);
        assert!(matches!(
            snapshot.last_signal,
            Some(CaptureInputSignalRuntimeSnapshot::Finished {
                sequence: 5,
                observed_unix_ns
            }) if observed_unix_ns > 0
        ));
        Ok(())
    }

    #[test]
    fn observed_input_activity_saturates_loss_counters() {
        let activity = CaptureInputActivityRuntimeState::default();

        activity.record_poll_at(&CapturePoll::event(capture_loss(u64::MAX)), 100);
        activity.record_poll_at(&CapturePoll::event(capture_loss(1)), 200);

        let snapshot = activity.snapshot();
        assert_eq!(snapshot.output_loss_events, 2);
        assert_eq!(snapshot.lost_events, u64::MAX);
        assert!(matches!(
            snapshot.last_signal,
            Some(CaptureInputSignalRuntimeSnapshot::OutputLoss {
                sequence: 2,
                observed_unix_ns: 200,
                lost_events: 1,
                ..
            })
        ));
    }

    struct FakeProvider {
        polls: VecDeque<CapturePoll>,
    }

    impl FakeProvider {
        fn new(polls: impl IntoIterator<Item = CapturePoll>) -> Self {
            Self {
                polls: polls.into_iter().collect(),
            }
        }
    }

    impl CaptureProvider for FakeProvider {
        fn name(&self) -> &'static str {
            "fake"
        }

        fn capabilities(&self) -> Vec<CapabilityState> {
            Vec::new()
        }

        fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
            Ok(self.polls.pop_front().unwrap_or(CapturePoll::Finished))
        }

        fn drain_before_handoff(&mut self) -> Result<CapturePoll, CaptureError> {
            self.poll_next()
        }
    }

    fn capture_loss(lost_events: u64) -> CaptureEvent {
        CaptureEvent::Loss(capture::CapturedLoss {
            timestamp: timestamp(17),
            origin: CaptureOrigin::from_source(CaptureSource::EbpfSyscall),
            enforcement_evidence: EnforcementEvidence::observation_only(
                ObservationOnlyReason::ProviderCaptureLoss,
            ),
            loss: CaptureLoss {
                lost_events,
                reason: "ringbuf reserve failed".to_string(),
            },
        })
    }

    fn timestamp(monotonic_ns: u64) -> Timestamp {
        Timestamp {
            monotonic_ns,
            wall_time_unix_ns: i64::try_from(monotonic_ns).expect("test timestamp fits i64"),
        }
    }

    fn flow() -> FlowContext {
        let process = ProcessIdentity {
            pid: 1,
            tgid: 1,
            start_time_ticks: 1,
            boot_id: "boot".to_string(),
            exe_path: "probe-test".to_string(),
            cmdline_hash: "hash".to_string(),
            uid: 1000,
            gid: 1000,
            cgroup: None,
            systemd_service: None,
            container_id: None,
            runtime_hint: None,
        };
        let local = AddressPort {
            address: "127.0.0.1".to_string(),
            port: 41000,
        };
        let remote = AddressPort {
            address: "127.0.0.1".to_string(),
            port: 8080,
        };
        FlowContext {
            id: FlowIdentity::stable(&process, &local, &remote, TransportProtocol::Tcp, 1, None),
            process: ProcessContext {
                identity: process,
                name: "probe-test".to_string(),
                cmdline: vec!["probe-test".to_string()],
            },
            local,
            remote,
            protocol: TransportProtocol::Tcp,
            start_monotonic_ns: 1,
            socket_cookie: None,
            attribution_confidence: 100,
        }
    }
}
