use probe_core::CapabilityState;

use crate::{CaptureError, CapturePoll, CaptureProvider, CaptureProviderRuntimeDiagnostics};

type DisableHandler = Box<dyn Fn(&str)>;

pub struct CaptureMultiplexer {
    providers: Vec<MultiplexedProvider>,
    next_index: usize,
}

impl CaptureMultiplexer {
    pub fn new(providers: impl IntoIterator<Item = Box<dyn CaptureProvider>>) -> Self {
        Self::from_providers(providers.into_iter().map(MultiplexedProvider::required))
    }

    pub fn from_providers(providers: impl IntoIterator<Item = MultiplexedProvider>) -> Self {
        Self {
            providers: providers.into_iter().collect(),
            next_index: 0,
        }
    }

    fn poll_round(&mut self) -> Result<CapturePoll, CaptureError> {
        self.poll_with(|provider| provider.poll_next())
    }

    fn drain_round_before_handoff(&mut self) -> Result<CapturePoll, CaptureError> {
        self.poll_with(|provider| provider.drain_before_handoff())
    }

    fn poll_with(
        &mut self,
        mut poll: impl FnMut(&mut dyn CaptureProvider) -> Result<CapturePoll, CaptureError>,
    ) -> Result<CapturePoll, CaptureError> {
        if self.providers.is_empty() || self.providers.iter().all(|provider| !provider.is_active())
        {
            return Ok(CapturePoll::Finished);
        }

        let provider_count = self.providers.len();
        let mut made_progress = false;
        for _ in 0..provider_count {
            let index = self.next_index % provider_count;
            self.next_index = (index + 1) % provider_count;
            let provider = &mut self.providers[index];
            if !provider.is_active() {
                continue;
            }
            match provider.poll_with(&mut poll) {
                Ok(CapturePoll::Event(event)) => return Ok(CapturePoll::Event(event)),
                Ok(CapturePoll::Progress) => made_progress = true,
                Ok(CapturePoll::Idle) => {}
                Ok(CapturePoll::Finished) => provider.finish(),
                Err(error) => match provider.failure_policy {
                    MultiplexFailurePolicy::Required => return Err(error),
                    MultiplexFailurePolicy::BestEffort => {
                        provider.disable_after_error(error);
                        made_progress = true;
                    }
                },
            }
        }

        if self.providers.iter().all(|provider| !provider.is_active()) {
            Ok(CapturePoll::Finished)
        } else if made_progress {
            Ok(CapturePoll::Progress)
        } else {
            Ok(CapturePoll::Idle)
        }
    }
}

impl CaptureProvider for CaptureMultiplexer {
    fn name(&self) -> &'static str {
        "multiplex"
    }

    fn capabilities(&self) -> Vec<CapabilityState> {
        self.providers
            .iter()
            .flat_map(MultiplexedProvider::capabilities)
            .collect()
    }

    fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
        self.poll_round()
    }

    fn drain_before_handoff(&mut self) -> Result<CapturePoll, CaptureError> {
        self.drain_round_before_handoff()
    }

    fn runtime_diagnostics(&mut self) -> CaptureProviderRuntimeDiagnostics {
        self.providers.iter_mut().fold(
            CaptureProviderRuntimeDiagnostics::default(),
            |mut diagnostics, provider| {
                diagnostics.merge(provider.runtime_diagnostics());
                diagnostics
            },
        )
    }
}

pub struct MultiplexedProvider {
    failure_policy: MultiplexFailurePolicy,
    state: MultiplexedProviderState,
    disable_handler: Option<DisableHandler>,
}

impl MultiplexedProvider {
    pub fn required(provider: Box<dyn CaptureProvider>) -> Self {
        Self::new(provider, MultiplexFailurePolicy::Required)
    }

    pub fn best_effort(provider: Box<dyn CaptureProvider>) -> Self {
        Self::new(provider, MultiplexFailurePolicy::BestEffort)
    }

    pub fn best_effort_with_disable_handler(
        provider: Box<dyn CaptureProvider>,
        handler: impl Fn(&str) + 'static,
    ) -> Self {
        Self::new(provider, MultiplexFailurePolicy::BestEffort)
            .with_disable_handler(Box::new(handler))
    }

    fn new(provider: Box<dyn CaptureProvider>, failure_policy: MultiplexFailurePolicy) -> Self {
        Self {
            failure_policy,
            state: MultiplexedProviderState::Active { provider },
            disable_handler: None,
        }
    }

    fn with_disable_handler(mut self, handler: DisableHandler) -> Self {
        self.disable_handler = Some(handler);
        self
    }

    fn is_active(&self) -> bool {
        matches!(self.state, MultiplexedProviderState::Active { .. })
    }

    fn poll_with(
        &mut self,
        poll: impl FnOnce(&mut dyn CaptureProvider) -> Result<CapturePoll, CaptureError>,
    ) -> Result<CapturePoll, CaptureError> {
        match &mut self.state {
            MultiplexedProviderState::Active { provider } => poll(provider.as_mut()),
            _ => Ok(CapturePoll::Finished),
        }
    }

    fn finish(&mut self) {
        let state = self.take_state();
        let MultiplexedProviderState::Active { provider } = state else {
            self.state = state;
            return;
        };
        let capabilities = provider.capabilities();
        drop(provider);
        self.state = MultiplexedProviderState::Finished { capabilities };
    }

    fn disable_after_error(&mut self, error: CaptureError) {
        let state = self.take_state();
        let MultiplexedProviderState::Active { provider } = state else {
            self.state = state;
            return;
        };
        let provider_name = provider.name();
        let reason =
            format!("best-effort capture provider {provider_name} disabled after error: {error}");
        let capabilities = provider
            .capabilities()
            .into_iter()
            .map(|capability| CapabilityState::unavailable(capability.kind, reason.clone()))
            .collect();
        drop(provider);
        if let Some(handler) = &self.disable_handler {
            handler(&reason);
        }
        self.state = MultiplexedProviderState::Disabled { capabilities };
    }

    fn capabilities(&self) -> Vec<CapabilityState> {
        match &self.state {
            MultiplexedProviderState::Active { provider } => provider.capabilities(),
            MultiplexedProviderState::Finished { capabilities } => capabilities.clone(),
            MultiplexedProviderState::Disabled { capabilities, .. } => capabilities.clone(),
        }
    }

    fn runtime_diagnostics(&mut self) -> CaptureProviderRuntimeDiagnostics {
        let MultiplexedProviderState::Active { provider } = &mut self.state else {
            return CaptureProviderRuntimeDiagnostics::default();
        };
        provider.runtime_diagnostics()
    }

    fn take_state(&mut self) -> MultiplexedProviderState {
        std::mem::replace(
            &mut self.state,
            MultiplexedProviderState::Finished {
                capabilities: Vec::new(),
            },
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MultiplexFailurePolicy {
    Required,
    BestEffort,
}

enum MultiplexedProviderState {
    Active { provider: Box<dyn CaptureProvider> },
    Finished { capabilities: Vec<CapabilityState> },
    Disabled { capabilities: Vec<CapabilityState> },
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        collections::VecDeque,
        rc::Rc,
    };

    use bytes::Bytes;
    use probe_core::{
        AddressPort, CapabilityKind, CaptureSource, Direction, FlowContext, FlowIdentity,
        ProcessContext, ProcessIdentity, Timestamp, TransportProtocol,
    };

    use crate::{
        CaptureEvent, CapturedBytes, EbpfProcessObservationRuntimeDiagnostics,
        EbpfProcessObservationTracepointDiagnostics, EbpfProcessObservationTracepointFiring,
        EbpfProcessPayloadAllowanceDiagnostics,
    };

    use super::*;

    #[test]
    fn multiplexer_keeps_polling_after_one_source_finishes()
    -> Result<(), Box<dyn std::error::Error>> {
        let first = VecProvider::new([captured_bytes("first")]);
        let second = VecProvider::new([captured_bytes("second")]);
        let mut provider = CaptureMultiplexer::new([
            Box::new(first) as Box<dyn CaptureProvider>,
            Box::new(second),
        ]);

        assert_bytes_payload(provider.next()?, b"first");
        assert_bytes_payload(provider.next()?, b"second");
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn multiplexer_reports_idle_until_an_active_source_emits()
    -> Result<(), Box<dyn std::error::Error>> {
        let idle = IdleThenProvider {
            idle_before_event: 1,
            event: Some(captured_bytes("late")),
        };
        let mut provider = CaptureMultiplexer::new([Box::new(idle) as Box<dyn CaptureProvider>]);

        assert_eq!(provider.poll_next()?, CapturePoll::Idle);
        assert_bytes_payload(
            Some(match provider.poll_next()? {
                CapturePoll::Event(event) => *event,
                other => panic!("expected event after idle, got {other:?}"),
            }),
            b"late",
        );
        assert_eq!(provider.poll_next()?, CapturePoll::Finished);
        Ok(())
    }

    #[test]
    fn multiplexer_reports_progress_without_marking_source_idle_or_finished()
    -> Result<(), Box<dyn std::error::Error>> {
        let progress = ProgressThenProvider {
            progressed: false,
            event: Some(captured_bytes("after-progress")),
        };
        let mut provider =
            CaptureMultiplexer::new([Box::new(progress) as Box<dyn CaptureProvider>]);

        assert_eq!(provider.poll_next()?, CapturePoll::Progress);
        assert_bytes_payload(
            Some(match provider.poll_next()? {
                CapturePoll::Event(event) => *event,
                other => panic!("expected event after progress, got {other:?}"),
            }),
            b"after-progress",
        );
        assert_eq!(provider.poll_next()?, CapturePoll::Finished);
        Ok(())
    }

    #[test]
    fn multiplexer_drains_handoff_without_polling_regular_path()
    -> Result<(), Box<dyn std::error::Error>> {
        let poll_count = Rc::new(Cell::new(0));
        let drain_count = Rc::new(Cell::new(0));
        let source = HandoffDrainProvider {
            poll_count: Rc::clone(&poll_count),
            drain_count: Rc::clone(&drain_count),
            handoff_event: Some(captured_bytes("handoff")),
        };
        let mut provider = CaptureMultiplexer::new([Box::new(source) as Box<dyn CaptureProvider>]);

        assert_bytes_payload(
            Some(match provider.drain_before_handoff()? {
                CapturePoll::Event(event) => *event,
                other => panic!("expected handoff event, got {other:?}"),
            }),
            b"handoff",
        );

        assert_eq!(poll_count.get(), 0);
        assert_eq!(drain_count.get(), 1);
        Ok(())
    }

    #[test]
    fn multiplexer_disables_best_effort_source_after_error()
    -> Result<(), Box<dyn std::error::Error>> {
        let primary = VecProvider::new([captured_bytes("primary")]);
        let sidecar = ErrorProvider;
        let mut provider = CaptureMultiplexer::from_providers([
            MultiplexedProvider::best_effort(Box::new(sidecar)),
            MultiplexedProvider::required(Box::new(primary)),
        ]);

        assert_bytes_payload(provider.next()?, b"primary");
        assert!(provider.next()?.is_none());
        assert_eq!(
            provider.capabilities(),
            vec![CapabilityState::unavailable(
                CapabilityKind::LibsslUprobe,
                "best-effort capture provider error disabled after error: capture provider error failed: boom",
            )]
        );
        Ok(())
    }

    #[test]
    fn multiplexer_notifies_best_effort_disable_handler_after_error()
    -> Result<(), Box<dyn std::error::Error>> {
        let disabled_reason = Rc::new(RefCell::new(None));
        let reason_sink = Rc::clone(&disabled_reason);
        let primary = VecProvider::new([captured_bytes("primary")]);
        let sidecar = ErrorProvider;
        let mut provider = CaptureMultiplexer::from_providers([
            MultiplexedProvider::best_effort_with_disable_handler(
                Box::new(sidecar),
                move |reason| {
                    *reason_sink.borrow_mut() = Some(reason.to_string());
                },
            ),
            MultiplexedProvider::required(Box::new(primary)),
        ]);

        assert_bytes_payload(provider.next()?, b"primary");

        let reason = disabled_reason
            .borrow()
            .clone()
            .expect("best-effort disable handler should be called");
        assert_eq!(
            reason,
            "best-effort capture provider error disabled after error: capture provider error failed: boom"
        );
        Ok(())
    }

    #[test]
    fn multiplexer_drops_best_effort_source_after_error() -> Result<(), Box<dyn std::error::Error>>
    {
        let dropped = Rc::new(Cell::new(false));
        let primary = VecProvider::new([captured_bytes("primary")]);
        let sidecar = DropNotifyErrorProvider {
            dropped: Rc::clone(&dropped),
        };
        let mut provider = CaptureMultiplexer::from_providers([
            MultiplexedProvider::best_effort(Box::new(sidecar)),
            MultiplexedProvider::required(Box::new(primary)),
        ]);

        assert_bytes_payload(provider.next()?, b"primary");

        assert!(dropped.get());
        Ok(())
    }

    #[test]
    fn multiplexer_propagates_required_source_error() {
        let mut provider =
            CaptureMultiplexer::new([Box::new(ErrorProvider) as Box<dyn CaptureProvider>]);

        let error = provider
            .poll_next()
            .expect_err("required provider errors must stop the multiplexer");

        assert!(error.to_string().contains("boom"));
    }

    #[test]
    fn multiplexer_merges_active_provider_runtime_diagnostics() {
        let mut provider = CaptureMultiplexer::new([
            Box::new(VecProvider::new([])) as Box<dyn CaptureProvider>,
            Box::new(DiagnosticProvider),
        ]);

        let diagnostics = provider
            .runtime_diagnostics()
            .into_ebpf_process_observation()
            .expect("multiplexer should expose active provider diagnostics");
        let tracepoints = diagnostics
            .tracepoints
            .expect("tracepoint diagnostics should be available");
        let firings = tracepoints.firings;
        assert_eq!(firings.len(), 1);
        assert_eq!(firings[0].program_name, "connect_enter");
        assert_eq!(firings[0].category, "syscalls");
        assert_eq!(firings[0].tracepoint_name, "sys_enter_connect");
        assert_eq!(firings[0].firing_count, 3);
    }

    fn assert_bytes_payload(event: Option<CaptureEvent>, expected: &[u8]) {
        match event.expect("expected capture event") {
            CaptureEvent::Bytes(bytes) => {
                assert_eq!(bytes.bytes.as_ref(), expected);
            }
            event => panic!("expected bytes event, got {event:?}"),
        }
    }

    fn captured_bytes(payload: &'static str) -> CaptureEvent {
        CaptureEvent::Bytes(CapturedBytes {
            timestamp: Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            flow: demo_flow(),
            origin: probe_core::CaptureOrigin::from_source(CaptureSource::Replay),
            direction: Direction::Outbound,
            stream_offset: 0,
            bytes: Bytes::from_static(payload.as_bytes()),
            attribution_confidence: 100,
            degraded: false,
            degradation_reason: None,
            enforcement_evidence: probe_core::EnforcementEvidence::default(),
            enforcement_evidence_propagation: crate::EnforcementEvidencePropagation::Event,
        })
    }

    fn demo_flow() -> FlowContext {
        let process = ProcessIdentity {
            pid: 1,
            tgid: 1,
            start_time_ticks: 1,
            boot_id: "boot".to_string(),
            exe_path: "/bin/demo".to_string(),
            cmdline_hash: "hash".to_string(),
            uid: 0,
            gid: 0,
            cgroup: None,
            systemd_service: None,
            container_id: None,
            runtime_hint: None,
        };
        let local = AddressPort {
            address: "127.0.0.1".to_string(),
            port: 50_000,
        };
        let remote = AddressPort {
            address: "127.0.0.1".to_string(),
            port: 443,
        };
        FlowContext {
            id: FlowIdentity::stable(&process, &local, &remote, TransportProtocol::Tcp, 1, None),
            process: ProcessContext {
                identity: process,
                name: "demo".to_string(),
                cmdline: vec!["demo".to_string()],
            },
            local,
            remote,
            protocol: TransportProtocol::Tcp,
            start_monotonic_ns: 1,
            socket_cookie: None,
            attribution_confidence: 100,
        }
    }

    struct VecProvider {
        events: VecDeque<CaptureEvent>,
    }

    impl VecProvider {
        fn new(events: impl IntoIterator<Item = CaptureEvent>) -> Self {
            Self {
                events: events.into_iter().collect(),
            }
        }
    }

    impl CaptureProvider for VecProvider {
        fn name(&self) -> &'static str {
            "vec"
        }

        fn capabilities(&self) -> Vec<CapabilityState> {
            Vec::new()
        }

        fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
            Ok(self
                .events
                .pop_front()
                .map(CapturePoll::event)
                .unwrap_or(CapturePoll::Finished))
        }

        fn drain_before_handoff(&mut self) -> Result<CapturePoll, CaptureError> {
            self.poll_next()
        }
    }

    struct ErrorProvider;

    impl CaptureProvider for ErrorProvider {
        fn name(&self) -> &'static str {
            "error"
        }

        fn capabilities(&self) -> Vec<CapabilityState> {
            vec![CapabilityState::degraded(
                CapabilityKind::LibsslUprobe,
                "test sidecar starts degraded",
            )]
        }

        fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
            Err(CaptureError::provider("error", "boom"))
        }

        fn drain_before_handoff(&mut self) -> Result<CapturePoll, CaptureError> {
            self.poll_next()
        }
    }

    struct DropNotifyErrorProvider {
        dropped: Rc<Cell<bool>>,
    }

    impl CaptureProvider for DropNotifyErrorProvider {
        fn name(&self) -> &'static str {
            "drop_notify_error"
        }

        fn capabilities(&self) -> Vec<CapabilityState> {
            vec![CapabilityState::degraded(
                CapabilityKind::LibsslUprobe,
                "test sidecar starts degraded",
            )]
        }

        fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
            Err(CaptureError::provider("drop_notify_error", "boom"))
        }

        fn drain_before_handoff(&mut self) -> Result<CapturePoll, CaptureError> {
            self.poll_next()
        }
    }

    impl Drop for DropNotifyErrorProvider {
        fn drop(&mut self) {
            self.dropped.set(true);
        }
    }

    struct DiagnosticProvider;

    impl CaptureProvider for DiagnosticProvider {
        fn name(&self) -> &'static str {
            "diagnostic"
        }

        fn capabilities(&self) -> Vec<CapabilityState> {
            Vec::new()
        }

        fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
            Ok(CapturePoll::Progress)
        }

        fn drain_before_handoff(&mut self) -> Result<CapturePoll, CaptureError> {
            Ok(CapturePoll::Idle)
        }

        fn runtime_diagnostics(&mut self) -> CaptureProviderRuntimeDiagnostics {
            CaptureProviderRuntimeDiagnostics::from_ebpf_process_observation(
                EbpfProcessObservationRuntimeDiagnostics {
                    tracepoints: Ok(EbpfProcessObservationTracepointDiagnostics {
                        firings: vec![EbpfProcessObservationTracepointFiring {
                            program_name: "connect_enter",
                            category: "syscalls",
                            tracepoint_name: "sys_enter_connect",
                            firing_count: 3,
                        }],
                        active_liveness: Err(
                            "active liveness diagnostics are not emitted by this test provider"
                                .to_string(),
                        ),
                    }),
                    process_payload_allowance: EbpfProcessPayloadAllowanceDiagnostics::default(),
                    payload_gates: Ok(Vec::new()),
                },
            )
        }
    }

    struct IdleThenProvider {
        idle_before_event: u8,
        event: Option<CaptureEvent>,
    }

    impl CaptureProvider for IdleThenProvider {
        fn name(&self) -> &'static str {
            "idle_then"
        }

        fn capabilities(&self) -> Vec<CapabilityState> {
            Vec::new()
        }

        fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
            if self.idle_before_event > 0 {
                self.idle_before_event -= 1;
                return Ok(CapturePoll::Idle);
            }
            Ok(self
                .event
                .take()
                .map(CapturePoll::event)
                .unwrap_or(CapturePoll::Finished))
        }

        fn drain_before_handoff(&mut self) -> Result<CapturePoll, CaptureError> {
            Ok(CapturePoll::Idle)
        }
    }

    struct ProgressThenProvider {
        progressed: bool,
        event: Option<CaptureEvent>,
    }

    impl CaptureProvider for ProgressThenProvider {
        fn name(&self) -> &'static str {
            "progress_then"
        }

        fn capabilities(&self) -> Vec<CapabilityState> {
            Vec::new()
        }

        fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
            if !self.progressed {
                self.progressed = true;
                return Ok(CapturePoll::Progress);
            }
            Ok(self
                .event
                .take()
                .map(CapturePoll::event)
                .unwrap_or(CapturePoll::Finished))
        }

        fn drain_before_handoff(&mut self) -> Result<CapturePoll, CaptureError> {
            Ok(CapturePoll::Idle)
        }
    }

    struct HandoffDrainProvider {
        poll_count: Rc<Cell<u64>>,
        drain_count: Rc<Cell<u64>>,
        handoff_event: Option<CaptureEvent>,
    }

    impl CaptureProvider for HandoffDrainProvider {
        fn name(&self) -> &'static str {
            "handoff_drain"
        }

        fn capabilities(&self) -> Vec<CapabilityState> {
            Vec::new()
        }

        fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
            self.poll_count.set(self.poll_count.get().saturating_add(1));
            Ok(CapturePoll::Idle)
        }

        fn drain_before_handoff(&mut self) -> Result<CapturePoll, CaptureError> {
            self.drain_count
                .set(self.drain_count.get().saturating_add(1));
            Ok(self
                .handoff_event
                .take()
                .map(CapturePoll::event)
                .unwrap_or(CapturePoll::Idle))
        }
    }
}
