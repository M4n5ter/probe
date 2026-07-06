use std::{
    collections::VecDeque,
    time::{SystemTime, UNIX_EPOCH},
};

use probe_core::{
    CancellationToken, CapabilityKind, CapabilityState, CaptureSource, CompiledSelector,
    FlowContext, Timestamp,
};
use thiserror::Error;

use crate::output_loss::{OutputLossTracker, provider_output_loss_event};
use crate::{
    CaptureError, CaptureEvent, CapturePoll, CaptureProvider, PlaintextEvent,
    tls::LibsslUprobeAttachPlan,
};

use super::{
    bridge::{
        LibsslUprobeFlowResolver, is_unresolved_libssl_flow, libssl_plaintext_events_from_sample,
    },
    loss::TlsPlaintextLossTracker,
    probe::{
        LibsslUprobePlaintextProbe, LibsslUprobePlaintextProbeConfig,
        LibsslUprobePlaintextProbeError, LibsslUprobePlaintextProbeLoad,
        LibsslUprobePlaintextReconcile,
    },
    record::LibsslUprobePlaintextSample,
};

pub(in crate::tls::plaintext) trait LibsslUprobePlaintextSampleSource {
    fn reconcile_libssl_uprobes(
        &mut self,
        next_plan: LibsslUprobeAttachPlan,
    ) -> Result<LibsslUprobePlaintextReconcile, CaptureError> {
        let _ = next_plan;
        Err(CaptureError::provider(
            "libssl_uprobe_plaintext",
            "TLS plaintext sample source does not support dynamic libssl uprobe reconcile",
        ))
    }

    fn next_tls_plaintext_sample(
        &mut self,
    ) -> Result<Option<LibsslUprobePlaintextSample>, CaptureError>;

    fn tls_plaintext_output_loss_count(&mut self) -> Result<u64, CaptureError> {
        Ok(0)
    }
}

pub struct LibsslUprobePlaintextProvider {
    source: Box<dyn LibsslUprobePlaintextSampleSource>,
    resolver: Box<dyn LibsslUprobeFlowResolver>,
    pending_events: VecDeque<CaptureEvent>,
    output_selector: Option<CompiledSelector>,
    output_loss: OutputLossTracker,
    tracked_loss_flows: TlsPlaintextLossTracker,
    clock: LibsslUprobePlaintextClock,
    idle_policy: LibsslUprobePlaintextIdlePolicy,
    poisoned_reason: Option<String>,
}

pub enum LibsslUprobePlaintextOpen {
    Enabled(Box<LibsslUprobePlaintextProvider>),
    Disabled { reason: String },
}

#[derive(Debug, Error)]
pub enum LibsslUprobePlaintextOpenError {
    #[error("libssl uprobe plaintext startup was cancelled")]
    StartupCancelled,
}

impl LibsslUprobePlaintextProvider {
    pub fn open(
        config: LibsslUprobePlaintextProbeConfig,
        resolver: Box<dyn LibsslUprobeFlowResolver>,
    ) -> Result<Self, CaptureError> {
        Self::open_with_cancellation(config, resolver, CancellationToken::default())
    }

    pub fn open_with_cancellation(
        config: LibsslUprobePlaintextProbeConfig,
        resolver: Box<dyn LibsslUprobeFlowResolver>,
        cancellation: CancellationToken,
    ) -> Result<Self, CaptureError> {
        let probe = LibsslUprobePlaintextProbe::load_with_cancellation(config, cancellation)
            .map_err(|error| {
                CaptureError::provider("libssl_uprobe_plaintext", error.to_string())
            })?;
        Ok(Self::from_live_source(Box::new(probe), resolver))
    }

    pub fn open_best_effort(
        config: LibsslUprobePlaintextProbeConfig,
        resolver: Box<dyn LibsslUprobeFlowResolver>,
    ) -> LibsslUprobePlaintextOpen {
        match Self::open_best_effort_with_cancellation(
            config,
            resolver,
            CancellationToken::default(),
        ) {
            Ok(open) => open,
            Err(error) => LibsslUprobePlaintextOpen::Disabled {
                reason: error.to_string(),
            },
        }
    }

    pub fn open_best_effort_with_cancellation(
        config: LibsslUprobePlaintextProbeConfig,
        resolver: Box<dyn LibsslUprobeFlowResolver>,
        cancellation: CancellationToken,
    ) -> Result<LibsslUprobePlaintextOpen, LibsslUprobePlaintextOpenError> {
        match LibsslUprobePlaintextProbe::load_best_effort_with_cancellation(config, cancellation) {
            Ok(LibsslUprobePlaintextProbeLoad::Enabled(probe)) => {
                Ok(LibsslUprobePlaintextOpen::Enabled(Box::new(
                    Self::from_live_source(probe, resolver),
                )))
            }
            Ok(LibsslUprobePlaintextProbeLoad::Disabled { reason }) => {
                Ok(LibsslUprobePlaintextOpen::Disabled { reason })
            }
            Err(LibsslUprobePlaintextProbeError::StartupCancelled) => {
                Err(LibsslUprobePlaintextOpenError::StartupCancelled)
            }
            Err(error) => Ok(LibsslUprobePlaintextOpen::Disabled {
                reason: error.to_string(),
            }),
        }
    }

    pub fn reconcile_libssl_uprobes(
        &mut self,
        next_plan: LibsslUprobeAttachPlan,
    ) -> Result<LibsslUprobePlaintextReconcile, CaptureError> {
        self.ensure_not_poisoned()?;
        match self.source.reconcile_libssl_uprobes(next_plan) {
            Ok(result) => Ok(result),
            Err(error) => Err(self.poison_after_reconcile_error(error)),
        }
    }

    pub fn with_output_selector(mut self, selector: Option<CompiledSelector>) -> Self {
        self.output_selector = selector;
        self
    }

    fn from_live_source(
        source: Box<dyn LibsslUprobePlaintextSampleSource>,
        resolver: Box<dyn LibsslUprobeFlowResolver>,
    ) -> Self {
        Self::with_idle_policy(source, resolver, LibsslUprobePlaintextIdlePolicy::Wait)
    }

    #[cfg(test)]
    pub(in crate::tls::plaintext) fn new(
        source: Box<dyn LibsslUprobePlaintextSampleSource>,
        resolver: Box<dyn LibsslUprobeFlowResolver>,
    ) -> Self {
        Self::with_idle_policy(source, resolver, LibsslUprobePlaintextIdlePolicy::Stop)
    }

    #[cfg(test)]
    fn with_output_loss_check_interval_for_test(mut self, interval: u32) -> Self {
        self.output_loss = OutputLossTracker::new(interval);
        self
    }

    fn with_idle_policy(
        source: Box<dyn LibsslUprobePlaintextSampleSource>,
        resolver: Box<dyn LibsslUprobeFlowResolver>,
        idle_policy: LibsslUprobePlaintextIdlePolicy,
    ) -> Self {
        Self {
            source,
            resolver,
            pending_events: VecDeque::new(),
            output_selector: None,
            output_loss: OutputLossTracker::default(),
            tracked_loss_flows: TlsPlaintextLossTracker::default(),
            clock: LibsslUprobePlaintextClock::default(),
            idle_policy,
            poisoned_reason: None,
        }
    }

    fn poll_event(&mut self) -> Result<CapturePoll, CaptureError> {
        self.ensure_not_poisoned()?;
        if let Some(event) = self.pending_events.pop_front() {
            return Ok(CapturePoll::event(event));
        }
        if self.output_loss.should_check_during_drain()
            && let Some(event) = self.output_loss_events()?
        {
            return Ok(CapturePoll::event(event));
        }
        let Some(sample) = self.source.next_tls_plaintext_sample()? else {
            if let Some(event) = self.output_loss_events()? {
                return Ok(CapturePoll::event(event));
            }
            return Ok(match self.idle_policy {
                #[cfg(test)]
                LibsslUprobePlaintextIdlePolicy::Stop => CapturePoll::Finished,
                LibsslUprobePlaintextIdlePolicy::Wait => CapturePoll::Idle,
            });
        };
        self.output_loss.record_observation();
        let events = libssl_plaintext_events_from_sample(
            &sample,
            self.clock.next_timestamp(),
            self.resolver.as_mut(),
        )?;
        for event in events {
            if !self.allows_event(&event) {
                continue;
            }
            self.tracked_loss_flows.observe_event(&event);
            self.pending_events.push_back(CaptureEvent::from(event));
        }
        Ok(self
            .pending_events
            .pop_front()
            .map(CapturePoll::event)
            .unwrap_or(CapturePoll::Progress))
    }

    fn ensure_not_poisoned(&self) -> Result<(), CaptureError> {
        match &self.poisoned_reason {
            Some(reason) => Err(CaptureError::provider(
                "libssl_uprobe_plaintext",
                reason.clone(),
            )),
            None => Ok(()),
        }
    }

    fn allows_event(&self, event: &PlaintextEvent) -> bool {
        let Some(selector) = &self.output_selector else {
            return true;
        };
        match &event.kind {
            crate::PlaintextEventKind::Bytes(chunk) => {
                selector_allows_flow(selector, &chunk.flow, Some(chunk.direction))
            }
            crate::PlaintextEventKind::Gap(gap) => {
                selector_allows_flow(selector, &gap.flow, Some(gap.gap.direction))
            }
            crate::PlaintextEventKind::ConnectionOpened(connection)
            | crate::PlaintextEventKind::ConnectionClosed(connection) => {
                selector.matches_flow_without_direction(&connection.flow)
            }
        }
    }

    fn poison_after_reconcile_error(&mut self, error: CaptureError) -> CaptureError {
        let reason = match error {
            CaptureError::Provider { provider, reason }
                if provider == "libssl_uprobe_plaintext" =>
            {
                reason
            }
            other => other.to_string(),
        };
        self.pending_events.clear();
        self.poisoned_reason = Some(reason.clone());
        CaptureError::provider("libssl_uprobe_plaintext", reason)
    }

    fn output_loss_events(&mut self) -> Result<Option<CaptureEvent>, CaptureError> {
        let count = self.source.tls_plaintext_output_loss_count()?;
        let lost_events = self.output_loss.checkpoint(count);
        let timestamp = self.clock.next_timestamp();
        let gap_events = self
            .tracked_loss_flows
            .finish_checkpoint(timestamp, lost_events);
        let Some(lost_events) = lost_events else {
            return Ok(None);
        };
        self.pending_events
            .push_back(output_loss_event(timestamp, lost_events));
        self.pending_events.extend(gap_events);
        Ok(self.pending_events.pop_front())
    }
}

fn selector_allows_flow(
    selector: &CompiledSelector,
    flow: &FlowContext,
    direction: Option<probe_core::Direction>,
) -> bool {
    match direction {
        Some(direction) if is_unresolved_libssl_flow(flow) => {
            selector.matches_unattributed_flow(&flow.process, direction)
        }
        Some(direction) => selector.matches_flow(flow, direction),
        None => selector.matches_flow_without_direction(flow),
    }
}

fn output_loss_event(timestamp: Timestamp, lost_events: u64) -> CaptureEvent {
    let reason = format!(
        "eBPF libssl uprobe plaintext output ring buffer could not accept {lost_events} event(s); TLS plaintext parser state may have missed encrypted stream observations"
    );
    provider_output_loss_event(timestamp, lost_events, CaptureSource::LibsslUprobe, reason)
}

impl CaptureProvider for LibsslUprobePlaintextProvider {
    fn name(&self) -> &'static str {
        "libssl_uprobe_plaintext"
    }

    fn capabilities(&self) -> Vec<CapabilityState> {
        vec![CapabilityState::degraded(
            CapabilityKind::LibsslUprobe,
            "libssl uprobe plaintext provider can attach configured uprobes, read bounded TLS plaintext samples, convert output ring-buffer failures to degraded capture_loss events, and fan out conservative unknown-offset gaps to plaintext flows observed since the previous output-loss checkpoint; flow lifecycle and fd-valid ownership remain best-effort",
        )]
    }

    fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
        self.poll_event()
    }

    fn drain_before_handoff(&mut self) -> Result<CapturePoll, CaptureError> {
        self.ensure_not_poisoned()?;
        if let Some(event) = self.pending_events.pop_front() {
            return Ok(CapturePoll::event(event));
        }
        if self.output_loss.should_check_during_drain()
            && let Some(event) = self.output_loss_events()?
        {
            return Ok(CapturePoll::event(event));
        }
        if let Some(event) = self.output_loss_events()? {
            return Ok(CapturePoll::event(event));
        }
        Ok(CapturePoll::Idle)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LibsslUprobePlaintextIdlePolicy {
    #[cfg(test)]
    Stop,
    Wait,
}

#[derive(Default)]
struct LibsslUprobePlaintextClock {
    monotonic_sequence: u64,
}

impl LibsslUprobePlaintextClock {
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
    use std::collections::VecDeque;

    use ebpf_abi::{
        EBPF_TLS_DIRECTION_OUTBOUND, EBPF_TLS_PLAINTEXT_FD_VALID, EBPF_TLS_PLAINTEXT_SAMPLE_BYTES,
        EBPF_TLS_PLAINTEXT_TRUNCATED, EbpfTlsPlaintextEvent, EbpfTlsPlaintextObservation,
    };
    use probe_core::{
        CaptureSource, Direction, ProcessContext, ProcessIdentity, ProcessSelector, Selector,
        TcpConnection, TcpEndpoint, TrafficSelector,
    };
    use tempfile::tempdir;

    use crate::{CaptureProviderKind, EnforcementEvidencePropagation};

    use super::{
        super::bridge::{LibsslResolvedFlow, LibsslUprobeFlowLookup, LibsslUprobeFlowResolver},
        *,
    };

    #[test]
    fn provider_decodes_tls_plaintext_source_samples() -> Result<(), Box<dyn std::error::Error>> {
        let event = sample_event();
        let resolver = Box::new(StaticFlowResolver {
            expected: lookup_for_sample_event(),
            resolved: Some(demo_resolved_flow()),
            seen: false,
        });
        let mut provider = LibsslUprobePlaintextProvider::new(
            Box::new(VecTlsPlaintextSource::new([event])),
            resolver,
        );

        let Some(crate::CaptureEvent::Bytes(bytes)) = provider.next()? else {
            panic!("expected provider to emit plaintext bytes");
        };

        assert_eq!(provider.name(), "libssl_uprobe_plaintext");
        assert_eq!(bytes.origin.source(), CaptureSource::LibsslUprobe);
        assert_eq!(bytes.origin.provider(), CaptureProviderKind::Plaintext);
        assert_eq!(bytes.stream_offset, 100);
        assert_eq!(bytes.bytes.as_ref(), b"GET /");
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn output_selector_allows_resolved_matching_flow() -> Result<(), Box<dyn std::error::Error>> {
        let mut provider = provider_with_flow(
            Some(demo_resolved_flow()),
            Some(remote_port_selector(443)),
            [sample_event()],
        );

        let Some(crate::CaptureEvent::Bytes(bytes)) = provider.next()? else {
            panic!("matching resolved flow should pass selector");
        };

        assert_eq!(bytes.flow.remote.port, 443);
        assert_eq!(bytes.bytes.as_ref(), b"GET /");
        Ok(())
    }

    #[test]
    fn output_selector_filters_resolved_mismatched_flow() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut provider = provider_with_flow(
            Some(demo_resolved_flow()),
            Some(remote_port_selector(8443)),
            [sample_event()],
        );

        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn output_selector_fails_closed_for_unresolved_unknown_remote_port()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut provider =
            provider_with_flow(None, Some(remote_port_selector(443)), [sample_event()]);

        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn output_selector_allows_unresolved_direction_only_scope()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut provider = provider_with_flow(
            None,
            Some(direction_selector(Direction::Outbound)),
            [sample_event()],
        );

        let Some(crate::CaptureEvent::Bytes(bytes)) = provider.next()? else {
            panic!("unresolved flow with known matching direction should pass selector");
        };

        assert_eq!(bytes.flow.remote.port, 0);
        assert_eq!(bytes.flow.attribution_confidence, 0);
        assert_eq!(bytes.bytes.as_ref(), b"GET /");
        Ok(())
    }

    #[test]
    fn live_provider_waits_on_idle_source_instead_of_reporting_eof()
    -> Result<(), Box<dyn std::error::Error>> {
        let resolver = Box::new(StaticFlowResolver {
            expected: lookup_for_sample_event(),
            resolved: Some(demo_resolved_flow()),
            seen: false,
        });
        let mut provider = LibsslUprobePlaintextProvider::with_idle_policy(
            Box::new(IdleThenTlsPlaintextSource {
                idle_before_samples: 1,
                samples: VecTlsPlaintextSource::new([sample_event()]),
            }),
            resolver,
            LibsslUprobePlaintextIdlePolicy::Wait,
        );

        let Some(crate::CaptureEvent::Bytes(bytes)) = provider.next()? else {
            panic!("live provider must wait through idle ringbuf polls");
        };

        assert_eq!(bytes.bytes.as_ref(), b"GET /");
        Ok(())
    }

    #[test]
    fn emits_output_loss_delta_through_poll() -> Result<(), Box<dyn std::error::Error>> {
        let resolver = Box::new(StaticFlowResolver {
            expected: lookup_for_sample_event(),
            resolved: Some(demo_resolved_flow()),
            seen: false,
        });
        let mut provider = LibsslUprobePlaintextProvider::with_idle_policy(
            Box::new(OutputLossTlsPlaintextSource {
                samples: VecTlsPlaintextSource::new([]),
                counts: VecDeque::from([2, 2, 5]),
            }),
            resolver,
            LibsslUprobePlaintextIdlePolicy::Wait,
        );

        let first = expect_output_loss(provider.poll_next()?);
        assert_eq!(first.origin.source(), CaptureSource::LibsslUprobe);
        assert_eq!(first.origin.provider(), CaptureProviderKind::Plaintext);
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
    fn interleaves_output_loss_during_plaintext_sample_drain()
    -> Result<(), Box<dyn std::error::Error>> {
        let resolver = Box::new(StaticFlowResolver {
            expected: lookup_for_sample_event(),
            resolved: Some(demo_resolved_flow()),
            seen: false,
        });
        let mut provider = LibsslUprobePlaintextProvider::new(
            Box::new(OutputLossTlsPlaintextSource {
                samples: VecTlsPlaintextSource::new([
                    sample_event(),
                    sample_event(),
                    sample_event(),
                ]),
                counts: VecDeque::from([4]),
            }),
            resolver,
        )
        .with_output_loss_check_interval_for_test(2);

        assert!(matches!(provider.poll_next()?, CapturePoll::Event(_)));
        assert!(matches!(provider.poll_next()?, CapturePoll::Event(_)));
        let loss = expect_output_loss(provider.poll_next()?);
        assert_eq!(loss.loss.lost_events, 4);
        let gap = expect_output_loss_gap(provider.poll_next()?);
        assert_eq!(gap.origin.source(), CaptureSource::LibsslUprobe);
        assert_eq!(
            gap.enforcement_evidence_propagation,
            EnforcementEvidencePropagation::Flow
        );
        assert_eq!(gap.gap.direction, Direction::Outbound);
        assert_eq!(gap.gap.expected_offset, 105);
        assert!(gap.gap.next_offset.is_none());
        assert!(gap.gap.reason.contains("lost 4 event(s)"));
        assert!(matches!(provider.poll_next()?, CapturePoll::Event(_)));
        Ok(())
    }

    #[test]
    fn output_loss_fans_out_unknown_offset_gap_to_tracked_plaintext_flow()
    -> Result<(), Box<dyn std::error::Error>> {
        let resolver = Box::new(StaticFlowResolver {
            expected: lookup_for_sample_event(),
            resolved: Some(demo_resolved_flow()),
            seen: false,
        });
        let mut provider = LibsslUprobePlaintextProvider::new(
            Box::new(OutputLossTlsPlaintextSource {
                samples: VecTlsPlaintextSource::new([sample_event()]),
                counts: VecDeque::from([2]),
            }),
            resolver,
        )
        .with_output_loss_check_interval_for_test(1);

        let Some(crate::CaptureEvent::Bytes(bytes)) = provider.next()? else {
            panic!("expected provider to emit plaintext bytes before output loss");
        };
        assert_eq!(bytes.stream_offset, 100);
        assert_eq!(bytes.bytes.as_ref(), b"GET /");

        let loss = expect_output_loss(provider.poll_next()?);
        assert_eq!(loss.origin.source(), CaptureSource::LibsslUprobe);
        assert_eq!(loss.loss.lost_events, 2);

        let gap = expect_output_loss_gap(provider.poll_next()?);
        assert_eq!(gap.origin.source(), CaptureSource::LibsslUprobe);
        assert_eq!(gap.flow.remote.port, 443);
        assert_eq!(
            gap.enforcement_evidence_propagation,
            EnforcementEvidencePropagation::Flow
        );
        assert!(
            gap.enforcement_evidence
                .destructive_enforcement_rejection_reason()
                .is_some_and(|reason| reason.contains("lost observations"))
        );
        assert_eq!(gap.gap.direction, Direction::Outbound);
        assert_eq!(gap.gap.expected_offset, 105);
        assert!(gap.gap.next_offset.is_none());
        assert!(gap.gap.reason.contains("lost 2 event(s)"));
        assert!(gap.gap.reason.contains("affected TLS record"));
        Ok(())
    }

    #[test]
    fn no_loss_checkpoint_clears_tracked_plaintext_flows_before_later_loss()
    -> Result<(), Box<dyn std::error::Error>> {
        let resolver = Box::new(StaticFlowResolver {
            expected: lookup_for_sample_event(),
            resolved: Some(demo_resolved_flow()),
            seen: false,
        });
        let mut provider = LibsslUprobePlaintextProvider::new(
            Box::new(OutputLossTlsPlaintextSource {
                samples: VecTlsPlaintextSource::new([sample_event()]),
                counts: VecDeque::from([0, 3, 3]),
            }),
            resolver,
        )
        .with_output_loss_check_interval_for_test(1);

        let Some(crate::CaptureEvent::Bytes(bytes)) = provider.next()? else {
            panic!("expected provider to emit plaintext bytes before output loss checkpoints");
        };
        assert_eq!(bytes.stream_offset, 100);
        assert_eq!(bytes.bytes.as_ref(), b"GET /");

        let loss = expect_output_loss(provider.poll_next()?);
        assert_eq!(loss.origin.source(), CaptureSource::LibsslUprobe);
        assert_eq!(loss.loss.lost_events, 3);
        assert!(matches!(provider.poll_next()?, CapturePoll::Finished));
        Ok(())
    }

    #[test]
    fn reconcile_failure_poisons_provider_before_pending_events_are_drained()
    -> Result<(), Box<dyn std::error::Error>> {
        let resolver = Box::new(StaticFlowResolver {
            expected: lookup_for_sample_event(),
            resolved: Some(demo_resolved_flow()),
            seen: false,
        });
        let mut provider = LibsslUprobePlaintextProvider::new(
            Box::new(FailingReconcileTlsPlaintextSource {
                samples: VecTlsPlaintextSource::new([truncated_sample_event()]),
            }),
            resolver,
        );

        let CapturePoll::Event(first_event) = provider.poll_next()? else {
            panic!("expected first truncated sample event");
        };
        assert!(matches!(*first_event, crate::CaptureEvent::Bytes(_)));

        let error = provider
            .reconcile_libssl_uprobes(empty_attach_plan())
            .expect_err("reconcile failure must poison provider");
        assert!(error.to_string().contains("reconcile failed"));

        let error = provider
            .poll_next()
            .expect_err("poisoned provider must not drain pending gap events");
        assert!(error.to_string().contains("reconcile failed"));
        Ok(())
    }

    #[test]
    fn handoff_drain_emits_pending_plaintext_events_without_polling_new_samples()
    -> Result<(), Box<dyn std::error::Error>> {
        let resolver = Box::new(StaticFlowResolver {
            expected: lookup_for_sample_event(),
            resolved: Some(demo_resolved_flow()),
            seen: false,
        });
        let mut provider = LibsslUprobePlaintextProvider::new(
            Box::new(VecTlsPlaintextSource::new([
                truncated_sample_event(),
                sample_event(),
            ])),
            resolver,
        );

        let CapturePoll::Event(first_event) = provider.poll_next()? else {
            panic!("expected first truncated sample event");
        };
        let crate::CaptureEvent::Bytes(bytes) = *first_event else {
            panic!("expected plaintext bytes before pending gap");
        };
        assert_eq!(bytes.bytes.as_ref(), b"GET /");

        let gap = expect_output_loss_gap(provider.drain_before_handoff()?);
        assert_eq!(gap.gap.direction, Direction::Outbound);
        assert_eq!(gap.gap.expected_offset, 105);
        assert_eq!(gap.gap.next_offset, Some(109));
        assert!(gap.gap.reason.contains("truncated"));
        assert!(matches!(
            provider.drain_before_handoff()?,
            CapturePoll::Idle
        ));

        let CapturePoll::Event(next_event) = provider.poll_next()? else {
            panic!("handoff drain must not consume the next live plaintext sample");
        };
        let crate::CaptureEvent::Bytes(bytes) = *next_event else {
            panic!("expected next live plaintext sample after handoff drain");
        };
        assert_eq!(bytes.bytes.as_ref(), b"GET /");
        Ok(())
    }

    #[test]
    fn handoff_drain_does_not_consume_live_plaintext_samples()
    -> Result<(), Box<dyn std::error::Error>> {
        let resolver = Box::new(StaticFlowResolver {
            expected: lookup_for_sample_event(),
            resolved: Some(demo_resolved_flow()),
            seen: false,
        });
        let mut provider = LibsslUprobePlaintextProvider::new(
            Box::new(VecTlsPlaintextSource::new([sample_event()])),
            resolver,
        );

        assert!(matches!(
            provider.drain_before_handoff()?,
            CapturePoll::Idle
        ));
        let Some(crate::CaptureEvent::Bytes(bytes)) = provider.next()? else {
            panic!("live plaintext sample should remain available after handoff drain");
        };
        assert_eq!(bytes.bytes.as_ref(), b"GET /");
        Ok(())
    }

    #[test]
    fn best_effort_open_disables_sidecar_for_runtime_load_failure()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let resolver = Box::new(StaticFlowResolver {
            expected: lookup_for_sample_event(),
            resolved: None,
            seen: false,
        });

        let open = LibsslUprobePlaintextProvider::open_best_effort(
            LibsslUprobePlaintextProbeConfig::new(
                temp.path().join("missing.o"),
                empty_attach_plan(),
            ),
            resolver,
        );

        let LibsslUprobePlaintextOpen::Disabled { reason } = open else {
            panic!("best-effort sidecar load failures should disable the sidecar");
        };
        assert!(reason.contains("missing.o"));
        Ok(())
    }

    fn empty_attach_plan() -> LibsslUprobeAttachPlan {
        LibsslUprobeAttachPlan::from_discovery_reports(std::iter::empty::<
            crate::tls::LibsslUprobeTargetDiscoveryReport,
        >())
    }

    fn provider_with_flow(
        resolved: Option<LibsslResolvedFlow>,
        selector: Option<probe_core::CompiledSelector>,
        events: impl IntoIterator<Item = EbpfTlsPlaintextEvent>,
    ) -> LibsslUprobePlaintextProvider {
        let resolver = Box::new(StaticFlowResolver {
            expected: lookup_for_sample_event(),
            resolved,
            seen: false,
        });
        LibsslUprobePlaintextProvider::new(Box::new(VecTlsPlaintextSource::new(events)), resolver)
            .with_output_selector(selector)
    }

    fn remote_port_selector(port: u16) -> probe_core::CompiledSelector {
        Selector::term(
            ProcessSelector {
                names: vec!["curl".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector {
                remote_ports: vec![port],
                ..TrafficSelector::default()
            },
        )
        .compile()
        .expect("test selector must compile")
    }

    fn direction_selector(direction: Direction) -> probe_core::CompiledSelector {
        Selector::term(
            ProcessSelector {
                names: vec!["curl".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector {
                directions: vec![direction],
                ..TrafficSelector::default()
            },
        )
        .compile()
        .expect("test selector must compile")
    }

    fn sample_event() -> EbpfTlsPlaintextEvent {
        let mut payload = [0; EBPF_TLS_PLAINTEXT_SAMPLE_BYTES];
        payload[..5].copy_from_slice(b"GET /");
        EbpfTlsPlaintextEvent::libssl_plaintext_sampled(
            11,
            22,
            33,
            44,
            nul_padded_command("curl"),
            EbpfTlsPlaintextObservation::new(
                0xfeed,
                7,
                EBPF_TLS_DIRECTION_OUTBOUND,
                100,
                5,
                5,
                payload,
            ),
            EBPF_TLS_PLAINTEXT_FD_VALID,
        )
    }

    fn lookup_for_sample_event() -> LibsslUprobeFlowLookup {
        LibsslUprobeFlowLookup {
            tgid: 22,
            thread_pid: 11,
            uid: 33,
            gid: 44,
            command: "curl".to_string(),
            ssl_pointer: 0xfeed,
            fd: Some(7),
            direction: Direction::Outbound,
        }
    }

    fn truncated_sample_event() -> EbpfTlsPlaintextEvent {
        let mut payload = [0; EBPF_TLS_PLAINTEXT_SAMPLE_BYTES];
        payload[..5].copy_from_slice(b"GET /");
        EbpfTlsPlaintextEvent::libssl_plaintext_sampled(
            11,
            22,
            33,
            44,
            nul_padded_command("curl"),
            EbpfTlsPlaintextObservation::new(
                0xfeed,
                7,
                EBPF_TLS_DIRECTION_OUTBOUND,
                100,
                9,
                5,
                payload,
            ),
            EBPF_TLS_PLAINTEXT_FD_VALID | EBPF_TLS_PLAINTEXT_TRUNCATED,
        )
    }

    fn demo_resolved_flow() -> LibsslResolvedFlow {
        let process = ProcessIdentity {
            pid: 22,
            tgid: 22,
            start_time_ticks: 1,
            boot_id: "boot".to_string(),
            exe_path: "/usr/bin/curl".to_string(),
            cmdline_hash: "hash".to_string(),
            uid: 33,
            gid: 44,
            cgroup: None,
            systemd_service: None,
            container_id: None,
            runtime_hint: None,
        };
        LibsslResolvedFlow {
            process: ProcessContext {
                identity: process,
                name: "curl".to_string(),
                cmdline: vec!["curl".to_string()],
            },
            confidence: 90,
            connection: TcpConnection::new(
                TcpEndpoint::new("127.0.0.1".parse().expect("valid local address"), 50_000),
                TcpEndpoint::new("127.0.0.1".parse().expect("valid remote address"), 443),
            ),
            socket_cookie: None,
            start_monotonic_ns: 1,
        }
    }

    fn nul_padded_command(command: &str) -> [u8; 16] {
        let mut bytes = [0; 16];
        for (target, source) in bytes.iter_mut().zip(command.as_bytes()) {
            *target = *source;
        }
        bytes
    }

    struct StaticFlowResolver {
        expected: LibsslUprobeFlowLookup,
        resolved: Option<LibsslResolvedFlow>,
        seen: bool,
    }

    impl LibsslUprobeFlowResolver for StaticFlowResolver {
        fn resolve_libssl_uprobe_flow(
            &mut self,
            lookup: LibsslUprobeFlowLookup,
        ) -> Result<Option<LibsslResolvedFlow>, CaptureError> {
            assert_eq!(lookup, self.expected);
            self.seen = true;
            Ok(self.resolved.clone())
        }
    }

    struct VecTlsPlaintextSource {
        samples: VecDeque<LibsslUprobePlaintextSample>,
    }

    impl VecTlsPlaintextSource {
        fn new(events: impl IntoIterator<Item = EbpfTlsPlaintextEvent>) -> Self {
            Self {
                samples: events
                    .into_iter()
                    .map(|event| {
                        LibsslUprobePlaintextSample::from_ebpf_event(&event)
                            .expect("test event must normalize")
                    })
                    .collect(),
            }
        }
    }

    impl LibsslUprobePlaintextSampleSource for VecTlsPlaintextSource {
        fn next_tls_plaintext_sample(
            &mut self,
        ) -> Result<Option<LibsslUprobePlaintextSample>, CaptureError> {
            Ok(self.samples.pop_front())
        }
    }

    struct IdleThenTlsPlaintextSource {
        idle_before_samples: u32,
        samples: VecTlsPlaintextSource,
    }

    impl LibsslUprobePlaintextSampleSource for IdleThenTlsPlaintextSource {
        fn next_tls_plaintext_sample(
            &mut self,
        ) -> Result<Option<LibsslUprobePlaintextSample>, CaptureError> {
            if self.idle_before_samples > 0 {
                self.idle_before_samples -= 1;
                return Ok(None);
            }
            self.samples.next_tls_plaintext_sample()
        }
    }

    struct OutputLossTlsPlaintextSource {
        samples: VecTlsPlaintextSource,
        counts: VecDeque<u64>,
    }

    impl LibsslUprobePlaintextSampleSource for OutputLossTlsPlaintextSource {
        fn next_tls_plaintext_sample(
            &mut self,
        ) -> Result<Option<LibsslUprobePlaintextSample>, CaptureError> {
            self.samples.next_tls_plaintext_sample()
        }

        fn tls_plaintext_output_loss_count(&mut self) -> Result<u64, CaptureError> {
            Ok(self.counts.pop_front().unwrap_or(5))
        }
    }

    fn expect_output_loss(poll: CapturePoll) -> crate::CapturedLoss {
        let CapturePoll::Event(event) = poll else {
            panic!("expected output loss event, got {poll:?}");
        };
        let crate::CaptureEvent::Loss(loss) = *event else {
            panic!("expected output loss event, got {event:?}");
        };
        loss
    }

    fn expect_output_loss_gap(poll: CapturePoll) -> crate::CapturedGap {
        let CapturePoll::Event(event) = poll else {
            panic!("expected output loss gap event, got {poll:?}");
        };
        let crate::CaptureEvent::Gap(gap) = *event else {
            panic!("expected output loss gap event, got {event:?}");
        };
        gap
    }

    struct FailingReconcileTlsPlaintextSource {
        samples: VecTlsPlaintextSource,
    }

    impl LibsslUprobePlaintextSampleSource for FailingReconcileTlsPlaintextSource {
        fn reconcile_libssl_uprobes(
            &mut self,
            next_plan: LibsslUprobeAttachPlan,
        ) -> Result<LibsslUprobePlaintextReconcile, CaptureError> {
            assert!(next_plan.processes().is_empty());
            Err(CaptureError::provider(
                "libssl_uprobe_plaintext",
                "reconcile failed",
            ))
        }

        fn next_tls_plaintext_sample(
            &mut self,
        ) -> Result<Option<LibsslUprobePlaintextSample>, CaptureError> {
            self.samples.next_tls_plaintext_sample()
        }
    }
}
