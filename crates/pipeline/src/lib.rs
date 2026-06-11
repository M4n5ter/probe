use std::time::{SystemTime, UNIX_EPOCH};

use capture::{
    CAPTURE_BYTES_JSON_SCHEMA, CaptureError, CaptureEvent, CaptureProvider, CapturedBytes,
};
use enforcement::{EnforcementPlanRequest, EnforcementPlanner};
use parsers::{ParserInput, ProtocolParserFactory};
use policy::{PolicyOutcome, PolicyRuntime, hook_for_event};
use probe_core::{CompiledSelector, EventEnvelope, EventKind, Timestamp};
use proto::EVENT_ENVELOPE_JSON_SCHEMA;
use storage::{DurableSpool, SpoolPayload};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PipelineError {
    #[error("capture error: {0}")]
    Capture(#[from] CaptureError),
    #[error("failed to serialize pipeline payload: {0}")]
    Json(#[from] serde_json::Error),
    #[error("storage error: {0}")]
    Storage(#[from] storage::StorageError),
    #[error("policy error: {0}")]
    Policy(#[from] policy::PolicyError),
    #[error("enforcement error: {0}")]
    Enforcement(#[from] enforcement::EnforcementError),
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PipelineSummary {
    pub capture_events: u64,
    pub ingress_chunks: u64,
    pub export_events: u64,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PipelineRunOptions {
    pub max_events: Option<u64>,
}

impl PipelineRunOptions {
    pub fn max_events(max_events: u64) -> Self {
        Self {
            max_events: Some(max_events),
        }
    }

    fn should_read_next_event(self, events_read: u64) -> bool {
        self.max_events
            .is_none_or(|max_events| events_read < max_events)
    }
}

pub struct CapturePipeline<'a, S> {
    spool: &'a S,
    parser_factory: &'a mut dyn ProtocolParserFactory,
    policy: Option<PipelinePolicy<'a>>,
    enforcement_planner: Option<&'a mut dyn EnforcementPlanner>,
    config_version: String,
    clock: PipelineClock,
}

#[derive(Clone, Copy)]
pub struct PipelinePolicy<'a> {
    runtime: &'a PolicyRuntime,
    selector: Option<&'a CompiledSelector>,
}

impl<'a> PipelinePolicy<'a> {
    pub fn new(runtime: &'a PolicyRuntime, selector: Option<&'a CompiledSelector>) -> Self {
        Self { runtime, selector }
    }

    pub fn unscoped(runtime: &'a PolicyRuntime) -> Self {
        Self::new(runtime, None)
    }

    fn matches(&self, envelope: &EventEnvelope) -> bool {
        self.selector.is_none_or(|selector| {
            envelope.kind.direction().map_or_else(
                || selector.matches_flow_without_direction(&envelope.flow),
                |direction| selector.matches_flow(&envelope.flow, direction),
            )
        })
    }
}

impl<'a, S> CapturePipeline<'a, S>
where
    S: DurableSpool,
{
    pub fn new(
        spool: &'a S,
        parser_factory: &'a mut dyn ProtocolParserFactory,
        policy: Option<PipelinePolicy<'a>>,
        config_version: impl Into<String>,
    ) -> Self {
        Self {
            spool,
            parser_factory,
            policy,
            enforcement_planner: None,
            config_version: config_version.into(),
            clock: PipelineClock::default(),
        }
    }

    pub fn with_enforcement_planner(
        mut self,
        enforcement_planner: &'a mut dyn EnforcementPlanner,
    ) -> Self {
        self.enforcement_planner = Some(enforcement_planner);
        self
    }

    pub fn run_provider(
        &mut self,
        provider: &mut dyn CaptureProvider,
    ) -> Result<PipelineSummary, PipelineError> {
        self.run_provider_with_options(provider, PipelineRunOptions::default())
    }

    pub fn run_provider_with_options(
        &mut self,
        provider: &mut dyn CaptureProvider,
        options: PipelineRunOptions,
    ) -> Result<PipelineSummary, PipelineError> {
        let mut summary = PipelineSummary::default();
        while options.should_read_next_event(summary.capture_events) {
            let Some(capture_event) = provider.next()? else {
                break;
            };
            summary.capture_events = summary.capture_events.saturating_add(1);
            self.handle_capture_event(capture_event, &mut summary)?;
        }
        Ok(summary)
    }

    fn handle_capture_event(
        &mut self,
        capture_event: CaptureEvent,
        summary: &mut PipelineSummary,
    ) -> Result<(), PipelineError> {
        match capture_event {
            CaptureEvent::Bytes(chunk) => {
                let capture_sequence = self.append_capture_chunk(&chunk)?;
                summary.ingress_chunks = summary.ingress_chunks.saturating_add(1);
                let events = self
                    .parser_factory
                    .parser_for_flow(&chunk.flow.id)
                    .ingest(ParserInput::Data {
                        direction: chunk.direction,
                        bytes: chunk.bytes.as_ref(),
                    })
                    .into_events();

                for event in events {
                    let envelope = EventEnvelope::new(
                        self.clock.next_timestamp(),
                        chunk.flow.clone(),
                        chunk.source,
                        self.config_version.clone(),
                        event,
                    )
                    .with_degraded(chunk.degraded);
                    summary.export_events = summary
                        .export_events
                        .saturating_add(self.append_envelope_and_policy_outcomes(envelope)?);
                }
                self.spool.ack_ingress("parser", capture_sequence)?;
            }
            CaptureEvent::Gap(gap) => {
                let parser_events = self
                    .parser_factory
                    .parser_for_flow(&gap.flow.id)
                    .ingest(ParserInput::Gap {
                        direction: gap.gap.direction,
                        expected_offset: gap.gap.expected_offset,
                        next_offset: gap.gap.next_offset,
                        reason: &gap.gap.reason,
                    })
                    .into_events();
                for event in parser_events {
                    let envelope = EventEnvelope::new(
                        gap.timestamp,
                        gap.flow.clone(),
                        gap.source,
                        self.config_version.clone(),
                        event,
                    );
                    summary.export_events = summary
                        .export_events
                        .saturating_add(self.append_envelope_and_policy_outcomes(envelope)?);
                }
            }
            CaptureEvent::ConnectionOpened {
                timestamp,
                flow,
                source,
                ..
            } => {
                let envelope = EventEnvelope::new(
                    timestamp,
                    flow,
                    source,
                    self.config_version.clone(),
                    EventKind::ConnectionOpened,
                );
                summary.export_events = summary
                    .export_events
                    .saturating_add(self.append_envelope_and_policy_outcomes(envelope)?);
            }
            CaptureEvent::ConnectionClosed {
                timestamp,
                flow,
                source,
                ..
            } => {
                let flow_id = flow.id.clone();
                let parser_events = self
                    .parser_factory
                    .parser_for_flow(&flow_id)
                    .ingest(ParserInput::ConnectionClosed)
                    .into_events();
                for event in parser_events {
                    let envelope = EventEnvelope::new(
                        timestamp,
                        flow.clone(),
                        source,
                        self.config_version.clone(),
                        event,
                    );
                    summary.export_events = summary
                        .export_events
                        .saturating_add(self.append_envelope_and_policy_outcomes(envelope)?);
                }
                let envelope = EventEnvelope::new(
                    timestamp,
                    flow,
                    source,
                    self.config_version.clone(),
                    EventKind::ConnectionClosed,
                );
                summary.export_events = summary
                    .export_events
                    .saturating_add(self.append_envelope_and_policy_outcomes(envelope)?);
                self.parser_factory.remove_flow(&flow_id);
            }
        }
        Ok(())
    }

    fn append_capture_chunk(&self, chunk: &CapturedBytes) -> Result<u64, PipelineError> {
        let payload = serde_json::to_vec(chunk)?;
        let stored = self
            .spool
            .append_ingress(SpoolPayload::new(CAPTURE_BYTES_JSON_SCHEMA, payload))?;
        Ok(stored.sequence)
    }

    fn append_envelope_and_policy_outcomes(
        &mut self,
        envelope: EventEnvelope,
    ) -> Result<u64, PipelineError> {
        self.append_envelope(&envelope)?;
        let mut written = 1;

        let Some(policy) = self.policy else {
            return Ok(written);
        };
        let Some(hook) = hook_for_event(&envelope) else {
            return Ok(written);
        };
        if !policy.matches(&envelope) {
            return Ok(written);
        }
        let policy_version = format!(
            "{}@{}",
            policy.runtime.manifest().id,
            policy.runtime.manifest().version
        );
        let outcomes = policy.runtime.handle_event(hook, &envelope)?;
        for outcome in outcomes {
            match outcome {
                PolicyOutcome::Alert(alert) => {
                    let policy_envelope = EventEnvelope::new(
                        self.clock.next_timestamp(),
                        envelope.flow.clone(),
                        envelope.source,
                        envelope.config_version.clone(),
                        EventKind::PolicyAlert(alert),
                    )
                    .with_policy_version(policy_version.clone())
                    .with_degraded(envelope.degraded);
                    self.append_envelope(&policy_envelope)?;
                    written += 1;
                }
                PolicyOutcome::Verdict(verdict) => {
                    let policy_envelope = EventEnvelope::new(
                        self.clock.next_timestamp(),
                        envelope.flow.clone(),
                        envelope.source,
                        envelope.config_version.clone(),
                        EventKind::PolicyVerdict(verdict.clone()),
                    )
                    .with_policy_version(policy_version.clone())
                    .with_degraded(envelope.degraded);
                    self.append_envelope(&policy_envelope)?;
                    written += 1;

                    if let Some(enforcement_planner) = self.enforcement_planner.as_deref_mut()
                        && let Some(decision) =
                            enforcement_planner.evaluate(EnforcementPlanRequest {
                                verdict: &verdict,
                                trigger: &envelope,
                            })?
                    {
                        let enforcement_envelope = EventEnvelope::new(
                            self.clock.next_timestamp(),
                            envelope.flow.clone(),
                            envelope.source,
                            envelope.config_version.clone(),
                            EventKind::EnforcementDecision(decision),
                        )
                        .with_policy_version(policy_version.clone())
                        .with_degraded(envelope.degraded);
                        self.append_envelope(&enforcement_envelope)?;
                        written += 1;
                    }
                }
            };
        }

        Ok(written)
    }

    fn append_envelope(&self, envelope: &EventEnvelope) -> Result<(), PipelineError> {
        let payload = serde_json::to_vec(envelope)?;
        self.spool
            .append_export(SpoolPayload::new(EVENT_ENVELOPE_JSON_SCHEMA, payload))?;
        Ok(())
    }
}

#[derive(Debug, Default)]
struct PipelineClock {
    next_monotonic_ns: u64,
}

impl PipelineClock {
    fn next_timestamp(&mut self) -> Timestamp {
        self.next_monotonic_ns = self.next_monotonic_ns.saturating_add(1);
        Timestamp {
            monotonic_ns: self.next_monotonic_ns,
            wall_time_unix_ns: wall_time_unix_ns(),
        }
    }
}

fn wall_time_unix_ns() -> i128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos() as i128)
}

#[cfg(test)]
mod tests;
