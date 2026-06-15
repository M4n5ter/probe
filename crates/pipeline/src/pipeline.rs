use std::time::{SystemTime, UNIX_EPOCH};

use capture::{CaptureError, CaptureEvent, CaptureProvider, CapturedBytes};
use enforcement::{EnforcementPlanRequest, EnforcementPlanner};
use parsers::{ParserInput, ProtocolParserFactory};
use policy::{PolicyOutcome, PolicyRuntime, hook_for_event};
use probe_core::{CompiledSelector, EventEnvelope, EventKind, SpoolPayloadSchema, Timestamp};
use storage::{DurableSpool, IngressCursorOwner, SpoolPayload};
use thiserror::Error;

use crate::runtime_metrics::PipelineRuntimeMetrics;

pub const PARSER_INGRESS_CURSOR_OWNER: IngressCursorOwner = IngressCursorOwner::new("parser");

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
    #[error(
        "unexpected ingress payload schema at sequence {sequence}: expected {expected}, got {actual}"
    )]
    UnexpectedIngressSchema {
        sequence: u64,
        expected: &'static str,
        actual: String,
    },
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PipelineSummary {
    pub capture_events_read: u64,
    pub ingress_records_journaled: u64,
    pub ingress_records_recovered: u64,
    pub ingress_records_processed: u64,
    pub export_events_written: u64,
}

impl PipelineSummary {
    pub fn merge(&mut self, other: Self) {
        self.capture_events_read = self
            .capture_events_read
            .saturating_add(other.capture_events_read);
        self.ingress_records_journaled = self
            .ingress_records_journaled
            .saturating_add(other.ingress_records_journaled);
        self.ingress_records_recovered = self
            .ingress_records_recovered
            .saturating_add(other.ingress_records_recovered);
        self.ingress_records_processed = self
            .ingress_records_processed
            .saturating_add(other.ingress_records_processed);
        self.export_events_written = self
            .export_events_written
            .saturating_add(other.export_events_written);
    }
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
    last_processed_ingress_sequence: Option<u64>,
    runtime_metrics: Option<PipelineRuntimeMetrics>,
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
        self.selector
            .is_none_or(|selector| selector.matches_event(envelope))
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
            last_processed_ingress_sequence: None,
            runtime_metrics: None,
        }
    }

    pub fn with_runtime_metrics(mut self, runtime_metrics: PipelineRuntimeMetrics) -> Self {
        self.runtime_metrics = Some(runtime_metrics);
        self
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
        while options.should_read_next_event(summary.capture_events_read) {
            let Some(capture_event) = provider.next()? else {
                break;
            };
            summary.capture_events_read = summary.capture_events_read.saturating_add(1);
            if let Some(metrics) = &self.runtime_metrics {
                metrics.record_capture_event_read();
            }
            self.handle_capture_event(capture_event, &mut summary)?;
        }
        Ok(summary)
    }

    pub fn recover_ingress_journal_until_idle(
        &mut self,
        batch_size: usize,
    ) -> Result<PipelineSummary, PipelineError> {
        let mut total = PipelineSummary::default();
        let mut after_sequence = self.spool.ingress_cursor(PARSER_INGRESS_CURSOR_OWNER)?;
        if batch_size == 0 {
            return Ok(total);
        }
        loop {
            let (batch, last_sequence) =
                self.recover_ingress_journal_after(after_sequence, batch_size)?;
            let recovered = batch.ingress_records_recovered;
            if let Some(sequence) = last_sequence {
                after_sequence = sequence;
            }
            total.merge(batch);
            if recovered < batch_size as u64 {
                return Ok(total);
            }
        }
    }

    fn recover_ingress_journal_after(
        &mut self,
        after_sequence: u64,
        limit: usize,
    ) -> Result<(PipelineSummary, Option<u64>), PipelineError> {
        let mut summary = PipelineSummary::default();
        let mut last_sequence = None;
        let stored_events = self.spool.read_ingress_batch_after(after_sequence, limit)?;
        for stored_event in stored_events {
            let capture_event = decode_ingress_capture_event(&stored_event)?;
            summary.ingress_records_recovered = summary.ingress_records_recovered.saturating_add(1);
            if let Some(metrics) = &self.runtime_metrics {
                metrics.record_ingress_record_recovered();
            }
            self.process_journaled_capture_event(
                capture_event,
                stored_event.sequence,
                &mut summary,
            )?;
            last_sequence = Some(stored_event.sequence);
        }
        Ok((summary, last_sequence))
    }

    fn handle_capture_event(
        &mut self,
        capture_event: CaptureEvent,
        summary: &mut PipelineSummary,
    ) -> Result<(), PipelineError> {
        let ingress_sequence = self.append_capture_event(&capture_event)?;
        summary.ingress_records_journaled = summary.ingress_records_journaled.saturating_add(1);
        if let Some(metrics) = &self.runtime_metrics {
            metrics.record_ingress_record_journaled();
        }
        self.process_journaled_capture_event(capture_event, ingress_sequence, summary)
    }

    fn process_journaled_capture_event(
        &mut self,
        capture_event: CaptureEvent,
        ingress_sequence: u64,
        summary: &mut PipelineSummary,
    ) -> Result<(), PipelineError> {
        match capture_event {
            CaptureEvent::Bytes(chunk) => {
                self.process_captured_bytes(chunk, summary)?;
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
                    let written = self.append_envelope_and_policy_outcomes(envelope)?;
                    add_export_events_to_summary(summary, written);
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
                let written = self.append_envelope_and_policy_outcomes(envelope)?;
                add_export_events_to_summary(summary, written);
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
                    let written = self.append_envelope_and_policy_outcomes(envelope)?;
                    add_export_events_to_summary(summary, written);
                }
                let envelope = EventEnvelope::new(
                    timestamp,
                    flow,
                    source,
                    self.config_version.clone(),
                    EventKind::ConnectionClosed,
                );
                let written = self.append_envelope_and_policy_outcomes(envelope)?;
                add_export_events_to_summary(summary, written);
                self.parser_factory.remove_flow(&flow_id);
            }
        }
        summary.ingress_records_processed = summary.ingress_records_processed.saturating_add(1);
        if let Some(metrics) = &self.runtime_metrics {
            metrics.record_ingress_record_processed();
        }
        self.last_processed_ingress_sequence = Some(ingress_sequence);
        self.ack_parser_checkpoint_if_safe()?;
        Ok(())
    }

    fn process_captured_bytes(
        &mut self,
        chunk: CapturedBytes,
        summary: &mut PipelineSummary,
    ) -> Result<(), PipelineError> {
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
            let written = self.append_envelope_and_policy_outcomes(envelope)?;
            add_export_events_to_summary(summary, written);
        }
        Ok(())
    }

    fn append_capture_event(&self, capture_event: &CaptureEvent) -> Result<u64, PipelineError> {
        let payload = serde_json::to_vec(capture_event)?;
        let stored = self.spool.append_ingress(SpoolPayload::new(
            SpoolPayloadSchema::CaptureEventJson,
            payload,
        ))?;
        Ok(stored.sequence)
    }

    fn ack_parser_checkpoint_if_safe(&self) -> Result<(), PipelineError> {
        if let Some(sequence) = self.last_processed_ingress_sequence
            && self.parser_factory.is_checkpoint_safe()
        {
            self.spool
                .ack_ingress(PARSER_INGRESS_CURSOR_OWNER, sequence)?;
        }
        Ok(())
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
            if let Some(metrics) = &self.runtime_metrics {
                metrics.record_policy_selector_miss();
            }
            return Ok(written);
        }
        let policy_version = format!(
            "{}@{}",
            policy.runtime.manifest().id,
            policy.runtime.manifest().version
        );
        let outcomes = policy.runtime.handle_event(hook, &envelope)?;
        if let Some(metrics) = &self.runtime_metrics {
            metrics.record_policy_evaluation();
        }
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
                    if let Some(metrics) = &self.runtime_metrics {
                        metrics.record_policy_alert();
                    }
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
                    if let Some(metrics) = &self.runtime_metrics {
                        metrics.record_policy_verdict();
                    }
                    written += 1;

                    if let Some(enforcement_planner) = self.enforcement_planner.as_deref_mut()
                        && let Some(decision) =
                            enforcement_planner.evaluate(EnforcementPlanRequest {
                                verdict: &verdict,
                                trigger: &envelope,
                            })?
                    {
                        let outcome = decision.outcome;
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
                        if let Some(metrics) = &self.runtime_metrics {
                            metrics.record_enforcement_decision(outcome);
                        }
                        written += 1;
                    }
                }
            };
        }

        Ok(written)
    }

    fn append_envelope(&self, envelope: &EventEnvelope) -> Result<(), PipelineError> {
        let payload = serde_json::to_vec(envelope)?;
        self.spool.append_export(SpoolPayload::new(
            SpoolPayloadSchema::EventEnvelopeJson,
            payload,
        ))?;
        if let Some(metrics) = &self.runtime_metrics {
            metrics.record_export_event_written();
        }
        Ok(())
    }
}

fn add_export_events_to_summary(summary: &mut PipelineSummary, written: u64) {
    summary.export_events_written = summary.export_events_written.saturating_add(written);
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

fn wall_time_unix_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_nanos()).unwrap_or(i64::MAX)
        })
}

fn decode_ingress_capture_event(
    stored_event: &storage::StoredEvent,
) -> Result<CaptureEvent, PipelineError> {
    match stored_event.payload.schema() {
        SpoolPayloadSchema::CaptureEventJson => Ok(serde_json::from_slice::<CaptureEvent>(
            stored_event.payload.bytes(),
        )?),
        schema => Err(PipelineError::UnexpectedIngressSchema {
            sequence: stored_event.sequence,
            expected: SpoolPayloadSchema::CAPTURE_EVENT_JSON,
            actual: schema.to_string(),
        }),
    }
}
