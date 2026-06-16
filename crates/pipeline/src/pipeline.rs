use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use capture::{CaptureError, CaptureEvent, CapturePoll, CaptureProvider, CapturedBytes};
use enforcement::{EnforcementPlanRequest, EnforcementPlanner};
use parsers::{ParserInput, ProtocolParserFactory};
use policy::{PolicyHook, PolicyOutcome, PolicyRuntime, hook_for_event};
use probe_core::{
    CompiledSelector, EnforcementDecision, EventEnvelope, EventKind, EventProvenance,
    PolicyEmissionStage, PolicyRuntimeError, SpoolPayloadSchema, Timestamp, Verdict,
};
use storage::{AppendOutcome, DurableSpool, IngressCursorOwner, SpoolPayload};
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

const PROVIDER_IDLE_SLEEP: Duration = Duration::from_millis(10);

#[derive(Default, Clone)]
pub struct PipelineRunOptions {
    pub max_events: Option<u64>,
    pub shutdown_requested: Option<Arc<AtomicBool>>,
}

impl PipelineRunOptions {
    pub fn max_events(max_events: u64) -> Self {
        Self {
            max_events: Some(max_events),
            shutdown_requested: None,
        }
    }

    pub fn with_shutdown_signal(mut self, shutdown_requested: Arc<AtomicBool>) -> Self {
        self.shutdown_requested = Some(shutdown_requested);
        self
    }

    fn should_poll_next_event(&self, events_read: u64) -> bool {
        self.max_events
            .is_none_or(|max_events| events_read < max_events)
            && !self
                .shutdown_requested
                .as_ref()
                .is_some_and(|shutdown| shutdown.load(Ordering::SeqCst))
    }
}

pub struct CapturePipeline<'a, S> {
    spool: &'a S,
    parser_factory: &'a mut dyn ProtocolParserFactory,
    policies: PipelinePolicySet,
    enforcement_planner: Option<&'a mut dyn EnforcementPlanner>,
    config_version: String,
    clock: PipelineClock,
    last_processed_ingress_sequence: Option<u64>,
    runtime_metrics: Option<PipelineRuntimeMetrics>,
}

#[derive(Clone)]
pub struct PipelinePolicy {
    runtime: Arc<Mutex<PolicyRuntime>>,
    selector: Option<Arc<CompiledSelector>>,
}

impl PipelinePolicy {
    pub fn new(runtime: PolicyRuntime, selector: Option<CompiledSelector>) -> Self {
        Self {
            runtime: Arc::new(Mutex::new(runtime)),
            selector: selector.map(Arc::new),
        }
    }

    pub fn unscoped(runtime: PolicyRuntime) -> Self {
        Self::new(runtime, None)
    }

    fn matches(&self, envelope: &EventEnvelope) -> bool {
        self.selector
            .as_ref()
            .is_none_or(|selector| selector.matches_event(envelope))
    }
}

#[derive(Clone)]
pub struct PipelinePolicySet {
    inner: Arc<Mutex<Vec<PipelinePolicy>>>,
}

impl Default for PipelinePolicySet {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

impl PipelinePolicySet {
    pub fn new(policies: Vec<PipelinePolicy>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(policies)),
        }
    }

    pub fn replace(&self, policies: Vec<PipelinePolicy>) {
        let mut current = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *current = policies;
    }

    fn snapshot(&self) -> Vec<PipelinePolicy> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

impl From<Vec<PipelinePolicy>> for PipelinePolicySet {
    fn from(policies: Vec<PipelinePolicy>) -> Self {
        Self::new(policies)
    }
}

impl<'a, S> CapturePipeline<'a, S>
where
    S: DurableSpool,
{
    pub fn new(
        spool: &'a S,
        parser_factory: &'a mut dyn ProtocolParserFactory,
        policies: impl Into<PipelinePolicySet>,
        config_version: impl Into<String>,
    ) -> Self {
        Self {
            spool,
            parser_factory,
            policies: policies.into(),
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
        while options.should_poll_next_event(summary.capture_events_read) {
            match provider.poll_next()? {
                CapturePoll::Event(capture_event) => {
                    summary.capture_events_read = summary.capture_events_read.saturating_add(1);
                    if let Some(metrics) = &self.runtime_metrics {
                        metrics.record_capture_event_read();
                    }
                    self.handle_capture_event(*capture_event, &mut summary)?;
                }
                CapturePoll::Progress => {}
                CapturePoll::Idle => thread::sleep(PROVIDER_IDLE_SLEEP),
                CapturePoll::Finished => break,
            }
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
        let mut emissions = IngressEmissions::new(ingress_sequence);
        match capture_event {
            CaptureEvent::Bytes(chunk) => {
                self.process_captured_bytes(chunk, summary, &mut emissions)?;
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
                    let written =
                        self.append_envelope_and_policy_outcomes(envelope, &mut emissions)?;
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
                let written = self.append_envelope_and_policy_outcomes(envelope, &mut emissions)?;
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
                    let written =
                        self.append_envelope_and_policy_outcomes(envelope, &mut emissions)?;
                    add_export_events_to_summary(summary, written);
                }
                let envelope = EventEnvelope::new(
                    timestamp,
                    flow,
                    source,
                    self.config_version.clone(),
                    EventKind::ConnectionClosed,
                );
                let written = self.append_envelope_and_policy_outcomes(envelope, &mut emissions)?;
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
        emissions: &mut IngressEmissions,
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
            let written = self.append_envelope_and_policy_outcomes(envelope, emissions)?;
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
        emissions: &mut IngressEmissions,
    ) -> Result<u64, PipelineError> {
        let envelope = envelope.with_provenance(emissions.next_primary());
        let mut written = u64::from(self.append_envelope(&envelope)?);

        if let Some(hook) = hook_for_event(&envelope) {
            let active_policies = self.policies.snapshot();
            for (policy_index, policy) in active_policies.iter().enumerate() {
                let evaluation =
                    evaluate_policy(policy, &envelope, hook, self.runtime_metrics.as_ref());
                written += self.append_policy_evaluation(&envelope, policy_index, evaluation)?;
            }
        }
        Ok(written)
    }

    fn append_policy_evaluation(
        &mut self,
        envelope: &EventEnvelope,
        policy_index: usize,
        evaluation: PolicyEvaluation,
    ) -> Result<u64, PipelineError> {
        let policy_index = policy_index as u64;
        match evaluation {
            PolicyEvaluation::SelectorMiss => Ok(0),
            PolicyEvaluation::RuntimeError {
                policy_version,
                reason,
            } => {
                let written = self.append_policy_runtime_error(
                    envelope,
                    &policy_version,
                    policy_index,
                    reason,
                )?;
                if written > 0
                    && let Some(metrics) = &self.runtime_metrics
                {
                    metrics.record_policy_error();
                }
                Ok(written)
            }
            PolicyEvaluation::Outcomes {
                policy_version,
                outcomes,
            } => {
                let mut written = 0;
                for (output_index, outcome) in outcomes.into_iter().enumerate() {
                    written += self.append_policy_outcome(
                        envelope,
                        &policy_version,
                        policy_index,
                        output_index as u64,
                        outcome,
                    )?;
                }
                Ok(written)
            }
        }
    }

    fn append_policy_runtime_error(
        &mut self,
        envelope: &EventEnvelope,
        policy_version: &str,
        policy_index: u64,
        reason: String,
    ) -> Result<u64, PipelineError> {
        self.append_policy_event(
            envelope,
            policy_version,
            policy_index,
            0,
            PolicyEmissionStage::RuntimeError,
            EventKind::PolicyRuntimeError(PolicyRuntimeError {
                event_type: envelope.kind.event_type(),
                reason,
            }),
        )
        .map(u64::from)
    }

    fn append_policy_outcome(
        &mut self,
        envelope: &EventEnvelope,
        policy_version: &str,
        policy_index: u64,
        output_index: u64,
        outcome: PolicyOutcome,
    ) -> Result<u64, PipelineError> {
        match outcome {
            PolicyOutcome::Alert(alert) => {
                let written = self.append_policy_event(
                    envelope,
                    policy_version,
                    policy_index,
                    output_index,
                    PolicyEmissionStage::Output,
                    EventKind::PolicyAlert(alert),
                )?;
                if written && let Some(metrics) = &self.runtime_metrics {
                    metrics.record_policy_alert();
                }
                Ok(u64::from(written))
            }
            PolicyOutcome::Verdict(verdict) => {
                let verdict_written = self.append_policy_event(
                    envelope,
                    policy_version,
                    policy_index,
                    output_index,
                    PolicyEmissionStage::Output,
                    EventKind::PolicyVerdict(verdict.clone()),
                )?;
                let mut written = u64::from(verdict_written);
                if verdict_written && let Some(metrics) = &self.runtime_metrics {
                    metrics.record_policy_verdict();
                }

                let Some(decision) = self.evaluate_enforcement_decision(envelope, &verdict) else {
                    return Ok(written);
                };
                let decision_outcome = decision.outcome;
                let decision_written = self.append_policy_event(
                    envelope,
                    policy_version,
                    policy_index,
                    output_index,
                    PolicyEmissionStage::EnforcementDecision,
                    EventKind::EnforcementDecision(decision),
                )?;
                written += u64::from(decision_written);
                if decision_written && let Some(metrics) = &self.runtime_metrics {
                    metrics.record_enforcement_decision(decision_outcome);
                }
                Ok(written)
            }
        }
    }

    fn evaluate_enforcement_decision(
        &mut self,
        trigger: &EventEnvelope,
        verdict: &Verdict,
    ) -> Option<EnforcementDecision> {
        let enforcement_planner = self.enforcement_planner.as_deref_mut()?;
        enforcement_planner.evaluate(EnforcementPlanRequest { verdict, trigger })
    }

    fn append_policy_event(
        &mut self,
        envelope: &EventEnvelope,
        policy_version: &str,
        policy_index: u64,
        output_index: u64,
        stage: PolicyEmissionStage,
        kind: EventKind,
    ) -> Result<bool, PipelineError> {
        let trigger_provenance = envelope
            .provenance
            .as_ref()
            .expect("primary pipeline event must carry provenance before policy evaluation");
        let policy_envelope = EventEnvelope::new(
            self.clock.next_timestamp(),
            envelope.flow.clone(),
            envelope.source,
            envelope.config_version.clone(),
            kind,
        )
        .with_policy_version(policy_version)
        .with_degraded(envelope.degraded)
        .with_provenance(EventProvenance::policy(
            trigger_provenance,
            policy_index,
            output_index,
            stage,
        ));
        self.append_envelope(&policy_envelope)
    }

    fn append_envelope(&self, envelope: &EventEnvelope) -> Result<bool, PipelineError> {
        let payload = serde_json::to_vec(envelope)?;
        let outcome = self.spool.append_export_once(
            &envelope.id.0,
            SpoolPayload::new(SpoolPayloadSchema::EventEnvelopeJson, payload),
        )?;
        let appended = matches!(outcome, AppendOutcome::Appended(_));
        if appended && let Some(metrics) = &self.runtime_metrics {
            metrics.record_export_event_written();
        }
        Ok(appended)
    }
}

enum PolicyEvaluation {
    SelectorMiss,
    RuntimeError {
        policy_version: String,
        reason: String,
    },
    Outcomes {
        policy_version: String,
        outcomes: Vec<PolicyOutcome>,
    },
}

fn evaluate_policy(
    policy: &PipelinePolicy,
    envelope: &EventEnvelope,
    hook: PolicyHook,
    metrics: Option<&PipelineRuntimeMetrics>,
) -> PolicyEvaluation {
    if !policy.matches(envelope) {
        if let Some(metrics) = metrics {
            metrics.record_policy_selector_miss();
        }
        return PolicyEvaluation::SelectorMiss;
    }

    let runtime = policy
        .runtime
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let policy_version = format!("{}@{}", runtime.manifest().id, runtime.manifest().version);
    if let Some(metrics) = metrics {
        metrics.record_policy_evaluation();
    }

    match runtime.handle_event(hook, envelope) {
        Ok(outcomes) => PolicyEvaluation::Outcomes {
            policy_version,
            outcomes,
        },
        Err(source) => PolicyEvaluation::RuntimeError {
            policy_version,
            reason: source.to_string(),
        },
    }
}

#[derive(Debug, Clone, Copy)]
struct IngressEmissions {
    ingress_sequence: u64,
    next_primary_index: u64,
}

impl IngressEmissions {
    fn new(ingress_sequence: u64) -> Self {
        Self {
            ingress_sequence,
            next_primary_index: 0,
        }
    }

    fn next_primary(&mut self) -> EventProvenance {
        let primary_index = self.next_primary_index;
        self.next_primary_index = self
            .next_primary_index
            .checked_add(1)
            .expect("ingress primary emission index overflowed");
        EventProvenance::primary(self.ingress_sequence, primary_index)
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
