use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use capture::{
    CaptureError, CaptureEvent, CapturePoll, CaptureProvider, CapturedBytes, CapturedGap,
    EnforcementEvidencePropagation,
};
use enforcement::{EnforcementPlanRequest, EnforcementPlanner};
use parsers::{ParserInput, ProtocolParserFactory};
use policy::{PolicyHook, PolicyOutcome, PolicyRuntime, hook_for_event};
use probe_core::{
    CompiledSelector, DEFAULT_POLICY_RUNTIME_ERROR_DISABLE_THRESHOLD, EnforcementDecision,
    EnforcementEvidence, EventEnvelope, EventKind, EventProvenance, FlowIdentity,
    ObservationOnlyReason, PolicyEmissionStage, PolicyRuntimeError, SpoolPayloadSchema, Timestamp,
    Verdict,
};
use storage::{DurableSpool, IngressCursorOwner, SpoolPayload};
use thiserror::Error;

use crate::{
    export_event_writer::{ExportEventWriteError, ExportEventWriter},
    policy_runtime::{
        PersistedRuntimeErrorPlan, PipelinePolicyRuntimeSnapshot, PolicyRuntimeErrorState,
    },
    runtime_metrics::PipelineRuntimeMetrics,
};

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

impl From<ExportEventWriteError> for PipelineError {
    fn from(error: ExportEventWriteError) -> Self {
        match error {
            ExportEventWriteError::Json(error) => Self::Json(error),
            ExportEventWriteError::Storage(error) => Self::Storage(error),
        }
    }
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
    flow_enforcement_evidence: FlowEvidenceTracker,
}

#[derive(Debug, Default)]
struct FlowEvidenceTracker {
    checkpoint_blockers: HashMap<FlowIdentity, EnforcementEvidence>,
}

impl FlowEvidenceTracker {
    fn effective_for_event(
        &mut self,
        flow_id: &FlowIdentity,
        evidence: &EnforcementEvidence,
        propagation: EnforcementEvidencePropagation,
    ) -> EnforcementEvidence {
        let effective = strongest_enforcement_evidence(self.current(flow_id), evidence);
        if propagation.is_flow_carried()
            && matches!(evidence, EnforcementEvidence::ObservationOnly { .. })
        {
            self.checkpoint_blockers
                .insert(flow_id.clone(), effective.clone());
        }
        effective
    }

    fn current(&self, flow_id: &FlowIdentity) -> EnforcementEvidence {
        self.checkpoint_blockers
            .get(flow_id)
            .cloned()
            .unwrap_or_default()
    }

    fn release(&mut self, flow_id: &FlowIdentity) {
        self.checkpoint_blockers.remove(flow_id);
    }

    fn is_checkpoint_safe(&self) -> bool {
        self.checkpoint_blockers.is_empty()
    }
}

fn strongest_enforcement_evidence(
    current: EnforcementEvidence,
    incoming: &EnforcementEvidence,
) -> EnforcementEvidence {
    if enforcement_evidence_priority(&current) >= enforcement_evidence_priority(incoming) {
        current
    } else {
        incoming.clone()
    }
}

fn enforcement_evidence_priority(evidence: &EnforcementEvidence) -> u8 {
    match evidence {
        EnforcementEvidence::DestructiveAllowed => 0,
        EnforcementEvidence::ObservationOnly { reason, .. } => match reason {
            ObservationOnlyReason::EbpfSyscallPayloadSnapshot => 1,
            ObservationOnlyReason::EbpfUnresolvedFlow => 2,
            ObservationOnlyReason::EbpfProcessLifecycleBoundary => 3,
            ObservationOnlyReason::ProviderStateBoundary => 4,
            ObservationOnlyReason::ProviderCaptureLoss => 5,
        },
    }
}

fn is_terminal_provider_state_boundary_gap(gap: &CapturedGap) -> bool {
    matches!(
        &gap.enforcement_evidence,
        EnforcementEvidence::ObservationOnly {
            reason: ObservationOnlyReason::ProviderStateBoundary,
            ..
        }
    )
}

#[derive(Clone)]
pub struct PipelinePolicy {
    runtime: Arc<Mutex<PolicyRuntime>>,
    selector: Option<Arc<CompiledSelector>>,
    runtime_errors: Arc<Mutex<PolicyRuntimeErrorState>>,
}

impl PipelinePolicy {
    pub fn new(runtime: PolicyRuntime, selector: Option<CompiledSelector>) -> Self {
        Self::with_runtime_error_disable_threshold(
            runtime,
            selector,
            DEFAULT_POLICY_RUNTIME_ERROR_DISABLE_THRESHOLD,
        )
    }

    pub fn with_runtime_error_disable_threshold(
        runtime: PolicyRuntime,
        selector: Option<CompiledSelector>,
        disable_threshold: u64,
    ) -> Self {
        Self {
            runtime: Arc::new(Mutex::new(runtime)),
            selector: selector.map(Arc::new),
            runtime_errors: Arc::new(Mutex::new(PolicyRuntimeErrorState::new(disable_threshold))),
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

    fn is_disabled(&self) -> bool {
        self.runtime_errors
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_disabled()
    }

    fn with_persisted_runtime_error<F>(
        &self,
        reason: &str,
        persist: F,
    ) -> Result<u64, PipelineError>
    where
        F: FnOnce(&PersistedRuntimeErrorPlan) -> Result<u64, PipelineError>,
    {
        let mut runtime_errors = self
            .runtime_errors
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let plan = runtime_errors.planned_persisted_error(reason);
        let written = persist(&plan)?;
        if written > 0 {
            runtime_errors.commit_persisted_error(plan);
        }
        Ok(written)
    }

    fn record_runtime_success(&self) {
        self.runtime_errors
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .record_success();
    }

    pub fn runtime_snapshot(&self) -> PipelinePolicyRuntimeSnapshot {
        let runtime = self
            .runtime
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let manifest = runtime.manifest();
        let runtime_errors = self
            .runtime_errors
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .snapshot();
        PipelinePolicyRuntimeSnapshot {
            id: manifest.id.clone(),
            version: manifest.version.clone(),
            policy_version: format!("{}@{}", manifest.id, manifest.version),
            selector_configured: self.selector.is_some(),
            runtime_errors,
        }
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

    pub fn runtime_snapshot(&self) -> Vec<PipelinePolicyRuntimeSnapshot> {
        self.snapshot()
            .iter()
            .map(PipelinePolicy::runtime_snapshot)
            .collect()
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
            flow_enforcement_evidence: FlowEvidenceTracker::default(),
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
            let poll = provider.poll_next()?;
            if let Some(metrics) = &self.runtime_metrics {
                metrics.record_capture_poll(&poll);
            }
            match poll {
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
        let capture_lost_events = match &capture_event {
            CaptureEvent::Loss(loss) => Some(loss.loss.lost_events),
            _ => None,
        };
        let ingress_sequence = self.append_capture_event(&capture_event)?;
        summary.ingress_records_journaled = summary.ingress_records_journaled.saturating_add(1);
        if let Some(metrics) = &self.runtime_metrics {
            metrics.record_ingress_record_journaled();
        }
        self.process_journaled_capture_event(capture_event, ingress_sequence, summary)?;
        if let (Some(metrics), Some(lost_events)) = (&self.runtime_metrics, capture_lost_events) {
            metrics.record_capture_loss(lost_events);
        }
        Ok(())
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
                let flow_id = gap.flow.id.clone();
                let terminal_provider_state_boundary =
                    is_terminal_provider_state_boundary_gap(&gap);
                let enforcement_evidence = self.flow_enforcement_evidence.effective_for_event(
                    &flow_id,
                    &gap.enforcement_evidence,
                    gap.enforcement_evidence_propagation,
                );
                let parser_events = self
                    .parser_factory
                    .parser_for_flow(&flow_id)
                    .ingest(ParserInput::Gap {
                        direction: gap.gap.direction,
                        expected_offset: gap.gap.expected_offset,
                        next_offset: gap.gap.next_offset,
                        reason: &gap.gap.reason,
                    })
                    .into_events();
                for event in parser_events {
                    let envelope = EventEnvelope::from_flow(
                        gap.timestamp,
                        gap.flow.clone(),
                        gap.origin,
                        self.config_version.clone(),
                        event,
                    )
                    .with_enforcement_evidence(enforcement_evidence.clone());
                    let written =
                        self.append_envelope_and_policy_outcomes(envelope, &mut emissions)?;
                    add_export_events_to_summary(summary, written);
                }
                if terminal_provider_state_boundary {
                    self.parser_factory.remove_flow(&flow_id);
                    self.flow_enforcement_evidence.release(&flow_id);
                }
            }
            CaptureEvent::Loss(loss) => {
                let envelope = EventEnvelope::from_provider(
                    loss.timestamp,
                    loss.origin,
                    self.config_version.clone(),
                    EventKind::CaptureLoss(loss.loss),
                )
                .with_enforcement_evidence(loss.enforcement_evidence);
                let written = self.append_envelope_and_policy_outcomes(envelope, &mut emissions)?;
                add_export_events_to_summary(summary, written);
            }
            CaptureEvent::ConnectionOpened {
                timestamp,
                flow,
                origin,
            } => {
                let envelope = EventEnvelope::from_flow(
                    timestamp,
                    flow,
                    origin,
                    self.config_version.clone(),
                    EventKind::ConnectionOpened,
                );
                let written = self.append_envelope_and_policy_outcomes(envelope, &mut emissions)?;
                add_export_events_to_summary(summary, written);
            }
            CaptureEvent::ConnectionClosed {
                timestamp,
                flow,
                origin,
            } => {
                let flow_id = flow.id.clone();
                let enforcement_evidence = self.current_flow_enforcement_evidence(&flow_id);
                let parser_events = self
                    .parser_factory
                    .parser_for_flow(&flow_id)
                    .ingest(ParserInput::ConnectionClosed)
                    .into_events();
                for event in parser_events {
                    let envelope = EventEnvelope::from_flow(
                        timestamp,
                        flow.clone(),
                        origin,
                        self.config_version.clone(),
                        event,
                    )
                    .with_enforcement_evidence(enforcement_evidence.clone());
                    let written =
                        self.append_envelope_and_policy_outcomes(envelope, &mut emissions)?;
                    add_export_events_to_summary(summary, written);
                }
                let envelope = EventEnvelope::from_flow(
                    timestamp,
                    flow,
                    origin,
                    self.config_version.clone(),
                    EventKind::ConnectionClosed,
                )
                .with_enforcement_evidence(enforcement_evidence);
                let written = self.append_envelope_and_policy_outcomes(envelope, &mut emissions)?;
                add_export_events_to_summary(summary, written);
                self.parser_factory.remove_flow(&flow_id);
                self.flow_enforcement_evidence.release(&flow_id);
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
        let enforcement_evidence = self.flow_enforcement_evidence.effective_for_event(
            &chunk.flow.id,
            &chunk.enforcement_evidence,
            chunk.enforcement_evidence_propagation,
        );
        let events = self
            .parser_factory
            .parser_for_flow(&chunk.flow.id)
            .ingest(ParserInput::Data {
                direction: chunk.direction,
                bytes: chunk.bytes.as_ref(),
            })
            .into_events();

        for event in events {
            let envelope = EventEnvelope::from_flow(
                self.clock.next_timestamp(),
                chunk.flow.clone(),
                chunk.origin,
                self.config_version.clone(),
                event,
            )
            .with_degraded(chunk.degraded)
            .with_enforcement_evidence(enforcement_evidence.clone());
            let written = self.append_envelope_and_policy_outcomes(envelope, emissions)?;
            add_export_events_to_summary(summary, written);
        }
        Ok(())
    }

    fn current_flow_enforcement_evidence(&self, flow_id: &FlowIdentity) -> EnforcementEvidence {
        self.flow_enforcement_evidence.current(flow_id)
    }

    fn append_capture_event(&self, capture_event: &CaptureEvent) -> Result<u64, PipelineError> {
        let payload = serde_json::to_vec(capture_event)?;
        let stored = self.spool.append_ingress(SpoolPayload::new(
            SpoolPayloadSchema::CaptureEventOriginJson,
            payload,
        ))?;
        Ok(stored.sequence)
    }

    fn ack_parser_checkpoint_if_safe(&self) -> Result<(), PipelineError> {
        if let Some(sequence) = self.last_processed_ingress_sequence
            && self.parser_factory.is_checkpoint_safe()
            && self.flow_enforcement_evidence.is_checkpoint_safe()
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
                written +=
                    self.append_policy_evaluation(&envelope, policy_index, policy, evaluation)?;
            }
        }
        Ok(written)
    }

    fn append_policy_evaluation(
        &mut self,
        envelope: &EventEnvelope,
        policy_index: usize,
        policy: &PipelinePolicy,
        evaluation: PolicyEvaluation,
    ) -> Result<u64, PipelineError> {
        let policy_index = policy_index as u64;
        match evaluation {
            PolicyEvaluation::SelectorMiss => Ok(0),
            PolicyEvaluation::Disabled => Ok(0),
            PolicyEvaluation::RuntimeError {
                policy_version,
                reason,
            } => {
                let written = policy.with_persisted_runtime_error(&reason, |plan| {
                    self.append_policy_runtime_error(
                        envelope,
                        &policy_version,
                        policy_index,
                        plan.event_reason.clone(),
                    )
                })?;
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
                event_type: envelope.kind().event_type(),
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
                let decision_metric =
                    crate::runtime_metrics::EnforcementDecisionMetric::from_decision_parts(
                        decision.outcome,
                        decision.execution.as_ref(),
                    );
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
                    metrics.record_enforcement_decision(decision_metric);
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
        let policy_envelope = EventEnvelope::from_policy_emission(
            self.clock.next_timestamp(),
            envelope,
            policy_version,
            policy_index,
            output_index,
            stage,
            kind,
        );
        self.append_envelope(&policy_envelope)
    }

    fn append_envelope(&self, envelope: &EventEnvelope) -> Result<bool, PipelineError> {
        Ok(ExportEventWriter::new(self.spool)
            .with_runtime_metrics(self.runtime_metrics.clone())
            .append_once(envelope)?)
    }
}

enum PolicyEvaluation {
    SelectorMiss,
    Disabled,
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
    if policy.is_disabled() {
        if let Some(metrics) = metrics {
            metrics.record_policy_disabled();
        }
        return PolicyEvaluation::Disabled;
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
        Ok(outcomes) => {
            policy.record_runtime_success();
            PolicyEvaluation::Outcomes {
                policy_version,
                outcomes,
            }
        }
        Err(source) => {
            let reason = source.to_string();
            PolicyEvaluation::RuntimeError {
                policy_version,
                reason,
            }
        }
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
        SpoolPayloadSchema::CaptureEventOriginJson => Ok(serde_json::from_slice::<CaptureEvent>(
            stored_event.payload.bytes(),
        )?),
        schema => Err(PipelineError::UnexpectedIngressSchema {
            sequence: stored_event.sequence,
            expected: SpoolPayloadSchema::CAPTURE_EVENT_ORIGIN_JSON,
            actual: schema.to_string(),
        }),
    }
}
