use std::{
    sync::{
        Arc, RwLock,
        atomic::{AtomicU8, Ordering},
        mpsc::SyncSender,
    },
    time::Instant,
};

use probe_core::{ActionId, ActionJournalId, PreparedActionId};
use store::{DurableFileError, PreallocatedFile};

use crate::{ActionResult, ActionResultSource, StateChangingAction};

use super::{
    ActionArchiveBatch, ActionArchiveCursor, ActionClock, ActionCompletionError,
    ActionJournalError, ActionJournalFailure, ActionJournalHealth, ActionJournalIntegrityError,
    ActionJournalKey, ActionJournalSnapshot, AuditUnavailable, AuditUnavailableReason,
    CompletionToken, ExecutionPermit, PreparedAction,
    anchor::{AnchorError, JournalAnchor},
    format::{JournalPayload, encode_slot},
    identity::{derive_execution_id, derive_prepare_ids},
    recovery::slot_offset,
    state::{ExistingPreparation, JournalState, JournalStateError},
    token::validate_action_window,
};

pub(super) type SharedSnapshot = Arc<RwLock<ActionJournalSnapshot>>;

pub(super) enum WorkerCommand {
    Prepare {
        action: StateChangingAction,
        deadline: Instant,
        reply: SyncSender<Result<PreparedAction, ActionJournalError>>,
    },
    Claim {
        prepared: PreparedAction,
        deadline: Instant,
        reply: SyncSender<Result<ExecutionPermit, ActionJournalError>>,
    },
    Complete {
        completion: CompletionToken,
        result: ActionResult,
        deadline: Instant,
        reply: SyncSender<Result<(), ActionCompletionError>>,
    },
    Reconcile {
        action_id: ActionId,
        result: ActionResult,
        deadline: Instant,
        reply: SyncSender<Result<(), ActionJournalError>>,
    },
    Archive {
        after: ActionArchiveCursor,
        limit: usize,
        reply: SyncSender<Result<ActionArchiveBatch, ActionJournalError>>,
    },
}

pub(super) struct JournalWorker {
    file: Box<dyn JournalStorage>,
    anchor: JournalAnchor,
    journal: ActionJournalId,
    key: Arc<ActionJournalKey>,
    clock: Arc<dyn ActionClock>,
    state: JournalState,
    shared_snapshot: SharedSnapshot,
    shared_health: Arc<AtomicU8>,
    failure: Option<ActionJournalFailure>,
}

pub(super) struct WorkerContext {
    pub(super) journal: ActionJournalId,
    pub(super) key: Arc<ActionJournalKey>,
    pub(super) clock: Arc<dyn ActionClock>,
    pub(super) snapshot: SharedSnapshot,
    pub(super) health: Arc<AtomicU8>,
}

impl JournalWorker {
    pub(super) fn new(
        file: impl JournalStorage + 'static,
        anchor: JournalAnchor,
        state: JournalState,
        context: WorkerContext,
    ) -> Self {
        Self {
            file: Box::new(file),
            anchor,
            journal: context.journal,
            key: context.key,
            clock: context.clock,
            state,
            shared_snapshot: context.snapshot,
            shared_health: context.health,
            failure: None,
        }
    }

    pub(super) fn run(mut self, receiver: std::sync::mpsc::Receiver<WorkerCommand>) {
        while let Ok(command) = receiver.recv() {
            match command {
                WorkerCommand::Prepare {
                    action,
                    deadline,
                    reply,
                } => {
                    self.publish_health(ActionJournalHealth::SyncStalled);
                    self.prepare(action, deadline, reply);
                }
                WorkerCommand::Claim {
                    prepared,
                    deadline,
                    reply,
                } => self.claim(prepared, deadline, reply),
                WorkerCommand::Complete {
                    completion,
                    result,
                    deadline,
                    reply,
                } => {
                    self.publish_health(ActionJournalHealth::SyncStalled);
                    self.complete(completion, result, deadline, reply);
                }
                WorkerCommand::Reconcile {
                    action_id,
                    result,
                    deadline,
                    reply,
                } => {
                    self.publish_health(ActionJournalHealth::SyncStalled);
                    self.reconcile(action_id, result, deadline, reply);
                }
                WorkerCommand::Archive {
                    after,
                    limit,
                    reply,
                } => {
                    let _ = reply.send(
                        self.state
                            .archive_after(after, limit)
                            .map_err(map_state_error),
                    );
                }
            }
        }
    }

    fn prepare(
        &mut self,
        action: StateChangingAction,
        deadline: Instant,
        reply: SyncSender<Result<PreparedAction, ActionJournalError>>,
    ) {
        let result = self.prepare_inner(action, deadline);
        let action_id = result.as_ref().ok().map(PreparedAction::action_id);
        self.finish_command();
        if reply.send(result).is_err()
            && let Some(action_id) = action_id
        {
            self.state.mark_preparation_orphaned(action_id);
            self.publish_state(ActionJournalHealth::Ready);
        }
    }

    fn prepare_inner(
        &mut self,
        action: StateChangingAction,
        deadline: Instant,
    ) -> Result<PreparedAction, ActionJournalError> {
        self.reject_late(deadline)?;
        match self
            .state
            .existing_preparation(action)
            .map_err(map_state_error)?
        {
            ExistingPreparation::Available {
                action_id,
                prepared_id,
            } => {
                return Ok(PreparedAction::new(
                    self.journal,
                    action_id,
                    prepared_id,
                    action,
                    &self.key,
                ));
            }
            ExistingPreparation::InDoubt(action) => {
                return Err(ActionJournalError::InDoubt { action });
            }
            ExistingPreparation::Completed { action_id, outcome } => {
                return Err(ActionJournalError::AlreadyCompleted {
                    action: action_id,
                    outcome,
                });
            }
            ExistingPreparation::New => {}
        }

        let now = self.clock.now().map_err(ActionJournalError::Clock)?;
        validate_action_window(action, now).map_err(ActionJournalError::PreparedAction)?;
        self.state
            .ensure_prepare_reserve()
            .map_err(map_state_error)?;
        let sequence = self.state.next_sequence();
        let (action_id, prepared_id) =
            derive_prepare_ids(self.journal, sequence, action, &self.key)
                .ok_or_else(|| self.quarantine_integrity())?;
        let payload = JournalPayload::Prepare {
            action_id,
            prepared_id,
            action: Box::new(action),
        };
        let slot_digest = self.write_record(sequence, payload)?;
        let on_time = Instant::now() <= deadline;
        self.state
            .record_prepare(action_id, prepared_id, action, slot_digest, on_time)
            .map_err(|_| self.quarantine_integrity())?;
        self.publish_state(ActionJournalHealth::Ready);
        if !on_time {
            return Err(sync_deadline_exceeded());
        }
        Ok(PreparedAction::new(
            self.journal,
            action_id,
            prepared_id,
            action,
            &self.key,
        ))
    }

    fn claim(
        &mut self,
        prepared: PreparedAction,
        deadline: Instant,
        reply: SyncSender<Result<ExecutionPermit, ActionJournalError>>,
    ) {
        let result = self.claim_inner(&prepared, deadline);
        let action_id = result.as_ref().ok().map(|_| prepared.action_id());
        self.finish_command();
        if reply.send(result).is_err()
            && let Some(action_id) = action_id
        {
            self.state.mark_claim_orphaned(action_id);
            self.publish_state(ActionJournalHealth::Ready);
        }
    }

    fn claim_inner(
        &mut self,
        prepared: &PreparedAction,
        deadline: Instant,
    ) -> Result<ExecutionPermit, ActionJournalError> {
        self.reject_late(deadline)?;
        if prepared.journal() != self.journal || !prepared.authenticates(&self.key) {
            return Err(ActionJournalError::InvalidPreparedToken);
        }
        let now = self.clock.now().map_err(ActionJournalError::Clock)?;
        validate_action_window(prepared.action(), now)
            .map_err(ActionJournalError::PreparedAction)?;
        let execution_id = derive_execution_id(
            self.journal,
            prepared.action_id(),
            prepared.prepared_id(),
            prepared.action(),
            &self.key,
        )
        .ok_or_else(|| self.quarantine_integrity())?;
        let action = self
            .state
            .claim(
                prepared.action_id(),
                prepared.prepared_id(),
                prepared.request(),
                prepared.intent(),
                execution_id,
            )
            .map_err(map_state_error)?;
        self.publish_state(ActionJournalHealth::Ready);
        Ok(ExecutionPermit::new(
            self.journal,
            prepared.action_id(),
            prepared.prepared_id(),
            execution_id,
            action,
            Arc::clone(&self.clock),
            &self.key,
        ))
    }

    fn complete(
        &mut self,
        completion: CompletionToken,
        result: ActionResult,
        deadline: Instant,
        reply: SyncSender<Result<(), ActionCompletionError>>,
    ) {
        let outcome = match self.complete_inner(&completion, result, deadline) {
            Ok(()) => Ok(()),
            Err(CompletionAttemptError::Retry(error)) => {
                Err(ActionCompletionError::retry(error, completion))
            }
            Err(CompletionAttemptError::Indeterminate(error)) => {
                Err(ActionCompletionError::indeterminate(error))
            }
        };
        self.finish_command();
        let _ = reply.send(outcome);
    }

    fn complete_inner(
        &mut self,
        completion: &CompletionToken,
        result: ActionResult,
        deadline: Instant,
    ) -> Result<(), CompletionAttemptError> {
        self.reject_late(deadline)
            .map_err(CompletionAttemptError::Retry)?;
        if completion.journal() != self.journal {
            return Err(CompletionAttemptError::Retry(
                ActionJournalError::InvalidCompletionToken,
            ));
        }
        let disposition = self
            .state
            .entry_for_completion(
                completion.action_id(),
                completion.prepared_id(),
                completion.execution_id(),
                completion.request(),
                completion.intent(),
            )
            .map_err(map_state_error)
            .map_err(CompletionAttemptError::Retry)?;
        if !completion.authenticates(disposition.action, &self.key) {
            return Err(CompletionAttemptError::Retry(
                ActionJournalError::InvalidCompletionToken,
            ));
        }
        validate_result_time(completion.action_id(), disposition.action, result)
            .map_err(CompletionAttemptError::Retry)?;
        if disposition.result.is_some() {
            return Err(CompletionAttemptError::Retry(
                ActionJournalError::CompletionConflict(completion.action_id()),
            ));
        }
        self.append_outcome(
            completion.action_id(),
            completion.prepared_id(),
            completion.request(),
            completion.intent(),
            result,
            deadline,
        )
        .map_err(CompletionAttemptError::Indeterminate)
    }

    fn reconcile(
        &mut self,
        action_id: ActionId,
        result: ActionResult,
        deadline: Instant,
        reply: SyncSender<Result<(), ActionJournalError>>,
    ) {
        let outcome = self.reconcile_inner(action_id, result, deadline);
        self.finish_command();
        let _ = reply.send(outcome);
    }

    fn reconcile_inner(
        &mut self,
        action_id: ActionId,
        result: ActionResult,
        deadline: Instant,
    ) -> Result<(), ActionJournalError> {
        self.reject_late(deadline)?;
        if result.source() != ActionResultSource::ReconciledEffectTruth
            || !result.outcome().is_terminal()
        {
            return Err(ActionJournalError::ReconciliationRequiresEffectTruth);
        }
        let target = self
            .state
            .reconciliation_target(action_id)
            .map_err(map_state_error)?;
        validate_result_time(action_id, target.action, result)?;
        if target.result == Some(result) {
            return Ok(());
        }
        self.append_outcome(
            action_id,
            target.prepared_id,
            target.action.request(),
            target.action.digest(),
            result,
            deadline,
        )
    }

    fn append_outcome(
        &mut self,
        action_id: ActionId,
        prepared_id: PreparedActionId,
        request: probe_core::ActionRequestId,
        intent: probe_core::ActionIntentDigest,
        result: ActionResult,
        deadline: Instant,
    ) -> Result<(), ActionJournalError> {
        let sequence = self.state.next_sequence();
        let payload = JournalPayload::Outcome {
            action_id,
            prepared_id,
            request,
            intent,
            result,
        };
        let slot_digest = self.write_record(sequence, payload)?;
        self.state
            .record_outcome(action_id, prepared_id, request, intent, result, slot_digest)
            .map_err(|_| self.quarantine_integrity())?;
        self.publish_state(ActionJournalHealth::Ready);
        if Instant::now() > deadline {
            Err(sync_deadline_exceeded())
        } else {
            Ok(())
        }
    }

    fn write_record(
        &mut self,
        sequence: u64,
        payload: JournalPayload,
    ) -> Result<[u8; 32], ActionJournalError> {
        let bytes = encode_slot(
            self.journal,
            sequence,
            self.state.previous_digest(),
            payload,
            self.key.as_bytes(),
        )
        .map_err(|_| self.quarantine_integrity())?;
        let offset = slot_offset(sequence).ok_or_else(|| self.quarantine_integrity())?;
        if let Err(error) = self.file.write_all_at(offset, &bytes) {
            return Err(self.quarantine_storage(error));
        }
        if let Err(error) = self.file.sync_data() {
            return Err(self.quarantine_storage(error));
        }
        let digest = *blake3::hash(&bytes).as_bytes();
        if let Err(error) = self.anchor.advance(sequence, digest) {
            return Err(match error {
                AnchorError::Storage(error) => self.quarantine_storage(error),
                AnchorError::Integrity => self.quarantine_integrity(),
            });
        }
        Ok(digest)
    }

    fn reject_late(&self, deadline: Instant) -> Result<(), ActionJournalError> {
        if Instant::now() > deadline {
            Err(sync_deadline_exceeded())
        } else {
            Ok(())
        }
    }

    fn quarantine_storage(&mut self, error: DurableFileError) -> ActionJournalError {
        self.failure = Some(ActionJournalFailure::Storage);
        self.publish_health(ActionJournalHealth::Quarantined);
        ActionJournalError::AuditUnavailable(AuditUnavailable::storage(error))
    }

    fn quarantine_integrity(&mut self) -> ActionJournalError {
        self.failure = Some(ActionJournalFailure::Integrity(
            ActionJournalIntegrityError::RecordConflict,
        ));
        self.publish_health(ActionJournalHealth::Quarantined);
        ActionJournalError::Integrity(ActionJournalIntegrityError::RecordConflict)
    }

    fn finish_command(&self) {
        if self.failure.is_none() {
            self.publish_health(ActionJournalHealth::Ready);
        }
    }

    fn publish_health(&self, health: ActionJournalHealth) {
        self.shared_health
            .store(health_tag(health), Ordering::Release);
        match self.shared_snapshot.write() {
            Ok(mut shared) => shared.set_runtime_status(health, self.failure),
            Err(poisoned) => poisoned
                .into_inner()
                .set_runtime_status(health, self.failure),
        }
    }

    fn publish_state(&self, health: ActionJournalHealth) {
        self.shared_health
            .store(health_tag(health), Ordering::Release);
        let snapshot = self.state.snapshot(health, self.failure);
        match self.shared_snapshot.write() {
            Ok(mut shared) => *shared = snapshot,
            Err(poisoned) => *poisoned.into_inner() = snapshot,
        }
    }
}

pub(super) trait JournalStorage: Send {
    fn write_all_at(&self, offset: u64, input: &[u8]) -> Result<(), DurableFileError>;
    fn sync_data(&self) -> Result<(), DurableFileError>;
}

impl JournalStorage for PreallocatedFile {
    fn write_all_at(&self, offset: u64, input: &[u8]) -> Result<(), DurableFileError> {
        PreallocatedFile::write_all_at(self, offset, input)
    }

    fn sync_data(&self) -> Result<(), DurableFileError> {
        PreallocatedFile::sync_data(self)
    }
}

pub(super) const fn health_tag(health: ActionJournalHealth) -> u8 {
    match health {
        ActionJournalHealth::Ready => 0,
        ActionJournalHealth::SyncStalled => 1,
        ActionJournalHealth::Quarantined => 2,
    }
}

pub(super) const fn health_from_tag(tag: u8) -> ActionJournalHealth {
    match tag {
        0 => ActionJournalHealth::Ready,
        1 => ActionJournalHealth::SyncStalled,
        _ => ActionJournalHealth::Quarantined,
    }
}

fn validate_result_time(
    action_id: ActionId,
    action: StateChangingAction,
    result: ActionResult,
) -> Result<(), ActionJournalError> {
    let observed = result.observed_at();
    if observed.boot() != action.boot() {
        return if result.source() == ActionResultSource::ReconciledEffectTruth {
            Ok(())
        } else {
            Err(ActionJournalError::ResultFromWrongBoot(action_id))
        };
    }
    if observed.instant() < action.decided_at() {
        Err(ActionJournalError::ResultBeforeDecision(action_id))
    } else {
        Ok(())
    }
}

enum CompletionAttemptError {
    Retry(ActionJournalError),
    Indeterminate(ActionJournalError),
}

fn sync_deadline_exceeded() -> ActionJournalError {
    ActionJournalError::AuditUnavailable(AuditUnavailable::without_source(
        AuditUnavailableReason::SyncDeadlineExceeded,
    ))
}

fn map_state_error(error: JournalStateError) -> ActionJournalError {
    match error {
        JournalStateError::RequestConflict {
            request,
            existing,
            requested,
        } => ActionJournalError::RequestConflict {
            request,
            existing,
            requested,
        },
        JournalStateError::EffectFenced(owner) => ActionJournalError::EffectFenced { owner },
        JournalStateError::JournalFull => ActionJournalError::AuditUnavailable(
            AuditUnavailable::without_source(AuditUnavailableReason::JournalFull),
        ),
        JournalStateError::OutcomeWithoutPrepare(action) => {
            ActionJournalError::UnknownAction(action)
        }
        JournalStateError::OutcomeIdentityMismatch(_) => ActionJournalError::InvalidPreparedToken,
        JournalStateError::ExecutionUnavailable(action) => ActionJournalError::InDoubt { action },
        JournalStateError::ArchiveCursorJournalMismatch => {
            ActionJournalError::ArchiveCursorJournalMismatch
        }
        JournalStateError::UnknownArchiveCursor => ActionJournalError::UnknownArchiveCursor,
        JournalStateError::ReconciliationRequiresInDoubt(action) => {
            ActionJournalError::ReconciliationRequiresInDoubt(action)
        }
        JournalStateError::DuplicateRequest(_)
        | JournalStateError::DuplicateAction(_)
        | JournalStateError::DuplicatePrepared(_)
        | JournalStateError::ConflictingEffect(_)
        | JournalStateError::DuplicateOutcome(_)
        | JournalStateError::OutcomeAfterTerminal(_)
        | JournalStateError::ConflictingInDoubt(_)
        | JournalStateError::SequenceOverflow => {
            ActionJournalError::Integrity(ActionJournalIntegrityError::RecordConflict)
        }
    }
}
