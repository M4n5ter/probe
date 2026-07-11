use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use probe_core::{
    ActionEffectDigest, ActionExecutionId, ActionId, ActionIntentDigest, ActionJournalId,
    ActionRequestId, PreparedActionId,
};

use crate::{ActionOutcome, ActionResult, StateChangingAction};

use super::ActionJournalIntegrityError;

const OUTCOME_ESCROW_PER_PREPARE: usize = 2;
const SAFETY_FLOOR_SLOTS: usize = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionJournalHealth {
    Ready,
    SyncStalled,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionJournalFailure {
    Integrity(ActionJournalIntegrityError),
    Storage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionRecordState {
    Prepared,
    Applied,
    NotApplied,
    InDoubt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionRecord {
    action_id: ActionId,
    prepared_id: PreparedActionId,
    action: StateChangingAction,
    state: ActionRecordState,
    result: Option<ActionResult>,
}

impl ActionRecord {
    pub const fn action_id(self) -> ActionId {
        self.action_id
    }

    pub const fn prepared_id(self) -> PreparedActionId {
        self.prepared_id
    }

    pub const fn action(self) -> StateChangingAction {
        self.action
    }

    pub const fn state(self) -> ActionRecordState {
        self.state
    }

    pub const fn result(self) -> Option<ActionResult> {
        self.result
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionJournalSnapshot {
    journal: ActionJournalId,
    health: ActionJournalHealth,
    total_slots: usize,
    used_slots: usize,
    failure: Option<ActionJournalFailure>,
    unresolved: Arc<[ActionRecord]>,
    terminal_count: usize,
    latest_terminal: Option<ActionRecord>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ActionArchiveCursor {
    journal: ActionJournalId,
    sequence: u64,
}

impl ActionArchiveCursor {
    pub const ENCODED_LEN: usize = 24;

    pub const fn begin(journal: ActionJournalId) -> Self {
        Self {
            journal,
            sequence: 0,
        }
    }

    pub const fn journal(self) -> ActionJournalId {
        self.journal
    }

    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    pub fn encode(self) -> [u8; Self::ENCODED_LEN] {
        let mut encoded = [0; Self::ENCODED_LEN];
        encoded[..16].copy_from_slice(self.journal.as_bytes());
        encoded[16..].copy_from_slice(&self.sequence.to_be_bytes());
        encoded
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, ActionArchiveCursorError> {
        if encoded.len() != Self::ENCODED_LEN {
            return Err(ActionArchiveCursorError::InvalidLength {
                actual: encoded.len(),
            });
        }
        let mut journal = [0; 16];
        journal.copy_from_slice(&encoded[..16]);
        let journal = ActionJournalId::new(journal)
            .map_err(|_| ActionArchiveCursorError::InvalidJournalIdentity)?;
        let mut sequence = [0; 8];
        sequence.copy_from_slice(&encoded[16..]);
        Ok(Self {
            journal,
            sequence: u64::from_be_bytes(sequence),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionArchiveCursorError {
    InvalidLength { actual: usize },
    InvalidJournalIdentity,
}

impl std::fmt::Display for ActionArchiveCursorError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLength { actual } => write!(
                formatter,
                "action archive cursor is {actual} bytes, expected {}",
                ActionArchiveCursor::ENCODED_LEN
            ),
            Self::InvalidJournalIdentity => {
                formatter.write_str("action archive cursor has an invalid journal identity")
            }
        }
    }
}

impl std::error::Error for ActionArchiveCursorError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchivedAction {
    cursor: ActionArchiveCursor,
    record: ActionRecord,
}

impl ArchivedAction {
    pub const fn cursor(self) -> ActionArchiveCursor {
        self.cursor
    }

    pub const fn record(self) -> ActionRecord {
        self.record
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionArchiveBatch {
    records: Arc<[ArchivedAction]>,
    next: ActionArchiveCursor,
    has_more: bool,
}

impl ActionArchiveBatch {
    pub fn records(&self) -> &[ArchivedAction] {
        &self.records
    }

    pub const fn next(&self) -> ActionArchiveCursor {
        self.next
    }

    pub const fn has_more(&self) -> bool {
        self.has_more
    }
}

impl ActionJournalSnapshot {
    pub const fn journal(&self) -> ActionJournalId {
        self.journal
    }

    pub const fn health(&self) -> ActionJournalHealth {
        self.health
    }

    pub const fn total_slots(&self) -> usize {
        self.total_slots
    }

    pub const fn used_slots(&self) -> usize {
        self.used_slots
    }

    pub const fn failure(&self) -> Option<ActionJournalFailure> {
        self.failure
    }

    pub fn unresolved(&self) -> &[ActionRecord] {
        &self.unresolved
    }

    pub const fn terminal_count(&self) -> usize {
        self.terminal_count
    }

    pub const fn latest_terminal(&self) -> Option<ActionRecord> {
        self.latest_terminal
    }

    pub fn in_doubt(&self) -> impl Iterator<Item = ActionRecord> + '_ {
        self.unresolved
            .iter()
            .copied()
            .filter(|record| record.state == ActionRecordState::InDoubt)
    }

    pub(super) fn set_runtime_status(
        &mut self,
        health: ActionJournalHealth,
        failure: Option<ActionJournalFailure>,
    ) {
        self.health = health;
        self.failure = failure;
    }
}

pub(super) struct JournalState {
    journal: ActionJournalId,
    total_slots: usize,
    next_sequence: u64,
    previous_digest: [u8; 32],
    entries: Vec<Entry>,
    requests: HashMap<ActionRequestId, usize>,
    actions: HashMap<ActionId, usize>,
    prepared: HashMap<PreparedActionId, usize>,
    effects: HashMap<ActionEffectDigest, usize>,
    unresolved: BTreeMap<ActionId, ActionRecord>,
    completion_escrow: usize,
    terminal_archive: BTreeMap<u64, ActionRecord>,
    terminal_count: usize,
    latest_terminal: Option<ActionRecord>,
}

struct Entry {
    action_id: ActionId,
    prepared_id: PreparedActionId,
    action: StateChangingAction,
    result: Option<ActionResult>,
    execution: ExecutionState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecutionState {
    Available,
    Claimed(ActionExecutionId),
    InDoubt,
}

pub(super) enum ExistingPreparation {
    New,
    Available {
        action_id: ActionId,
        prepared_id: PreparedActionId,
    },
    InDoubt(ActionId),
    Completed {
        action_id: ActionId,
        outcome: ActionOutcome,
    },
}

impl JournalState {
    pub(super) fn new(
        journal: ActionJournalId,
        total_slots: usize,
        genesis_digest: [u8; 32],
    ) -> Self {
        Self {
            journal,
            total_slots,
            next_sequence: 1,
            previous_digest: genesis_digest,
            entries: Vec::new(),
            requests: HashMap::new(),
            actions: HashMap::new(),
            prepared: HashMap::new(),
            effects: HashMap::new(),
            unresolved: BTreeMap::new(),
            completion_escrow: 0,
            terminal_archive: BTreeMap::new(),
            terminal_count: 0,
            latest_terminal: None,
        }
    }

    pub(super) const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    pub(super) const fn journal(&self) -> ActionJournalId {
        self.journal
    }

    pub(super) const fn previous_digest(&self) -> [u8; 32] {
        self.previous_digest
    }

    pub(super) fn used_slots(&self) -> Result<usize, JournalStateError> {
        usize::try_from(self.next_sequence.saturating_sub(1))
            .map_err(|_| JournalStateError::SequenceOverflow)
    }

    pub(super) fn record_prepare(
        &mut self,
        action_id: ActionId,
        prepared_id: PreparedActionId,
        action: StateChangingAction,
        slot_digest: [u8; 32],
        available: bool,
    ) -> Result<(), JournalStateError> {
        if self.requests.contains_key(&action.request()) {
            return Err(JournalStateError::DuplicateRequest(action.request()));
        }
        if self.actions.contains_key(&action_id) {
            return Err(JournalStateError::DuplicateAction(action_id));
        }
        if self.prepared.contains_key(&prepared_id) {
            return Err(JournalStateError::DuplicatePrepared(prepared_id));
        }
        if self.effects.contains_key(&action.effect()) {
            return Err(JournalStateError::ConflictingEffect(action.effect()));
        }
        let completion_escrow = self
            .completion_escrow
            .checked_add(OUTCOME_ESCROW_PER_PREPARE)
            .ok_or(JournalStateError::SequenceOverflow)?;
        let index = self.entries.len();
        self.entries.push(Entry {
            action_id,
            prepared_id,
            action,
            result: None,
            execution: if available {
                ExecutionState::Available
            } else {
                ExecutionState::InDoubt
            },
        });
        self.requests.insert(action.request(), index);
        self.actions.insert(action_id, index);
        self.prepared.insert(prepared_id, index);
        self.effects.insert(action.effect(), index);
        self.unresolved
            .insert(action_id, self.entries[index].record());
        self.completion_escrow = completion_escrow;
        self.advance(slot_digest)
    }

    pub(super) fn record_outcome(
        &mut self,
        action_id: ActionId,
        prepared_id: PreparedActionId,
        request: ActionRequestId,
        intent: ActionIntentDigest,
        result: ActionResult,
        slot_digest: [u8; 32],
    ) -> Result<(), JournalStateError> {
        let index = self
            .actions
            .get(&action_id)
            .copied()
            .ok_or(JournalStateError::OutcomeWithoutPrepare(action_id))?;
        let entry = &mut self.entries[index];
        if entry.prepared_id != prepared_id
            || entry.action.request() != request
            || entry.action.digest() != intent
        {
            return Err(JournalStateError::OutcomeIdentityMismatch(action_id));
        }
        let previous_result = entry.result;
        match previous_result {
            Some(previous) if previous == result => {
                return Err(JournalStateError::DuplicateOutcome(action_id));
            }
            Some(previous) if previous.outcome().is_terminal() => {
                return Err(JournalStateError::OutcomeAfterTerminal(action_id));
            }
            Some(_) if !result.outcome().is_terminal() => {
                return Err(JournalStateError::ConflictingInDoubt(action_id));
            }
            Some(_) | None => {}
        }
        let consumed_escrow = match (previous_result, result.outcome()) {
            (None, ActionOutcome::InDoubt) | (Some(_), _) => 1,
            (None, ActionOutcome::Applied | ActionOutcome::NotApplied) => 2,
        };
        let completion_escrow = self
            .completion_escrow
            .checked_sub(consumed_escrow)
            .ok_or(JournalStateError::SequenceOverflow)?;
        entry.result = Some(result);
        entry.execution = ExecutionState::InDoubt;
        let record = entry.record();
        self.completion_escrow = completion_escrow;
        if result.outcome().is_terminal() {
            self.effects.remove(&entry.action.effect());
            self.unresolved.remove(&action_id);
            self.terminal_count = self
                .terminal_count
                .checked_add(1)
                .ok_or(JournalStateError::SequenceOverflow)?;
            self.latest_terminal = Some(record);
            self.terminal_archive.insert(self.next_sequence, record);
        } else {
            self.unresolved.insert(action_id, record);
        }
        self.advance(slot_digest)
    }

    pub(super) fn mark_all_unfinished_in_doubt(&mut self) {
        for entry in &mut self.entries {
            if !entry
                .result
                .is_some_and(|result| result.outcome().is_terminal())
            {
                entry.execution = ExecutionState::InDoubt;
                self.unresolved.insert(entry.action_id, entry.record());
            }
        }
    }

    pub(super) fn existing_preparation(
        &self,
        action: StateChangingAction,
    ) -> Result<ExistingPreparation, JournalStateError> {
        let Some(index) = self.requests.get(&action.request()).copied() else {
            if let Some(owner) = self.effects.get(&action.effect()) {
                return Err(JournalStateError::EffectFenced(
                    self.entries[*owner].action_id,
                ));
            }
            return Ok(ExistingPreparation::New);
        };
        let entry = &self.entries[index];
        if entry.action.digest() != action.digest() {
            return Err(JournalStateError::RequestConflict {
                request: action.request(),
                existing: entry.action.digest(),
                requested: action.digest(),
            });
        }
        match entry.result {
            Some(result) if result.outcome().is_terminal() => Ok(ExistingPreparation::Completed {
                action_id: entry.action_id,
                outcome: result.outcome(),
            }),
            Some(_) => Ok(ExistingPreparation::InDoubt(entry.action_id)),
            None if entry.execution == ExecutionState::Available => {
                Ok(ExistingPreparation::Available {
                    action_id: entry.action_id,
                    prepared_id: entry.prepared_id,
                })
            }
            None => Ok(ExistingPreparation::InDoubt(entry.action_id)),
        }
    }

    pub(super) fn claim(
        &mut self,
        action_id: ActionId,
        prepared_id: PreparedActionId,
        request: ActionRequestId,
        intent: ActionIntentDigest,
        execution_id: ActionExecutionId,
    ) -> Result<StateChangingAction, JournalStateError> {
        let index = self
            .actions
            .get(&action_id)
            .copied()
            .ok_or(JournalStateError::OutcomeWithoutPrepare(action_id))?;
        let entry = &mut self.entries[index];
        if entry.prepared_id != prepared_id
            || entry.action.request() != request
            || entry.action.digest() != intent
        {
            return Err(JournalStateError::OutcomeIdentityMismatch(action_id));
        }
        if entry.result.is_some() || entry.execution != ExecutionState::Available {
            return Err(JournalStateError::ExecutionUnavailable(action_id));
        }
        entry.execution = ExecutionState::Claimed(execution_id);
        self.unresolved.insert(action_id, entry.record());
        Ok(entry.action)
    }

    pub(super) fn ensure_prepare_reserve(&self) -> Result<(), JournalStateError> {
        let used = self.used_slots()?;
        let required = used
            .checked_add(1)
            .and_then(|used| used.checked_add(self.completion_escrow))
            .and_then(|used| used.checked_add(OUTCOME_ESCROW_PER_PREPARE))
            .and_then(|used| used.checked_add(SAFETY_FLOOR_SLOTS))
            .ok_or(JournalStateError::SequenceOverflow)?;
        if required > self.total_slots {
            Err(JournalStateError::JournalFull)
        } else {
            Ok(())
        }
    }

    pub(super) fn entry_for_completion(
        &self,
        action_id: ActionId,
        prepared_id: PreparedActionId,
        execution_id: ActionExecutionId,
        request: ActionRequestId,
        intent: ActionIntentDigest,
    ) -> Result<CompletionDisposition, JournalStateError> {
        let index = self
            .actions
            .get(&action_id)
            .copied()
            .ok_or(JournalStateError::OutcomeWithoutPrepare(action_id))?;
        let entry = &self.entries[index];
        if entry.prepared_id != prepared_id
            || entry.action.request() != request
            || entry.action.digest() != intent
            || entry.execution != ExecutionState::Claimed(execution_id)
        {
            return Err(JournalStateError::OutcomeIdentityMismatch(action_id));
        }
        Ok(CompletionDisposition {
            action: entry.action,
            result: entry.result,
        })
    }

    pub(super) fn reconciliation_target(
        &self,
        action_id: ActionId,
    ) -> Result<ReconciliationTarget, JournalStateError> {
        let index = self
            .actions
            .get(&action_id)
            .copied()
            .ok_or(JournalStateError::OutcomeWithoutPrepare(action_id))?;
        let entry = &self.entries[index];
        if entry.state() != ActionRecordState::InDoubt {
            return Err(JournalStateError::ReconciliationRequiresInDoubt(action_id));
        }
        Ok(ReconciliationTarget {
            prepared_id: entry.prepared_id,
            action: entry.action,
            result: entry.result,
        })
    }

    pub(super) fn mark_preparation_orphaned(&mut self, action_id: ActionId) {
        if let Some(index) = self.actions.get(&action_id) {
            self.entries[*index].execution = ExecutionState::InDoubt;
            self.unresolved
                .insert(action_id, self.entries[*index].record());
        }
    }

    pub(super) fn mark_claim_orphaned(&mut self, action_id: ActionId) {
        if let Some(index) = self.actions.get(&action_id) {
            let entry = &mut self.entries[*index];
            if matches!(entry.execution, ExecutionState::Claimed(_)) {
                entry.execution = ExecutionState::InDoubt;
                self.unresolved.insert(action_id, entry.record());
            }
        }
    }

    pub(super) fn snapshot(
        &self,
        health: ActionJournalHealth,
        failure: Option<ActionJournalFailure>,
    ) -> ActionJournalSnapshot {
        let unresolved = self.unresolved.values().copied().collect::<Vec<_>>().into();
        ActionJournalSnapshot {
            journal: self.journal,
            health,
            total_slots: self.total_slots,
            used_slots: self.used_slots().unwrap_or(self.total_slots),
            failure,
            unresolved,
            terminal_count: self.terminal_count,
            latest_terminal: self.latest_terminal,
        }
    }

    pub(super) fn archive_after(
        &self,
        after: ActionArchiveCursor,
        limit: usize,
    ) -> Result<ActionArchiveBatch, JournalStateError> {
        if after.journal != self.journal {
            return Err(JournalStateError::ArchiveCursorJournalMismatch);
        }
        if after.sequence != 0 && !self.terminal_archive.contains_key(&after.sequence) {
            return Err(JournalStateError::UnknownArchiveCursor);
        }
        let mut records = self
            .terminal_archive
            .range((
                std::ops::Bound::Excluded(after.sequence),
                std::ops::Bound::Unbounded,
            ))
            .take(limit.saturating_add(1))
            .map(|(sequence, record)| ArchivedAction {
                cursor: ActionArchiveCursor {
                    journal: self.journal,
                    sequence: *sequence,
                },
                record: *record,
            })
            .collect::<Vec<_>>();
        let has_more = records.len() > limit;
        if has_more {
            records.pop();
        }
        let next = records.last().map_or(after, |archived| archived.cursor);
        Ok(ActionArchiveBatch {
            records: records.into(),
            next,
            has_more,
        })
    }

    fn advance(&mut self, slot_digest: [u8; 32]) -> Result<(), JournalStateError> {
        self.previous_digest = slot_digest;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(JournalStateError::SequenceOverflow)?;
        Ok(())
    }
}

impl Entry {
    fn state(&self) -> ActionRecordState {
        match self.result.map(ActionResult::outcome) {
            Some(ActionOutcome::Applied) => ActionRecordState::Applied,
            Some(ActionOutcome::NotApplied) => ActionRecordState::NotApplied,
            Some(ActionOutcome::InDoubt) => ActionRecordState::InDoubt,
            None if self.execution == ExecutionState::Available => ActionRecordState::Prepared,
            None => ActionRecordState::InDoubt,
        }
    }

    fn record(&self) -> ActionRecord {
        ActionRecord {
            action_id: self.action_id,
            prepared_id: self.prepared_id,
            action: self.action,
            state: self.state(),
            result: self.result,
        }
    }
}

pub(super) struct CompletionDisposition {
    pub(super) action: StateChangingAction,
    pub(super) result: Option<ActionResult>,
}

pub(super) struct ReconciliationTarget {
    pub(super) prepared_id: PreparedActionId,
    pub(super) action: StateChangingAction,
    pub(super) result: Option<ActionResult>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum JournalStateError {
    DuplicateRequest(ActionRequestId),
    DuplicateAction(ActionId),
    DuplicatePrepared(PreparedActionId),
    ConflictingEffect(ActionEffectDigest),
    OutcomeWithoutPrepare(ActionId),
    OutcomeIdentityMismatch(ActionId),
    DuplicateOutcome(ActionId),
    OutcomeAfterTerminal(ActionId),
    ConflictingInDoubt(ActionId),
    EffectFenced(ActionId),
    RequestConflict {
        request: ActionRequestId,
        existing: ActionIntentDigest,
        requested: ActionIntentDigest,
    },
    JournalFull,
    SequenceOverflow,
    ReconciliationRequiresInDoubt(ActionId),
    ExecutionUnavailable(ActionId),
    ArchiveCursorJournalMismatch,
    UnknownArchiveCursor,
}
