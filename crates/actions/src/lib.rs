//! Durable authorization and recovery boundary for state-changing actions.
//!
//! The journal and its authenticated checkpoint share one local rollback domain. They detect
//! corruption, torn updates, gaps, and rollback of the journal alone. They cannot detect a
//! coordinated restoration of both files to an older internally valid snapshot. A threat model
//! that includes coordinated storage rollback requires an independent monotonic authority such
//! as a TPM, KMS, or externally persisted witness.

mod journal;
mod model;

pub use journal::{
    ActionArchiveBatch, ActionArchiveCursor, ActionArchiveCursorError, ActionClockError,
    ActionCompletionError, ActionJournal, ActionJournalError, ActionJournalFailure,
    ActionJournalHealth, ActionJournalIntegrityError, ActionJournalKey, ActionJournalKeyError,
    ActionJournalOptions, ActionJournalOptionsError, ActionJournalSnapshot, ActionRecord,
    ActionRecordState, ArchivedAction, AuditUnavailable, AuditUnavailableReason, CompletionToken,
    ExecutableAction, ExecutionAttempt, ExecutionPermit, PreparedAction, PreparedActionError,
};
pub use model::{
    ActionCausality, ActionDecisionPoint, ActionFailureProfile, ActionKind, ActionOutcome,
    ActionResult, ActionResultError, ActionResultSource, ActionScopeProof, StateChangingAction,
    StateChangingActionError, StateChangingActionParts,
};
