use std::fmt;

use probe_core::{ActionId, ActionIntentDigest, ActionRequestId};
use store::DurableFileError;

use crate::ActionOutcome;

use super::{ActionClockError, ActionJournalOptionsError, CompletionToken, PreparedActionError};

#[derive(Debug)]
pub struct ActionCompletionError {
    error: Box<ActionJournalError>,
    retry: Option<Box<CompletionToken>>,
}

impl ActionCompletionError {
    pub const fn error(&self) -> &ActionJournalError {
        &self.error
    }

    pub const fn retry_token(&self) -> Option<&CompletionToken> {
        match &self.retry {
            Some(token) => Some(token),
            None => None,
        }
    }

    pub fn into_parts(self) -> (ActionJournalError, Option<CompletionToken>) {
        (*self.error, self.retry.map(|token| *token))
    }

    pub(super) fn retry(error: ActionJournalError, token: CompletionToken) -> Self {
        Self {
            error: Box::new(error),
            retry: Some(Box::new(token)),
        }
    }

    pub(super) fn indeterminate(error: ActionJournalError) -> Self {
        Self {
            error: Box::new(error),
            retry: None,
        }
    }
}

impl fmt::Display for ActionCompletionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for ActionCompletionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.error.as_ref())
    }
}

#[derive(Debug)]
pub enum ActionJournalError {
    InvalidOptions(ActionJournalOptionsError),
    Storage(DurableFileError),
    WorkerStart(std::io::Error),
    Clock(ActionClockError),
    Integrity(ActionJournalIntegrityError),
    AuditUnavailable(AuditUnavailable),
    RequestConflict {
        request: ActionRequestId,
        existing: ActionIntentDigest,
        requested: ActionIntentDigest,
    },
    EffectFenced {
        owner: ActionId,
    },
    InDoubt {
        action: ActionId,
    },
    AlreadyCompleted {
        action: ActionId,
        outcome: ActionOutcome,
    },
    InvalidPreparedToken,
    InvalidCompletionToken,
    PreparedAction(PreparedActionError),
    UnknownAction(ActionId),
    CompletionConflict(ActionId),
    ResultBeforeDecision(ActionId),
    ResultFromWrongBoot(ActionId),
    ReconciliationRequiresInDoubt(ActionId),
    ReconciliationRequiresEffectTruth,
    InvalidArchiveLimit {
        requested: usize,
        maximum: usize,
    },
    ArchiveCursorJournalMismatch,
    UnknownArchiveCursor,
}

impl fmt::Display for ActionJournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOptions(error) => {
                write!(formatter, "invalid action journal options: {error}")
            }
            Self::Storage(error) => write!(formatter, "action journal storage failed: {error}"),
            Self::WorkerStart(error) => {
                write!(formatter, "failed to start action journal worker: {error}")
            }
            Self::Clock(error) => write!(formatter, "action journal clock failed: {error}"),
            Self::Integrity(error) => write!(formatter, "action journal integrity failed: {error}"),
            Self::AuditUnavailable(error) => error.fmt(formatter),
            Self::RequestConflict { request, .. } => write!(
                formatter,
                "action request {request:?} was reused with a different intent"
            ),
            Self::EffectFenced { owner } => write!(
                formatter,
                "action effect is fenced by unresolved action {owner:?}"
            ),
            Self::InDoubt { action } => write!(
                formatter,
                "action {action:?} is in doubt and must be reconciled without re-execution"
            ),
            Self::AlreadyCompleted { action, outcome } => write!(
                formatter,
                "action {action:?} already completed with outcome {outcome:?}"
            ),
            Self::InvalidPreparedToken => {
                formatter.write_str("prepared action token is invalid for this journal")
            }
            Self::InvalidCompletionToken => {
                formatter.write_str("completion token is invalid for this journal")
            }
            Self::PreparedAction(error) => error.fmt(formatter),
            Self::UnknownAction(action) => {
                write!(
                    formatter,
                    "action {action:?} is not present in this journal"
                )
            }
            Self::CompletionConflict(action) => write!(
                formatter,
                "action {action:?} already has a conflicting outcome"
            ),
            Self::ResultBeforeDecision(action) => {
                write!(formatter, "action {action:?} result predates its decision")
            }
            Self::ResultFromWrongBoot(action) => {
                write!(
                    formatter,
                    "action {action:?} result belongs to another boot"
                )
            }
            Self::ReconciliationRequiresInDoubt(action) => write!(
                formatter,
                "action {action:?} is not eligible for recovery reconciliation"
            ),
            Self::ReconciliationRequiresEffectTruth => formatter
                .write_str("recovery reconciliation requires terminal backend effect truth"),
            Self::InvalidArchiveLimit { requested, maximum } => write!(
                formatter,
                "action archive batch limit {requested} is outside 1..={maximum}"
            ),
            Self::ArchiveCursorJournalMismatch => {
                formatter.write_str("action archive cursor belongs to another journal")
            }
            Self::UnknownArchiveCursor => {
                formatter.write_str("action archive cursor was not issued for a terminal record")
            }
        }
    }
}

impl std::error::Error for ActionJournalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidOptions(error) => Some(error),
            Self::Storage(error) => Some(error),
            Self::WorkerStart(error) => Some(error),
            Self::Clock(error) => Some(error),
            Self::Integrity(error) => Some(error),
            Self::AuditUnavailable(error) => Some(error),
            Self::PreparedAction(error) => Some(error),
            Self::RequestConflict { .. }
            | Self::EffectFenced { .. }
            | Self::InDoubt { .. }
            | Self::AlreadyCompleted { .. }
            | Self::InvalidPreparedToken
            | Self::InvalidCompletionToken
            | Self::UnknownAction(_)
            | Self::CompletionConflict(_)
            | Self::ResultBeforeDecision(_)
            | Self::ResultFromWrongBoot(_)
            | Self::ReconciliationRequiresInDoubt(_)
            | Self::ReconciliationRequiresEffectTruth
            | Self::InvalidArchiveLimit { .. }
            | Self::ArchiveCursorJournalMismatch
            | Self::UnknownArchiveCursor => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionJournalIntegrityError {
    HeaderAuthentication,
    HeaderIdentity,
    HeaderLayout,
    CheckpointCorruption,
    JournalRollback,
    RecordCorruption,
    RecordGap,
    RecordConflict,
}

impl fmt::Display for ActionJournalIntegrityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeaderAuthentication => {
                formatter.write_str("journal header authentication failed")
            }
            Self::HeaderIdentity => formatter.write_str("journal identity does not match"),
            Self::HeaderLayout => formatter.write_str("journal layout does not match"),
            Self::CheckpointCorruption => {
                formatter.write_str("journal local checkpoint authentication failed")
            }
            Self::JournalRollback => {
                formatter.write_str("journal is older than its authenticated local checkpoint")
            }
            Self::RecordCorruption => formatter.write_str("journal record authentication failed"),
            Self::RecordGap => formatter.write_str("journal contains a non-contiguous record"),
            Self::RecordConflict => {
                formatter.write_str("journal records violate the action state machine")
            }
        }
    }
}

impl std::error::Error for ActionJournalIntegrityError {}

#[derive(Debug)]
pub struct AuditUnavailable {
    reason: AuditUnavailableReason,
    source: Option<DurableFileError>,
}

impl AuditUnavailable {
    pub const fn reason(&self) -> AuditUnavailableReason {
        self.reason
    }

    pub(super) const fn without_source(reason: AuditUnavailableReason) -> Self {
        Self {
            reason,
            source: None,
        }
    }

    pub(super) const fn storage(source: DurableFileError) -> Self {
        Self {
            reason: AuditUnavailableReason::StorageFailure,
            source: Some(source),
        }
    }
}

impl fmt::Display for AuditUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "action audit is unavailable: {}",
            self.reason.description()
        )
    }
}

impl std::error::Error for AuditUnavailable {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditUnavailableReason {
    Busy,
    SyncDeadlineExceeded,
    SyncStalled,
    JournalFull,
    Quarantined,
    StorageFailure,
    WorkerStopped,
    ShutdownTimedOut,
}

impl AuditUnavailableReason {
    const fn description(self) -> &'static str {
        match self {
            Self::Busy => "journal command queue is busy",
            Self::SyncDeadlineExceeded => "durability deadline was exceeded",
            Self::SyncStalled => "a durability operation is still in progress",
            Self::JournalFull => "preallocated journal reserve is exhausted",
            Self::Quarantined => "journal is quarantined after an integrity failure",
            Self::StorageFailure => "journal storage failed",
            Self::WorkerStopped => "journal worker is not running",
            Self::ShutdownTimedOut => "journal worker did not stop before the shutdown deadline",
        }
    }
}
