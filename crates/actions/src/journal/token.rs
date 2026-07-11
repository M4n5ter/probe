use std::{fmt, marker::PhantomData, sync::Arc};

use blake3::Hasher;
use probe_core::{
    ActionBackendId, ActionEffectDigest, ActionExecutionId, ActionId, ActionIntentDigest,
    ActionJournalId, ActionRequestId, BootScopedInstant, PreparedActionId,
};
use zeroize::Zeroize;

use crate::StateChangingAction;

use super::{ActionClock, ActionJournalKey};

#[derive(Clone)]
pub struct PreparedAction {
    journal: ActionJournalId,
    action_id: ActionId,
    prepared_id: PreparedActionId,
    action: StateChangingAction,
    capability: [u8; 32],
}

impl PreparedAction {
    pub(crate) fn new(
        journal: ActionJournalId,
        action_id: ActionId,
        prepared_id: PreparedActionId,
        action: StateChangingAction,
        key: &ActionJournalKey,
    ) -> Self {
        let capability = prepared_capability(journal, action_id, prepared_id, action, key);
        Self {
            journal,
            action_id,
            prepared_id,
            action,
            capability,
        }
    }

    pub const fn journal(&self) -> ActionJournalId {
        self.journal
    }

    pub const fn action_id(&self) -> ActionId {
        self.action_id
    }

    pub const fn prepared_id(&self) -> PreparedActionId {
        self.prepared_id
    }

    pub const fn request(&self) -> ActionRequestId {
        self.action.request()
    }

    pub const fn intent(&self) -> ActionIntentDigest {
        self.action.digest()
    }

    pub const fn effect(&self) -> ActionEffectDigest {
        self.action.effect()
    }

    pub const fn backend(&self) -> ActionBackendId {
        self.action.backend()
    }

    pub const fn action(&self) -> StateChangingAction {
        self.action
    }

    pub(crate) fn authenticates(&self, key: &ActionJournalKey) -> bool {
        let expected = prepared_capability(
            self.journal,
            self.action_id,
            self.prepared_id,
            self.action,
            key,
        );
        constant_time_eq(&self.capability, &expected)
    }
}

impl fmt::Debug for PreparedAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedAction")
            .field("journal", &self.journal)
            .field("action_id", &self.action_id)
            .field("prepared_id", &self.prepared_id)
            .field("action", &self.action)
            .field("capability", &"[REDACTED]")
            .finish()
    }
}

impl Drop for PreparedAction {
    fn drop(&mut self) {
        self.capability.zeroize();
    }
}

pub struct ExecutionPermit {
    journal: ActionJournalId,
    action_id: ActionId,
    prepared_id: PreparedActionId,
    execution_id: ActionExecutionId,
    action: StateChangingAction,
    clock: Arc<dyn ActionClock>,
    completion_capability: [u8; 32],
}

impl ExecutionPermit {
    pub(crate) fn new(
        journal: ActionJournalId,
        action_id: ActionId,
        prepared_id: PreparedActionId,
        execution_id: ActionExecutionId,
        action: StateChangingAction,
        clock: Arc<dyn ActionClock>,
        key: &ActionJournalKey,
    ) -> Self {
        let completion_capability =
            completion_capability(journal, action_id, prepared_id, execution_id, action, key);
        Self {
            journal,
            action_id,
            prepared_id,
            execution_id,
            action,
            clock,
            completion_capability,
        }
    }

    /// Runs an action only within the trusted-time scope that created it.
    ///
    /// The scoped action cannot be returned from the callback:
    ///
    /// ```compile_fail
    /// use actions::ExecutionPermit;
    ///
    /// fn escape(permit: ExecutionPermit) {
    ///     let _escaped = permit.execute(|action| action);
    /// }
    /// ```
    pub fn execute<T, F>(self, operation: F) -> Result<ExecutionAttempt<T>, PreparedActionError>
    where
        F: for<'scope> FnOnce(ExecutableAction<'scope>) -> T,
    {
        let observed_at = self.clock.now().map_err(PreparedActionError::Clock)?;
        validate_action_window(self.action, observed_at)?;
        let executable = ExecutableAction {
            action_id: self.action_id,
            prepared_id: self.prepared_id,
            execution_id: self.execution_id,
            action: self.action,
            scope: PhantomData,
        };
        let output = operation(executable);
        Ok(ExecutionAttempt {
            completion: CompletionToken {
                journal: self.journal,
                action_id: self.action_id,
                prepared_id: self.prepared_id,
                execution_id: self.execution_id,
                request: self.action.request(),
                intent: self.action.digest(),
                capability: self.completion_capability,
            },
            output,
        })
    }
}

impl fmt::Debug for ExecutionPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionPermit")
            .field("journal", &self.journal)
            .field("action_id", &self.action_id)
            .field("prepared_id", &self.prepared_id)
            .field("execution_id", &self.execution_id)
            .field("action", &self.action)
            .field("completion_capability", &"[REDACTED]")
            .finish()
    }
}

impl Drop for ExecutionPermit {
    fn drop(&mut self) {
        self.completion_capability.zeroize();
    }
}

pub struct ExecutableAction<'scope> {
    action_id: ActionId,
    prepared_id: PreparedActionId,
    execution_id: ActionExecutionId,
    action: StateChangingAction,
    scope: PhantomData<&'scope mut &'scope ()>,
}

impl ExecutableAction<'_> {
    pub const fn action_id(&self) -> ActionId {
        self.action_id
    }

    pub const fn prepared_id(&self) -> PreparedActionId {
        self.prepared_id
    }

    pub const fn execution_id(&self) -> ActionExecutionId {
        self.execution_id
    }

    pub const fn action(&self) -> StateChangingAction {
        self.action
    }
}

impl fmt::Debug for ExecutableAction<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutableAction")
            .field("action_id", &self.action_id)
            .field("prepared_id", &self.prepared_id)
            .field("execution_id", &self.execution_id)
            .field("action", &self.action)
            .finish()
    }
}

pub struct ExecutionAttempt<T> {
    completion: CompletionToken,
    output: T,
}

impl<T> ExecutionAttempt<T> {
    pub const fn output(&self) -> &T {
        &self.output
    }

    pub fn into_parts(self) -> (CompletionToken, T) {
        (self.completion, self.output)
    }
}

impl<T: fmt::Debug> fmt::Debug for ExecutionAttempt<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionAttempt")
            .field("completion", &self.completion)
            .field("output", &self.output)
            .finish()
    }
}

pub struct CompletionToken {
    journal: ActionJournalId,
    action_id: ActionId,
    prepared_id: PreparedActionId,
    execution_id: ActionExecutionId,
    request: ActionRequestId,
    intent: ActionIntentDigest,
    capability: [u8; 32],
}

impl CompletionToken {
    pub const fn action_id(&self) -> ActionId {
        self.action_id
    }

    pub const fn execution_id(&self) -> ActionExecutionId {
        self.execution_id
    }

    pub(crate) const fn journal(&self) -> ActionJournalId {
        self.journal
    }

    pub(crate) const fn prepared_id(&self) -> PreparedActionId {
        self.prepared_id
    }

    pub(crate) const fn request(&self) -> ActionRequestId {
        self.request
    }

    pub(crate) const fn intent(&self) -> ActionIntentDigest {
        self.intent
    }

    pub(crate) fn authenticates(
        &self,
        action: StateChangingAction,
        key: &ActionJournalKey,
    ) -> bool {
        let expected = completion_capability(
            self.journal,
            self.action_id,
            self.prepared_id,
            self.execution_id,
            action,
            key,
        );
        constant_time_eq(&self.capability, &expected)
    }
}

impl fmt::Debug for CompletionToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompletionToken")
            .field("journal", &self.journal)
            .field("action_id", &self.action_id)
            .field("prepared_id", &self.prepared_id)
            .field("execution_id", &self.execution_id)
            .field("request", &self.request)
            .field("intent", &self.intent)
            .field("capability", &"[REDACTED]")
            .finish()
    }
}

impl Drop for CompletionToken {
    fn drop(&mut self) {
        self.capability.zeroize();
    }
}

pub(crate) fn validate_action_window(
    action: StateChangingAction,
    now: BootScopedInstant,
) -> Result<(), PreparedActionError> {
    if now.boot() != action.boot() {
        return Err(PreparedActionError::WrongBoot);
    }
    if now.instant() < action.decided_at() {
        return Err(PreparedActionError::NotYetValid);
    }
    if now.instant() > action.execute_before() {
        return Err(PreparedActionError::Expired);
    }
    Ok(())
}

#[derive(Debug)]
pub enum PreparedActionError {
    Clock(super::ActionClockError),
    WrongBoot,
    NotYetValid,
    Expired,
}

impl fmt::Display for PreparedActionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clock(error) => write!(formatter, "failed to read execution clock: {error}"),
            Self::WrongBoot => formatter.write_str("prepared action belongs to another boot"),
            Self::NotYetValid => formatter.write_str("prepared action predates its decision time"),
            Self::Expired => formatter.write_str("prepared action execution deadline has passed"),
        }
    }
}

impl std::error::Error for PreparedActionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Clock(error) => Some(error),
            Self::WrongBoot | Self::NotYetValid | Self::Expired => None,
        }
    }
}

fn prepared_capability(
    journal: ActionJournalId,
    action_id: ActionId,
    prepared_id: PreparedActionId,
    action: StateChangingAction,
    key: &ActionJournalKey,
) -> [u8; 32] {
    let mut hasher = capability_hasher(b"probe.action.prepared-capability\0", journal, key);
    hasher.update(action_id.as_bytes());
    hasher.update(prepared_id.as_bytes());
    hash_action_identity(&mut hasher, action);
    *hasher.finalize().as_bytes()
}

fn completion_capability(
    journal: ActionJournalId,
    action_id: ActionId,
    prepared_id: PreparedActionId,
    execution_id: ActionExecutionId,
    action: StateChangingAction,
    key: &ActionJournalKey,
) -> [u8; 32] {
    let mut hasher = capability_hasher(b"probe.action.completion-capability\0", journal, key);
    hasher.update(action_id.as_bytes());
    hasher.update(prepared_id.as_bytes());
    hasher.update(execution_id.as_bytes());
    hash_action_identity(&mut hasher, action);
    *hasher.finalize().as_bytes()
}

fn capability_hasher(domain: &[u8], journal: ActionJournalId, key: &ActionJournalKey) -> Hasher {
    let mut hasher = Hasher::new_keyed(key.as_bytes());
    hasher.update(domain);
    hasher.update(journal.as_bytes());
    hasher
}

fn hash_action_identity(hasher: &mut Hasher, action: StateChangingAction) {
    hasher.update(action.request().as_bytes());
    hasher.update(action.digest().as_bytes());
    hasher.update(action.effect().as_bytes());
    hasher.update(action.backend().as_bytes());
    hasher.update(action.boot().as_bytes());
    hasher.update(&action.execute_before().as_nanos().to_be_bytes());
}

fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}
