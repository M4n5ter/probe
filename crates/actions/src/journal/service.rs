use std::{
    path::Path,
    sync::{
        Arc, Condvar, Mutex, RwLock,
        atomic::{AtomicU8, Ordering},
        mpsc::{RecvTimeoutError, SyncSender, TrySendError, sync_channel},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use probe_core::{ActionId, ActionJournalId, BootScopedInstant};
use store::{DurableDirectory, PreallocatedFile};

use crate::{ActionResult, StateChangingAction};

use super::{
    ActionArchiveBatch, ActionArchiveCursor, ActionClock, ActionCompletionError,
    ActionJournalError, ActionJournalFailure, ActionJournalHealth, ActionJournalIntegrityError,
    ActionJournalKey, ActionJournalOptions, ActionJournalSnapshot, AuditUnavailable,
    AuditUnavailableReason, CompletionToken, ExecutionPermit, LinuxActionClock, PreparedAction,
    anchor::{ANCHOR_FILE_CAPACITY, AnchorError, JournalAnchor},
    format::{HEADER_LEN, JournalHeader, SLOT_LEN, decode_header, encode_header, header_digest},
    recovery::recover,
    state::JournalState,
    worker::{
        JournalWorker, SharedSnapshot, WorkerCommand, WorkerContext, health_from_tag, health_tag,
    },
};

const JOURNAL_FILE: &str = "actions.journal";
const CHECKPOINT_FILE: &str = "actions.checkpoint";
const COMMAND_QUEUE_DEPTH: usize = 1;
const MAX_ARCHIVE_BATCH: usize = 1024;

pub struct ActionJournal {
    sender: Option<SyncSender<WorkerCommand>>,
    snapshot: SharedSnapshot,
    health: Arc<AtomicU8>,
    clock: Arc<dyn ActionClock>,
    sync_timeout: Duration,
    worker_done: Arc<WorkerCompletion>,
    worker: Option<JoinHandle<()>>,
}

impl ActionJournal {
    pub fn open(
        root: &Path,
        journal: ActionJournalId,
        key: ActionJournalKey,
        options: ActionJournalOptions,
    ) -> Result<Self, ActionJournalError> {
        let clock: Arc<dyn ActionClock> =
            Arc::new(LinuxActionClock::open().map_err(ActionJournalError::Clock)?);
        Self::open_with_clock(root, journal, key, options, clock)
    }

    fn open_with_clock(
        root: &Path,
        journal: ActionJournalId,
        key: ActionJournalKey,
        options: ActionJournalOptions,
        clock: Arc<dyn ActionClock>,
    ) -> Result<Self, ActionJournalError> {
        let key = Arc::new(key);
        let directory = DurableDirectory::ensure(root).map_err(ActionJournalError::Storage)?;
        let file = directory
            .open_or_create_preallocated(Path::new(JOURNAL_FILE), options.capacity())
            .map_err(ActionJournalError::Storage)?;
        let genesis = initialize_or_validate_header(&file, journal, options, &key)?;
        let anchor_file = directory
            .open_or_create_preallocated(Path::new(CHECKPOINT_FILE), ANCHOR_FILE_CAPACITY)
            .map_err(ActionJournalError::Storage)?;
        let mut anchor = JournalAnchor::open(anchor_file, journal, genesis, Arc::clone(&key))
            .map_err(map_anchor_open_error)?;
        let state = JournalState::new(
            journal,
            options
                .total_slots()
                .map_err(ActionJournalError::InvalidOptions)?,
            genesis,
        );
        let recovery =
            recover(&file, &mut anchor, state, &key).map_err(ActionJournalError::Storage)?;
        let initial_health = if recovery.quarantine.is_some() {
            ActionJournalHealth::Quarantined
        } else {
            ActionJournalHealth::Ready
        };
        let initial_failure = recovery.quarantine.map(ActionJournalFailure::Integrity);
        let snapshot = Arc::new(RwLock::new(
            recovery.state.snapshot(initial_health, initial_failure),
        ));
        let health = Arc::new(AtomicU8::new(health_tag(initial_health)));
        let worker_done = Arc::new(WorkerCompletion::new(recovery.quarantine.is_some()));
        if recovery.quarantine.is_some() {
            return Ok(Self {
                sender: None,
                snapshot,
                health,
                clock,
                sync_timeout: options.sync_timeout(),
                worker_done,
                worker: None,
            });
        }

        let (sender, receiver) = sync_channel(COMMAND_QUEUE_DEPTH);
        let worker = JournalWorker::new(
            file,
            anchor,
            recovery.state,
            WorkerContext {
                journal,
                key,
                clock: Arc::clone(&clock),
                snapshot: Arc::clone(&snapshot),
                health: Arc::clone(&health),
            },
        );
        let completion = Arc::clone(&worker_done);
        let handle = thread::Builder::new()
            .name("probe-action-journal".to_owned())
            .spawn(move || {
                let _completion = WorkerCompletionGuard(completion);
                worker.run(receiver);
            })
            .map_err(ActionJournalError::WorkerStart)?;
        Ok(Self {
            sender: Some(sender),
            snapshot,
            health,
            clock,
            sync_timeout: options.sync_timeout(),
            worker_done,
            worker: Some(handle),
        })
    }

    pub fn now(&self) -> Result<BootScopedInstant, ActionJournalError> {
        self.clock.now().map_err(ActionJournalError::Clock)
    }

    pub fn prepare(
        &self,
        action: StateChangingAction,
    ) -> Result<PreparedAction, ActionJournalError> {
        self.submit(|deadline, reply| WorkerCommand::Prepare {
            action,
            deadline,
            reply,
        })
    }

    pub fn claim(&self, prepared: &PreparedAction) -> Result<ExecutionPermit, ActionJournalError> {
        self.submit(|deadline, reply| WorkerCommand::Claim {
            prepared: prepared.clone(),
            deadline,
            reply,
        })
    }

    pub fn complete(
        &self,
        completion: CompletionToken,
        result: ActionResult,
    ) -> Result<(), ActionCompletionError> {
        if let Err(error) = self.ensure_available() {
            return Err(ActionCompletionError::retry(error, completion));
        }
        let Some(sender) = self.sender.as_ref() else {
            return Err(ActionCompletionError::retry(worker_stopped(), completion));
        };
        let Some(deadline) = Instant::now().checked_add(self.sync_timeout) else {
            return Err(ActionCompletionError::retry(
                sync_deadline_exceeded(),
                completion,
            ));
        };
        let (reply, receiver) = sync_channel(1);
        let command = WorkerCommand::Complete {
            completion,
            result,
            deadline,
            reply,
        };
        match sender.try_send(command) {
            Ok(()) => {}
            Err(TrySendError::Full(command)) => {
                return Err(ActionCompletionError::retry(
                    busy(),
                    take_completion(command),
                ));
            }
            Err(TrySendError::Disconnected(command)) => {
                return Err(ActionCompletionError::retry(
                    worker_stopped(),
                    take_completion(command),
                ));
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        match receiver.recv_timeout(remaining) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => Err(ActionCompletionError::indeterminate(
                sync_deadline_exceeded(),
            )),
            Err(RecvTimeoutError::Disconnected) => {
                Err(ActionCompletionError::indeterminate(worker_stopped()))
            }
        }
    }

    pub fn reconcile(
        &self,
        action: ActionId,
        result: ActionResult,
    ) -> Result<(), ActionJournalError> {
        self.submit(|deadline, reply| WorkerCommand::Reconcile {
            action_id: action,
            result,
            deadline,
            reply,
        })
    }

    pub fn archive_after(
        &self,
        after: ActionArchiveCursor,
        limit: usize,
    ) -> Result<ActionArchiveBatch, ActionJournalError> {
        if !(1..=MAX_ARCHIVE_BATCH).contains(&limit) {
            return Err(ActionJournalError::InvalidArchiveLimit {
                requested: limit,
                maximum: MAX_ARCHIVE_BATCH,
            });
        }
        self.submit(|_deadline, reply| WorkerCommand::Archive {
            after,
            limit,
            reply,
        })
    }

    pub fn archive_begin(&self) -> ActionArchiveCursor {
        ActionArchiveCursor::begin(self.snapshot().journal())
    }

    pub fn snapshot(&self) -> ActionJournalSnapshot {
        match self.snapshot.read() {
            Ok(snapshot) => snapshot.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    pub fn health(&self) -> ActionJournalHealth {
        health_from_tag(self.health.load(Ordering::Acquire))
    }

    pub fn close(mut self) -> Result<(), ActionJournalError> {
        self.sender.take();
        if self.worker.is_none() {
            return Ok(());
        }
        if !self.worker_done.wait(self.sync_timeout) {
            self.worker.take();
            return Err(ActionJournalError::AuditUnavailable(
                AuditUnavailable::without_source(AuditUnavailableReason::ShutdownTimedOut),
            ));
        }
        if let Some(worker) = self.worker.take() {
            worker.join().map_err(|_| {
                ActionJournalError::AuditUnavailable(AuditUnavailable::without_source(
                    AuditUnavailableReason::WorkerStopped,
                ))
            })?;
        }
        Ok(())
    }

    fn submit<T: Send + 'static>(
        &self,
        command: impl FnOnce(Instant, SyncSender<Result<T, ActionJournalError>>) -> WorkerCommand,
    ) -> Result<T, ActionJournalError> {
        self.ensure_available()?;
        let sender = self.sender.as_ref().ok_or_else(|| {
            ActionJournalError::AuditUnavailable(AuditUnavailable::without_source(
                AuditUnavailableReason::WorkerStopped,
            ))
        })?;
        let deadline = Instant::now()
            .checked_add(self.sync_timeout)
            .ok_or_else(sync_deadline_exceeded)?;
        let (reply, receiver) = sync_channel(1);
        match sender.try_send(command(deadline, reply)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                return Err(ActionJournalError::AuditUnavailable(
                    AuditUnavailable::without_source(AuditUnavailableReason::Busy),
                ));
            }
            Err(TrySendError::Disconnected(_)) => {
                return Err(ActionJournalError::AuditUnavailable(
                    AuditUnavailable::without_source(AuditUnavailableReason::WorkerStopped),
                ));
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        match receiver.recv_timeout(remaining) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => Err(sync_deadline_exceeded()),
            Err(RecvTimeoutError::Disconnected) => Err(ActionJournalError::AuditUnavailable(
                AuditUnavailable::without_source(AuditUnavailableReason::WorkerStopped),
            )),
        }
    }

    fn ensure_available(&self) -> Result<(), ActionJournalError> {
        match self.health() {
            ActionJournalHealth::Ready => Ok(()),
            ActionJournalHealth::SyncStalled => Err(ActionJournalError::AuditUnavailable(
                AuditUnavailable::without_source(AuditUnavailableReason::SyncStalled),
            )),
            ActionJournalHealth::Quarantined => Err(ActionJournalError::AuditUnavailable(
                AuditUnavailable::without_source(AuditUnavailableReason::Quarantined),
            )),
        }
    }
}

impl Drop for ActionJournal {
    fn drop(&mut self) {
        self.sender.take();
        self.worker.take();
    }
}

struct WorkerCompletion {
    complete: Mutex<bool>,
    changed: Condvar,
}

impl WorkerCompletion {
    fn new(complete: bool) -> Self {
        Self {
            complete: Mutex::new(complete),
            changed: Condvar::new(),
        }
    }

    fn mark_complete(&self) {
        let mut complete = self
            .complete
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *complete = true;
        self.changed.notify_all();
    }

    fn wait(&self, timeout: Duration) -> bool {
        let complete = self
            .complete
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *complete {
            return true;
        }
        let (complete, _) = self
            .changed
            .wait_timeout_while(complete, timeout, |complete| !*complete)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *complete
    }
}

struct WorkerCompletionGuard(Arc<WorkerCompletion>);

impl Drop for WorkerCompletionGuard {
    fn drop(&mut self) {
        self.0.mark_complete();
    }
}

fn initialize_or_validate_header(
    file: &PreallocatedFile,
    journal: ActionJournalId,
    options: ActionJournalOptions,
    key: &ActionJournalKey,
) -> Result<[u8; 32], ActionJournalError> {
    let mut bytes = [0_u8; HEADER_LEN];
    file.read_exact_at(0, &mut bytes)
        .map_err(ActionJournalError::Storage)?;
    if bytes == [0; HEADER_LEN] {
        if !file.was_created() && !record_region_is_empty(file)? {
            return Err(ActionJournalError::Integrity(
                ActionJournalIntegrityError::HeaderAuthentication,
            ));
        }
        let header = JournalHeader::new(journal, options.capacity().get());
        bytes = encode_header(&header, key.as_bytes());
        file.write_all_at(0, &bytes)
            .map_err(ActionJournalError::Storage)?;
        file.sync_data().map_err(ActionJournalError::Storage)?;
        return Ok(header_digest(&bytes));
    }
    let header = decode_header(&bytes, key.as_bytes()).map_err(|_| {
        ActionJournalError::Integrity(ActionJournalIntegrityError::HeaderAuthentication)
    })?;
    if header.journal() != journal {
        return Err(ActionJournalError::Integrity(
            ActionJournalIntegrityError::HeaderIdentity,
        ));
    }
    if header.capacity() != options.capacity().get() {
        return Err(ActionJournalError::Integrity(
            ActionJournalIntegrityError::HeaderLayout,
        ));
    }
    Ok(header_digest(&bytes))
}

fn record_region_is_empty(file: &PreallocatedFile) -> Result<bool, ActionJournalError> {
    let slots = (file.capacity() - HEADER_LEN as u64) / SLOT_LEN as u64;
    let mut bytes = [0_u8; SLOT_LEN];
    for index in 0..slots {
        let invalid_layout =
            ActionJournalError::Integrity(ActionJournalIntegrityError::HeaderLayout);
        let offset = (HEADER_LEN as u64)
            .checked_add(index.checked_mul(SLOT_LEN as u64).ok_or(
                ActionJournalError::Integrity(ActionJournalIntegrityError::HeaderLayout),
            )?)
            .ok_or(invalid_layout)?;
        file.read_exact_at(offset, &mut bytes)
            .map_err(ActionJournalError::Storage)?;
        if bytes != [0; SLOT_LEN] {
            return Ok(false);
        }
    }
    Ok(true)
}

fn map_anchor_open_error(error: AnchorError) -> ActionJournalError {
    match error {
        AnchorError::Storage(error) => ActionJournalError::Storage(error),
        AnchorError::Integrity => {
            ActionJournalError::Integrity(ActionJournalIntegrityError::CheckpointCorruption)
        }
    }
}

fn sync_deadline_exceeded() -> ActionJournalError {
    ActionJournalError::AuditUnavailable(AuditUnavailable::without_source(
        AuditUnavailableReason::SyncDeadlineExceeded,
    ))
}

fn busy() -> ActionJournalError {
    ActionJournalError::AuditUnavailable(AuditUnavailable::without_source(
        AuditUnavailableReason::Busy,
    ))
}

fn worker_stopped() -> ActionJournalError {
    ActionJournalError::AuditUnavailable(AuditUnavailable::without_source(
        AuditUnavailableReason::WorkerStopped,
    ))
}

fn take_completion(command: WorkerCommand) -> CompletionToken {
    match command {
        WorkerCommand::Complete { completion, .. } => completion,
        _ => unreachable!("completion submission created a non-completion command"),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        num::NonZeroU64,
        sync::{Condvar, Mutex},
    };

    use probe_core::{
        ActionAuditId, ActionAuthorizationDigest, ActionAuthorizationId, ActionBackendId,
        ActionEffectDigest, ActionParametersDigest, ActionRequestId, ActionScopeProofId, BootId,
        BpfLinkId, CapabilitySnapshotDigest, CgroupId, MonotonicInstant, PolicyDigest,
        PolicyRevisionId, TimeInterval,
    };
    use store::DurableFileError;
    use tempfile::tempdir;

    use crate::{
        ActionDecisionPoint, ActionFailureProfile, ActionKind, ActionOutcome, ActionScopeProof,
        StateChangingActionParts,
    };

    use super::super::{
        anchor::JournalAnchor,
        worker::{JournalStorage, JournalWorker},
    };
    use super::*;

    #[test]
    fn idempotent_prepare_is_resolved_before_deadline_validation() {
        let temp = tempdir().expect("temporary journal");
        let boot = BootId::new([2; 16]).expect("boot ID");
        let clock = Arc::new(FakeClock::new(boot, 200));
        let journal = ActionJournal::open_with_clock(
            &temp.path().join("journal"),
            ActionJournalId::new([1; 16]).expect("journal ID"),
            ActionJournalKey::new([3; 32]).expect("journal key"),
            options(Duration::from_secs(1)),
            clock.clone(),
        )
        .expect("open action journal");
        let intent = action(boot, 4, 5);
        let first = journal.prepare(intent).expect("initial prepare");

        clock.set(1_000);
        let repeated = journal
            .prepare(intent)
            .expect("expired retry resolves existing request");
        assert_eq!(repeated.action_id(), first.action_id());
        assert!(matches!(
            journal.prepare(action(boot, 6, 7)),
            Err(ActionJournalError::PreparedAction(
                super::super::PreparedActionError::Expired
            ))
        ));
        journal.close().expect("close journal");
    }

    #[test]
    fn pre_admission_completion_failure_returns_the_affine_token() {
        let temp = tempdir().expect("temporary journal");
        let boot = BootId::new([2; 16]).expect("boot ID");
        let clock = Arc::new(FakeClock::new(boot, 200));
        let journal = ActionJournal::open_with_clock(
            &temp.path().join("journal"),
            ActionJournalId::new([1; 16]).expect("journal ID"),
            ActionJournalKey::new([3; 32]).expect("journal key"),
            options(Duration::from_secs(1)),
            clock,
        )
        .expect("open action journal");
        let prepared = journal
            .prepare(action(boot, 4, 5))
            .expect("durable preparation");
        let completion = journal
            .claim(&prepared)
            .expect("execution permit")
            .execute(|_| ())
            .expect("scoped execution")
            .into_parts()
            .0;
        let result = ActionResult::direct(
            ActionOutcome::Applied,
            BootScopedInstant::new(boot, MonotonicInstant::from_nanos(210)),
            probe_core::ActionResultDigest::new([17; 32]).expect("result evidence"),
        )
        .expect("direct result");

        journal.health.store(
            health_tag(ActionJournalHealth::SyncStalled),
            Ordering::Release,
        );
        let rejected = journal
            .complete(completion, result)
            .expect_err("completion admission must observe stalled journal");
        assert!(rejected.retry_token().is_some());
        let (_, completion) = rejected.into_parts();
        journal
            .health
            .store(health_tag(ActionJournalHealth::Ready), Ordering::Release);
        journal
            .complete(completion.expect("returned completion token"), result)
            .expect("retry preserves direct receipt");
        journal.close().expect("close journal");
    }

    #[test]
    fn close_is_bounded_when_storage_sync_never_returns() {
        let temp = tempdir().expect("temporary journal");
        let journal_id = ActionJournalId::new([1; 16]).expect("journal ID");
        let boot = BootId::new([2; 16]).expect("boot ID");
        let key = Arc::new(ActionJournalKey::new([3; 32]).expect("journal key"));
        let genesis = [9; 32];
        let directory =
            DurableDirectory::ensure(&temp.path().join("journal")).expect("durable directory");
        let anchor_file = directory
            .open_or_create_preallocated(Path::new(CHECKPOINT_FILE), ANCHOR_FILE_CAPACITY)
            .expect("anchor file");
        let anchor = JournalAnchor::open(anchor_file, journal_id, genesis, Arc::clone(&key))
            .expect("journal anchor");
        let state = JournalState::new(journal_id, 8, genesis);
        let snapshot = Arc::new(RwLock::new(
            state.snapshot(ActionJournalHealth::Ready, None),
        ));
        let health = Arc::new(AtomicU8::new(health_tag(ActionJournalHealth::Ready)));
        let gate = Arc::new((Mutex::new(SyncGate::default()), Condvar::new()));
        let clock: Arc<dyn ActionClock> = Arc::new(FakeClock::new(boot, 200));
        let worker = JournalWorker::new(
            BlockingStorage {
                gate: Arc::clone(&gate),
            },
            anchor,
            state,
            WorkerContext {
                journal: journal_id,
                key,
                clock: Arc::clone(&clock),
                snapshot: Arc::clone(&snapshot),
                health: Arc::clone(&health),
            },
        );
        let (sender, receiver) = sync_channel(1);
        let worker_done = Arc::new(WorkerCompletion::new(false));
        let completion = Arc::clone(&worker_done);
        let handle = thread::spawn(move || {
            let _completion = WorkerCompletionGuard(completion);
            worker.run(receiver);
        });
        let journal = ActionJournal {
            sender: Some(sender),
            snapshot,
            health,
            clock,
            sync_timeout: Duration::from_millis(50),
            worker_done: Arc::clone(&worker_done),
            worker: Some(handle),
        };

        let error = thread::scope(|scope| {
            let prepare = scope.spawn(|| journal.prepare(action(boot, 4, 5)));
            wait_until_sync_is_blocked(&gate);
            prepare
                .join()
                .expect("prepare caller")
                .expect_err("blocked synchronization exceeds its deadline")
        });
        assert!(matches!(
            error,
            ActionJournalError::AuditUnavailable(ref unavailable)
                if unavailable.reason() == AuditUnavailableReason::SyncDeadlineExceeded
        ));

        let started = Instant::now();
        let close = journal
            .close()
            .expect_err("blocked worker cannot stop in time");
        assert!(started.elapsed() < Duration::from_millis(500));
        assert!(matches!(
            close,
            ActionJournalError::AuditUnavailable(ref unavailable)
                if unavailable.reason() == AuditUnavailableReason::ShutdownTimedOut
        ));

        let (state, condition) = &*gate;
        state.lock().expect("release lock").released = true;
        condition.notify_all();
        assert!(worker_done.wait(Duration::from_secs(1)));
    }

    struct FakeClock {
        boot: BootId,
        nanos: Mutex<u64>,
    }

    impl FakeClock {
        fn new(boot: BootId, nanos: u64) -> Self {
            Self {
                boot,
                nanos: Mutex::new(nanos),
            }
        }

        fn set(&self, nanos: u64) {
            *self.nanos.lock().expect("clock lock") = nanos;
        }
    }

    impl ActionClock for FakeClock {
        fn now(&self) -> Result<BootScopedInstant, super::super::ActionClockError> {
            Ok(BootScopedInstant::new(
                self.boot,
                MonotonicInstant::from_nanos(*self.nanos.lock().expect("clock lock")),
            ))
        }
    }

    struct BlockingStorage {
        gate: Arc<(Mutex<SyncGate>, Condvar)>,
    }

    #[derive(Default)]
    struct SyncGate {
        entered: bool,
        released: bool,
    }

    impl JournalStorage for BlockingStorage {
        fn write_all_at(&self, _offset: u64, _input: &[u8]) -> Result<(), DurableFileError> {
            Ok(())
        }

        fn sync_data(&self) -> Result<(), DurableFileError> {
            let (state, condition) = &*self.gate;
            let mut state = state.lock().expect("synchronization gate");
            state.entered = true;
            condition.notify_all();
            while !state.released {
                state = condition.wait(state).expect("synchronization gate wait");
            }
            Ok(())
        }
    }

    fn wait_until_sync_is_blocked(gate: &Arc<(Mutex<SyncGate>, Condvar)>) {
        let (state, condition) = &**gate;
        let state = state.lock().expect("synchronization gate");
        let (_state, timeout) = condition
            .wait_timeout_while(state, Duration::from_secs(1), |state| !state.entered)
            .expect("synchronization entry wait");
        assert!(!timeout.timed_out(), "worker did not enter synchronization");
    }

    fn options(timeout: Duration) -> ActionJournalOptions {
        ActionJournalOptions::new(
            NonZeroU64::new(HEADER_LEN as u64 + 8 * SLOT_LEN as u64).expect("capacity"),
            timeout,
        )
        .expect("journal options")
    }

    fn action(boot: BootId, request: u8, effect: u8) -> StateChangingAction {
        let validity = TimeInterval::new(
            MonotonicInstant::from_nanos(100),
            MonotonicInstant::from_nanos(900),
        )
        .expect("validity interval");
        StateChangingAction::new(StateChangingActionParts {
            request: ActionRequestId::new([request; 16]).expect("request ID"),
            audit: ActionAuditId::new([5; 16]).expect("audit ID"),
            backend: ActionBackendId::new([6; 16]).expect("backend ID"),
            authorization: ActionAuthorizationId::new([7; 16]).expect("authorization ID"),
            authorization_digest: ActionAuthorizationDigest::new([8; 32])
                .expect("authorization digest"),
            authorization_validity: validity,
            policy_revision: PolicyRevisionId::new([9; 16]).expect("policy revision"),
            policy_digest: PolicyDigest::new([10; 32]).expect("policy digest"),
            capability_snapshot: CapabilitySnapshotDigest::new([11; 32])
                .expect("capability snapshot"),
            boot,
            decided_at: MonotonicInstant::from_nanos(150),
            execute_before: MonotonicInstant::from_nanos(900),
            decision_point: ActionDecisionPoint::OutboundConnect,
            requested: ActionKind::Deny,
            effective: ActionKind::Deny,
            failure: ActionFailureProfile::FailOpen,
            scope: ActionScopeProof::CgroupHook {
                proof: ActionScopeProofId::new([12; 16]).expect("scope proof"),
                cgroup: CgroupId::new([13; 16]).expect("cgroup ID"),
                attachment: BpfLinkId::new([14; 16]).expect("BPF link ID"),
                valid_during: validity,
            },
            parameters: ActionParametersDigest::new([15; 32]).expect("parameters digest"),
            effect: ActionEffectDigest::new([effect; 32]).expect("effect digest"),
        })
        .expect("state-changing action")
    }
}
