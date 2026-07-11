use std::{
    env,
    fs::OpenOptions,
    num::NonZeroU64,
    os::unix::fs::FileExt,
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};

use actions::{
    ActionArchiveCursor, ActionDecisionPoint, ActionFailureProfile, ActionJournal,
    ActionJournalError, ActionJournalFailure, ActionJournalHealth, ActionJournalIntegrityError,
    ActionJournalKey, ActionJournalOptions, ActionKind, ActionOutcome, ActionRecordState,
    ActionResult, ActionScopeProof, AuditUnavailableReason, CompletionToken, PreparedAction,
    StateChangingAction, StateChangingActionParts,
};
use probe_core::{
    ActionAuditId, ActionAuthorizationDigest, ActionAuthorizationId, ActionBackendId,
    ActionEffectDigest, ActionJournalId, ActionParametersDigest, ActionRequestId,
    ActionResultDigest, ActionScopeProofId, BootId, BootScopedInstant, CapabilitySnapshotDigest,
    MonotonicInstant, NetworkNamespaceId, PolicyDigest, PolicyRevisionId, SocketId, TimeInterval,
    WorkloadId,
};
use tempfile::tempdir;

const CRASH_PREPARED: &str = "PROBE_ACTION_JOURNAL_CRASH_PREPARED";
const CRASH_COMPLETED: &str = "PROBE_ACTION_JOURNAL_CRASH_COMPLETED";
const KEY: [u8; 32] = [0x5a; 32];
const JOURNAL_CAPACITY: u64 = 64 * 1024;
const SLOT_LEN: u64 = 1024;
const HEADER_LEN: u64 = 4096;

#[test]
fn durable_claim_is_single_use_idempotent_and_fenced() {
    let temp = tempdir().expect("temporary action journal parent");
    let journal = open_journal(temp.path(), 1, JOURNAL_CAPACITY);
    let intent = action(&journal, 1, 1, 1);

    let prepared = journal.prepare(intent).expect("durable prepared action");
    let repeated = journal.prepare(intent).expect("idempotent prepare");
    assert_eq!(repeated.action_id(), prepared.action_id());
    assert_eq!(repeated.prepared_id(), prepared.prepared_id());

    assert!(matches!(
        journal.prepare(action(&journal, 1, 1, 2)),
        Err(ActionJournalError::RequestConflict { .. })
    ));
    assert!(matches!(
        journal.prepare(action(&journal, 2, 1, 1)),
        Err(ActionJournalError::EffectFenced { owner }) if owner == prepared.action_id()
    ));

    let permit = journal.claim(&prepared).expect("single execution permit");
    assert!(matches!(
        journal.claim(&repeated),
        Err(ActionJournalError::InDoubt { action }) if action == prepared.action_id()
    ));
    let attempt = permit
        .execute(|executable| executable.action_id())
        .expect("execution within trusted window");
    assert_eq!(*attempt.output(), prepared.action_id());
    let (completion, _) = attempt.into_parts();
    journal
        .complete(
            completion,
            direct_result(&journal, ActionOutcome::Applied, 1),
        )
        .expect("durable completion");

    let snapshot = journal.snapshot();
    assert_eq!(snapshot.health(), ActionJournalHealth::Ready);
    assert!(snapshot.unresolved().is_empty());
    assert_eq!(snapshot.terminal_count(), 1);
    assert_eq!(
        snapshot.latest_terminal().expect("latest terminal").state(),
        ActionRecordState::Applied
    );
    assert!(matches!(
        journal.prepare(intent),
        Err(ActionJournalError::AlreadyCompleted {
            outcome: ActionOutcome::Applied,
            ..
        })
    ));
    journal.close().expect("close journal");

    let reopened = open_journal(temp.path(), 1, JOURNAL_CAPACITY);
    let recovered = reopened.snapshot();
    assert!(recovered.unresolved().is_empty());
    assert_eq!(recovered.terminal_count(), 1);
    assert_eq!(
        recovered
            .latest_terminal()
            .expect("latest terminal")
            .result()
            .expect("terminal result")
            .causality(),
        actions::ActionCausality::Known
    );
    reopened.close().expect("close reopened journal");
}

#[test]
fn reserve_exhaustion_preserves_every_completion_slot() {
    let temp = tempdir().expect("temporary action journal parent");
    let capacity = HEADER_LEN + 12 * SLOT_LEN;
    let journal = open_journal(temp.path(), 1, capacity);
    let prepared = (1..=3)
        .map(|value| {
            journal
                .prepare(action(&journal, value, value, value))
                .expect("reserved prepared action")
        })
        .collect::<Vec<_>>();

    let error = journal
        .prepare(action(&journal, 4, 4, 4))
        .expect_err("prepare reserve must be exhausted");
    assert!(matches!(
        error,
        ActionJournalError::AuditUnavailable(ref unavailable)
            if unavailable.reason() == AuditUnavailableReason::JournalFull
    ));
    for (index, prepared) in prepared.into_iter().enumerate() {
        let completion = execute(&journal, &prepared);
        journal
            .complete(
                completion,
                direct_result(&journal, ActionOutcome::NotApplied, index as u8 + 1),
            )
            .expect("escrowed completion");
    }
    let snapshot = journal.snapshot();
    assert!(snapshot.unresolved().is_empty());
    assert_eq!(snapshot.terminal_count(), 3);
    journal.close().expect("close journal");
}

#[test]
fn archive_cursor_catches_up_terminal_records_after_reopen() {
    let temp = tempdir().expect("temporary action journal parent");
    let journal = open_journal(temp.path(), 1, JOURNAL_CAPACITY);
    for value in 1..=2 {
        let prepared = journal
            .prepare(action(&journal, value, value, value))
            .expect("durable prepared action");
        journal
            .complete(
                execute(&journal, &prepared),
                direct_result(&journal, ActionOutcome::Applied, value),
            )
            .expect("durable completion");
    }
    journal.close().expect("close journal");

    let reopened = open_journal(temp.path(), 1, JOURNAL_CAPACITY);
    let first = reopened
        .archive_after(reopened.archive_begin(), 1)
        .expect("first archive batch");
    assert_eq!(first.records().len(), 1);
    assert!(first.has_more());
    let persisted = first.next().encode();
    reopened.close().expect("close first archive reader");

    let resumed_cursor = ActionArchiveCursor::decode(&persisted).expect("persisted cursor");
    let resumed = open_journal(temp.path(), 1, JOURNAL_CAPACITY);
    let mut fabricated = persisted;
    fabricated[16..].copy_from_slice(&1_u64.to_be_bytes());
    assert!(matches!(
        resumed.archive_after(
            ActionArchiveCursor::decode(&fabricated).expect("structural cursor decode"),
            1,
        ),
        Err(ActionJournalError::UnknownArchiveCursor)
    ));
    let second = resumed
        .archive_after(resumed_cursor, 1)
        .expect("second archive batch");
    assert_eq!(second.records().len(), 1);
    assert!(!second.has_more());
    assert!(second.next() > first.next());
    resumed.close().expect("close resumed archive reader");

    let other = tempdir().expect("other journal parent");
    let other = open_journal(other.path(), 2, JOURNAL_CAPACITY);
    assert!(matches!(
        other.archive_after(resumed_cursor, 1),
        Err(ActionJournalError::ArchiveCursorJournalMismatch)
    ));
    other.close().expect("close other journal");
}

#[test]
fn uncertain_execution_requires_effect_reconciliation() {
    let temp = tempdir().expect("temporary action journal parent");
    let journal = open_journal(temp.path(), 1, HEADER_LEN + 8 * SLOT_LEN);
    let prepared = journal
        .prepare(action(&journal, 1, 1, 1))
        .expect("durable prepared action");
    let completion = execute(&journal, &prepared);
    journal
        .complete(
            completion,
            ActionResult::uncertain(
                journal.now().expect("trusted time"),
                ActionResultDigest::new([1; 32]).expect("uncertainty evidence"),
            ),
        )
        .expect("durable uncertainty");
    assert_eq!(journal.snapshot().in_doubt().count(), 1);

    let reconciliation = reconciled_result(&journal, ActionOutcome::Applied, 2);
    journal
        .reconcile(prepared.action_id(), reconciliation)
        .expect("terminal effect reconciliation");
    assert!(journal.snapshot().unresolved().is_empty());
    journal.close().expect("close journal");
}

#[test]
fn cross_boot_direct_receipts_are_rejected_but_reconciliation_is_valid() {
    let temp = tempdir().expect("temporary action journal parent");
    let journal = open_journal(temp.path(), 1, JOURNAL_CAPACITY);
    let prepared = journal
        .prepare(action(&journal, 1, 1, 1))
        .expect("durable prepared action");
    let completion = execute(&journal, &prepared);
    let foreign_time = BootScopedInstant::new(
        BootId::new([0xf1; 16]).expect("foreign boot"),
        MonotonicInstant::from_nanos(1),
    );
    let direct = ActionResult::direct(
        ActionOutcome::Applied,
        foreign_time,
        ActionResultDigest::new([1; 32]).expect("receipt"),
    )
    .expect("well-formed direct result");
    let rejected = journal
        .complete(completion, direct)
        .expect_err("foreign direct receipt must be rejected");
    assert!(matches!(
        rejected.error(),
        ActionJournalError::ResultFromWrongBoot(action) if *action == prepared.action_id()
    ));
    let (_, completion) = rejected.into_parts();
    journal
        .complete(
            completion.expect("deterministic rejection returns completion token"),
            direct_result(&journal, ActionOutcome::Applied, 3),
        )
        .expect("corrected direct receipt preserves known causality");

    let uncertain = journal
        .prepare(action(&journal, 2, 2, 2))
        .expect("second durable action");
    {
        let _unreported_completion = execute(&journal, &uncertain);
    }

    let reconciled = ActionResult::reconciled(
        ActionOutcome::NotApplied,
        foreign_time,
        ActionResultDigest::new([2; 32]).expect("effect truth"),
    )
    .expect("cross-boot reconciliation");
    journal
        .reconcile(uncertain.action_id(), reconciled)
        .expect("cross-boot effect truth is comparable without monotonic ordering");
    journal.close().expect("close journal");
}

#[test]
fn crash_after_prepare_recovers_in_doubt_without_reexecution() {
    if let Some(path) = env::var_os(CRASH_PREPARED) {
        let journal = open_journal(Path::new(&path), 1, JOURNAL_CAPACITY);
        journal
            .prepare(action(&journal, 1, 1, 1))
            .expect("child durable prepare");
        std::process::abort();
    }

    let temp = tempdir().expect("temporary action journal parent");
    run_crash_child(
        "crash_after_prepare_recovers_in_doubt_without_reexecution",
        CRASH_PREPARED,
        temp.path(),
    );
    let journal = open_journal(temp.path(), 1, JOURNAL_CAPACITY);
    let record = journal
        .snapshot()
        .in_doubt()
        .next()
        .expect("recovered in-doubt action");
    assert!(matches!(
        journal.prepare(record.action()),
        Err(ActionJournalError::InDoubt { action }) if action == record.action_id()
    ));
    journal
        .reconcile(
            record.action_id(),
            reconciled_result(&journal, ActionOutcome::NotApplied, 9),
        )
        .expect("durable reconciliation");
    journal.close().expect("close journal");
}

#[test]
fn crash_after_completion_recovers_the_terminal_receipt() {
    if let Some(path) = env::var_os(CRASH_COMPLETED) {
        let journal = open_journal(Path::new(&path), 1, JOURNAL_CAPACITY);
        let prepared = journal
            .prepare(action(&journal, 1, 1, 1))
            .expect("child durable prepare");
        let completion = execute(&journal, &prepared);
        journal
            .complete(
                completion,
                direct_result(&journal, ActionOutcome::Applied, 1),
            )
            .expect("child durable completion");
        std::process::abort();
    }

    let temp = tempdir().expect("temporary action journal parent");
    run_crash_child(
        "crash_after_completion_recovers_the_terminal_receipt",
        CRASH_COMPLETED,
        temp.path(),
    );
    let journal = open_journal(temp.path(), 1, JOURNAL_CAPACITY);
    let record = journal
        .snapshot()
        .latest_terminal()
        .expect("recovered terminal");
    assert_eq!(record.state(), ActionRecordState::Applied);
    journal.close().expect("close journal");
}

#[test]
fn authenticated_record_corruption_quarantines_the_journal() {
    let temp = tempdir().expect("temporary action journal parent");
    let journal = open_journal(temp.path(), 1, JOURNAL_CAPACITY);
    journal
        .prepare(action(&journal, 1, 1, 1))
        .expect("durable prepared action");
    journal.close().expect("close journal");

    mutate_byte(
        &temp.path().join("journal/actions.journal"),
        HEADER_LEN + 128,
    );
    let journal = open_journal(temp.path(), 1, JOURNAL_CAPACITY);
    assert_eq!(journal.health(), ActionJournalHealth::Quarantined);
    assert_eq!(
        journal.snapshot().failure(),
        Some(ActionJournalFailure::Integrity(
            ActionJournalIntegrityError::RecordCorruption
        ))
    );
}

#[test]
fn authenticated_checkpoint_rejects_a_valid_prefix_rollback() {
    let temp = tempdir().expect("temporary action journal parent");
    let journal = open_journal(temp.path(), 1, JOURNAL_CAPACITY);
    let prepared = journal
        .prepare(action(&journal, 1, 1, 1))
        .expect("durable prepared action");
    let completion = execute(&journal, &prepared);
    journal
        .complete(
            completion,
            direct_result(&journal, ActionOutcome::Applied, 1),
        )
        .expect("durable completion");
    journal.close().expect("close journal");

    let file = OpenOptions::new()
        .write(true)
        .open(temp.path().join("journal/actions.journal"))
        .expect("journal file");
    file.write_all_at(&[0; SLOT_LEN as usize], HEADER_LEN + SLOT_LEN)
        .expect("roll back terminal slot");
    file.sync_data().expect("durable rollback");
    drop(file);

    let journal = open_journal(temp.path(), 1, JOURNAL_CAPACITY);
    assert_eq!(journal.health(), ActionJournalHealth::Quarantined);
    assert_eq!(
        journal.snapshot().failure(),
        Some(ActionJournalFailure::Integrity(
            ActionJournalIntegrityError::JournalRollback
        ))
    );
}

#[test]
fn torn_checkpoint_cell_recovers_from_authenticated_journal_successor() {
    let temp = tempdir().expect("temporary action journal parent");
    let journal = open_journal(temp.path(), 1, JOURNAL_CAPACITY);
    let prepared = journal
        .prepare(action(&journal, 1, 1, 1))
        .expect("durable prepared action");
    journal
        .complete(
            execute(&journal, &prepared),
            direct_result(&journal, ActionOutcome::Applied, 1),
        )
        .expect("durable completion");
    journal.close().expect("close journal");

    mutate_byte(&temp.path().join("journal/actions.checkpoint"), 80);
    let recovered = open_journal(temp.path(), 1, JOURNAL_CAPACITY);
    assert_eq!(
        recovered
            .snapshot()
            .latest_terminal()
            .expect("terminal record after checkpoint repair")
            .state(),
        ActionRecordState::Applied
    );
    recovered.close().expect("close repaired journal");

    open_journal(temp.path(), 1, JOURNAL_CAPACITY)
        .close()
        .expect("repaired checkpoint remains valid");
}

#[test]
fn torn_checkpoint_cannot_hide_a_matching_journal_rollback() {
    let temp = tempdir().expect("temporary action journal parent");
    let journal = open_journal(temp.path(), 1, JOURNAL_CAPACITY);
    let prepared = journal
        .prepare(action(&journal, 1, 1, 1))
        .expect("durable prepared action");
    journal
        .complete(
            execute(&journal, &prepared),
            direct_result(&journal, ActionOutcome::Applied, 1),
        )
        .expect("durable completion");
    journal.close().expect("close journal");

    mutate_byte(&temp.path().join("journal/actions.checkpoint"), 80);
    let file = OpenOptions::new()
        .write(true)
        .open(temp.path().join("journal/actions.journal"))
        .expect("journal file");
    file.write_all_at(&[0; SLOT_LEN as usize], HEADER_LEN + SLOT_LEN)
        .expect("roll back terminal slot");
    file.sync_data().expect("durable rollback");

    let journal = open_journal(temp.path(), 1, JOURNAL_CAPACITY);
    assert_eq!(journal.health(), ActionJournalHealth::Quarantined);
    assert_eq!(
        journal.snapshot().failure(),
        Some(ActionJournalFailure::Integrity(
            ActionJournalIntegrityError::CheckpointCorruption
        ))
    );
}

fn open_journal(path: &Path, journal: u8, capacity: u64) -> ActionJournal {
    ActionJournal::open(
        &path.join("journal"),
        ActionJournalId::new([journal; 16]).expect("journal ID"),
        ActionJournalKey::new(KEY).expect("journal key"),
        ActionJournalOptions::new(
            NonZeroU64::new(capacity).expect("journal capacity"),
            Duration::from_secs(2),
        )
        .expect("journal options"),
    )
    .expect("open action journal")
}

fn action(journal: &ActionJournal, request: u8, effect: u8, parameters: u8) -> StateChangingAction {
    let now = journal.now().expect("trusted action time");
    let decided_at = now.instant();
    let execute_before = MonotonicInstant::from_nanos(
        decided_at
            .as_nanos()
            .checked_add(60_000_000_000)
            .expect("execution deadline"),
    );
    let validity = TimeInterval::new(decided_at, execute_before).expect("validity interval");
    StateChangingAction::new(StateChangingActionParts {
        request: ActionRequestId::new([request; 16]).expect("request ID"),
        audit: ActionAuditId::new([3; 16]).expect("audit ID"),
        backend: ActionBackendId::new([4; 16]).expect("backend ID"),
        authorization: ActionAuthorizationId::new([5; 16]).expect("authorization ID"),
        authorization_digest: ActionAuthorizationDigest::new([6; 32])
            .expect("authorization digest"),
        authorization_validity: validity,
        policy_revision: PolicyRevisionId::new([7; 16]).expect("policy revision"),
        policy_digest: PolicyDigest::new([8; 32]).expect("policy digest"),
        capability_snapshot: CapabilitySnapshotDigest::new([9; 32]).expect("capability snapshot"),
        boot: now.boot(),
        decided_at,
        execute_before,
        decision_point: ActionDecisionPoint::OutboundConnect,
        requested: ActionKind::DestroySocket,
        effective: ActionKind::DestroySocket,
        failure: ActionFailureProfile::FailOpen,
        scope: ActionScopeProof::KernelSocket {
            proof: ActionScopeProofId::new([10; 16]).expect("scope proof"),
            socket: SocketId::new([11; 16]).expect("socket ID"),
            network_namespace: NetworkNamespaceId::new([12; 16]).expect("network namespace"),
            workload: WorkloadId::new([13; 16]).expect("workload ID"),
            valid_during: validity,
        },
        parameters: ActionParametersDigest::new([parameters; 32]).expect("parameters digest"),
        effect: ActionEffectDigest::new([effect; 32]).expect("effect digest"),
    })
    .expect("state-changing action")
}

fn execute(journal: &ActionJournal, prepared: &PreparedAction) -> CompletionToken {
    journal
        .claim(prepared)
        .expect("execution permit")
        .execute(|_| ())
        .expect("execution within trusted window")
        .into_parts()
        .0
}

fn direct_result(journal: &ActionJournal, outcome: ActionOutcome, evidence: u8) -> ActionResult {
    ActionResult::direct(
        outcome,
        journal.now().expect("trusted result time"),
        ActionResultDigest::new([evidence; 32]).expect("result evidence"),
    )
    .expect("direct backend result")
}

fn reconciled_result(
    journal: &ActionJournal,
    outcome: ActionOutcome,
    evidence: u8,
) -> ActionResult {
    ActionResult::reconciled(
        outcome,
        journal.now().expect("trusted reconciliation time"),
        ActionResultDigest::new([evidence; 32]).expect("reconciliation evidence"),
    )
    .expect("reconciled effect truth")
}

fn mutate_byte(path: &Path, offset: u64) {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("journal file");
    let mut byte = [0_u8; 1];
    file.read_exact_at(&mut byte, offset)
        .expect("read authenticated byte");
    byte[0] ^= 0x80;
    file.write_all_at(&byte, offset)
        .expect("tamper authenticated byte");
    file.sync_data().expect("durable corruption");
}

fn run_crash_child(test: &str, environment: &str, journal_path: &Path) {
    let status = Command::new(env::current_exe().expect("integration test executable"))
        .arg("--exact")
        .arg(test)
        .arg("--nocapture")
        .env(environment, journal_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("crash child");
    assert!(!status.success());
}
