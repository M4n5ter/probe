use std::{
    env,
    io::Cursor,
    path::Path,
    process::{Command, Stdio},
};

use evidence::{EvidenceId, SegmentId};
use store::{
    BatchId, DurabilityProfile, EvidenceStore, KeyReference, PublishOutcome, RecordKind,
    SegmentHeader, SegmentKey,
};
use tempfile::tempdir;

const CRASH_CHILD: &str = "PROBE_STORE_CRASH_CHILD";
const ORPHAN_CHILD: &str = "PROBE_STORE_ORPHAN_CHILD";
const KEY: [u8; 32] = [0x5a; 32];

#[test]
fn process_crash_discards_uncommitted_tail_without_hiding_committed_evidence() {
    if let Some(path) = env::var_os(CRASH_CHILD) {
        write_then_abort(Path::new(&path));
    }

    let temp = tempdir().expect("temporary store parent");
    let store_path = temp.path().join("store");
    run_crash_child(
        "process_crash_discards_uncommitted_tail_without_hiding_committed_evidence",
        CRASH_CHILD,
        &store_path,
    );

    let store = EvidenceStore::open(&store_path, DurabilityProfile::ProcessCrash)
        .expect("reopened evidence store");
    let segment = SegmentId::new(1).expect("segment ID");
    let report = store
        .recover_segment(segment, SegmentKey::new(KEY))
        .expect("published-boundary recovery");
    assert!(report.truncated_uncommitted_bytes > 0);

    let snapshot = store.snapshot().expect("metadata snapshot");
    let committed = snapshot
        .record(EvidenceId::new(1).expect("committed evidence ID"))
        .expect("committed metadata")
        .expect("committed record");
    assert_eq!(
        snapshot
            .record(EvidenceId::new(2).expect("uncommitted evidence ID"))
            .expect("uncommitted metadata"),
        None
    );
    drop(snapshot);

    let mut payload = Vec::new();
    store
        .read_record_to(committed, SegmentKey::new(KEY), &mut payload)
        .expect("committed payload");
    assert_eq!(payload, b"committed before crash");
}

#[test]
fn committed_orphan_forces_a_new_segment_nonce_domain() {
    if let Some(path) = env::var_os(ORPHAN_CHILD) {
        write_committed_orphan_then_abort(Path::new(&path));
    }

    let temp = tempdir().expect("temporary store parent");
    let store_path = temp.path().join("store");
    run_crash_child(
        "committed_orphan_forces_a_new_segment_nonce_domain",
        ORPHAN_CHILD,
        &store_path,
    );

    let store = EvidenceStore::open(&store_path, DurabilityProfile::ProcessCrash)
        .expect("reopened evidence store");
    let old_segment = SegmentId::new(1).expect("old segment ID");
    let report = store
        .recover_segment(old_segment, SegmentKey::new(KEY))
        .expect("published-boundary recovery");
    assert!(report.discarded_committed_orphan_bytes > 0);
    let repeated = store
        .recover_segment(old_segment, SegmentKey::new(KEY))
        .expect("repeat retired-segment recovery");
    assert_eq!(repeated.discarded_committed_orphan_bytes, 0);
    assert_eq!(repeated.truncated_uncommitted_bytes, 0);
    assert_eq!(
        store
            .snapshot()
            .expect("snapshot")
            .record(EvidenceId::new(2).expect("orphan evidence ID"))
            .expect("orphan metadata"),
        None
    );

    let new_segment = SegmentId::new(2).expect("new segment ID");
    let mut writer = store
        .create_segment(
            SegmentHeader::new(
                new_segment,
                1,
                KeyReference::new("test/key").expect("key reference"),
            ),
            SegmentKey::new(KEY),
        )
        .expect("replacement segment writer");
    let mut batch = writer
        .begin_batch(BatchId::new(3).expect("replacement batch ID"))
        .expect("replacement batch");
    batch
        .append_reader(
            EvidenceId::new(3).expect("replacement evidence ID"),
            RecordKind::Plaintext,
            Cursor::new(b"replacement in a fresh nonce domain"),
        )
        .expect("replacement record");
    let committed = batch.commit().expect("replacement commit");
    let (outcome, published) = store
        .publish_batch(committed)
        .expect("replacement metadata");
    assert_eq!(outcome, PublishOutcome::Published);
    let replacement = published.records()[0];
    assert_eq!(replacement.bytes().range.start(), 0);
    drop(writer);

    let mut loaded = Vec::new();
    store
        .read_record_to(replacement, SegmentKey::new(KEY), &mut loaded)
        .expect("replacement payload");
    assert_eq!(loaded, b"replacement in a fresh nonce domain");
}

fn run_crash_child(test: &str, environment: &str, store_path: &Path) {
    let status = Command::new(env::current_exe().expect("integration test executable"))
        .arg("--exact")
        .arg(test)
        .arg("--nocapture")
        .env(environment, store_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("crash child");
    assert!(!status.success());
}

fn write_then_abort(path: &Path) -> ! {
    let store = EvidenceStore::open(path, DurabilityProfile::ProcessCrash).expect("child store");
    let mut writer = create_writer(&store, SegmentId::new(1).expect("segment ID"));

    let mut committed_batch = writer
        .begin_batch(BatchId::new(1).expect("committed batch ID"))
        .expect("committed batch");
    committed_batch
        .append_reader(
            EvidenceId::new(1).expect("committed evidence ID"),
            RecordKind::Plaintext,
            Cursor::new(b"committed before crash"),
        )
        .expect("committed record");
    let committed = committed_batch.commit().expect("segment commit");
    store.publish_batch(committed).expect("metadata publish");

    let mut uncommitted_batch = writer
        .begin_batch(BatchId::new(2).expect("uncommitted batch ID"))
        .expect("uncommitted batch");
    uncommitted_batch
        .append_reader(
            EvidenceId::new(2).expect("uncommitted evidence ID"),
            RecordKind::Plaintext,
            Cursor::new(b"must be discarded"),
        )
        .expect("uncommitted record");
    std::process::abort()
}

fn write_committed_orphan_then_abort(path: &Path) -> ! {
    let store = EvidenceStore::open(path, DurabilityProfile::ProcessCrash).expect("child store");
    let mut writer = create_writer(&store, SegmentId::new(1).expect("segment ID"));

    let mut first_batch = writer
        .begin_batch(BatchId::new(1).expect("first batch ID"))
        .expect("first batch");
    first_batch
        .append_reader(
            EvidenceId::new(1).expect("first evidence ID"),
            RecordKind::Plaintext,
            Cursor::new(b"published before orphan"),
        )
        .expect("first record");
    store
        .publish_batch(first_batch.commit().expect("first commit"))
        .expect("first metadata");

    let mut orphan_batch = writer
        .begin_batch(BatchId::new(2).expect("orphan batch ID"))
        .expect("orphan batch");
    orphan_batch
        .append_reader(
            EvidenceId::new(2).expect("orphan evidence ID"),
            RecordKind::Plaintext,
            Cursor::new(b"committed but never published"),
        )
        .expect("orphan record");
    orphan_batch.commit().expect("orphan segment commit");
    std::process::abort()
}

fn create_writer(store: &EvidenceStore, segment: SegmentId) -> store::SegmentWriter {
    store
        .create_segment(
            SegmentHeader::new(
                segment,
                1,
                KeyReference::new("test/key").expect("key reference"),
            ),
            SegmentKey::new(KEY),
        )
        .expect("segment writer")
}
