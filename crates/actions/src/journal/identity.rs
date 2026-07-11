use blake3::Hasher;
use probe_core::{ActionExecutionId, ActionId, ActionJournalId, PreparedActionId};

use crate::StateChangingAction;

use super::ActionJournalKey;

pub(super) fn derive_prepare_ids(
    journal: ActionJournalId,
    sequence: u64,
    action: StateChangingAction,
    key: &ActionJournalKey,
) -> Option<(ActionId, PreparedActionId)> {
    let action_id = derive_id(b"probe.action.id\0", journal, sequence, action, key);
    let prepared_id = derive_id(
        b"probe.action.prepared-id\0",
        journal,
        sequence,
        action,
        key,
    );
    Some((
        ActionId::new(action_id).ok()?,
        PreparedActionId::new(prepared_id).ok()?,
    ))
}

pub(super) fn derive_execution_id(
    journal: ActionJournalId,
    action_id: ActionId,
    prepared_id: PreparedActionId,
    action: StateChangingAction,
    key: &ActionJournalKey,
) -> Option<ActionExecutionId> {
    let mut hasher = Hasher::new_keyed(key.as_bytes());
    hasher.update(b"probe.action.execution-id\0");
    hasher.update(journal.as_bytes());
    hasher.update(action_id.as_bytes());
    hasher.update(prepared_id.as_bytes());
    hasher.update(action.request().as_bytes());
    hasher.update(action.digest().as_bytes());
    canonical_id(hasher).and_then(|id| ActionExecutionId::new(id).ok())
}

fn derive_id(
    domain: &[u8],
    journal: ActionJournalId,
    sequence: u64,
    action: StateChangingAction,
    key: &ActionJournalKey,
) -> [u8; 16] {
    let mut hasher = Hasher::new_keyed(key.as_bytes());
    hasher.update(domain);
    hasher.update(journal.as_bytes());
    hasher.update(&sequence.to_be_bytes());
    hasher.update(action.request().as_bytes());
    hasher.update(action.digest().as_bytes());
    canonical_id(hasher).expect("derived action identifier is non-zero")
}

fn canonical_id(hasher: Hasher) -> Option<[u8; 16]> {
    let mut id = [0_u8; 16];
    id.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    id[0] |= 1;
    (id != [0; 16]).then_some(id)
}
