use store::{DurableFileError, PreallocatedFile};

use super::{
    ActionJournalIntegrityError, ActionJournalKey,
    anchor::{AnchorError, JournalAnchor},
    format::{HEADER_LEN, JournalPayload, SLOT_LEN, decode_slot},
    identity::derive_prepare_ids,
    state::JournalState,
};

pub(super) struct Recovery {
    pub(super) state: JournalState,
    pub(super) quarantine: Option<ActionJournalIntegrityError>,
}

pub(super) fn recover(
    file: &PreallocatedFile,
    anchor: &mut JournalAnchor,
    mut state: JournalState,
    key: &ActionJournalKey,
) -> Result<Recovery, DurableFileError> {
    let checkpoint = anchor.checkpoint();
    let total_slots = usize::try_from((file.capacity() - HEADER_LEN as u64) / SLOT_LEN as u64)
        .map_err(|_| DurableFileError::RangeOverflow)?;
    let mut found_empty = false;
    let mut anchored_tail_found = checkpoint.sequence() == 0;
    let mut quarantine = None;
    for slot_index in 0..total_slots {
        let sequence = u64::try_from(slot_index)
            .ok()
            .and_then(|index| index.checked_add(1))
            .ok_or(DurableFileError::RangeOverflow)?;
        let offset = slot_offset(sequence).ok_or(DurableFileError::RangeOverflow)?;
        let mut bytes = [0_u8; SLOT_LEN];
        file.read_exact_at(offset, &mut bytes)?;
        if bytes == [0; SLOT_LEN] {
            found_empty = true;
            continue;
        }
        if found_empty {
            quarantine = Some(ActionJournalIntegrityError::RecordGap);
            break;
        }
        let decoded = match decode_slot(
            state.journal(),
            sequence,
            state.previous_digest(),
            &bytes,
            key.as_bytes(),
        ) {
            Ok(Some(decoded)) => decoded,
            Ok(None) => {
                found_empty = true;
                continue;
            }
            Err(_) => {
                quarantine = Some(ActionJournalIntegrityError::RecordCorruption);
                break;
            }
        };
        if sequence == checkpoint.sequence() {
            if decoded.digest() != checkpoint.tail() {
                quarantine = Some(ActionJournalIntegrityError::JournalRollback);
                break;
            }
            anchored_tail_found = true;
        }
        let result = match decoded.payload() {
            JournalPayload::Prepare {
                action_id,
                prepared_id,
                action,
            } => {
                let derived = derive_prepare_ids(state.journal(), sequence, **action, key);
                if derived != Some((*action_id, *prepared_id)) {
                    quarantine = Some(ActionJournalIntegrityError::RecordConflict);
                    break;
                }
                state.record_prepare(*action_id, *prepared_id, **action, decoded.digest(), false)
            }
            JournalPayload::Outcome {
                action_id,
                prepared_id,
                request,
                intent,
                result,
            } => state.record_outcome(
                *action_id,
                *prepared_id,
                *request,
                *intent,
                *result,
                decoded.digest(),
            ),
        };
        if result.is_err() {
            quarantine = Some(ActionJournalIntegrityError::RecordConflict);
            break;
        }
    }

    let recovered_sequence = state.next_sequence().saturating_sub(1);
    if quarantine.is_none()
        && anchor.interrupted_update()
        && recovered_sequence <= checkpoint.sequence()
    {
        quarantine = Some(ActionJournalIntegrityError::CheckpointCorruption);
    }
    if quarantine.is_none() && (!anchored_tail_found || checkpoint.sequence() > recovered_sequence)
    {
        quarantine = Some(ActionJournalIntegrityError::JournalRollback);
    }
    if quarantine.is_none()
        && let Err(error) = anchor.advance(recovered_sequence, state.previous_digest())
    {
        match error {
            AnchorError::Storage(error) => return Err(error),
            AnchorError::Integrity => {
                quarantine = Some(ActionJournalIntegrityError::JournalRollback)
            }
        }
    }
    state.mark_all_unfinished_in_doubt();
    Ok(Recovery { state, quarantine })
}

pub(super) fn slot_offset(sequence: u64) -> Option<u64> {
    sequence
        .checked_sub(1)?
        .checked_mul(SLOT_LEN as u64)?
        .checked_add(HEADER_LEN as u64)
}
