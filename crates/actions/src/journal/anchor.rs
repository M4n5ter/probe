use std::{fmt, num::NonZeroU64, sync::Arc};

use blake3::Hasher;
use probe_core::ActionJournalId;
use store::{DurableFileError, PreallocatedFile};

use super::ActionJournalKey;

pub(super) const ANCHOR_FILE_CAPACITY: NonZeroU64 =
    NonZeroU64::new(2 * ANCHOR_CELL_LEN as u64).expect("anchor capacity is non-zero");

const ANCHOR_CELL_LEN: usize = 4096;
const ANCHOR_MAGIC: &[u8; 16] = b"PROBE_ACTION_ANC";
const ANCHOR_CONTRACT: &[u8] = b"probe.action-journal.anchor\n\
cell=magic,fingerprint,journal-id,revision,committed-sequence,tail-digest,padding,mac\n\
integers=big-endian;identifiers=canonical-nonzero;unused-bytes=zero";
const AUTHENTICATOR_LEN: usize = 32;
const AUTHENTICATOR_OFFSET: usize = ANCHOR_CELL_LEN - AUTHENTICATOR_LEN;
const AUTHENTICATION_DOMAIN: &[u8] = b"probe.action-journal.anchor-authentication\0";

pub(super) struct JournalAnchor {
    storage: Box<dyn AnchorStorage>,
    journal: ActionJournalId,
    key: Arc<ActionJournalKey>,
    checkpoint: AnchorCheckpoint,
    interrupted_update: bool,
}

impl JournalAnchor {
    pub(super) fn open(
        storage: impl AnchorStorage + 'static,
        journal: ActionJournalId,
        genesis: [u8; 32],
        key: Arc<ActionJournalKey>,
    ) -> Result<Self, AnchorError> {
        let storage: Box<dyn AnchorStorage> = Box::new(storage);
        let first = read_cell(storage.as_ref(), 0, journal, &key)?;
        let second = read_cell(storage.as_ref(), 1, journal, &key)?;
        let selection = select_checkpoint(first, second)?;
        let checkpoint = selection.checkpoint.unwrap_or(AnchorCheckpoint {
            revision: 0,
            sequence: 0,
            tail: genesis,
        });
        if checkpoint.sequence == 0 && checkpoint.tail != genesis {
            return Err(AnchorError::Integrity);
        }
        let mut anchor = Self {
            storage,
            journal,
            key,
            checkpoint,
            interrupted_update: selection.interrupted_update,
        };
        if first == Cell::Empty && second == Cell::Empty {
            anchor.persist(checkpoint)?;
        }
        Ok(anchor)
    }

    pub(super) const fn checkpoint(&self) -> AnchorCheckpoint {
        self.checkpoint
    }

    pub(super) const fn interrupted_update(&self) -> bool {
        self.interrupted_update
    }

    pub(super) fn advance(&mut self, sequence: u64, tail: [u8; 32]) -> Result<(), AnchorError> {
        if sequence < self.checkpoint.sequence
            || (sequence == self.checkpoint.sequence && tail != self.checkpoint.tail)
        {
            return Err(AnchorError::Integrity);
        }
        if sequence == self.checkpoint.sequence {
            return Ok(());
        }
        let checkpoint = AnchorCheckpoint {
            revision: self
                .checkpoint
                .revision
                .checked_add(1)
                .ok_or(AnchorError::Integrity)?,
            sequence,
            tail,
        };
        self.persist(checkpoint)?;
        self.checkpoint = checkpoint;
        self.interrupted_update = false;
        Ok(())
    }

    fn persist(&mut self, checkpoint: AnchorCheckpoint) -> Result<(), AnchorError> {
        let cell = encode_cell(self.journal, checkpoint, &self.key);
        let cell_index = usize::from((checkpoint.revision & 1) != 0);
        let offset =
            u64::try_from(cell_index * ANCHOR_CELL_LEN).map_err(|_| AnchorError::Integrity)?;
        self.storage
            .write_all_at(offset, &cell)
            .map_err(AnchorError::Storage)?;
        self.storage.sync_data().map_err(AnchorError::Storage)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct AnchorCheckpoint {
    revision: u64,
    sequence: u64,
    tail: [u8; 32],
}

impl AnchorCheckpoint {
    pub(super) const fn sequence(self) -> u64 {
        self.sequence
    }

    pub(super) const fn tail(self) -> [u8; 32] {
        self.tail
    }
}

#[derive(Debug)]
pub(super) enum AnchorError {
    Storage(DurableFileError),
    Integrity,
}

impl fmt::Display for AnchorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(error) => write!(formatter, "anchor storage failed: {error}"),
            Self::Integrity => {
                formatter.write_str("action journal local rollback checkpoint is invalid")
            }
        }
    }
}

impl std::error::Error for AnchorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(error) => Some(error),
            Self::Integrity => None,
        }
    }
}

pub(super) trait AnchorStorage: Send {
    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<(), DurableFileError>;
    fn write_all_at(&self, offset: u64, input: &[u8]) -> Result<(), DurableFileError>;
    fn sync_data(&self) -> Result<(), DurableFileError>;
}

impl AnchorStorage for PreallocatedFile {
    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<(), DurableFileError> {
        PreallocatedFile::read_exact_at(self, offset, output)
    }

    fn write_all_at(&self, offset: u64, input: &[u8]) -> Result<(), DurableFileError> {
        PreallocatedFile::write_all_at(self, offset, input)
    }

    fn sync_data(&self) -> Result<(), DurableFileError> {
        PreallocatedFile::sync_data(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Cell {
    Empty,
    Valid(AnchorCheckpoint),
    Invalid,
}

fn read_cell(
    storage: &dyn AnchorStorage,
    index: usize,
    journal: ActionJournalId,
    key: &ActionJournalKey,
) -> Result<Cell, AnchorError> {
    let offset = u64::try_from(index * ANCHOR_CELL_LEN).map_err(|_| AnchorError::Integrity)?;
    let mut bytes = [0_u8; ANCHOR_CELL_LEN];
    storage
        .read_exact_at(offset, &mut bytes)
        .map_err(AnchorError::Storage)?;
    let cell = decode_cell(&bytes, journal, key);
    if matches!(cell, Cell::Valid(checkpoint) if usize::from((checkpoint.revision & 1) != 0) != index)
    {
        Ok(Cell::Invalid)
    } else {
        Ok(cell)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AnchorSelection {
    checkpoint: Option<AnchorCheckpoint>,
    interrupted_update: bool,
}

fn select_checkpoint(first: Cell, second: Cell) -> Result<AnchorSelection, AnchorError> {
    match (first, second) {
        (Cell::Invalid, Cell::Valid(checkpoint)) | (Cell::Valid(checkpoint), Cell::Invalid) => {
            Ok(AnchorSelection {
                checkpoint: Some(checkpoint),
                interrupted_update: true,
            })
        }
        (Cell::Invalid, Cell::Invalid)
        | (Cell::Invalid, Cell::Empty)
        | (Cell::Empty, Cell::Invalid) => Err(AnchorError::Integrity),
        (Cell::Empty, Cell::Empty) => Ok(AnchorSelection {
            checkpoint: None,
            interrupted_update: false,
        }),
        (Cell::Valid(checkpoint), Cell::Empty) | (Cell::Empty, Cell::Valid(checkpoint)) => {
            Ok(AnchorSelection {
                checkpoint: Some(checkpoint),
                interrupted_update: false,
            })
        }
        (Cell::Valid(left), Cell::Valid(right)) if left.revision == right.revision => (left
            == right)
            .then_some(AnchorSelection {
                checkpoint: Some(left),
                interrupted_update: false,
            })
            .ok_or(AnchorError::Integrity),
        (Cell::Valid(left), Cell::Valid(right)) => Ok(AnchorSelection {
            checkpoint: Some(if left.revision > right.revision {
                left
            } else {
                right
            }),
            interrupted_update: false,
        }),
    }
}

fn encode_cell(
    journal: ActionJournalId,
    checkpoint: AnchorCheckpoint,
    key: &ActionJournalKey,
) -> [u8; ANCHOR_CELL_LEN] {
    let mut cell = [0_u8; ANCHOR_CELL_LEN];
    cell[..16].copy_from_slice(ANCHOR_MAGIC);
    cell[16..48].copy_from_slice(&anchor_fingerprint());
    cell[48..64].copy_from_slice(journal.as_bytes());
    cell[64..72].copy_from_slice(&checkpoint.revision.to_be_bytes());
    cell[72..80].copy_from_slice(&checkpoint.sequence.to_be_bytes());
    cell[80..112].copy_from_slice(&checkpoint.tail);
    let authenticator = authenticator(key, &cell[..AUTHENTICATOR_OFFSET]);
    cell[AUTHENTICATOR_OFFSET..].copy_from_slice(&authenticator);
    cell
}

fn decode_cell(
    cell: &[u8; ANCHOR_CELL_LEN],
    journal: ActionJournalId,
    key: &ActionJournalKey,
) -> Cell {
    if cell == &[0; ANCHOR_CELL_LEN] {
        return Cell::Empty;
    }
    let expected = authenticator(key, &cell[..AUTHENTICATOR_OFFSET]);
    if !constant_time_eq(&cell[AUTHENTICATOR_OFFSET..], &expected)
        || &cell[..16] != ANCHOR_MAGIC
        || cell[16..48] != anchor_fingerprint()
        || &cell[48..64] != journal.as_bytes()
        || cell[112..AUTHENTICATOR_OFFSET]
            .iter()
            .any(|byte| *byte != 0)
    {
        return Cell::Invalid;
    }
    Cell::Valid(AnchorCheckpoint {
        revision: u64::from_be_bytes(copy_array(&cell[64..72])),
        sequence: u64::from_be_bytes(copy_array(&cell[72..80])),
        tail: copy_array(&cell[80..112]),
    })
}

fn anchor_fingerprint() -> [u8; 32] {
    *blake3::hash(ANCHOR_CONTRACT).as_bytes()
}

fn authenticator(key: &ActionJournalKey, authenticated_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new_keyed(key.as_bytes());
    hasher.update(AUTHENTICATION_DOMAIN);
    hasher.update(authenticated_bytes);
    *hasher.finalize().as_bytes()
}

fn constant_time_eq(actual: &[u8], expected: &[u8; AUTHENTICATOR_LEN]) -> bool {
    actual.len() == expected.len()
        && actual
            .iter()
            .zip(expected)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
}

fn copy_array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut array = [0; N];
    array.copy_from_slice(bytes);
    array
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticated_cells_select_the_latest_checkpoint() {
        let journal = ActionJournalId::new([1; 16]).expect("journal ID");
        let key = ActionJournalKey::new([2; 32]).expect("journal key");
        let older = AnchorCheckpoint {
            revision: 4,
            sequence: 8,
            tail: [3; 32],
        };
        let newer = AnchorCheckpoint {
            revision: 5,
            sequence: 9,
            tail: [4; 32],
        };

        assert_eq!(
            select_checkpoint(
                decode_cell(&encode_cell(journal, older, &key), journal, &key),
                decode_cell(&encode_cell(journal, newer, &key), journal, &key),
            )
            .expect("valid cells"),
            AnchorSelection {
                checkpoint: Some(newer),
                interrupted_update: false,
            }
        );
    }

    #[test]
    fn a_torn_target_cell_retains_the_last_complete_checkpoint() {
        let checkpoint = AnchorCheckpoint {
            revision: 8,
            sequence: 13,
            tail: [7; 32],
        };

        assert_eq!(
            select_checkpoint(Cell::Valid(checkpoint), Cell::Invalid)
                .expect("recoverable interrupted update"),
            AnchorSelection {
                checkpoint: Some(checkpoint),
                interrupted_update: true,
            }
        );
    }

    #[test]
    fn journal_identity_and_tampering_are_authenticated() {
        let journal = ActionJournalId::new([1; 16]).expect("journal ID");
        let other = ActionJournalId::new([9; 16]).expect("other journal ID");
        let key = ActionJournalKey::new([2; 32]).expect("journal key");
        let checkpoint = AnchorCheckpoint {
            revision: 1,
            sequence: 2,
            tail: [3; 32],
        };
        let mut encoded = encode_cell(journal, checkpoint, &key);
        assert_eq!(decode_cell(&encoded, other, &key), Cell::Invalid);
        encoded[80] ^= 1;
        assert_eq!(decode_cell(&encoded, journal, &key), Cell::Invalid);
    }
}
