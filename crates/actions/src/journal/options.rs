use std::{fmt, num::NonZeroU64, time::Duration};

use super::format::{HEADER_LEN, SLOT_LEN};

const MINIMUM_SLOT_COUNT: u64 = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionJournalOptions {
    capacity: NonZeroU64,
    sync_timeout: Duration,
}

impl ActionJournalOptions {
    pub fn new(
        capacity: NonZeroU64,
        sync_timeout: Duration,
    ) -> Result<Self, ActionJournalOptionsError> {
        let payload_capacity = capacity
            .get()
            .checked_sub(HEADER_LEN as u64)
            .ok_or(ActionJournalOptionsError::CapacityTooSmall)?;
        if payload_capacity % SLOT_LEN as u64 != 0 {
            return Err(ActionJournalOptionsError::CapacityMisaligned);
        }
        if payload_capacity / (SLOT_LEN as u64) < MINIMUM_SLOT_COUNT {
            return Err(ActionJournalOptionsError::CapacityTooSmall);
        }
        if sync_timeout.is_zero() {
            return Err(ActionJournalOptionsError::ZeroSyncTimeout);
        }
        Ok(Self {
            capacity,
            sync_timeout,
        })
    }

    pub const fn capacity(self) -> NonZeroU64 {
        self.capacity
    }

    pub const fn sync_timeout(self) -> Duration {
        self.sync_timeout
    }

    pub(super) fn total_slots(self) -> Result<usize, ActionJournalOptionsError> {
        let slots = (self.capacity.get() - HEADER_LEN as u64) / SLOT_LEN as u64;
        usize::try_from(slots).map_err(|_| ActionJournalOptionsError::CapacityTooLarge)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActionJournalOptionsError {
    CapacityTooSmall,
    CapacityTooLarge,
    CapacityMisaligned,
    ZeroSyncTimeout,
}

impl fmt::Display for ActionJournalOptionsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapacityTooSmall => {
                formatter.write_str("action journal capacity cannot hold its safety reserve")
            }
            Self::CapacityTooLarge => {
                formatter.write_str("action journal capacity exceeds addressable memory")
            }
            Self::CapacityMisaligned => {
                formatter.write_str("action journal capacity is not slot aligned")
            }
            Self::ZeroSyncTimeout => {
                formatter.write_str("action journal synchronization timeout must be non-zero")
            }
        }
    }
}

impl std::error::Error for ActionJournalOptionsError {}
