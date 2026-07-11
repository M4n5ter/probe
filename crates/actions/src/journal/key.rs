use std::fmt;

use zeroize::Zeroize;

pub struct ActionJournalKey([u8; 32]);

impl ActionJournalKey {
    pub fn new(bytes: [u8; 32]) -> Result<Self, ActionJournalKeyError> {
        if bytes == [0; 32] {
            Err(ActionJournalKeyError)
        } else {
            Ok(Self(bytes))
        }
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ActionJournalKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ActionJournalKey([REDACTED])")
    }
}

impl Drop for ActionJournalKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionJournalKeyError;

impl fmt::Display for ActionJournalKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("action journal key must not be all zero")
    }
}

impl std::error::Error for ActionJournalKeyError {}
