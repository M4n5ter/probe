use std::{fmt, num::NonZeroU64};

use crate::{ByteSpaceId, ContentDigest, SegmentId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RangeError {
    Empty,
    Overflow,
}

impl fmt::Display for RangeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("byte range must not be empty"),
            Self::Overflow => formatter.write_str("byte range exceeds u64 coordinates"),
        }
    }
}

impl std::error::Error for RangeError {}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ByteLength(NonZeroU64);

impl ByteLength {
    pub fn new(value: u64) -> Result<Self, RangeError> {
        NonZeroU64::new(value).map(Self).ok_or(RangeError::Empty)
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OffsetRange {
    start: u64,
    length: ByteLength,
}

impl OffsetRange {
    pub fn new(start: u64, length: u64) -> Result<Self, RangeError> {
        let length = ByteLength::new(length)?;
        start
            .checked_add(length.get())
            .ok_or(RangeError::Overflow)?;
        Ok(Self { start, length })
    }

    pub const fn start(self) -> u64 {
        self.start
    }

    pub const fn length(self) -> ByteLength {
        self.length
    }

    pub fn end(self) -> u64 {
        self.start + self.length.get()
    }

    pub fn overlaps(self, other: Self) -> bool {
        self.start < other.end() && other.start < self.end()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ByteExtentRef {
    pub space: ByteSpaceId,
    pub range: OffsetRange,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ByteRangeRef {
    pub segment: SegmentId,
    pub range: OffsetRange,
    pub digest: ContentDigest,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supports_payloads_larger_than_four_gibibytes_without_special_cases() {
        let range =
            OffsetRange::new(17, 4 * 1024 * 1024 * 1024 + 1).expect("large range should be valid");
        assert_eq!(range.end(), 4 * 1024 * 1024 * 1024 + 18);
    }

    #[test]
    fn rejects_empty_and_overflowing_ranges() {
        assert_eq!(OffsetRange::new(0, 0), Err(RangeError::Empty));
        assert_eq!(OffsetRange::new(u64::MAX, 1), Err(RangeError::Overflow));
    }
}
