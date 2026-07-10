use std::fmt;

use crate::{
    ByteExtentRef, ByteRangeRef, CapturePointId, ContentDigest, LossRecordId,
    PlaintextSourceStreamId,
};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum GapReason {
    KernelRingOverrun,
    UserspaceQueueFull,
    PacketSnaplen,
    TcpSequenceMissing,
    DecryptUnavailable,
    DecryptAuthenticationFailed,
    SourceAttachedLate,
    RetentionEvicted,
    ExplicitRedaction,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SourceScope {
    CapturePoint(CapturePointId),
    PlaintextStream(PlaintextSourceStreamId),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LocatedGap {
    pub reason: GapReason,
    pub source_scope: SourceScope,
    pub observed_loss: Option<LossRecordId>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ConflictSetRef {
    pub root: ContentDigest,
    pub alternatives: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RangeStateError {
    LengthMismatch,
    TooFewConflictAlternatives,
}

impl fmt::Display for RangeStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthMismatch => {
                formatter.write_str("stored bytes and byte-space extent have different lengths")
            }
            Self::TooFewConflictAlternatives => {
                formatter.write_str("a conflict requires at least two alternatives")
            }
        }
    }
}

impl std::error::Error for RangeStateError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RangeState {
    Present {
        extent: ByteExtentRef,
        storage: ByteRangeRef,
    },
    Missing {
        extent: ByteExtentRef,
        gap: LocatedGap,
    },
    Conflicting {
        extent: ByteExtentRef,
        alternatives: ConflictSetRef,
    },
}

impl RangeState {
    pub fn present(extent: ByteExtentRef, storage: ByteRangeRef) -> Result<Self, RangeStateError> {
        let state = Self::Present { extent, storage };
        state.validate()?;
        Ok(state)
    }

    pub const fn missing(extent: ByteExtentRef, gap: LocatedGap) -> Self {
        Self::Missing { extent, gap }
    }

    pub fn conflicting(
        extent: ByteExtentRef,
        alternatives: ConflictSetRef,
    ) -> Result<Self, RangeStateError> {
        let state = Self::Conflicting {
            extent,
            alternatives,
        };
        state.validate()?;
        Ok(state)
    }

    pub const fn extent(&self) -> ByteExtentRef {
        match self {
            Self::Present { extent, .. }
            | Self::Missing { extent, .. }
            | Self::Conflicting { extent, .. } => *extent,
        }
    }

    pub fn validate(&self) -> Result<(), RangeStateError> {
        match self {
            Self::Present { extent, storage } => {
                if extent.range.length() != storage.range.length() {
                    return Err(RangeStateError::LengthMismatch);
                }
            }
            Self::Missing { .. } => {}
            Self::Conflicting { alternatives, .. } => {
                if alternatives.alternatives < 2 {
                    return Err(RangeStateError::TooFewConflictAlternatives);
                }
            }
        }
        Ok(())
    }
}
