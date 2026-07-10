use std::{fmt, num::NonZeroU64};

use super::super::AttributionConfidence;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PayloadAccess {
    MetadataOnly,
    FullPayload,
}

impl PayloadAccess {
    const fn exposure_rank(self) -> u8 {
        match self {
            Self::MetadataOnly => 0,
            Self::FullPayload => 1,
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CompletenessAllowance {
    RequireComplete,
    AllowIncomplete,
}

impl CompletenessAllowance {
    const fn exposure_rank(self) -> u8 {
        match self {
            Self::RequireComplete => 0,
            Self::AllowIncomplete => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RetentionLimit {
    max_age_ns: NonZeroU64,
    max_bytes: NonZeroU64,
}

impl RetentionLimit {
    pub fn new(max_age_ns: u64, max_bytes: u64) -> Result<Self, RetentionLimitError> {
        Ok(Self {
            max_age_ns: NonZeroU64::new(max_age_ns).ok_or(RetentionLimitError::ZeroMaxAge)?,
            max_bytes: NonZeroU64::new(max_bytes).ok_or(RetentionLimitError::ZeroMaxBytes)?,
        })
    }

    pub const fn max_age_ns(self) -> u64 {
        self.max_age_ns.get()
    }

    pub const fn max_bytes(self) -> u64 {
        self.max_bytes.get()
    }

    pub const fn is_within(self, maximum: Self) -> bool {
        self.max_age_ns.get() <= maximum.max_age_ns.get()
            && self.max_bytes.get() <= maximum.max_bytes.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetentionLimitError {
    ZeroMaxAge,
    ZeroMaxBytes,
}

impl fmt::Display for RetentionLimitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroMaxAge => formatter.write_str("retention maximum age must be non-zero"),
            Self::ZeroMaxBytes => formatter.write_str("retention maximum bytes must be non-zero"),
        }
    }
}

impl std::error::Error for RetentionLimitError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureGrant {
    payload: PayloadAccess,
    completeness: CompletenessAllowance,
    retention: RetentionLimit,
}

impl CaptureGrant {
    pub const fn new(
        payload: PayloadAccess,
        completeness: CompletenessAllowance,
        retention: RetentionLimit,
    ) -> Self {
        Self {
            payload,
            completeness,
            retention,
        }
    }

    pub const fn payload(self) -> PayloadAccess {
        self.payload
    }

    pub const fn completeness(self) -> CompletenessAllowance {
        self.completeness
    }

    pub const fn retention(self) -> RetentionLimit {
        self.retention
    }

    pub const fn is_within(self, maximum: Self) -> bool {
        self.payload.exposure_rank() <= maximum.payload.exposure_rank()
            && self.completeness.exposure_rank() <= maximum.completeness.exposure_rank()
            && self.retention.is_within(maximum.retention)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttributionConfidenceGrant(u8);

impl AttributionConfidenceGrant {
    const ATTRIBUTED: u8 = 1 << 0;
    const INFERRED: u8 = 1 << 1;
    const UNKNOWN: u8 = 1 << 2;

    pub fn new(
        retain_attributed: bool,
        retain_inferred: bool,
        retain_unknown: bool,
    ) -> Result<Self, AttributionConfidenceGrantError> {
        let mut bits = 0;
        if retain_attributed {
            bits |= Self::ATTRIBUTED;
        }
        if retain_inferred {
            bits |= Self::INFERRED;
        }
        if retain_unknown {
            bits |= Self::UNKNOWN;
        }
        if bits == 0 {
            Err(AttributionConfidenceGrantError)
        } else {
            Ok(Self(bits))
        }
    }

    pub const fn allows(self, confidence: AttributionConfidence) -> bool {
        let required = match confidence {
            AttributionConfidence::Proven | AttributionConfidence::CorrelatedUnique => {
                Self::ATTRIBUTED
            }
            AttributionConfidence::Inferred => Self::INFERRED,
            AttributionConfidence::Unknown => Self::UNKNOWN,
        };
        self.0 & required != 0
    }

    pub(super) const fn bits(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttributionConfidenceGrantError;

impl fmt::Display for AttributionConfidenceGrantError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("host capture grant must allow at least one confidence class")
    }
}

impl std::error::Error for AttributionConfidenceGrantError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostCaptureGrant {
    confidences: AttributionConfidenceGrant,
    maximum_capture: CaptureGrant,
}

impl HostCaptureGrant {
    pub const fn new(
        confidences: AttributionConfidenceGrant,
        maximum_capture: CaptureGrant,
    ) -> Self {
        Self {
            confidences,
            maximum_capture,
        }
    }

    pub const fn confidences(self) -> AttributionConfidenceGrant {
        self.confidences
    }

    pub const fn maximum_capture(self) -> CaptureGrant {
        self.maximum_capture
    }

    pub const fn allows(self, confidence: AttributionConfidence, requested: CaptureGrant) -> bool {
        self.confidences.allows(confidence) && requested.is_within(self.maximum_capture)
    }
}
