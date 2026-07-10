use std::{fmt, num::NonZeroU64};

macro_rules! canonical_ids {
    ($($name:ident),+ $(,)?) => {
        $(
            #[repr(transparent)]
            #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
            pub struct $name([u8; 16]);

            impl $name {
                pub fn new(bytes: [u8; 16]) -> Result<Self, CanonicalIdError> {
                    if bytes == [0; 16] {
                        Err(CanonicalIdError)
                    } else {
                        Ok(Self(bytes))
                    }
                }

                pub const fn as_bytes(&self) -> &[u8; 16] {
                    &self.0
                }
            }

            impl fmt::Debug for $name {
                fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    write!(formatter, "{}({})", stringify!($name), HexId(&self.0))
                }
            }
        )+
    };
}

macro_rules! canonical_digests {
    ($($name:ident),+ $(,)?) => {
        $(
            #[repr(transparent)]
            #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
            pub struct $name([u8; 32]);

            impl $name {
                pub fn new(bytes: [u8; 32]) -> Result<Self, CanonicalIdError> {
                    if bytes == [0; 32] {
                        Err(CanonicalIdError)
                    } else {
                        Ok(Self(bytes))
                    }
                }

                pub const fn as_bytes(&self) -> &[u8; 32] {
                    &self.0
                }
            }

            impl fmt::Debug for $name {
                fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    write!(formatter, "{}({})", stringify!($name), HexId(&self.0))
                }
            }
        )+
    };
}

canonical_ids!(
    AttributionEvidenceId,
    AuthorizationAuditId,
    AuthorizationId,
    AuthorizationIssuerId,
    AuthorizationNonce,
    BootId,
    CaptureStageId,
    CgroupId,
    ClockCalibrationId,
    FlowId,
    NetworkNamespaceId,
    ObservationIntentId,
    ProcessId,
    SelectionProofId,
    SocketId,
    SourceEpochId,
    SourceInstanceId,
    SubjectId,
    WorkloadId,
);

canonical_digests!(
    AttributionSnapshotDigest,
    CandidateSetDigest,
    CaptureSelectorDigest,
    HostAuthorizationDigest,
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalIdError;

impl fmt::Display for CanonicalIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("canonical identifier must not be all zero")
    }
}

impl std::error::Error for CanonicalIdError {}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Revision(NonZeroU64);

impl Revision {
    pub fn new(value: u64) -> Result<Self, RevisionError> {
        NonZeroU64::new(value).map(Self).ok_or(RevisionError)
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevisionError;

impl fmt::Display for RevisionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("revision must be non-zero")
    }
}

impl std::error::Error for RevisionError {}

struct HexId<'a>(&'a [u8]);

impl fmt::Display for HexId<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_identifiers_and_revisions_reject_zero() {
        assert_eq!(SubjectId::new([0; 16]), Err(CanonicalIdError));
        assert_eq!(Revision::new(0), Err(RevisionError));
        assert_eq!(Revision::new(7).expect("revision").get(), 7);
    }
}
