use std::{fmt, num::NonZeroU64};

use uuid::Uuid;

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
    ActionAuditId,
    ActionAuthorizationId,
    ActionBackendId,
    ActionExecutionId,
    ActionId,
    ActionJournalId,
    ActionRequestId,
    ActionScopeProofId,
    AttributionEvidenceId,
    AuthorizationAuditId,
    AuthorizationId,
    AuthorizationIssuerId,
    AuthorizationNonce,
    BootId,
    BpfLinkId,
    CaptureStageId,
    CgroupId,
    ClockCalibrationId,
    EffectiveStateRevisionId,
    FlowId,
    InterceptionAuthorizationId,
    InterceptionConversationId,
    NetworkNamespaceId,
    ObservationIntentId,
    PolicyRevisionId,
    PreparedActionId,
    ProcessId,
    SelectionProofId,
    SocketId,
    SourceEpochId,
    SourceInstanceId,
    SubjectId,
    WorkloadId,
);

canonical_digests!(
    ActionAuthorizationDigest,
    ActionEffectDigest,
    ActionIntentDigest,
    ActionParametersDigest,
    ActionResultDigest,
    AttributionSnapshotDigest,
    CandidateSetDigest,
    CaptureSelectorDigest,
    CapabilitySnapshotDigest,
    HostAuthorizationDigest,
    PolicyDigest,
);

impl std::str::FromStr for BootId {
    type Err = BootIdParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let uuid = Uuid::parse_str(input.trim()).map_err(BootIdParseError::InvalidUuid)?;
        Self::new(*uuid.as_bytes()).map_err(|_| BootIdParseError::Nil)
    }
}

#[derive(Debug)]
pub enum BootIdParseError {
    InvalidUuid(uuid::Error),
    Nil,
}

impl fmt::Display for BootIdParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUuid(error) => write!(formatter, "invalid Linux boot UUID: {error}"),
            Self::Nil => formatter.write_str("Linux boot UUID must not be nil"),
        }
    }
}

impl std::error::Error for BootIdParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidUuid(error) => Some(error),
            Self::Nil => None,
        }
    }
}

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

    #[test]
    fn linux_boot_id_parses_canonical_uuid_text() {
        let boot: BootId = "00112233-4455-6677-8899-aabbccddeeff"
            .parse()
            .expect("boot ID");
        assert_eq!(
            boot.as_bytes(),
            &[
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ]
        );
        assert!(matches!(
            "00000000-0000-0000-0000-000000000000".parse::<BootId>(),
            Err(BootIdParseError::Nil)
        ));
    }
}
