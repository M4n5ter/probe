use std::{fmt, num::NonZeroU128};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdError;

impl fmt::Display for IdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("identifier must be non-zero")
    }
}

impl std::error::Error for IdError {}

macro_rules! identifier {
    ($($name:ident),+ $(,)?) => {
        $(
            #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
            pub struct $name(NonZeroU128);

            impl $name {
                pub fn new(value: u128) -> Result<Self, IdError> {
                    NonZeroU128::new(value).map(Self).ok_or(IdError)
                }

                pub const fn get(self) -> u128 {
                    self.0.get()
                }
            }
        )+
    };
}

identifier!(
    AlignmentProofId,
    ByteSpaceId,
    ByteViewId,
    CapturePointId,
    ConversationId,
    EvidenceId,
    ExchangeId,
    Http2StreamId,
    LossRecordId,
    PlaintextSourceStreamId,
    SegmentId,
    TlsSessionId,
    TransformId,
    TransportLegId,
);
