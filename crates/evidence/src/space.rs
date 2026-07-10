use crate::{
    ByteSpaceId, ConversationId, EvidenceId, ExchangeId, Http2StreamId, PlaintextSourceStreamId,
    TlsSessionId, TransportLegId,
};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FlowDirection {
    Inbound,
    Outbound,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MessageSide {
    Request,
    Response,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BodyRepresentation {
    TransferEncoded,
    TransferDecoded,
    ContentDecoded,
    Presentation,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ByteSpace {
    id: ByteSpaceId,
    kind: ByteSpaceKind,
}

impl ByteSpace {
    pub const fn new(id: ByteSpaceId, kind: ByteSpaceKind) -> Self {
        Self { id, kind }
    }

    pub const fn id(self) -> ByteSpaceId {
        self.id
    }

    pub const fn kind(self) -> ByteSpaceKind {
        self.kind
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ByteSpaceKind {
    PacketFrame(EvidenceId),
    TransportStream {
        leg: TransportLegId,
        direction: FlowDirection,
    },
    SourcePlaintext(PlaintextSourceStreamId),
    TlsPlaintext {
        session: TlsSessionId,
        leg: TransportLegId,
        direction: FlowDirection,
    },
    Http2Stream {
        conversation: ConversationId,
        stream: Http2StreamId,
        direction: FlowDirection,
    },
    EntityBody {
        exchange: ExchangeId,
        side: MessageSide,
        representation: BodyRepresentation,
    },
}
