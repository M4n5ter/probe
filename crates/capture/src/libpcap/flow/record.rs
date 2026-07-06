use probe_core::{Direction, FlowContext, TcpEndpoint};

use super::super::decoder::DecodedTcpSegment;
use super::super::tcp_seq;
use super::model::{FlowCloseSequence, FlowClosure};

#[derive(Debug, Clone)]
pub(super) struct FlowRecord {
    local_endpoint: TcpEndpoint,
    pub(super) confidence: u8,
    pub(super) flow: FlowContext,
    pub(super) last_seen_wall_time_unix_ns: i64,
    local_close: Option<FlowCloseSequence>,
    remote_close: Option<FlowCloseSequence>,
    local_syn: Option<u32>,
    remote_syn: Option<u32>,
    reset: bool,
}

impl FlowRecord {
    pub(super) fn new(
        local_endpoint: TcpEndpoint,
        confidence: u8,
        flow: FlowContext,
        last_seen_wall_time_unix_ns: i64,
    ) -> Self {
        Self {
            local_endpoint,
            confidence,
            flow,
            last_seen_wall_time_unix_ns,
            local_close: None,
            remote_close: None,
            local_syn: None,
            remote_syn: None,
            reset: false,
        }
    }

    pub(super) fn direction_for(&self, decoded: &DecodedTcpSegment<'_>) -> Direction {
        if decoded.source_endpoint() == self.local_endpoint {
            Direction::Outbound
        } else {
            Direction::Inbound
        }
    }

    pub(super) fn observe_lifecycle(&mut self, decoded: &DecodedTcpSegment<'_>) {
        let direction = self.direction_for(decoded);
        if decoded.has_syn() {
            self.set_syn_sequence(direction, decoded.sequence);
        }
        let Some(sequence) = decoded.close_sequence() else {
            return;
        };
        let close_sequence = FlowCloseSequence {
            direction,
            sequence,
        };
        if decoded.has_rst() {
            self.reset = true;
            self.set_close_sequence(close_sequence);
            return;
        }
        if !decoded.has_fin() {
            return;
        }
        self.set_close_sequence(close_sequence);
    }

    pub(super) fn closed(&self) -> bool {
        self.reset || (self.local_close.is_some() && self.remote_close.is_some())
    }

    pub(super) fn close_sequence_for(&self, direction: Direction) -> Option<FlowCloseSequence> {
        match direction {
            Direction::Outbound => self.local_close,
            Direction::Inbound => self.remote_close,
        }
    }

    pub(super) fn syn_sequence_matches(&self, decoded: &DecodedTcpSegment<'_>) -> bool {
        let direction = self.direction_for(decoded);
        self.syn_sequence_for(direction)
            .is_some_and(|sequence| sequence == decoded.sequence)
    }

    pub(super) fn syn_belongs_to_existing_flow(&self, decoded: &DecodedTcpSegment<'_>) -> bool {
        if !decoded.has_syn() {
            return false;
        }
        let direction = self.direction_for(decoded);
        if self.syn_sequence_for(direction).is_some() {
            return self.syn_sequence_matches(decoded);
        }
        self.syn_sequence_for(opposite_direction(direction))
            .is_some_and(|sequence| {
                decoded.has_syn_ack() && decoded.acknowledges_syn_sequence(sequence)
            })
    }

    pub(super) fn payload_starts_after_close(
        &self,
        direction: Direction,
        decoded: &DecodedTcpSegment<'_>,
    ) -> bool {
        if decoded.payload.is_empty() {
            return false;
        }
        self.close_sequence_for(direction)
            .is_some_and(|close_sequence| {
                !tcp_seq::before(decoded.payload_sequence(), close_sequence.sequence)
            })
    }

    pub(super) fn into_closure(self) -> FlowClosure {
        FlowClosure::new(
            self.flow,
            [self.local_close, self.remote_close]
                .into_iter()
                .flatten()
                .collect(),
        )
    }

    fn set_close_sequence(&mut self, close_sequence: FlowCloseSequence) {
        match close_sequence.direction {
            Direction::Outbound => self.local_close.get_or_insert(close_sequence),
            Direction::Inbound => self.remote_close.get_or_insert(close_sequence),
        };
    }

    fn set_syn_sequence(&mut self, direction: Direction, sequence: u32) {
        match direction {
            Direction::Outbound => self.local_syn.get_or_insert(sequence),
            Direction::Inbound => self.remote_syn.get_or_insert(sequence),
        };
    }

    fn syn_sequence_for(&self, direction: Direction) -> Option<u32> {
        match direction {
            Direction::Outbound => self.local_syn,
            Direction::Inbound => self.remote_syn,
        }
    }
}

fn opposite_direction(direction: Direction) -> Direction {
    match direction {
        Direction::Outbound => Direction::Inbound,
        Direction::Inbound => Direction::Outbound,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct ConnectionKey {
    lower: TcpEndpoint,
    higher: TcpEndpoint,
}

impl ConnectionKey {
    pub(super) fn from_decoded(decoded: &DecodedTcpSegment<'_>) -> Self {
        let source = decoded.source_endpoint();
        let destination = decoded.destination_endpoint();
        if source <= destination {
            Self {
                lower: source,
                higher: destination,
            }
        } else {
            Self {
                lower: destination,
                higher: source,
            }
        }
    }
}
