use probe_core::{Direction, EventKind, Gap};

#[derive(Debug, Clone, Copy)]
pub enum ParserInput<'a> {
    Data {
        direction: Direction,
        bytes: &'a [u8],
    },
    Gap {
        direction: Direction,
        expected_offset: u64,
        next_offset: Option<u64>,
        reason: &'a str,
    },
    ConnectionClosed,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ParserOutput {
    events: Vec<EventKind>,
}

impl ParserOutput {
    pub fn from_events(events: Vec<EventKind>) -> Self {
        Self { events }
    }

    pub fn events(&self) -> &[EventKind] {
        &self.events
    }

    pub fn into_events(self) -> Vec<EventKind> {
        self.events
    }
}

pub trait ProtocolParser {
    fn ingest(&mut self, input: ParserInput<'_>) -> ParserOutput;

    fn is_checkpoint_safe(&self) -> bool {
        false
    }
}

pub trait ProtocolParserFactory {
    fn parser_for_flow(&mut self, flow_id: &probe_core::FlowIdentity) -> &mut dyn ProtocolParser;

    fn remove_flow(&mut self, flow_id: &probe_core::FlowIdentity);

    fn is_checkpoint_safe(&self) -> bool;
}

pub fn gap_event(
    direction: Direction,
    expected_offset: u64,
    next_offset: Option<u64>,
    reason: impl Into<String>,
) -> EventKind {
    EventKind::Gap(Gap {
        direction,
        expected_offset,
        next_offset,
        reason: reason.into(),
    })
}
