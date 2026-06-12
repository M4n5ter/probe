mod http1;
mod websocket;

use std::collections::HashMap;

use probe_core::{Direction, EventKind, FlowIdentity, Gap};

pub use http1::{Http1Parser, ParserError};
pub use websocket::WebSocketFrameParser;

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
    fn parser_for_flow(&mut self, flow_id: &FlowIdentity) -> &mut dyn ProtocolParser;

    fn remove_flow(&mut self, flow_id: &FlowIdentity);

    fn is_checkpoint_safe(&self) -> bool;
}

#[derive(Debug)]
pub struct ParserPool<P> {
    parsers: HashMap<String, P>,
}

impl<P> Default for ParserPool<P> {
    fn default() -> Self {
        Self {
            parsers: HashMap::new(),
        }
    }
}

impl<P> ProtocolParserFactory for ParserPool<P>
where
    P: ProtocolParser + Default,
{
    fn parser_for_flow(&mut self, flow_id: &FlowIdentity) -> &mut dyn ProtocolParser {
        self.parsers.entry(flow_id.0.clone()).or_default()
    }

    fn remove_flow(&mut self, flow_id: &FlowIdentity) {
        self.parsers.remove(&flow_id.0);
    }

    fn is_checkpoint_safe(&self) -> bool {
        self.parsers
            .values()
            .all(ProtocolParser::is_checkpoint_safe)
    }
}

pub type Http1ParserFactory = ParserPool<Http1Parser>;

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
