use std::collections::HashMap;

use probe_core::FlowIdentity;

use crate::{Http1Parser, ProtocolParser, ProtocolParserFactory};

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
