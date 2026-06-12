mod assembler;
mod budget;
mod tracker;

use probe_core::{Direction, FlowIdentity};

pub(in crate::libpcap) use tracker::{StreamTracker, degradation_reason};

const MAX_PENDING_SEGMENTS: usize = 64;
const MAX_PENDING_BYTES: usize = 256 * 1024;
const MAX_TOTAL_PENDING_SEGMENTS: usize = 4_096;
const MAX_TOTAL_PENDING_BYTES: usize = 16 * 1024 * 1024;
const BUFFER_LIMIT_GAP_REASON: &str =
    "libpcap TCP stream gap: out-of-order buffer limit reached before missing payload arrived";
const GLOBAL_BUFFER_LIMIT_GAP_REASON: &str = "libpcap TCP stream gap: global out-of-order buffer limit reached before missing payload arrived";
const REORDER_TIMEOUT_GAP_REASON: &str =
    "libpcap TCP stream gap: read timeout expired before missing payload arrived";
const FLOW_CLOSE_GAP_REASON: &str =
    "libpcap TCP stream gap: flow closed with unresolved out-of-order payload";

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct StreamKey {
    flow_id: FlowIdentity,
    direction: Direction,
}

impl StreamKey {
    fn new(flow_id: FlowIdentity, direction: Direction) -> Self {
        Self { flow_id, direction }
    }
}
