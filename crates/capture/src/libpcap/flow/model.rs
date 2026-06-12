use probe_core::{Direction, FlowContext};

#[derive(Debug, Clone)]
pub(in crate::libpcap) struct FlowPayloadObservation {
    pub(in crate::libpcap) before_payload_closures: Vec<FlowClosure>,
    pub(in crate::libpcap) payload: FlowPayload,
    pub(in crate::libpcap) after_payload: Option<FlowEnd>,
}

impl FlowPayloadObservation {
    pub(in crate::libpcap) fn new(
        before_payload_closures: Vec<FlowClosure>,
        payload: FlowPayload,
        after_payload: Option<FlowEnd>,
    ) -> Self {
        Self {
            before_payload_closures,
            payload,
            after_payload,
        }
    }
}

#[derive(Debug, Clone)]
pub(in crate::libpcap) struct FlowLifecycleObservation {
    pub(in crate::libpcap) before_lifecycle_closures: Vec<FlowClosure>,
    pub(in crate::libpcap) after_lifecycle: Option<FlowEnd>,
}

impl FlowLifecycleObservation {
    pub(in crate::libpcap) fn new(
        before_lifecycle_closures: Vec<FlowClosure>,
        after_lifecycle: Option<FlowEnd>,
    ) -> Self {
        Self {
            before_lifecycle_closures,
            after_lifecycle,
        }
    }
}

#[derive(Debug, Clone)]
pub(in crate::libpcap) enum FlowEnd {
    Close(FlowClosure),
    Finalize(FlowFinalization),
}

impl FlowEnd {
    pub(in crate::libpcap) fn close(flow: FlowClosure) -> Self {
        Self::Close(flow)
    }

    pub(in crate::libpcap) fn finalize(finalization: FlowFinalization) -> Self {
        Self::Finalize(finalization)
    }
}

#[derive(Debug, Clone)]
pub(in crate::libpcap) struct FlowPayload {
    pub(in crate::libpcap) direction: Direction,
    pub(in crate::libpcap) flow: FlowContext,
    pub(in crate::libpcap) attribution_confidence: u8,
    pub(in crate::libpcap) attribution_failure: Option<String>,
}

impl FlowPayload {
    pub(in crate::libpcap) fn new(
        direction: Direction,
        flow: FlowContext,
        attribution_confidence: u8,
        attribution_failure: Option<String>,
    ) -> Self {
        Self {
            direction,
            flow,
            attribution_confidence,
            attribution_failure,
        }
    }
}

#[derive(Debug, Clone)]
pub(in crate::libpcap) struct FlowClosure {
    pub(in crate::libpcap) flow: FlowContext,
    pub(in crate::libpcap) finalizations: Vec<FlowCloseSequence>,
}

impl FlowClosure {
    pub(in crate::libpcap) fn new(
        flow: FlowContext,
        finalizations: Vec<FlowCloseSequence>,
    ) -> Self {
        Self {
            flow,
            finalizations,
        }
    }
}

#[derive(Debug, Clone)]
pub(in crate::libpcap) struct FlowFinalization {
    pub(in crate::libpcap) flow: FlowContext,
    pub(in crate::libpcap) close_sequence: FlowCloseSequence,
}

impl FlowFinalization {
    pub(in crate::libpcap) fn new(flow: FlowContext, close_sequence: FlowCloseSequence) -> Self {
        Self {
            flow,
            close_sequence,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::libpcap) struct FlowCloseSequence {
    pub(in crate::libpcap) direction: Direction,
    pub(in crate::libpcap) sequence: u32,
}
