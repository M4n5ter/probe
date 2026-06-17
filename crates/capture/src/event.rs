use bytes::Bytes;
use probe_core::{
    CaptureLoss, CaptureOrigin, Direction, EnforcementEvidence, FlowContext, Gap, Timestamp,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedBytes {
    pub timestamp: Timestamp,
    pub flow: FlowContext,
    pub origin: CaptureOrigin,
    pub direction: Direction,
    pub stream_offset: u64,
    pub bytes: Bytes,
    pub attribution_confidence: u8,
    pub degraded: bool,
    pub degradation_reason: Option<String>,
    pub enforcement_evidence: EnforcementEvidence,
    pub enforcement_evidence_propagation: EnforcementEvidencePropagation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum CaptureEvent {
    Bytes(CapturedBytes),
    Gap(CapturedGap),
    Loss(CapturedLoss),
    ConnectionOpened {
        timestamp: Timestamp,
        flow: FlowContext,
        origin: CaptureOrigin,
    },
    ConnectionClosed {
        timestamp: Timestamp,
        flow: FlowContext,
        origin: CaptureOrigin,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedGap {
    pub timestamp: Timestamp,
    pub flow: FlowContext,
    pub origin: CaptureOrigin,
    pub enforcement_evidence: EnforcementEvidence,
    pub enforcement_evidence_propagation: EnforcementEvidencePropagation,
    pub gap: Gap,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedLoss {
    pub timestamp: Timestamp,
    pub origin: CaptureOrigin,
    pub enforcement_evidence: EnforcementEvidence,
    pub loss: CaptureLoss,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementEvidencePropagation {
    Event,
    Flow,
}

impl EnforcementEvidencePropagation {
    pub fn is_flow_carried(self) -> bool {
        matches!(self, Self::Flow)
    }
}
