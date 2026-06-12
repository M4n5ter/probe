use bytes::Bytes;
use probe_core::{CaptureSource, Direction, FlowContext, Gap, Timestamp};
use serde::{Deserialize, Serialize};

use crate::provider::CaptureProviderKind;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturedBytes {
    pub timestamp: Timestamp,
    pub flow: FlowContext,
    pub source: CaptureSource,
    pub provider: CaptureProviderKind,
    pub direction: Direction,
    pub stream_offset: u64,
    pub bytes: Bytes,
    pub attribution_confidence: u8,
    pub degraded: bool,
    pub degradation_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CaptureEvent {
    Bytes(CapturedBytes),
    Gap(CapturedGap),
    ConnectionOpened {
        timestamp: Timestamp,
        flow: FlowContext,
        source: CaptureSource,
        provider: CaptureProviderKind,
    },
    ConnectionClosed {
        timestamp: Timestamp,
        flow: FlowContext,
        source: CaptureSource,
        provider: CaptureProviderKind,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturedGap {
    pub timestamp: Timestamp,
    pub flow: FlowContext,
    pub source: CaptureSource,
    pub provider: CaptureProviderKind,
    pub gap: Gap,
}
