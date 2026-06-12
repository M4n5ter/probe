use probe_core::{CapabilityState, CaptureSource, ProcessContext, TcpConnection};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::event::CaptureEvent;

#[derive(Debug, Error)]
pub enum CaptureError {
    #[error("capture provider {provider} failed: {reason}")]
    Provider { provider: String, reason: String },
}

impl CaptureError {
    pub fn provider(provider: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Provider {
            provider: provider.into(),
            reason: reason.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureProviderKind {
    Replay,
    Ebpf,
    Libpcap,
    Plaintext,
}

pub trait CaptureProvider {
    fn name(&self) -> &'static str;

    fn kind(&self) -> CaptureProviderKind;

    fn source(&self) -> CaptureSource;

    fn capabilities(&self) -> Vec<CapabilityState>;

    fn next(&mut self) -> Result<Option<CaptureEvent>, CaptureError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedProcess {
    pub process: ProcessContext,
    pub confidence: u8,
}

pub trait ProcessResolver {
    fn resolve_tcp_process(
        &mut self,
        connection: TcpConnection,
    ) -> Result<Option<ResolvedProcess>, CaptureError>;

    fn invalidate_cached_resolution(&mut self) {}
}
