use std::{thread, time::Duration};

pub use probe_core::CaptureProviderKind;
use probe_core::{CapabilityState, ProcessContext, TcpConnection};
use thiserror::Error;

use crate::event::CaptureEvent;

const DEFAULT_IDLE_SLEEP: Duration = Duration::from_millis(10);

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapturePoll {
    Event(Box<CaptureEvent>),
    Progress,
    Idle,
    Finished,
}

impl CapturePoll {
    pub fn event(event: CaptureEvent) -> Self {
        Self::Event(Box::new(event))
    }
}

pub trait CaptureProvider {
    fn name(&self) -> &'static str;

    fn capabilities(&self) -> Vec<CapabilityState>;

    fn poll_next(&mut self) -> Result<CapturePoll, CaptureError>;

    fn next(&mut self) -> Result<Option<CaptureEvent>, CaptureError> {
        loop {
            match self.poll_next()? {
                CapturePoll::Event(event) => return Ok(Some(*event)),
                CapturePoll::Progress => {}
                CapturePoll::Idle => thread::sleep(DEFAULT_IDLE_SLEEP),
                CapturePoll::Finished => return Ok(None),
            }
        }
    }
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
