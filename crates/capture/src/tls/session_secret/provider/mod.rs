use std::collections::VecDeque;

use probe_core::{CapabilityKind, CapabilityState, Direction, FlowIdentity};
use thiserror::Error;

use crate::{CaptureError, CaptureEvent, CapturePoll, CaptureProvider};

use super::{Tls13SessionSecretFlowBinding, Tls13SessionSecretFlowDecryptError};

mod automatic;
mod close;
mod evidence;
mod lifecycle;

pub use automatic::Tls13SessionSecretAutoBindingProvider;
use evidence::Tls13SessionSecretFlowRegistry;

const TLS13_SESSION_SECRET_DECRYPTING_PROVIDER_NAME: &str = "tls_session_secret_decrypting";

pub struct Tls13SessionSecretDecryptingProvider {
    inner: Box<dyn CaptureProvider>,
    engine: Tls13SessionSecretDecryptingEngine,
}

struct Tls13SessionSecretDecryptingEngine {
    decryptor: super::Tls13SessionSecretFlowDecryptor,
    flow_registry: Tls13SessionSecretFlowRegistry,
    pending_events: VecDeque<CaptureEvent>,
}

impl Tls13SessionSecretDecryptingProvider {
    pub fn new(inner: Box<dyn CaptureProvider>) -> Self {
        Self {
            inner,
            engine: Tls13SessionSecretDecryptingEngine::new(),
        }
    }

    pub fn with_bindings(
        inner: Box<dyn CaptureProvider>,
        bindings: impl IntoIterator<Item = Tls13SessionSecretFlowBinding>,
    ) -> Result<Self, Tls13SessionSecretDecryptingProviderError> {
        let mut provider = Self::new(inner);
        for binding in bindings {
            provider.bind(binding)?;
        }
        Ok(provider)
    }

    pub fn bind(
        &mut self,
        binding: Tls13SessionSecretFlowBinding,
    ) -> Result<(), Tls13SessionSecretDecryptingProviderError> {
        self.engine.bind(binding)
    }
}

impl Tls13SessionSecretDecryptingEngine {
    fn new() -> Self {
        Self {
            decryptor: super::Tls13SessionSecretFlowDecryptor::new(),
            flow_registry: Tls13SessionSecretFlowRegistry::new(),
            pending_events: VecDeque::new(),
        }
    }

    fn bind(
        &mut self,
        binding: Tls13SessionSecretFlowBinding,
    ) -> Result<(), Tls13SessionSecretDecryptingProviderError> {
        let key =
            Tls13SessionSecretDecryptingStreamKey::new(binding.flow.id.clone(), binding.direction);
        if self.flow_registry.flow_is_closed(&key.flow) {
            return Err(Tls13SessionSecretDecryptingProviderError::ClosedFlow {
                flow: key.flow,
                direction: key.direction,
            });
        }
        if self.flow_registry.contains(&key) {
            return Err(Tls13SessionSecretFlowDecryptError::AlreadyBound {
                flow: key.flow,
                direction: key.direction,
            }
            .into());
        }
        let flow = binding.flow.clone();
        self.decryptor.bind(binding)?;
        self.flow_registry.insert(key, flow);
        Ok(())
    }
}

impl CaptureProvider for Tls13SessionSecretDecryptingProvider {
    fn name(&self) -> &'static str {
        TLS13_SESSION_SECRET_DECRYPTING_PROVIDER_NAME
    }

    fn capabilities(&self) -> Vec<CapabilityState> {
        let mut capabilities = self.inner.capabilities();
        capabilities.push(CapabilityState::degraded(
            CapabilityKind::TlsSessionSecretRecordDecrypt,
            "TLS session-secret decrypting provider requires explicit flow bindings and best-effort ciphertext capture",
        ));
        capabilities
    }

    fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
        self.engine.poll_pending_or_inner(
            TLS13_SESSION_SECRET_DECRYPTING_PROVIDER_NAME,
            self.inner.as_mut(),
        )
    }

    fn runtime_diagnostics(&mut self) -> crate::CaptureProviderRuntimeDiagnostics {
        self.inner.runtime_diagnostics()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Tls13SessionSecretDecryptingProviderError {
    #[error("{source}")]
    FlowDecrypt {
        #[from]
        source: Tls13SessionSecretFlowDecryptError,
    },
    #[error("TLS session-secret stream is closed for flow {flow:?} direction {direction:?}")]
    ClosedFlow {
        flow: FlowIdentity,
        direction: Direction,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Tls13SessionSecretDecryptingStreamKey {
    flow: FlowIdentity,
    direction: Direction,
}

impl Tls13SessionSecretDecryptingStreamKey {
    fn new(flow: FlowIdentity, direction: Direction) -> Self {
        Self { flow, direction }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tls13SessionSecretCaptureDisposition {
    BoundStream(Tls13SessionSecretDecryptingStreamKey),
    BoundFlow(FlowIdentity),
    ClosedFlow,
    Unbound,
}

impl Tls13SessionSecretCaptureDisposition {
    fn suppress_ciphertext(&self) -> bool {
        !matches!(self, Self::Unbound)
    }
}

#[cfg(test)]
mod tests;
