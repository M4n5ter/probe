use interception::TransparentInterceptionHostRuleSet;
use probe_core::{CapabilityKind, CapabilityState, RuntimeMode};

use super::{
    TransparentInterceptionError,
    nftables::{
        NftablesOutboundTransparentProxy, NftablesOutboundTransparentProxyGuard,
        NftablesTransparentInterception, NftablesTransparentInterceptionGuard,
    },
    proxy::{TransparentProxyRuntime, TransparentProxyRuntimeHandle},
};

pub(crate) struct TransparentInterceptionRuntime {
    capability: CapabilityState,
    activation: Option<Box<dyn TransparentInterceptionLifecycle>>,
    proxy_runtime: TransparentProxyRuntime,
}

pub(super) trait TransparentInterceptionLifecycle: Send {
    fn activate(
        self: Box<Self>,
        setup_scope: TransparentInterceptionHostRuleSet,
    ) -> Result<Box<dyn TransparentInterceptionGuardLifecycle>, TransparentInterceptionError>;
}

pub(super) trait TransparentInterceptionGuardLifecycle {
    fn deactivate(self: Box<Self>) -> Result<(), TransparentInterceptionError>;
}

impl TransparentInterceptionRuntime {
    pub(crate) fn capability(&self) -> CapabilityState {
        self.capability.clone()
    }

    pub(crate) fn proxy_runtime_handle(&self) -> TransparentProxyRuntimeHandle {
        self.proxy_runtime.handle()
    }

    pub(crate) fn activate(
        self,
        setup_scope: Option<TransparentInterceptionHostRuleSet>,
    ) -> Result<Option<TransparentInterceptionGuard>, TransparentInterceptionError> {
        self.activation
            .map(|activation| {
                let setup_scope = setup_scope.ok_or_else(|| {
                    TransparentInterceptionError::Nftables(
                        "transparent interception setup scope is missing".to_string(),
                    )
                })?;
                activation
                    .activate(setup_scope)
                    .map(TransparentInterceptionGuard::new)
            })
            .transpose()
    }

    pub(super) fn unavailable(
        reason: impl Into<String>,
        proxy_runtime: TransparentProxyRuntime,
    ) -> Self {
        Self {
            capability: CapabilityState::unavailable(
                CapabilityKind::TransparentInterception,
                reason,
            ),
            activation: None,
            proxy_runtime,
        }
    }

    pub(super) fn available(
        activation: impl TransparentInterceptionLifecycle + 'static,
        proxy_runtime: TransparentProxyRuntime,
        note: impl Into<String>,
    ) -> Self {
        Self {
            capability: CapabilityState {
                kind: CapabilityKind::TransparentInterception,
                mode: RuntimeMode::Available,
                reason: Some(note.into()),
            },
            activation: Some(Box::new(activation)),
            proxy_runtime,
        }
    }
}

pub(crate) struct TransparentInterceptionGuard {
    inner: Box<dyn TransparentInterceptionGuardLifecycle>,
}

impl TransparentInterceptionGuard {
    fn new(inner: Box<dyn TransparentInterceptionGuardLifecycle>) -> Self {
        Self { inner }
    }

    pub(crate) fn deactivate(self) -> Result<(), TransparentInterceptionError> {
        self.inner.deactivate()
    }
}

impl TransparentInterceptionLifecycle for NftablesTransparentInterception {
    fn activate(
        self: Box<Self>,
        setup_scope: TransparentInterceptionHostRuleSet,
    ) -> Result<Box<dyn TransparentInterceptionGuardLifecycle>, TransparentInterceptionError> {
        NftablesTransparentInterception::activate(*self, setup_scope)
            .map(|guard| Box::new(guard) as Box<dyn TransparentInterceptionGuardLifecycle>)
    }
}

impl TransparentInterceptionLifecycle for NftablesOutboundTransparentProxy {
    fn activate(
        self: Box<Self>,
        setup_scope: TransparentInterceptionHostRuleSet,
    ) -> Result<Box<dyn TransparentInterceptionGuardLifecycle>, TransparentInterceptionError> {
        NftablesOutboundTransparentProxy::activate(*self, setup_scope)
            .map(|guard| Box::new(guard) as Box<dyn TransparentInterceptionGuardLifecycle>)
    }
}

impl TransparentInterceptionGuardLifecycle for NftablesTransparentInterceptionGuard {
    fn deactivate(self: Box<Self>) -> Result<(), TransparentInterceptionError> {
        NftablesTransparentInterceptionGuard::deactivate(*self)
    }
}

impl TransparentInterceptionGuardLifecycle for NftablesOutboundTransparentProxyGuard {
    fn deactivate(self: Box<Self>) -> Result<(), TransparentInterceptionError> {
        NftablesOutboundTransparentProxyGuard::deactivate(*self)
    }
}
