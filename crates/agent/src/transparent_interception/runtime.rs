use interception::TransparentInterceptionHostRuleSet;
use probe_core::{CapabilityKind, CapabilityState, RuntimeMode};

use super::{
    TransparentInterceptionError, TransparentInterceptionFlowClassifier,
    nftables::{
        NftablesOutboundTransparentProxy, NftablesOutboundTransparentProxyGuard,
        NftablesTransparentInterception, NftablesTransparentInterceptionGuard,
    },
    proxy::{TransparentProxyRuntime, TransparentProxyRuntimeHandle},
};

#[derive(Debug)]
pub(crate) struct TransparentInterceptionActivationScope {
    setup_rules: TransparentInterceptionHostRuleSet,
    flow_classifier: Option<TransparentInterceptionFlowClassifier>,
}

impl TransparentInterceptionActivationScope {
    pub(crate) fn host_rules(setup_rules: TransparentInterceptionHostRuleSet) -> Self {
        Self {
            setup_rules,
            flow_classifier: None,
        }
    }

    pub(crate) fn with_flow_classifier(
        setup_rules: TransparentInterceptionHostRuleSet,
        flow_classifier: TransparentInterceptionFlowClassifier,
    ) -> Self {
        Self {
            setup_rules,
            flow_classifier: Some(flow_classifier),
        }
    }

    pub(crate) fn setup_rules(&self) -> &TransparentInterceptionHostRuleSet {
        &self.setup_rules
    }

    #[cfg(test)]
    pub(crate) fn has_flow_classifier(&self) -> bool {
        self.flow_classifier.is_some()
    }

    pub(super) fn into_parts(
        self,
    ) -> (
        TransparentInterceptionHostRuleSet,
        Option<TransparentInterceptionFlowClassifier>,
    ) {
        (self.setup_rules, self.flow_classifier)
    }
}

pub(crate) struct TransparentInterceptionRuntime {
    capability: CapabilityState,
    activation: Option<Box<dyn TransparentInterceptionLifecycle>>,
    proxy_runtime: TransparentProxyRuntime,
}

pub(super) trait TransparentInterceptionLifecycle: Send {
    fn activate(
        self: Box<Self>,
        activation_scope: TransparentInterceptionActivationScope,
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
        activation_scope: Option<TransparentInterceptionActivationScope>,
    ) -> Result<Option<TransparentInterceptionGuard>, TransparentInterceptionError> {
        self.activation
            .map(|activation| {
                let activation_scope = activation_scope.ok_or_else(|| {
                    TransparentInterceptionError::Nftables(
                        "transparent interception setup scope is missing".to_string(),
                    )
                })?;
                activation
                    .activate(activation_scope)
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
        activation_scope: TransparentInterceptionActivationScope,
    ) -> Result<Box<dyn TransparentInterceptionGuardLifecycle>, TransparentInterceptionError> {
        NftablesTransparentInterception::activate(*self, activation_scope)
            .map(|guard| Box::new(guard) as Box<dyn TransparentInterceptionGuardLifecycle>)
    }
}

impl TransparentInterceptionLifecycle for NftablesOutboundTransparentProxy {
    fn activate(
        self: Box<Self>,
        activation_scope: TransparentInterceptionActivationScope,
    ) -> Result<Box<dyn TransparentInterceptionGuardLifecycle>, TransparentInterceptionError> {
        NftablesOutboundTransparentProxy::activate(*self, activation_scope)
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
