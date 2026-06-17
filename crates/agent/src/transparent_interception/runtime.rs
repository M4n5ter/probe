use interception::TransparentInterceptionHostRuleScope;
use probe_core::{CapabilityKind, CapabilityState};

use super::{
    TransparentInterceptionError,
    nftables::{NftablesTransparentInterception, NftablesTransparentInterceptionGuard},
};

pub(crate) struct TransparentInterceptionRuntime {
    capability: CapabilityState,
    activation: Option<Box<dyn TransparentInterceptionLifecycle>>,
}

pub(super) trait TransparentInterceptionLifecycle: Send {
    fn activate(
        self: Box<Self>,
        setup_scope: TransparentInterceptionHostRuleScope,
    ) -> Result<Box<dyn TransparentInterceptionGuardLifecycle>, TransparentInterceptionError>;
}

pub(super) trait TransparentInterceptionGuardLifecycle {
    fn deactivate(self: Box<Self>) -> Result<(), TransparentInterceptionError>;
}

impl TransparentInterceptionRuntime {
    pub(crate) fn capability(&self) -> CapabilityState {
        self.capability.clone()
    }

    pub(crate) fn activate(
        self,
        setup_scope: Option<TransparentInterceptionHostRuleScope>,
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

    pub(super) fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            capability: CapabilityState::unavailable(
                CapabilityKind::TransparentInterception,
                reason,
            ),
            activation: None,
        }
    }

    pub(super) fn available(
        activation: impl TransparentInterceptionLifecycle + 'static,
        note: impl Into<String>,
    ) -> Self {
        Self {
            capability: CapabilityState {
                kind: CapabilityKind::TransparentInterception,
                mode: probe_core::RuntimeMode::Available,
                reason: Some(note.into()),
            },
            activation: Some(Box::new(activation)),
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
        setup_scope: TransparentInterceptionHostRuleScope,
    ) -> Result<Box<dyn TransparentInterceptionGuardLifecycle>, TransparentInterceptionError> {
        NftablesTransparentInterception::activate(*self, setup_scope)
            .map(|guard| Box::new(guard) as Box<dyn TransparentInterceptionGuardLifecycle>)
    }
}

impl TransparentInterceptionGuardLifecycle for NftablesTransparentInterceptionGuard {
    fn deactivate(self: Box<Self>) -> Result<(), TransparentInterceptionError> {
        NftablesTransparentInterceptionGuard::deactivate(*self)
    }
}
