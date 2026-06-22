use runtime::{CapturePlanMode, RuntimePlan, TlsPlaintextMaterialPlan};

pub(crate) enum TlsSessionSecretAutoBindingPlan<'a> {
    Disabled,
    Enabled(TlsSessionSecretAutoBindingMaterials<'a>),
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct TlsSessionSecretAutoBindingMaterials<'a> {
    key_logs: &'a [TlsPlaintextMaterialPlan],
    session_secrets: &'a [TlsPlaintextMaterialPlan],
}

#[derive(Debug, Clone)]
pub(crate) enum TlsSessionSecretAutoBindingMaterial {
    KeyLog(TlsPlaintextMaterialPlan),
    SessionSecret(TlsPlaintextMaterialPlan),
}

impl TlsSessionSecretAutoBindingMaterial {
    pub(crate) fn plan(&self) -> &TlsPlaintextMaterialPlan {
        match self {
            Self::KeyLog(plan) | Self::SessionSecret(plan) => plan,
        }
    }
}

impl<'a> TlsSessionSecretAutoBindingMaterials<'a> {
    pub(crate) fn new(
        key_logs: &'a [TlsPlaintextMaterialPlan],
        session_secrets: &'a [TlsPlaintextMaterialPlan],
    ) -> Self {
        Self {
            key_logs,
            session_secrets,
        }
    }

    pub(crate) fn key_logs(self) -> &'a [TlsPlaintextMaterialPlan] {
        self.key_logs
    }

    pub(crate) fn session_secrets(self) -> &'a [TlsPlaintextMaterialPlan] {
        self.session_secrets
    }

    pub(crate) fn len(self) -> usize {
        self.key_logs.len() + self.session_secrets.len()
    }

    pub(crate) fn is_empty(self) -> bool {
        self.len() == 0
    }

    pub(crate) fn to_owned_materials(self) -> Vec<TlsSessionSecretAutoBindingMaterial> {
        self.key_logs
            .iter()
            .cloned()
            .map(TlsSessionSecretAutoBindingMaterial::KeyLog)
            .chain(
                self.session_secrets
                    .iter()
                    .cloned()
                    .map(TlsSessionSecretAutoBindingMaterial::SessionSecret),
            )
            .collect()
    }
}

impl<'a> TlsSessionSecretAutoBindingPlan<'a> {
    pub(crate) fn for_runtime(plan: &'a RuntimePlan) -> Self {
        let materials = TlsSessionSecretAutoBindingMaterials::new(
            plan.tls.plaintext.decrypt_hints.key_logs.as_slice(),
            plan.tls.plaintext.decrypt_hints.session_secrets.as_slice(),
        );
        if materials.is_empty() {
            return Self::Disabled;
        }
        match plan.capture.mode {
            CapturePlanMode::Live => Self::Enabled(materials),
            CapturePlanMode::PlaintextFeed
            | CapturePlanMode::Replay
            | CapturePlanMode::Unavailable => Self::Disabled,
        }
    }

    pub(crate) fn enabled_materials(&self) -> Option<TlsSessionSecretAutoBindingMaterials<'a>> {
        match self {
            Self::Disabled => None,
            Self::Enabled(materials) => Some(*materials),
        }
    }

    pub(crate) fn configured_ref_count(plan: &'a RuntimePlan) -> usize {
        TlsSessionSecretAutoBindingMaterials::new(
            plan.tls.plaintext.decrypt_hints.key_logs.as_slice(),
            plan.tls.plaintext.decrypt_hints.session_secrets.as_slice(),
        )
        .len()
    }
}
