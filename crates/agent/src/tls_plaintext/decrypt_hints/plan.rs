use runtime::{CapturePlanMode, RuntimePlan, TlsPlaintextMaterialPlan};

pub(crate) enum TlsSessionSecretAutoBindingPlan<'a> {
    Disabled,
    Enabled {
        materials: &'a [TlsPlaintextMaterialPlan],
    },
}

impl<'a> TlsSessionSecretAutoBindingPlan<'a> {
    pub(crate) fn for_runtime(plan: &'a RuntimePlan) -> Self {
        let materials = plan.tls.plaintext.decrypt_hints.session_secrets.as_slice();
        if materials.is_empty() {
            return Self::Disabled;
        }
        match plan.capture.mode {
            CapturePlanMode::Live => Self::Enabled { materials },
            CapturePlanMode::PlaintextFeed
            | CapturePlanMode::Replay
            | CapturePlanMode::Unavailable => Self::Disabled,
        }
    }

    pub(crate) fn is_enabled(&self) -> bool {
        matches!(self, Self::Enabled { .. })
    }
}
