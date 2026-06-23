use probe_core::Selector;

use super::{
    TransparentInterceptionSetupDirection, TransparentInterceptionSetupPlan,
    TransparentInterceptionSetupProjectionError,
};

#[derive(Debug, Clone, Copy)]
pub struct TransparentInterceptionSetupSelectorSources<'a> {
    pub local_enforcement_selector: Option<&'a Selector>,
    pub effective_enforcement_selector: Option<&'a Selector>,
    pub interception_selector: Option<&'a Selector>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentInterceptionSetupSelectors {
    local_config_scope: Option<Selector>,
    final_effective_scope: Option<Selector>,
}

impl TransparentInterceptionSetupSelectors {
    pub fn from_sources(sources: TransparentInterceptionSetupSelectorSources<'_>) -> Self {
        Self {
            local_config_scope: setup_selector(
                sources.local_enforcement_selector,
                sources.interception_selector,
            ),
            final_effective_scope: setup_selector(
                sources.effective_enforcement_selector,
                sources.interception_selector,
            ),
        }
    }

    pub fn local_config_scope(&self) -> Option<&Selector> {
        self.local_config_scope.as_ref()
    }

    pub fn final_effective_scope(&self) -> Option<&Selector> {
        self.final_effective_scope.as_ref()
    }

    pub fn local_setup_plan(
        &self,
        direction: TransparentInterceptionSetupDirection,
    ) -> Result<TransparentInterceptionSetupPlan, TransparentInterceptionSetupProjectionError> {
        setup_plan(self.local_config_scope(), direction)
    }

    pub fn final_setup_plan(
        &self,
        direction: TransparentInterceptionSetupDirection,
    ) -> Result<TransparentInterceptionSetupPlan, TransparentInterceptionSetupProjectionError> {
        setup_plan(self.final_effective_scope(), direction)
    }
}

fn setup_plan(
    selector: Option<&Selector>,
    direction: TransparentInterceptionSetupDirection,
) -> Result<TransparentInterceptionSetupPlan, TransparentInterceptionSetupProjectionError> {
    TransparentInterceptionSetupPlan::from_selector(selector, direction)
}

fn setup_selector(
    enforcement_selector: Option<&Selector>,
    interception_selector: Option<&Selector>,
) -> Option<Selector> {
    match (enforcement_selector, interception_selector) {
        (Some(enforcement), Some(interception)) => Some(Selector::All {
            selectors: vec![enforcement.clone(), interception.clone()],
        }),
        (Some(selector), None) | (None, Some(selector)) => Some(selector.clone()),
        (None, None) => None,
    }
}
