use probe_core::{ResolvedSelector, Selector};

use super::{
    TransparentInterceptionSetupDirection, TransparentInterceptionSetupPlan,
    TransparentInterceptionSetupProjectionError,
};

type SetupSelectorResult =
    Result<Option<ResolvedSelector>, TransparentInterceptionSetupProjectionError>;

#[derive(Debug, Clone, Copy)]
pub struct TransparentInterceptionSetupSelectorSources<'a> {
    pub local_enforcement_selector: Option<&'a ResolvedSelector>,
    pub effective_enforcement_selector: Option<&'a ResolvedSelector>,
    pub interception_selector: Option<&'a ResolvedSelector>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentInterceptionSetupSelectors {
    local_config_scope: SetupSelectorResult,
    final_effective_scope: SetupSelectorResult,
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

    pub fn local_config_scope(&self) -> Option<&ResolvedSelector> {
        self.local_config_scope
            .as_ref()
            .ok()
            .and_then(Option::as_ref)
    }

    pub fn final_effective_scope(&self) -> Option<&ResolvedSelector> {
        self.final_effective_scope
            .as_ref()
            .ok()
            .and_then(Option::as_ref)
    }

    pub fn local_config_scope_configured(&self) -> bool {
        !matches!(self.local_config_scope, Ok(None))
    }

    pub fn local_setup_plan(
        &self,
        direction: TransparentInterceptionSetupDirection,
    ) -> Result<TransparentInterceptionSetupPlan, TransparentInterceptionSetupProjectionError> {
        setup_plan(&self.local_config_scope, direction)
    }

    pub fn final_setup_plan(
        &self,
        direction: TransparentInterceptionSetupDirection,
    ) -> Result<TransparentInterceptionSetupPlan, TransparentInterceptionSetupProjectionError> {
        setup_plan(&self.final_effective_scope, direction)
    }
}

fn setup_plan(
    selector: &SetupSelectorResult,
    direction: TransparentInterceptionSetupDirection,
) -> Result<TransparentInterceptionSetupPlan, TransparentInterceptionSetupProjectionError> {
    match selector {
        Ok(selector) => TransparentInterceptionSetupPlan::from_selector(
            selector.as_ref().map(ResolvedSelector::as_selector),
            direction,
        ),
        Err(error) => Err(error.clone()),
    }
}

fn setup_selector(
    enforcement_selector: Option<&ResolvedSelector>,
    interception_selector: Option<&ResolvedSelector>,
) -> SetupSelectorResult {
    match (enforcement_selector, interception_selector) {
        (Some(enforcement), Some(interception)) => ResolvedSelector::new(Selector::All {
            selectors: vec![
                enforcement.as_selector().clone(),
                interception.as_selector().clone(),
            ],
        })
        .map(Some)
        .map_err(
            |error| TransparentInterceptionSetupProjectionError::Unsupported {
                reason: format!("invalid composed setup selector: {error}"),
            },
        ),
        (Some(selector), None) | (None, Some(selector)) => Ok(Some(selector.clone())),
        (None, None) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use probe_core::{ProcessSelector, TrafficSelector};

    use super::*;

    #[test]
    fn selector_composition_over_budget_returns_projection_error() {
        let enforcement = resolved_selector_with_match_terms(2_048);
        let interception = resolved_selector_with_match_terms(2_048);
        let selectors = TransparentInterceptionSetupSelectors::from_sources(
            TransparentInterceptionSetupSelectorSources {
                local_enforcement_selector: Some(&enforcement),
                effective_enforcement_selector: Some(&enforcement),
                interception_selector: Some(&interception),
            },
        );

        assert!(selectors.local_config_scope_configured());
        let error = selectors
            .local_setup_plan(TransparentInterceptionSetupDirection::Inbound)
            .expect_err("over-budget composition should fail closed");

        assert!(error.to_string().contains("maximum expanded node count"));
    }

    fn resolved_selector_with_match_terms(count: usize) -> ResolvedSelector {
        ResolvedSelector::new(Selector::All {
            selectors: (0..count)
                .map(|_| Selector::term(ProcessSelector::default(), TrafficSelector::default()))
                .collect(),
        })
        .expect("test selector should fit the per-source resolved selector budget")
    }
}
