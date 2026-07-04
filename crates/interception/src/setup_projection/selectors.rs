use probe_core::ResolvedSelector;

use super::{
    TransparentInterceptionSetupDirection, TransparentInterceptionSetupPlan,
    TransparentInterceptionSetupProjectionError,
};

#[derive(Debug, Clone, Copy)]
pub struct TransparentInterceptionSetupSelectorSources<'a> {
    pub local_enforcement_selector: Option<&'a ResolvedSelector>,
    pub effective_enforcement_selector: Option<&'a ResolvedSelector>,
    pub interception_selector: Option<&'a ResolvedSelector>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentInterceptionSetupSelectors {
    local_config_scope: Option<ResolvedSelector>,
    final_effective_scope: Option<ResolvedSelector>,
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
        self.local_config_scope.as_ref()
    }

    pub fn final_effective_scope(&self) -> Option<&ResolvedSelector> {
        self.final_effective_scope.as_ref()
    }

    pub fn local_config_scope_configured(&self) -> bool {
        self.local_config_scope.is_some()
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
    selector: &Option<ResolvedSelector>,
    direction: TransparentInterceptionSetupDirection,
) -> Result<TransparentInterceptionSetupPlan, TransparentInterceptionSetupProjectionError> {
    TransparentInterceptionSetupPlan::from_selector(
        selector.as_ref().map(ResolvedSelector::as_selector),
        direction,
    )
}

fn setup_selector(
    enforcement_selector: Option<&ResolvedSelector>,
    interception_selector: Option<&ResolvedSelector>,
) -> Option<ResolvedSelector> {
    interception_selector.or(enforcement_selector).cloned()
}

#[cfg(test)]
mod tests {
    use probe_core::{Direction, ProcessSelector, Selector, TrafficSelector};

    use super::*;

    #[test]
    fn explicit_interception_selector_owns_setup_scope() {
        let enforcement = ResolvedSelector::new(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                local_ports: vec![8443],
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        ))
        .expect("test selector should be valid");
        let interception = ResolvedSelector::new(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                local_ports: vec![9443],
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        ))
        .expect("test selector should be valid");
        let selectors = TransparentInterceptionSetupSelectors::from_sources(
            TransparentInterceptionSetupSelectorSources {
                local_enforcement_selector: Some(&enforcement),
                effective_enforcement_selector: Some(&enforcement),
                interception_selector: Some(&interception),
            },
        );

        assert!(selectors.local_config_scope_configured());
        let TransparentInterceptionSetupPlan::HostRules(local_rules) = selectors
            .local_setup_plan(TransparentInterceptionSetupDirection::Inbound)
            .expect("explicit interception selector should project to host rules")
        else {
            panic!("explicit interception selector should own local setup scope");
        };
        let TransparentInterceptionSetupPlan::HostRules(final_rules) = selectors
            .final_setup_plan(TransparentInterceptionSetupDirection::Inbound)
            .expect("explicit interception selector should project to host rules")
        else {
            panic!("explicit interception selector should own final setup scope");
        };

        assert_eq!(local_rules.explicit_local_ports(), Some(vec![9443]));
        assert_eq!(final_rules.explicit_local_ports(), Some(vec![9443]));
    }

    #[test]
    fn enforcement_selector_is_setup_scope_when_interception_selector_is_absent() {
        let enforcement = ResolvedSelector::new(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                local_ports: vec![8443],
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        ))
        .expect("test selector should be valid");
        let selectors = TransparentInterceptionSetupSelectors::from_sources(
            TransparentInterceptionSetupSelectorSources {
                local_enforcement_selector: Some(&enforcement),
                effective_enforcement_selector: Some(&enforcement),
                interception_selector: None,
            },
        );

        let TransparentInterceptionSetupPlan::HostRules(local_rules) = selectors
            .local_setup_plan(TransparentInterceptionSetupDirection::Inbound)
            .expect("enforcement selector should project to host rules")
        else {
            panic!(
                "enforcement selector should own setup scope when interception selector is absent"
            );
        };

        assert_eq!(local_rules.explicit_local_ports(), Some(vec![8443]));
    }
}
