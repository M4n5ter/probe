use interception::{
    TransparentInterceptionHostRuleScope, TransparentInterceptionSetupProjectionError,
    TransparentInterceptionSetupSelectorSources, TransparentInterceptionSetupSelectors,
};
use probe_config::TransparentInterceptionStrategyConfig;
use probe_core::Selector;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum TransparentInterceptionLocalSetupScopePlan {
    NotConfigured,
    HostRules,
    RequiresProcessClassifier { reason: String },
    RequiresFlowClassifier { reason: String },
    Unsupported { reason: String },
}

impl TransparentInterceptionLocalSetupScopePlan {
    pub(super) fn from_strategy_and_selectors(
        strategy: TransparentInterceptionStrategyConfig,
        enforcement_selector: Option<&Selector>,
        interception_selector: Option<&Selector>,
    ) -> Self {
        match strategy {
            TransparentInterceptionStrategyConfig::None => Self::NotConfigured,
            TransparentInterceptionStrategyConfig::OutboundMitm => Self::Unsupported {
                reason: "outbound transparent MITM requires proxy self-bypass and MITM lifecycle before local setup rules can be planned".to_string(),
            },
            TransparentInterceptionStrategyConfig::InboundTproxy => {
                Self::from_selectors(enforcement_selector, interception_selector)
            }
        }
    }

    fn from_selectors(
        enforcement_selector: Option<&Selector>,
        interception_selector: Option<&Selector>,
    ) -> Self {
        let selectors = TransparentInterceptionSetupSelectors::from_sources(
            TransparentInterceptionSetupSelectorSources {
                local_enforcement_selector: enforcement_selector,
                effective_enforcement_selector: enforcement_selector,
                interception_selector,
            },
        );
        Self::from_projection_result(selectors.local_host_rule_scope())
    }

    fn from_projection_result(
        result: Result<
            TransparentInterceptionHostRuleScope,
            TransparentInterceptionSetupProjectionError,
        >,
    ) -> Self {
        match result {
            Ok(_) => Self::HostRules,
            Err(TransparentInterceptionSetupProjectionError::RequiresProcessClassifier {
                reason,
            }) => Self::RequiresProcessClassifier { reason },
            Err(TransparentInterceptionSetupProjectionError::RequiresFlowClassifier { reason }) => {
                Self::RequiresFlowClassifier { reason }
            }
            Err(
                error @ (TransparentInterceptionSetupProjectionError::MissingSelector
                | TransparentInterceptionSetupProjectionError::UnconstrainedSelector
                | TransparentInterceptionSetupProjectionError::Unsupported { .. }),
            ) => Self::Unsupported {
                reason: error.to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use probe_core::{Direction, ProcessSelector, TrafficSelector};

    use super::*;

    #[test]
    fn disabled_strategy_is_not_configured_even_when_selector_exists() {
        let scope = scope_for(
            TransparentInterceptionStrategyConfig::None,
            Selector::term(
                ProcessSelector::default(),
                TrafficSelector {
                    local_ports: vec![8443],
                    ..TrafficSelector::default()
                },
            ),
        );

        assert_eq!(
            scope,
            TransparentInterceptionLocalSetupScopePlan::NotConfigured
        );
    }

    #[test]
    fn outbound_mitm_is_not_reported_as_host_rules() {
        let scope = scope_for(
            TransparentInterceptionStrategyConfig::OutboundMitm,
            Selector::term(
                ProcessSelector::default(),
                TrafficSelector {
                    remote_ports: vec![443],
                    directions: vec![Direction::Outbound],
                    ..TrafficSelector::default()
                },
            ),
        );

        assert!(matches!(
            scope,
            TransparentInterceptionLocalSetupScopePlan::Unsupported { .. }
        ));
    }

    #[test]
    fn inbound_projectable_selector_reports_host_rules() {
        let scope = scope_for(
            TransparentInterceptionStrategyConfig::InboundTproxy,
            Selector::term(
                ProcessSelector::default(),
                TrafficSelector {
                    local_ports: vec![8443],
                    directions: vec![Direction::Inbound],
                    remote_addresses: vec!["203.0.113.10".to_string()],
                    ..TrafficSelector::default()
                },
            ),
        );

        assert_eq!(scope, TransparentInterceptionLocalSetupScopePlan::HostRules);
    }

    #[test]
    fn inbound_without_local_selector_is_unsupported() {
        let scope = TransparentInterceptionLocalSetupScopePlan::from_strategy_and_selectors(
            TransparentInterceptionStrategyConfig::InboundTproxy,
            None,
            None,
        );

        assert!(matches!(
            scope,
            TransparentInterceptionLocalSetupScopePlan::Unsupported { .. }
        ));
    }

    #[test]
    fn process_selector_reports_process_classifier_requirement() {
        let scope = scope_for(
            TransparentInterceptionStrategyConfig::InboundTproxy,
            Selector::term(
                ProcessSelector {
                    names: vec!["curl".to_string()],
                    ..ProcessSelector::default()
                },
                TrafficSelector {
                    remote_ports: vec![443],
                    directions: vec![Direction::Inbound],
                    ..TrafficSelector::default()
                },
            ),
        );

        assert!(matches!(
            scope,
            TransparentInterceptionLocalSetupScopePlan::RequiresProcessClassifier { .. }
        ));
    }

    #[test]
    fn any_selector_reports_flow_classifier_requirement() {
        let scope = scope_for(
            TransparentInterceptionStrategyConfig::InboundTproxy,
            Selector::Any {
                selectors: vec![
                    Selector::term(
                        ProcessSelector::default(),
                        TrafficSelector {
                            local_ports: vec![8443],
                            ..TrafficSelector::default()
                        },
                    ),
                    Selector::term(
                        ProcessSelector::default(),
                        TrafficSelector {
                            local_ports: vec![9443],
                            ..TrafficSelector::default()
                        },
                    ),
                ],
            },
        );

        assert!(matches!(
            scope,
            TransparentInterceptionLocalSetupScopePlan::RequiresFlowClassifier { .. }
        ));
    }

    #[test]
    fn wrong_direction_is_unsupported() {
        let scope = scope_for(
            TransparentInterceptionStrategyConfig::InboundTproxy,
            Selector::term(
                ProcessSelector::default(),
                TrafficSelector {
                    local_ports: vec![8443],
                    directions: vec![Direction::Outbound],
                    ..TrafficSelector::default()
                },
            ),
        );

        assert!(matches!(
            scope,
            TransparentInterceptionLocalSetupScopePlan::Unsupported { .. }
        ));
    }

    #[test]
    fn disjoint_all_selector_is_unsupported() {
        let scope = scope_for(
            TransparentInterceptionStrategyConfig::InboundTproxy,
            Selector::All {
                selectors: vec![
                    Selector::term(
                        ProcessSelector::default(),
                        TrafficSelector {
                            local_ports: vec![8443],
                            ..TrafficSelector::default()
                        },
                    ),
                    Selector::term(
                        ProcessSelector::default(),
                        TrafficSelector {
                            local_ports: vec![9443],
                            ..TrafficSelector::default()
                        },
                    ),
                ],
            },
        );

        assert!(matches!(
            scope,
            TransparentInterceptionLocalSetupScopePlan::Unsupported { .. }
        ));
    }

    #[test]
    fn invalid_remote_address_is_unsupported() {
        let scope = scope_for(
            TransparentInterceptionStrategyConfig::InboundTproxy,
            Selector::term(
                ProcessSelector::default(),
                TrafficSelector {
                    remote_addresses: vec!["not an ip".to_string()],
                    ..TrafficSelector::default()
                },
            ),
        );

        assert!(matches!(
            scope,
            TransparentInterceptionLocalSetupScopePlan::Unsupported { .. }
        ));
    }

    fn scope_for(
        strategy: TransparentInterceptionStrategyConfig,
        selector: Selector,
    ) -> TransparentInterceptionLocalSetupScopePlan {
        TransparentInterceptionLocalSetupScopePlan::from_strategy_and_selectors(
            strategy,
            Some(&selector),
            None,
        )
    }
}
