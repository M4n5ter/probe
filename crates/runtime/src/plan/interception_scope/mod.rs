use std::net::{Ipv4Addr, Ipv6Addr};

use interception::{
    TransparentInterceptionClassifierSelector, TransparentInterceptionClassifierTerm,
    TransparentInterceptionFlowClassifierScope, TransparentInterceptionHostRuleBoundary,
    TransparentInterceptionHostRuleScope, TransparentInterceptionHostRuleSet,
    TransparentInterceptionProcessScope, TransparentInterceptionProcessScopeExpression,
    TransparentInterceptionSetupDirection, TransparentInterceptionSetupPlan,
    TransparentInterceptionSetupProjectionError, TransparentInterceptionSetupSelectorSources,
    TransparentInterceptionSetupSelectors, TransparentInterceptionSocketOwnerScope,
};
use probe_config::TransparentInterceptionStrategyConfig;
use probe_core::{ProcessSelector, Selector, TrafficSelector};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum TransparentInterceptionLocalSetupProjectionPlan {
    NotConfigured,
    HostRules {
        scopes: Vec<TransparentInterceptionProjectedHostRuleScopePlan>,
    },
    RequiresProcessClassifier {
        reason: String,
        host_rule_boundary: TransparentInterceptionProjectedHostRuleBoundaryPlan,
        process_scope: Box<TransparentInterceptionProcessScopePlan>,
    },
    RequiresFlowClassifier {
        reason: String,
        host_rule_boundary: TransparentInterceptionProjectedHostRuleBoundaryPlan,
        flow_scope: Box<TransparentInterceptionFlowClassifierScopePlan>,
    },
    Unsupported {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum TransparentInterceptionProjectedHostRuleBoundaryPlan {
    NoHostRuleBoundary,
    HostRules {
        scopes: Vec<TransparentInterceptionProjectedHostRuleScopePlan>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparentInterceptionProjectedHostRuleScopePlan {
    pub local_ports: TransparentInterceptionProjectedPortScopePlan,
    pub remote_ports: TransparentInterceptionProjectedPortScopePlan,
    pub remote_addresses: TransparentInterceptionProjectedRemoteAddressScopePlan,
    pub socket_owners: TransparentInterceptionProjectedSocketOwnerScopePlan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum TransparentInterceptionProjectedPortScopePlan {
    Any,
    Only { ports: Vec<u16> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparentInterceptionProjectedRemoteAddressScopePlan {
    pub ipv4: Vec<Ipv4Addr>,
    pub ipv6: Vec<Ipv6Addr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparentInterceptionProjectedSocketOwnerScopePlan {
    pub uids: Vec<u32>,
    pub gids: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparentInterceptionProcessScopePlan {
    pub expression: TransparentInterceptionProcessScopeExpressionPlan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum TransparentInterceptionProcessScopeExpressionPlan {
    Match {
        process: ProcessSelector,
    },
    All {
        expressions: Vec<TransparentInterceptionProcessScopeExpressionPlan>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparentInterceptionFlowClassifierScopePlan {
    pub selector: TransparentInterceptionClassifierSelectorPlan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "op")]
pub enum TransparentInterceptionClassifierSelectorPlan {
    Match {
        term: Box<TransparentInterceptionClassifierTermPlan>,
    },
    All {
        selectors: Vec<TransparentInterceptionClassifierSelectorPlan>,
    },
    Any {
        selectors: Vec<TransparentInterceptionClassifierSelectorPlan>,
    },
    Not {
        selector: Box<TransparentInterceptionClassifierSelectorPlan>,
    },
    Ref {
        name: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparentInterceptionClassifierTermPlan {
    pub process: ProcessSelector,
    pub traffic: TrafficSelector,
}

impl TransparentInterceptionLocalSetupProjectionPlan {
    pub(super) fn from_strategy_and_selectors(
        strategy: TransparentInterceptionStrategyConfig,
        enforcement_selector: Option<&Selector>,
        interception_selector: Option<&Selector>,
    ) -> Self {
        match strategy {
            TransparentInterceptionStrategyConfig::None => Self::NotConfigured,
            TransparentInterceptionStrategyConfig::InboundTproxy => {
                Self::from_inbound_selectors(enforcement_selector, interception_selector)
            }
            TransparentInterceptionStrategyConfig::OutboundTransparentProxy => {
                Self::from_outbound_selectors(enforcement_selector, interception_selector)
            }
        }
    }

    fn from_inbound_selectors(
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
        Self::from_projection_result(
            selectors.local_setup_plan(TransparentInterceptionSetupDirection::Inbound),
        )
    }

    fn from_outbound_selectors(
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
        Self::from_projection_result(
            selectors.local_setup_plan(TransparentInterceptionSetupDirection::Outbound),
        )
    }

    fn from_projection_result(
        result: Result<
            TransparentInterceptionSetupPlan,
            TransparentInterceptionSetupProjectionError,
        >,
    ) -> Self {
        match result {
            Ok(TransparentInterceptionSetupPlan::HostRules(rules)) => Self::HostRules {
                scopes: TransparentInterceptionProjectedHostRuleScopePlan::from_rule_set(&rules),
            },
            Ok(TransparentInterceptionSetupPlan::RequiresProcessClassifier {
                host_rule_boundary,
                process_scope,
                reason,
            }) => Self::RequiresProcessClassifier {
                reason,
                host_rule_boundary:
                    TransparentInterceptionProjectedHostRuleBoundaryPlan::from_boundary(
                        &host_rule_boundary,
                    ),
                process_scope: Box::new(TransparentInterceptionProcessScopePlan::from_scope(
                    &process_scope,
                )),
            },
            Ok(TransparentInterceptionSetupPlan::RequiresFlowClassifier {
                host_rule_boundary,
                flow_scope,
                reason,
            }) => Self::RequiresFlowClassifier {
                reason,
                host_rule_boundary:
                    TransparentInterceptionProjectedHostRuleBoundaryPlan::from_boundary(
                        &host_rule_boundary,
                    ),
                flow_scope: Box::new(TransparentInterceptionFlowClassifierScopePlan::from_scope(
                    &flow_scope,
                )),
            },
            Err(error) => Self::Unsupported {
                reason: error.to_string(),
            },
        }
    }
}

impl TransparentInterceptionProjectedHostRuleBoundaryPlan {
    fn from_boundary(boundary: &TransparentInterceptionHostRuleBoundary) -> Self {
        match boundary {
            TransparentInterceptionHostRuleBoundary::NoHostRuleBoundary => Self::NoHostRuleBoundary,
            TransparentInterceptionHostRuleBoundary::HostRules(rules) => Self::HostRules {
                scopes: TransparentInterceptionProjectedHostRuleScopePlan::from_rule_set(rules),
            },
        }
    }
}

impl TransparentInterceptionProjectedHostRuleScopePlan {
    fn from_rule_set(
        rules: &TransparentInterceptionHostRuleSet,
    ) -> Vec<TransparentInterceptionProjectedHostRuleScopePlan> {
        rules.scopes().iter().map(Self::from_scope).collect()
    }

    fn from_scope(scope: &TransparentInterceptionHostRuleScope) -> Self {
        Self {
            local_ports: TransparentInterceptionProjectedPortScopePlan::from_values(
                scope.local_ports().only_values(),
            ),
            remote_ports: TransparentInterceptionProjectedPortScopePlan::from_values(
                scope.remote_ports().only_values(),
            ),
            remote_addresses: TransparentInterceptionProjectedRemoteAddressScopePlan {
                ipv4: scope.remote_addresses().ipv4().to_vec(),
                ipv6: scope.remote_addresses().ipv6().to_vec(),
            },
            socket_owners: TransparentInterceptionProjectedSocketOwnerScopePlan::from_scope(
                scope.socket_owners(),
            ),
        }
    }
}

impl TransparentInterceptionProjectedSocketOwnerScopePlan {
    fn from_scope(scope: &TransparentInterceptionSocketOwnerScope) -> Self {
        Self {
            uids: scope.uids().to_vec(),
            gids: scope.gids().to_vec(),
        }
    }
}

impl TransparentInterceptionProjectedPortScopePlan {
    fn from_values(values: Option<&[u16]>) -> Self {
        match values {
            Some(ports) => Self::Only {
                ports: ports.to_vec(),
            },
            None => Self::Any,
        }
    }
}

impl TransparentInterceptionProcessScopePlan {
    fn from_scope(scope: &TransparentInterceptionProcessScope) -> Self {
        Self {
            expression: TransparentInterceptionProcessScopeExpressionPlan::from_expression(
                scope.expression(),
            ),
        }
    }
}

impl TransparentInterceptionProcessScopeExpressionPlan {
    fn from_expression(expression: &TransparentInterceptionProcessScopeExpression) -> Self {
        match expression {
            TransparentInterceptionProcessScopeExpression::Match { process } => Self::Match {
                process: process.clone(),
            },
            TransparentInterceptionProcessScopeExpression::All { expressions } => Self::All {
                expressions: expressions.iter().map(Self::from_expression).collect(),
            },
        }
    }
}

impl TransparentInterceptionFlowClassifierScopePlan {
    fn from_scope(scope: &TransparentInterceptionFlowClassifierScope) -> Self {
        Self {
            selector: TransparentInterceptionClassifierSelectorPlan::from_selector(
                scope.selector(),
            ),
        }
    }
}

impl TransparentInterceptionClassifierSelectorPlan {
    fn from_selector(selector: &TransparentInterceptionClassifierSelector) -> Self {
        match selector {
            TransparentInterceptionClassifierSelector::Match { term } => Self::Match {
                term: Box::new(TransparentInterceptionClassifierTermPlan::from_term(term)),
            },
            TransparentInterceptionClassifierSelector::All { selectors } => Self::All {
                selectors: selectors.iter().map(Self::from_selector).collect(),
            },
            TransparentInterceptionClassifierSelector::Any { selectors } => Self::Any {
                selectors: selectors.iter().map(Self::from_selector).collect(),
            },
            TransparentInterceptionClassifierSelector::Not { selector } => Self::Not {
                selector: Box::new(Self::from_selector(selector)),
            },
            TransparentInterceptionClassifierSelector::Ref { name } => {
                Self::Ref { name: name.clone() }
            }
        }
    }
}

impl TransparentInterceptionClassifierTermPlan {
    fn from_term(term: &TransparentInterceptionClassifierTerm) -> Self {
        Self {
            process: term.process.clone(),
            traffic: term.traffic.clone(),
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
            TransparentInterceptionLocalSetupProjectionPlan::NotConfigured
        );
    }

    #[test]
    fn outbound_transparent_proxy_projectable_selector_reports_host_rules() {
        let scope = scope_for(
            TransparentInterceptionStrategyConfig::OutboundTransparentProxy,
            Selector::term(
                ProcessSelector::default(),
                TrafficSelector {
                    remote_ports: vec![443],
                    directions: vec![Direction::Outbound],
                    ..TrafficSelector::default()
                },
            ),
        );

        let TransparentInterceptionLocalSetupProjectionPlan::HostRules { scopes } = scope else {
            panic!("projectable outbound selector should report host rules");
        };
        let scope = single_scope(&scopes);
        assert_eq!(
            scope.remote_ports,
            TransparentInterceptionProjectedPortScopePlan::Only { ports: vec![443] }
        );
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

        let TransparentInterceptionLocalSetupProjectionPlan::HostRules { scopes } = scope else {
            panic!("projectable selector should report host rules");
        };
        let scope = single_scope(&scopes);
        assert_eq!(
            scope.local_ports,
            TransparentInterceptionProjectedPortScopePlan::Only { ports: vec![8443] }
        );
        assert_eq!(
            scope.remote_addresses.ipv4,
            [Ipv4Addr::new(203, 0, 113, 10)]
        );
    }

    #[test]
    fn inbound_without_local_selector_is_unsupported() {
        let scope = TransparentInterceptionLocalSetupProjectionPlan::from_strategy_and_selectors(
            TransparentInterceptionStrategyConfig::InboundTproxy,
            None,
            None,
        );

        assert!(matches!(
            scope,
            TransparentInterceptionLocalSetupProjectionPlan::Unsupported { .. }
        ));
    }

    #[test]
    fn process_only_selector_reports_typed_classifier_requirement_without_host_scope() {
        let scope = scope_for(
            TransparentInterceptionStrategyConfig::InboundTproxy,
            Selector::term(
                ProcessSelector {
                    names: vec!["curl".to_string()],
                    ..ProcessSelector::default()
                },
                TrafficSelector {
                    directions: vec![Direction::Inbound],
                    ..TrafficSelector::default()
                },
            ),
        );

        let TransparentInterceptionLocalSetupProjectionPlan::RequiresProcessClassifier {
            host_rule_boundary,
            process_scope,
            ..
        } = scope
        else {
            panic!("process-only selector should require process classifier");
        };
        assert_eq!(
            host_rule_boundary,
            TransparentInterceptionProjectedHostRuleBoundaryPlan::NoHostRuleBoundary
        );
        assert_eq!(process_scope_names(&process_scope), ["curl"]);
    }

    #[test]
    fn process_scoped_traffic_reports_typed_host_scope() {
        let scope = scope_for(
            TransparentInterceptionStrategyConfig::InboundTproxy,
            Selector::term(
                ProcessSelector {
                    names: vec!["curl".to_string()],
                    ..ProcessSelector::default()
                },
                TrafficSelector {
                    local_ports: vec![8443],
                    directions: vec![Direction::Inbound],
                    remote_addresses: vec!["203.0.113.10".to_string()],
                    ..TrafficSelector::default()
                },
            ),
        );

        let TransparentInterceptionLocalSetupProjectionPlan::RequiresProcessClassifier {
            host_rule_boundary,
            process_scope,
            ..
        } = scope
        else {
            panic!("process-scoped traffic should require process classifier");
        };
        let TransparentInterceptionProjectedHostRuleBoundaryPlan::HostRules { scopes } =
            host_rule_boundary
        else {
            panic!("traffic selector should keep a projected host-rule boundary");
        };
        let host_rule_scope = single_scope(&scopes);
        assert_eq!(
            host_rule_scope.local_ports,
            TransparentInterceptionProjectedPortScopePlan::Only { ports: vec![8443] }
        );
        assert_eq!(
            host_rule_scope.remote_addresses.ipv4,
            [Ipv4Addr::new(203, 0, 113, 10)]
        );
        assert_eq!(process_scope_names(&process_scope), ["curl"]);
    }

    #[test]
    fn any_selector_projects_single_host_rule_dimension() {
        let scope = scope_for(
            TransparentInterceptionStrategyConfig::InboundTproxy,
            Selector::Any {
                selectors: vec![
                    Selector::term(
                        ProcessSelector::default(),
                        TrafficSelector {
                            local_ports: vec![8443],
                            remote_addresses: vec![
                                "203.0.113.10".to_string(),
                                "203.0.113.20".to_string(),
                            ],
                            ..TrafficSelector::default()
                        },
                    ),
                    Selector::term(
                        ProcessSelector::default(),
                        TrafficSelector {
                            local_ports: vec![9443],
                            remote_addresses: vec![
                                "203.0.113.20".to_string(),
                                "203.0.113.10".to_string(),
                            ],
                            ..TrafficSelector::default()
                        },
                    ),
                ],
            },
        );

        let TransparentInterceptionLocalSetupProjectionPlan::HostRules { scopes } = scope else {
            panic!("single-dimension any selector should report host rules");
        };
        let scope = single_scope(&scopes);
        assert_eq!(
            scope.local_ports,
            TransparentInterceptionProjectedPortScopePlan::Only {
                ports: vec![8443, 9443]
            }
        );
        assert_eq!(
            scope.remote_addresses.ipv4,
            [
                Ipv4Addr::new(203, 0, 113, 10),
                Ipv4Addr::new(203, 0, 113, 20)
            ]
        );
    }

    #[test]
    fn any_selector_with_multiple_dimensions_reports_disjoint_host_rules() {
        let scope = scope_for(
            TransparentInterceptionStrategyConfig::InboundTproxy,
            Selector::Any {
                selectors: vec![
                    Selector::term(
                        ProcessSelector::default(),
                        TrafficSelector {
                            local_ports: vec![8443],
                            remote_addresses: vec!["203.0.113.10".to_string()],
                            ..TrafficSelector::default()
                        },
                    ),
                    Selector::term(
                        ProcessSelector::default(),
                        TrafficSelector {
                            local_ports: vec![9443],
                            remote_addresses: vec!["203.0.113.20".to_string()],
                            ..TrafficSelector::default()
                        },
                    ),
                ],
            },
        );

        let TransparentInterceptionLocalSetupProjectionPlan::HostRules { scopes } = scope else {
            panic!("disjoint any selector should report multiple host rules");
        };
        assert_eq!(scopes.len(), 2);
        assert_eq!(
            scopes[0].local_ports,
            TransparentInterceptionProjectedPortScopePlan::Only { ports: vec![8443] }
        );
        assert_eq!(
            scopes[0].remote_addresses.ipv4,
            [Ipv4Addr::new(203, 0, 113, 10)]
        );
        assert_eq!(
            scopes[1].local_ports,
            TransparentInterceptionProjectedPortScopePlan::Only { ports: vec![9443] }
        );
        assert_eq!(
            scopes[1].remote_addresses.ipv4,
            [Ipv4Addr::new(203, 0, 113, 20)]
        );
    }

    #[test]
    fn nested_any_with_host_boundary_reports_disjoint_host_rules() {
        let scope = scope_for(
            TransparentInterceptionStrategyConfig::InboundTproxy,
            Selector::All {
                selectors: vec![
                    Selector::term(
                        ProcessSelector::default(),
                        TrafficSelector {
                            local_ports: vec![8443],
                            directions: vec![Direction::Inbound],
                            ..TrafficSelector::default()
                        },
                    ),
                    Selector::Any {
                        selectors: vec![
                            Selector::term(
                                ProcessSelector::default(),
                                TrafficSelector {
                                    remote_ports: vec![443],
                                    remote_addresses: vec!["203.0.113.10".to_string()],
                                    ..TrafficSelector::default()
                                },
                            ),
                            Selector::term(
                                ProcessSelector::default(),
                                TrafficSelector {
                                    remote_ports: vec![444],
                                    remote_addresses: vec!["203.0.113.20".to_string()],
                                    ..TrafficSelector::default()
                                },
                            ),
                        ],
                    },
                ],
            },
        );

        let TransparentInterceptionLocalSetupProjectionPlan::HostRules { scopes } = scope else {
            panic!("nested host-rule any selector should report host rules");
        };
        assert_eq!(scopes.len(), 2);
        let host_rule_scope = &scopes[0];
        assert_eq!(
            host_rule_scope.local_ports,
            TransparentInterceptionProjectedPortScopePlan::Only { ports: vec![8443] }
        );
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
            TransparentInterceptionLocalSetupProjectionPlan::Unsupported { .. }
        ));
    }

    #[test]
    fn any_selector_with_wrong_direction_is_unsupported() {
        let scope = scope_for(
            TransparentInterceptionStrategyConfig::InboundTproxy,
            Selector::Any {
                selectors: vec![
                    Selector::term(
                        ProcessSelector {
                            names: vec!["curl".to_string()],
                            ..ProcessSelector::default()
                        },
                        TrafficSelector {
                            local_ports: vec![8443],
                            directions: vec![Direction::Outbound],
                            ..TrafficSelector::default()
                        },
                    ),
                    Selector::Ref {
                        name: "external".to_string(),
                    },
                ],
            },
        );

        assert!(matches!(
            scope,
            TransparentInterceptionLocalSetupProjectionPlan::Unsupported { .. }
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
            TransparentInterceptionLocalSetupProjectionPlan::Unsupported { .. }
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
            TransparentInterceptionLocalSetupProjectionPlan::Unsupported { .. }
        ));
    }

    fn scope_for(
        strategy: TransparentInterceptionStrategyConfig,
        selector: Selector,
    ) -> TransparentInterceptionLocalSetupProjectionPlan {
        TransparentInterceptionLocalSetupProjectionPlan::from_strategy_and_selectors(
            strategy,
            Some(&selector),
            None,
        )
    }

    fn process_scope_names(scope: &TransparentInterceptionProcessScopePlan) -> Vec<&str> {
        let TransparentInterceptionProcessScopeExpressionPlan::Match { process } =
            &scope.expression
        else {
            panic!("test process scope should be a match expression");
        };
        process.names.iter().map(String::as_str).collect()
    }

    fn single_scope(
        scopes: &[TransparentInterceptionProjectedHostRuleScopePlan],
    ) -> &TransparentInterceptionProjectedHostRuleScopePlan {
        let [scope] = scopes else {
            panic!("expected exactly one projected host-rule scope, got {scopes:?}");
        };
        scope
    }
}
