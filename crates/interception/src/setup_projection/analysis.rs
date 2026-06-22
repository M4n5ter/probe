use std::net::IpAddr;

use probe_core::{Direction, ProcessSelector, Selector, TrafficSelector};

use super::model::process_selector_has_constraints;
use super::{
    TransparentInterceptionFlowClassifierScope, TransparentInterceptionHostRuleBoundary,
    TransparentInterceptionHostRuleScope, TransparentInterceptionPortScope,
    TransparentInterceptionProcessScope, TransparentInterceptionProcessScopeExpression,
    TransparentInterceptionRemoteAddressScope, TransparentInterceptionSetupPlan,
    TransparentInterceptionSetupProjectionError,
};

const PROCESS_CLASSIFIER_REASON: &str = "selector contains process constraints that require a process classifier such as cgroup/owner marking or proxy-side process classification before host rules can be safely narrowed";
const ANY_NOT_FLOW_CLASSIFIER_REASON: &str = "any/not selectors require a flow-aware classifier and cannot be projected to setup-time host rules";
const REF_FLOW_CLASSIFIER_REASON: &str = "named selector refs require registry-backed classifier resolution before transparent interception setup";

impl TransparentInterceptionSetupPlan {
    pub fn from_inbound_tproxy_selector(
        selector: Option<&Selector>,
    ) -> Result<Self, TransparentInterceptionSetupProjectionError> {
        let Some(selector) = selector else {
            return Err(TransparentInterceptionSetupProjectionError::MissingSelector);
        };
        let analysis = analyze_selector(selector)?;
        let host_rule_boundary = host_rule_boundary_from_term(analysis.host_term)?;

        match analysis.classifier {
            Some(SetupClassifierRequirement::Flow { reason }) => Ok(Self::RequiresFlowClassifier {
                host_rule_boundary,
                flow_scope: TransparentInterceptionFlowClassifierScope::from_selector(selector),
                reason,
            }),
            Some(SetupClassifierRequirement::Process { expression }) => {
                Ok(Self::RequiresProcessClassifier {
                    host_rule_boundary,
                    process_scope: TransparentInterceptionProcessScope::new(expression)?,
                    reason: PROCESS_CLASSIFIER_REASON.to_string(),
                })
            }
            None => match host_rule_boundary {
                TransparentInterceptionHostRuleBoundary::Scope(scope) => Ok(Self::HostRules(scope)),
                TransparentInterceptionHostRuleBoundary::NoHostRuleBoundary => {
                    Err(TransparentInterceptionSetupProjectionError::UnconstrainedSelector)
                }
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SelectorSetupAnalysis {
    host_term: Option<ProjectableLocalSetupTerm>,
    classifier: Option<SetupClassifierRequirement>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SetupClassifierRequirement {
    Process {
        expression: TransparentInterceptionProcessScopeExpression,
    },
    Flow {
        reason: String,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ProjectableLocalSetupTerm {
    traffic: TrafficSelector,
}

impl ProjectableLocalSetupTerm {
    fn intersect(self, other: Self) -> Result<Self, TransparentInterceptionSetupProjectionError> {
        Ok(Self {
            traffic: intersect_traffic_selectors(self.traffic, other.traffic)?,
        })
    }
}

fn analyze_selector(
    selector: &Selector,
) -> Result<SelectorSetupAnalysis, TransparentInterceptionSetupProjectionError> {
    match selector {
        Selector::Match { term } => Ok(SelectorSetupAnalysis {
            host_term: Some(ProjectableLocalSetupTerm {
                traffic: term.traffic.clone(),
            }),
            classifier: process_classifier_requirement(&term.process),
        }),
        Selector::All { selectors } => analyze_all_selector(selectors),
        Selector::Any { selectors } => {
            if selectors.is_empty() {
                return Err(TransparentInterceptionSetupProjectionError::Unsupported {
                    reason: "any selector requires at least one child".to_string(),
                });
            }
            Ok(flow_classifier_analysis(
                ANY_NOT_FLOW_CLASSIFIER_REASON.to_string(),
            ))
        }
        Selector::Not { .. } => Ok(flow_classifier_analysis(
            ANY_NOT_FLOW_CLASSIFIER_REASON.to_string(),
        )),
        Selector::Ref { .. } => Ok(flow_classifier_analysis(
            REF_FLOW_CLASSIFIER_REASON.to_string(),
        )),
    }
}

fn analyze_all_selector(
    selectors: &[Selector],
) -> Result<SelectorSetupAnalysis, TransparentInterceptionSetupProjectionError> {
    if selectors.is_empty() {
        return Err(TransparentInterceptionSetupProjectionError::Unsupported {
            reason: "all selector requires at least one child".to_string(),
        });
    }

    let mut host_term = None;
    let mut process_expressions = Vec::new();
    let mut flow_reason = None;

    for selector in selectors {
        let analysis = analyze_selector(selector)?;
        host_term = intersect_projectable_terms(host_term, analysis.host_term)?;
        match analysis.classifier {
            Some(SetupClassifierRequirement::Flow { reason }) => {
                flow_reason.get_or_insert(reason);
            }
            Some(SetupClassifierRequirement::Process { expression }) => {
                process_expressions.push(expression);
            }
            None => {}
        }
    }

    let classifier = match flow_reason {
        Some(reason) => Some(SetupClassifierRequirement::Flow { reason }),
        None => process_classifier_requirement_from_expressions(process_expressions),
    };

    Ok(SelectorSetupAnalysis {
        host_term,
        classifier,
    })
}

fn flow_classifier_analysis(reason: String) -> SelectorSetupAnalysis {
    SelectorSetupAnalysis {
        host_term: None,
        classifier: Some(SetupClassifierRequirement::Flow { reason }),
    }
}

fn process_classifier_requirement(process: &ProcessSelector) -> Option<SetupClassifierRequirement> {
    process_selector_has_constraints(process).then(|| SetupClassifierRequirement::Process {
        expression: TransparentInterceptionProcessScopeExpression::Match {
            process: process.clone(),
        },
    })
}

fn process_classifier_requirement_from_expressions(
    expressions: Vec<TransparentInterceptionProcessScopeExpression>,
) -> Option<SetupClassifierRequirement> {
    match expressions.as_slice() {
        [] => None,
        [expression] => Some(SetupClassifierRequirement::Process {
            expression: expression.clone(),
        }),
        _ => Some(SetupClassifierRequirement::Process {
            expression: TransparentInterceptionProcessScopeExpression::All { expressions },
        }),
    }
}

fn host_rule_boundary_from_term(
    term: Option<ProjectableLocalSetupTerm>,
) -> Result<TransparentInterceptionHostRuleBoundary, TransparentInterceptionSetupProjectionError> {
    let Some(term) = term else {
        return Ok(TransparentInterceptionHostRuleBoundary::NoHostRuleBoundary);
    };
    match host_rule_scope_from_term(term) {
        Ok(scope) => Ok(TransparentInterceptionHostRuleBoundary::Scope(scope)),
        Err(TransparentInterceptionSetupProjectionError::UnconstrainedSelector) => {
            Ok(TransparentInterceptionHostRuleBoundary::NoHostRuleBoundary)
        }
        Err(error) => Err(error),
    }
}

fn host_rule_scope_from_term(
    term: ProjectableLocalSetupTerm,
) -> Result<TransparentInterceptionHostRuleScope, TransparentInterceptionSetupProjectionError> {
    validate_direction_projection(&term.traffic)?;
    TransparentInterceptionHostRuleScope::new(
        TransparentInterceptionPortScope::from_values(term.traffic.local_ports),
        TransparentInterceptionPortScope::from_values(term.traffic.remote_ports),
        parse_remote_addresses(&term.traffic.remote_addresses)?,
    )
}

fn intersect_projectable_terms(
    current: Option<ProjectableLocalSetupTerm>,
    next: Option<ProjectableLocalSetupTerm>,
) -> Result<Option<ProjectableLocalSetupTerm>, TransparentInterceptionSetupProjectionError> {
    let Some(next) = next else {
        return Ok(current);
    };
    match current {
        Some(current) => current.intersect(next).map(Some),
        None => Ok(Some(next)),
    }
}

fn intersect_traffic_selectors(
    left: TrafficSelector,
    right: TrafficSelector,
) -> Result<TrafficSelector, TransparentInterceptionSetupProjectionError> {
    Ok(TrafficSelector {
        local_ports: intersect_values(left.local_ports, right.local_ports)?,
        remote_ports: intersect_values(left.remote_ports, right.remote_ports)?,
        directions: intersect_values(left.directions, right.directions)?,
        remote_addresses: intersect_remote_addresses(
            left.remote_addresses,
            right.remote_addresses,
        )?,
    })
}

fn intersect_values<T>(
    left: Vec<T>,
    right: Vec<T>,
) -> Result<Vec<T>, TransparentInterceptionSetupProjectionError>
where
    T: Clone + Eq,
{
    match (left.is_empty(), right.is_empty()) {
        (true, true) => Ok(Vec::new()),
        (true, false) => Ok(right),
        (false, true) => Ok(left),
        (false, false) => {
            let mut values = Vec::new();
            for value in left {
                if right.contains(&value) && !values.contains(&value) {
                    values.push(value);
                }
            }
            if values.is_empty() {
                Err(TransparentInterceptionSetupProjectionError::Unsupported {
                    reason: "selector intersections do not overlap".to_string(),
                })
            } else {
                Ok(values)
            }
        }
    }
}

fn validate_direction_projection(
    traffic: &TrafficSelector,
) -> Result<(), TransparentInterceptionSetupProjectionError> {
    if traffic.directions.is_empty()
        || traffic
            .directions
            .iter()
            .all(|direction| *direction == Direction::Inbound)
    {
        Ok(())
    } else {
        Err(TransparentInterceptionSetupProjectionError::Unsupported {
            reason: "inbound TPROXY can only project Inbound traffic selectors".to_string(),
        })
    }
}

fn intersect_remote_addresses(
    left: Vec<String>,
    right: Vec<String>,
) -> Result<Vec<String>, TransparentInterceptionSetupProjectionError> {
    match (left.is_empty(), right.is_empty()) {
        (true, true) => Ok(Vec::new()),
        (true, false) => normalize_remote_addresses(&right),
        (false, true) => normalize_remote_addresses(&left),
        (false, false) => {
            let left = parse_ip_addresses(&left)?;
            let right = parse_ip_addresses(&right)?;
            let values = left
                .into_iter()
                .filter(|address| right.contains(address))
                .fold(Vec::new(), |mut values, address| {
                    if !values.contains(&address) {
                        values.push(address);
                    }
                    values
                });
            if values.is_empty() {
                Err(TransparentInterceptionSetupProjectionError::Unsupported {
                    reason: "selector remote address intersections do not overlap".to_string(),
                })
            } else {
                Ok(format_ip_addresses(values))
            }
        }
    }
}

fn parse_remote_addresses(
    addresses: &[String],
) -> Result<TransparentInterceptionRemoteAddressScope, TransparentInterceptionSetupProjectionError>
{
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    for address in parse_ip_addresses(addresses)? {
        match address {
            IpAddr::V4(address) => ipv4.push(address),
            IpAddr::V6(address) => ipv6.push(address),
        }
    }
    Ok(TransparentInterceptionRemoteAddressScope::new(ipv4, ipv6))
}

fn normalize_remote_addresses(
    addresses: &[String],
) -> Result<Vec<String>, TransparentInterceptionSetupProjectionError> {
    parse_ip_addresses(addresses).map(format_ip_addresses)
}

fn parse_ip_addresses(
    addresses: &[String],
) -> Result<Vec<IpAddr>, TransparentInterceptionSetupProjectionError> {
    addresses
        .iter()
        .map(|address| {
            address.parse::<IpAddr>().map_err(|error| {
                TransparentInterceptionSetupProjectionError::Unsupported {
                    reason: format!(
                        "remote address {address:?} is not a valid IP address: {error}"
                    ),
                }
            })
        })
        .collect()
}

fn format_ip_addresses(addresses: Vec<IpAddr>) -> Vec<String> {
    addresses
        .into_iter()
        .map(|address| address.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::super::TransparentInterceptionClassifierSelector;
    use super::*;

    #[test]
    fn projects_inbound_host_rule_scope() {
        let scope = scope_for(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                local_ports: vec![8443],
                directions: vec![Direction::Inbound],
                remote_addresses: vec!["203.0.113.10".to_string()],
                ..TrafficSelector::default()
            },
        ))
        .expect("selector should project");

        assert_eq!(scope.local_ports().values(), &[8443]);
        assert_eq!(
            scope.remote_addresses().ipv4(),
            &[Ipv4Addr::new(203, 0, 113, 10)]
        );
        assert!(scope.remote_addresses().ipv6().is_empty());
    }

    #[test]
    fn setup_plan_preserves_all_process_scope_without_flattening_globs() {
        let plan =
            TransparentInterceptionSetupPlan::from_inbound_tproxy_selector(Some(&Selector::All {
                selectors: vec![
                    Selector::term(
                        ProcessSelector {
                            exe_path_globs: vec!["/usr/bin/*".to_string()],
                            ..ProcessSelector::default()
                        },
                        TrafficSelector::default(),
                    ),
                    Selector::term(
                        ProcessSelector {
                            exe_path_globs: vec!["/usr/bin/curl".to_string()],
                            ..ProcessSelector::default()
                        },
                        TrafficSelector::default(),
                    ),
                ],
            }))
            .expect("process-only all selector should produce a classifier setup plan");

        let TransparentInterceptionSetupPlan::RequiresProcessClassifier {
            host_rule_boundary,
            process_scope,
            ..
        } = plan
        else {
            panic!("process-scoped setup should require a process classifier");
        };
        assert!(matches!(
            host_rule_boundary,
            TransparentInterceptionHostRuleBoundary::NoHostRuleBoundary
        ));
        let TransparentInterceptionProcessScopeExpression::All { expressions } =
            process_scope.expression()
        else {
            panic!("process all scope should remain an all expression");
        };
        assert_eq!(expressions.len(), 2);
    }

    #[test]
    fn setup_plan_preserves_all_process_scope_and_traffic_boundary() {
        let plan =
            TransparentInterceptionSetupPlan::from_inbound_tproxy_selector(Some(&Selector::All {
                selectors: vec![
                    Selector::term(
                        ProcessSelector {
                            exe_path_globs: vec!["/usr/bin/*".to_string()],
                            ..ProcessSelector::default()
                        },
                        TrafficSelector {
                            local_ports: vec![8443],
                            ..TrafficSelector::default()
                        },
                    ),
                    Selector::term(
                        ProcessSelector {
                            exe_path_globs: vec!["/usr/bin/curl".to_string()],
                            ..ProcessSelector::default()
                        },
                        TrafficSelector {
                            directions: vec![Direction::Inbound],
                            ..TrafficSelector::default()
                        },
                    ),
                ],
            }))
            .expect("process-scoped all selector should produce a classifier setup plan");

        let TransparentInterceptionSetupPlan::RequiresProcessClassifier {
            host_rule_boundary,
            process_scope,
            ..
        } = plan
        else {
            panic!("process-scoped setup should require a process classifier");
        };
        let Some(host_rule_scope) = host_rule_boundary.scope() else {
            panic!("traffic selector should preserve a host-rule boundary");
        };
        assert_eq!(host_rule_scope.local_ports().values(), &[8443]);
        assert!(matches!(
            process_scope.expression(),
            TransparentInterceptionProcessScopeExpression::All { .. }
        ));
    }

    #[test]
    fn setup_plan_preserves_process_only_classifier_requirement() {
        let plan =
            TransparentInterceptionSetupPlan::from_inbound_tproxy_selector(Some(&Selector::term(
                ProcessSelector {
                    names: vec!["curl".to_string()],
                    ..ProcessSelector::default()
                },
                TrafficSelector {
                    directions: vec![Direction::Inbound],
                    ..TrafficSelector::default()
                },
            )))
            .expect("process-only selector should produce a classifier plan");

        let TransparentInterceptionSetupPlan::RequiresProcessClassifier {
            host_rule_boundary,
            process_scope,
            ..
        } = plan
        else {
            panic!("process-only setup should require a process classifier");
        };
        assert!(matches!(
            host_rule_boundary,
            TransparentInterceptionHostRuleBoundary::NoHostRuleBoundary
        ));
        assert_eq!(process_scope_names(&process_scope), ["curl"]);
    }

    #[test]
    fn setup_plan_preserves_process_scoped_host_rule_boundary() {
        let plan =
            TransparentInterceptionSetupPlan::from_inbound_tproxy_selector(Some(&Selector::term(
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
            )))
            .expect("process-scoped traffic selector should produce a classifier plan");

        let TransparentInterceptionSetupPlan::RequiresProcessClassifier {
            host_rule_boundary,
            process_scope,
            ..
        } = plan
        else {
            panic!("process-scoped setup should require a process classifier");
        };
        let Some(host_rule_scope) = host_rule_boundary.scope() else {
            panic!("traffic selector should preserve host-rule boundary");
        };
        assert_eq!(host_rule_scope.local_ports().values(), &[8443]);
        assert_eq!(
            host_rule_scope.remote_addresses().ipv4(),
            &[Ipv4Addr::new(203, 0, 113, 10)]
        );
        assert_eq!(process_scope_names(&process_scope), ["curl"]);
    }

    #[test]
    fn any_selector_reports_flow_classifier_requirement() {
        let plan =
            TransparentInterceptionSetupPlan::from_inbound_tproxy_selector(Some(&Selector::Any {
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
            }))
            .expect("any selector should produce a flow classifier setup plan");

        let TransparentInterceptionSetupPlan::RequiresFlowClassifier { flow_scope, .. } = plan
        else {
            panic!("any selector should require a flow classifier");
        };
        assert!(matches!(
            flow_scope.selector(),
            TransparentInterceptionClassifierSelector::Any { .. }
        ));
    }

    #[test]
    fn flow_classifier_requirement_preserves_host_rule_boundary() {
        let plan =
            TransparentInterceptionSetupPlan::from_inbound_tproxy_selector(Some(&Selector::All {
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
                        selectors: vec![Selector::term(
                            ProcessSelector::default(),
                            TrafficSelector {
                                remote_ports: vec![443],
                                ..TrafficSelector::default()
                            },
                        )],
                    },
                ],
            }))
            .expect("flow-aware selector should produce a classifier setup plan");

        let TransparentInterceptionSetupPlan::RequiresFlowClassifier {
            host_rule_boundary, ..
        } = plan
        else {
            panic!("flow-aware setup should require a flow classifier");
        };
        let Some(host_rule_scope) = host_rule_boundary.scope() else {
            panic!("traffic selector should preserve host-rule boundary");
        };
        assert_eq!(host_rule_scope.local_ports().values(), &[8443]);
    }

    #[test]
    fn empty_any_selector_is_unsupported() {
        let error =
            TransparentInterceptionSetupPlan::from_inbound_tproxy_selector(Some(&Selector::Any {
                selectors: Vec::new(),
            }))
            .expect_err("empty any selector is invalid setup input");

        assert!(matches!(
            error,
            TransparentInterceptionSetupProjectionError::Unsupported { .. }
        ));
    }

    #[test]
    fn wrong_direction_is_unsupported() {
        let error = scope_for(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                local_ports: vec![8443],
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
        ))
        .expect_err("wrong direction should not project");

        assert!(matches!(
            error,
            TransparentInterceptionSetupProjectionError::Unsupported { .. }
        ));
    }

    #[test]
    fn disjoint_all_selector_is_unsupported() {
        let error = scope_for(Selector::All {
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
        })
        .expect_err("disjoint selector should not project");

        assert!(matches!(
            error,
            TransparentInterceptionSetupProjectionError::Unsupported { .. }
        ));
    }

    #[test]
    fn remote_address_intersection_uses_ip_value() {
        let scope = scope_for(Selector::All {
            selectors: vec![
                Selector::term(
                    ProcessSelector::default(),
                    TrafficSelector {
                        local_ports: vec![8443],
                        remote_addresses: vec!["2001:0db8::1".to_string()],
                        ..TrafficSelector::default()
                    },
                ),
                Selector::term(
                    ProcessSelector::default(),
                    TrafficSelector {
                        local_ports: vec![8443],
                        remote_addresses: vec!["2001:db8::1".to_string()],
                        ..TrafficSelector::default()
                    },
                ),
            ],
        })
        .expect("equivalent IP address text should intersect");

        assert_eq!(
            scope.remote_addresses().ipv6(),
            &[Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)]
        );
    }

    #[test]
    fn invalid_remote_address_is_unsupported() {
        let error = scope_for(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                remote_addresses: vec!["not an ip".to_string()],
                ..TrafficSelector::default()
            },
        ))
        .expect_err("invalid remote address should not project");

        assert!(matches!(
            error,
            TransparentInterceptionSetupProjectionError::Unsupported { .. }
        ));
    }

    #[test]
    fn checked_constructor_rejects_empty_host_rule_scope() {
        let error = TransparentInterceptionHostRuleScope::new(
            TransparentInterceptionPortScope::any(),
            TransparentInterceptionPortScope::any(),
            TransparentInterceptionRemoteAddressScope::empty(),
        )
        .expect_err("empty host-rule scope would render broad host rules");

        assert!(matches!(
            error,
            TransparentInterceptionSetupProjectionError::UnconstrainedSelector
        ));
    }

    fn scope_for(
        selector: Selector,
    ) -> Result<TransparentInterceptionHostRuleScope, TransparentInterceptionSetupProjectionError>
    {
        match TransparentInterceptionSetupPlan::from_inbound_tproxy_selector(Some(&selector))? {
            TransparentInterceptionSetupPlan::HostRules(scope) => Ok(scope),
            TransparentInterceptionSetupPlan::RequiresProcessClassifier { reason, .. }
            | TransparentInterceptionSetupPlan::RequiresFlowClassifier { reason, .. } => {
                Err(TransparentInterceptionSetupProjectionError::Unsupported { reason })
            }
        }
    }

    fn process_scope_names(scope: &TransparentInterceptionProcessScope) -> Vec<&str> {
        let TransparentInterceptionProcessScopeExpression::Match { process } = scope.expression()
        else {
            panic!("test process scope should be a match expression");
        };
        process.names.iter().map(String::as_str).collect()
    }
}
