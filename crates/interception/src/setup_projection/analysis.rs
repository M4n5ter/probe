use std::net::IpAddr;

use probe_core::{Direction, ProcessSelector, Selector, TrafficSelector};

use super::model::process_selector_has_constraints;
use super::{
    TransparentInterceptionFlowClassifierScope, TransparentInterceptionHostRuleBoundary,
    TransparentInterceptionHostRuleScope, TransparentInterceptionPortScope,
    TransparentInterceptionProcessScope, TransparentInterceptionProcessScopeExpression,
    TransparentInterceptionRemoteAddressScope, TransparentInterceptionSetupDirection,
    TransparentInterceptionSetupPlan, TransparentInterceptionSetupProjectionError,
};

const PROCESS_CLASSIFIER_REASON: &str = "selector contains process constraints that require a process classifier such as cgroup/owner marking or proxy-side process classification before host rules can be safely narrowed";
const ANY_FLOW_CLASSIFIER_REASON: &str = "any selectors that cannot be represented as one setup-time host-rule scope require a flow-aware classifier";
const NOT_FLOW_CLASSIFIER_REASON: &str = "not selectors require a flow-aware classifier and cannot be projected to setup-time host rules";
const REF_FLOW_CLASSIFIER_REASON: &str = "named selector refs require registry-backed classifier resolution before transparent interception setup";

impl TransparentInterceptionSetupPlan {
    pub fn from_inbound_tproxy_selector(
        selector: Option<&Selector>,
    ) -> Result<Self, TransparentInterceptionSetupProjectionError> {
        Self::from_selector(selector, TransparentInterceptionSetupDirection::Inbound)
    }

    pub fn from_outbound_mitm_selector(
        selector: Option<&Selector>,
    ) -> Result<Self, TransparentInterceptionSetupProjectionError> {
        Self::from_selector(selector, TransparentInterceptionSetupDirection::Outbound)
    }

    fn from_selector(
        selector: Option<&Selector>,
        direction: TransparentInterceptionSetupDirection,
    ) -> Result<Self, TransparentInterceptionSetupProjectionError> {
        let Some(selector) = selector else {
            return Err(TransparentInterceptionSetupProjectionError::MissingSelector);
        };
        let analysis = analyze_selector(selector, direction)?;
        let host_rule_boundary = host_rule_boundary_from_term(analysis.host_term, direction)?;

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

    fn from_scope(
        scope: TransparentInterceptionHostRuleScope,
        direction: TransparentInterceptionSetupDirection,
    ) -> Self {
        Self {
            traffic: scope.to_traffic_selector(direction),
        }
    }
}

fn analyze_selector(
    selector: &Selector,
    direction: TransparentInterceptionSetupDirection,
) -> Result<SelectorSetupAnalysis, TransparentInterceptionSetupProjectionError> {
    match selector {
        Selector::Match { term } => {
            validate_traffic_selector(&term.traffic, direction)?;
            Ok(SelectorSetupAnalysis {
                host_term: Some(ProjectableLocalSetupTerm {
                    traffic: term.traffic.clone(),
                }),
                classifier: process_classifier_requirement(&term.process),
            })
        }
        Selector::All { selectors } => analyze_all_selector(selectors, direction),
        Selector::Any { selectors } => analyze_any_selector(selectors, direction),
        Selector::Not { .. } => Ok(flow_classifier_analysis(
            NOT_FLOW_CLASSIFIER_REASON.to_string(),
        )),
        Selector::Ref { .. } => Ok(flow_classifier_analysis(
            REF_FLOW_CLASSIFIER_REASON.to_string(),
        )),
    }
}

fn analyze_any_selector(
    selectors: &[Selector],
    direction: TransparentInterceptionSetupDirection,
) -> Result<SelectorSetupAnalysis, TransparentInterceptionSetupProjectionError> {
    if selectors.is_empty() {
        return Err(TransparentInterceptionSetupProjectionError::Unsupported {
            reason: "any selector requires at least one child".to_string(),
        });
    }

    let analyses = selectors
        .iter()
        .map(|selector| analyze_selector(selector, direction))
        .collect::<Result<Vec<_>, _>>()?;
    match project_any_selector_host_term(&analyses, direction)? {
        Some(host_term) => Ok(SelectorSetupAnalysis {
            host_term: Some(host_term),
            classifier: None,
        }),
        None => Ok(flow_classifier_analysis(
            ANY_FLOW_CLASSIFIER_REASON.to_string(),
        )),
    }
}

fn analyze_all_selector(
    selectors: &[Selector],
    direction: TransparentInterceptionSetupDirection,
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
        let analysis = analyze_selector(selector, direction)?;
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

fn project_any_selector_host_term(
    analyses: &[SelectorSetupAnalysis],
    direction: TransparentInterceptionSetupDirection,
) -> Result<Option<ProjectableLocalSetupTerm>, TransparentInterceptionSetupProjectionError> {
    if analyses
        .iter()
        .any(|analysis| analysis.classifier.is_some() || analysis.host_term.is_none())
    {
        return Ok(None);
    }

    let mut scopes = Vec::new();
    for analysis in analyses {
        let Some(scope) = optional_host_rule_scope_for_any_branch(
            analysis
                .host_term
                .clone()
                .expect("host term presence checked above"),
            direction,
        )?
        else {
            return Ok(None);
        };
        scopes.push(scope);
    }
    Ok(
        TransparentInterceptionHostRuleScope::union_without_expansion(&scopes)
            .map(|scope| ProjectableLocalSetupTerm::from_scope(scope, direction)),
    )
}

fn optional_host_rule_scope_for_any_branch(
    term: ProjectableLocalSetupTerm,
    direction: TransparentInterceptionSetupDirection,
) -> Result<Option<TransparentInterceptionHostRuleScope>, TransparentInterceptionSetupProjectionError>
{
    match host_rule_scope_from_term(term, direction) {
        Ok(scope) => Ok(Some(scope)),
        Err(TransparentInterceptionSetupProjectionError::UnconstrainedSelector) => Ok(None),
        Err(error) => Err(error),
    }
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
    direction: TransparentInterceptionSetupDirection,
) -> Result<TransparentInterceptionHostRuleBoundary, TransparentInterceptionSetupProjectionError> {
    let Some(term) = term else {
        return Ok(TransparentInterceptionHostRuleBoundary::NoHostRuleBoundary);
    };
    match host_rule_scope_from_term(term, direction) {
        Ok(scope) => Ok(TransparentInterceptionHostRuleBoundary::Scope(scope)),
        Err(TransparentInterceptionSetupProjectionError::UnconstrainedSelector) => {
            Ok(TransparentInterceptionHostRuleBoundary::NoHostRuleBoundary)
        }
        Err(error) => Err(error),
    }
}

fn host_rule_scope_from_term(
    term: ProjectableLocalSetupTerm,
    direction: TransparentInterceptionSetupDirection,
) -> Result<TransparentInterceptionHostRuleScope, TransparentInterceptionSetupProjectionError> {
    validate_direction_projection(&term.traffic, direction)?;
    TransparentInterceptionHostRuleScope::new(
        TransparentInterceptionPortScope::from_values(term.traffic.local_ports),
        TransparentInterceptionPortScope::from_values(term.traffic.remote_ports),
        parse_remote_addresses(&term.traffic.remote_addresses)?,
    )
}

fn validate_traffic_selector(
    traffic: &TrafficSelector,
    direction: TransparentInterceptionSetupDirection,
) -> Result<(), TransparentInterceptionSetupProjectionError> {
    validate_direction_projection(traffic, direction)?;
    parse_ip_addresses(&traffic.remote_addresses).map(|_| ())
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
    direction: TransparentInterceptionSetupDirection,
) -> Result<(), TransparentInterceptionSetupProjectionError> {
    let expected = Direction::from(direction);
    if traffic.directions.is_empty()
        || traffic
            .directions
            .iter()
            .all(|selected| *selected == expected)
    {
        Ok(())
    } else {
        Err(TransparentInterceptionSetupProjectionError::Unsupported {
            reason: direction.wrong_direction_reason().to_string(),
        })
    }
}

impl TransparentInterceptionSetupDirection {
    fn wrong_direction_reason(self) -> &'static str {
        match self {
            Self::Inbound => "inbound TPROXY can only project Inbound traffic selectors",
            Self::Outbound => "outbound MITM can only project Outbound traffic selectors",
        }
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
        let scope = scope_for(term(inbound_local_port_addresses(8443, &["203.0.113.10"])))
            .expect("selector should project");

        assert_eq!(scope.local_ports().values(), &[8443]);
        assert_eq!(
            scope.remote_addresses().ipv4(),
            &[Ipv4Addr::new(203, 0, 113, 10)]
        );
        assert!(scope.remote_addresses().ipv6().is_empty());
    }

    #[test]
    fn projects_outbound_host_rule_scope() {
        let scope =
            outbound_scope_for(term(outbound_remote_port_addresses(443, &["203.0.113.10"])))
                .expect("selector should project");

        assert_eq!(scope.remote_ports().values(), &[443]);
        assert_eq!(
            scope.remote_addresses().ipv4(),
            &[Ipv4Addr::new(203, 0, 113, 10)]
        );
        assert!(scope.remote_addresses().ipv6().is_empty());
    }

    #[test]
    fn setup_plan_preserves_all_process_scope_without_flattening_globs() {
        let plan = plan_for(Selector::All {
            selectors: vec![
                Selector::term(process_globs(&["/usr/bin/*"]), TrafficSelector::default()),
                Selector::term(
                    process_globs(&["/usr/bin/curl"]),
                    TrafficSelector::default(),
                ),
            ],
        })
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
        let plan = plan_for(Selector::All {
            selectors: vec![
                Selector::term(process_globs(&["/usr/bin/*"]), local_port(8443)),
                Selector::term(process_globs(&["/usr/bin/curl"]), inbound_traffic()),
            ],
        })
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
        let plan = plan_for(Selector::term(process_names(&["curl"]), inbound_traffic()))
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
        let plan = plan_for(Selector::term(
            process_names(&["curl"]),
            inbound_local_port_addresses(8443, &["203.0.113.10"]),
        ))
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
    fn any_selector_projects_single_host_rule_dimension() {
        let plan = plan_for(Selector::Any {
            selectors: vec![
                term(local_port_addresses(
                    8443,
                    &["203.0.113.10", "203.0.113.20"],
                )),
                term(local_port_addresses(
                    9443,
                    &["203.0.113.20", "203.0.113.10"],
                )),
            ],
        })
        .expect("single-dimension any selector should project to host rules");

        let TransparentInterceptionSetupPlan::HostRules(scope) = plan else {
            panic!("single-dimension any selector should not require a flow classifier");
        };
        assert_eq!(scope.local_ports().values(), &[8443, 9443]);
        assert!(scope.remote_ports().is_any());
        assert_eq!(
            scope.remote_addresses().ipv4(),
            &[
                Ipv4Addr::new(203, 0, 113, 10),
                Ipv4Addr::new(203, 0, 113, 20)
            ]
        );
    }

    #[test]
    fn any_selector_with_cross_product_risk_reports_flow_classifier_requirement() {
        let plan = plan_for(Selector::Any {
            selectors: vec![
                term(local_port_addresses(8443, &["203.0.113.10"])),
                term(local_port_addresses(9443, &["203.0.113.20"])),
            ],
        })
        .expect("cross-product any selector should produce a flow classifier setup plan");

        let TransparentInterceptionSetupPlan::RequiresFlowClassifier { flow_scope, .. } = plan
        else {
            panic!("cross-product any selector should require a flow classifier");
        };
        assert!(matches!(
            flow_scope.selector(),
            TransparentInterceptionClassifierSelector::Any { .. }
        ));
    }

    #[test]
    fn process_scoped_any_selector_reports_flow_classifier_requirement() {
        let plan = plan_for(Selector::Any {
            selectors: vec![
                Selector::term(process_names(&["curl"]), local_port(8443)),
                Selector::term(process_names(&["nginx"]), local_port(9443)),
            ],
        })
        .expect("process-scoped any selector should produce a classifier setup plan");

        let TransparentInterceptionSetupPlan::RequiresFlowClassifier { flow_scope, .. } = plan
        else {
            panic!("process-scoped any selector should require a flow classifier");
        };
        assert!(matches!(
            flow_scope.selector(),
            TransparentInterceptionClassifierSelector::Any { .. }
        ));
    }

    #[test]
    fn flow_classifier_requirement_preserves_host_rule_boundary() {
        let plan = plan_for(Selector::All {
            selectors: vec![
                term(inbound_local_port(8443)),
                Selector::Any {
                    selectors: vec![
                        term(remote_port_addresses(443, &["203.0.113.10"])),
                        term(remote_port_addresses(444, &["203.0.113.20"])),
                    ],
                },
            ],
        })
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
        let error = scope_for(term(outbound_local_port(8443)))
            .expect_err("wrong direction should not project");

        assert!(matches!(
            error,
            TransparentInterceptionSetupProjectionError::Unsupported { .. }
        ));

        let error = plan_for(Selector::Any {
            selectors: vec![term(outbound_local_port(8443))],
        })
        .expect_err("wrong direction in any should not become a classifier requirement");

        assert!(matches!(
            error,
            TransparentInterceptionSetupProjectionError::Unsupported { .. }
        ));

        let error = plan_for(Selector::Any {
            selectors: vec![
                Selector::term(process_names(&["curl"]), outbound_local_port(8443)),
                Selector::Ref {
                    name: "external".to_string(),
                },
            ],
        })
        .expect_err("classifier-bearing wrong direction should remain unsupported");

        assert!(matches!(
            error,
            TransparentInterceptionSetupProjectionError::Unsupported { .. }
        ));

        let error = outbound_scope_for(term(inbound_local_port(8443)))
            .expect_err("wrong direction should not project to outbound");

        assert!(matches!(
            error,
            TransparentInterceptionSetupProjectionError::Unsupported { .. }
        ));
    }

    #[test]
    fn disjoint_all_selector_is_unsupported() {
        let error = scope_for(Selector::All {
            selectors: vec![term(local_port(8443)), term(local_port(9443))],
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
                term(local_port_addresses(8443, &["2001:0db8::1"])),
                term(local_port_addresses(8443, &["2001:db8::1"])),
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
        let error = scope_for(term(TrafficSelector {
            remote_addresses: strings(&["not an ip"]),
            ..TrafficSelector::default()
        }))
        .expect_err("invalid remote address should not project");

        assert!(matches!(
            error,
            TransparentInterceptionSetupProjectionError::Unsupported { .. }
        ));
    }

    #[test]
    fn invalid_any_child_remote_address_is_unsupported() {
        let error = plan_for(Selector::Any {
            selectors: vec![term(local_port_addresses(8443, &["not an ip"]))],
        })
        .expect_err("invalid any child remote address should not become a classifier requirement");

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
        scope_from_plan(plan_for(selector)?)
    }

    fn outbound_scope_for(
        selector: Selector,
    ) -> Result<TransparentInterceptionHostRuleScope, TransparentInterceptionSetupProjectionError>
    {
        scope_from_plan(outbound_plan_for(selector)?)
    }

    fn scope_from_plan(
        plan: TransparentInterceptionSetupPlan,
    ) -> Result<TransparentInterceptionHostRuleScope, TransparentInterceptionSetupProjectionError>
    {
        match plan {
            TransparentInterceptionSetupPlan::HostRules(scope) => Ok(scope),
            TransparentInterceptionSetupPlan::RequiresProcessClassifier { reason, .. }
            | TransparentInterceptionSetupPlan::RequiresFlowClassifier { reason, .. } => {
                Err(TransparentInterceptionSetupProjectionError::Unsupported { reason })
            }
        }
    }

    fn plan_for(
        selector: Selector,
    ) -> Result<TransparentInterceptionSetupPlan, TransparentInterceptionSetupProjectionError> {
        TransparentInterceptionSetupPlan::from_inbound_tproxy_selector(Some(&selector))
    }

    fn outbound_plan_for(
        selector: Selector,
    ) -> Result<TransparentInterceptionSetupPlan, TransparentInterceptionSetupProjectionError> {
        TransparentInterceptionSetupPlan::from_outbound_mitm_selector(Some(&selector))
    }

    fn term(traffic: TrafficSelector) -> Selector {
        Selector::term(ProcessSelector::default(), traffic)
    }

    fn local_port(port: u16) -> TrafficSelector {
        TrafficSelector {
            local_ports: vec![port],
            ..TrafficSelector::default()
        }
    }

    fn inbound_traffic() -> TrafficSelector {
        TrafficSelector {
            directions: vec![Direction::Inbound],
            ..TrafficSelector::default()
        }
    }

    fn inbound_local_port(port: u16) -> TrafficSelector {
        TrafficSelector {
            directions: vec![Direction::Inbound],
            ..local_port(port)
        }
    }

    fn outbound_local_port(port: u16) -> TrafficSelector {
        TrafficSelector {
            directions: vec![Direction::Outbound],
            ..local_port(port)
        }
    }

    fn local_port_addresses(port: u16, addresses: &[&str]) -> TrafficSelector {
        TrafficSelector {
            remote_addresses: strings(addresses),
            ..local_port(port)
        }
    }

    fn inbound_local_port_addresses(port: u16, addresses: &[&str]) -> TrafficSelector {
        TrafficSelector {
            directions: vec![Direction::Inbound],
            ..local_port_addresses(port, addresses)
        }
    }

    fn remote_port_addresses(port: u16, addresses: &[&str]) -> TrafficSelector {
        TrafficSelector {
            remote_ports: vec![port],
            remote_addresses: strings(addresses),
            ..TrafficSelector::default()
        }
    }

    fn outbound_remote_port_addresses(port: u16, addresses: &[&str]) -> TrafficSelector {
        TrafficSelector {
            directions: vec![Direction::Outbound],
            ..remote_port_addresses(port, addresses)
        }
    }

    fn process_names(names: &[&str]) -> ProcessSelector {
        ProcessSelector {
            names: strings(names),
            ..ProcessSelector::default()
        }
    }

    fn process_globs(globs: &[&str]) -> ProcessSelector {
        ProcessSelector {
            exe_path_globs: strings(globs),
            ..ProcessSelector::default()
        }
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn process_scope_names(scope: &TransparentInterceptionProcessScope) -> Vec<&str> {
        let TransparentInterceptionProcessScopeExpression::Match { process } = scope.expression()
        else {
            panic!("test process scope should be a match expression");
        };
        process.names.iter().map(String::as_str).collect()
    }
}
