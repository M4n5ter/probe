mod error;
mod flow_classifier;
mod ip_family;
mod nftables;
mod process_classifier;
mod proxy;
mod runtime;

use ::runtime::{
    TransparentInterceptionClassificationPlan, TransparentInterceptionExecutionPlan,
    TransparentInterceptionOutboundProxyPlan,
};
use interception::{
    TransparentInterceptionFlowClassifierScope, TransparentInterceptionHostRuleBoundary,
    TransparentInterceptionSetupDirection, TransparentInterceptionSetupPlan,
    TransparentInterceptionSetupProjectionError, TransparentInterceptionSetupSelectors,
};
use probe_config::{TransparentInterceptionProxyModeConfig, TransparentInterceptionStrategyConfig};
use probe_core::{CapabilityState, RuntimeMode};

pub(crate) use error::TransparentInterceptionError;
pub(crate) use flow_classifier::TransparentInterceptionFlowClassifier;
pub(crate) use ip_family::TransparentInterceptionIpFamily;
pub(crate) use process_classifier::TransparentInterceptionProcessClassifier;
use proxy::TransparentProxyRuntime;
pub(crate) use proxy::{
    TransparentProxyHealthProbeMode, TransparentProxyRuntimeHandle, TransparentProxyRuntimeMode,
    TransparentProxyRuntimeSnapshot,
};
pub(crate) use runtime::{
    TransparentInterceptionActivationScope, TransparentInterceptionGuard,
    TransparentInterceptionRuntime,
};

const MISSING_LOCAL_SETUP_SELECTOR: &str =
    "transparent interception requires an explicit local selector for setup-time rules";

pub(crate) fn unavailable_for_config_error(
    error: impl Into<String>,
) -> TransparentInterceptionRuntime {
    TransparentInterceptionRuntime::unavailable(error.into(), TransparentProxyRuntime::disabled())
}

pub(crate) fn resolve(
    execution_plan: TransparentInterceptionExecutionPlan,
) -> TransparentInterceptionRuntime {
    let proxy_runtime = TransparentProxyRuntime::for_execution_plan(&execution_plan);
    match execution_plan {
        TransparentInterceptionExecutionPlan::Disabled => {
            TransparentInterceptionRuntime::unavailable(
                "transparent interception backend is not configured",
                proxy_runtime,
            )
        }
        TransparentInterceptionExecutionPlan::InboundTproxy(inbound_plan) => {
            nftables::resolve(inbound_plan, proxy_runtime)
        }
        TransparentInterceptionExecutionPlan::OutboundTransparentProxy(outbound_plan) => {
            nftables::resolve_outbound(outbound_plan, proxy_runtime)
        }
    }
}

pub(crate) fn effective_setup_scope(
    execution_plan: &TransparentInterceptionExecutionPlan,
    classification: &TransparentInterceptionClassificationPlan,
    process_classifier: &mut TransparentInterceptionProcessClassifier,
    selectors: TransparentInterceptionSetupSelectors,
) -> Result<Option<TransparentInterceptionActivationScope>, TransparentInterceptionError> {
    if execution_plan.strategy() == TransparentInterceptionStrategyConfig::None {
        return Ok(None);
    }
    if !selectors.local_config_scope_configured() {
        return Err(TransparentInterceptionError::Setup(
            MISSING_LOCAL_SETUP_SELECTOR.to_string(),
        ));
    }
    match execution_plan {
        TransparentInterceptionExecutionPlan::Disabled => Ok(None),
        TransparentInterceptionExecutionPlan::InboundTproxy(inbound_plan) => {
            inbound_tproxy_effective_setup_scope(
                inbound_plan,
                classification,
                process_classifier,
                selectors,
            )
        }
        TransparentInterceptionExecutionPlan::OutboundTransparentProxy(outbound_plan) => {
            validate_outbound_redirect_setup_scope(outbound_plan, classification, selectors)
                .map(Some)
        }
    }
}

fn inbound_tproxy_effective_setup_scope(
    inbound_plan: &::runtime::TransparentInterceptionInboundTproxyPlan,
    classification: &TransparentInterceptionClassificationPlan,
    process_classifier: &mut TransparentInterceptionProcessClassifier,
    selectors: TransparentInterceptionSetupSelectors,
) -> Result<Option<TransparentInterceptionActivationScope>, TransparentInterceptionError> {
    validate_local_setup_plan(
        selectors.local_setup_plan(TransparentInterceptionSetupDirection::Inbound),
    )?;
    let scope = executable_host_rule_scope(
        selectors.final_setup_plan(TransparentInterceptionSetupDirection::Inbound),
        classification,
        process_classifier,
        inbound_plan.proxy_mode(),
    )?;
    nftables::validate_inbound_tproxy_setup_scope(inbound_plan, scope.setup_rules())?;
    Ok(Some(scope))
}

fn validate_outbound_redirect_setup_scope(
    outbound_plan: &TransparentInterceptionOutboundProxyPlan,
    classification: &TransparentInterceptionClassificationPlan,
    selectors: TransparentInterceptionSetupSelectors,
) -> Result<TransparentInterceptionActivationScope, TransparentInterceptionError> {
    validate_local_setup_plan(
        selectors.local_setup_plan(TransparentInterceptionSetupDirection::Outbound),
    )?;
    match selectors.final_setup_plan(TransparentInterceptionSetupDirection::Outbound) {
        Ok(TransparentInterceptionSetupPlan::HostRules(rules)) => {
            nftables::validate_outbound_redirect_setup_scope(outbound_plan, &rules)?;
            Ok(TransparentInterceptionActivationScope::host_rules(rules))
        }
        Ok(TransparentInterceptionSetupPlan::RequiresProcessClassifier { reason, .. }) => {
            Err(TransparentInterceptionError::Setup(format!(
                "{reason}; {}",
                outbound_transparent_proxy_classifier_unavailable()
            )))
        }
        Ok(TransparentInterceptionSetupPlan::RequiresFlowClassifier {
            host_rule_boundary,
            flow_scope,
            reason,
        }) => flow_classifier_activation_scope(
            reason,
            host_rule_boundary,
            flow_scope,
            classification,
            outbound_plan.proxy_mode(),
        )
        .and_then(|scope| {
            nftables::validate_outbound_redirect_setup_scope(outbound_plan, scope.setup_rules())?;
            Ok(scope)
        }),
        Err(error) => Err(TransparentInterceptionError::Setup(error.to_string())),
    }
}

fn outbound_transparent_proxy_classifier_unavailable() -> String {
    format!(
        "outbound transparent proxy requires host-rule setup rules before rule installation; existing {}, proxy upstream SO_MARK, and agent control-plane SO_MARK only make host-rule OUTPUT redirect executable",
        proxy::outbound_original_destination_recovery_name()
    )
}

fn validate_local_setup_plan(
    plan: Result<TransparentInterceptionSetupPlan, TransparentInterceptionSetupProjectionError>,
) -> Result<(), TransparentInterceptionError> {
    match plan {
        Ok(_) => Ok(()),
        Err(error) => Err(TransparentInterceptionError::Setup(error.to_string())),
    }
}

fn executable_host_rule_scope(
    plan: Result<TransparentInterceptionSetupPlan, TransparentInterceptionSetupProjectionError>,
    classification: &TransparentInterceptionClassificationPlan,
    process_classifier: &mut TransparentInterceptionProcessClassifier,
    proxy_mode: TransparentInterceptionProxyModeConfig,
) -> Result<TransparentInterceptionActivationScope, TransparentInterceptionError> {
    match plan {
        Ok(TransparentInterceptionSetupPlan::HostRules(rules)) => {
            Ok(TransparentInterceptionActivationScope::host_rules(rules))
        }
        Ok(TransparentInterceptionSetupPlan::RequiresProcessClassifier {
            host_rule_boundary,
            process_scope,
            reason,
        }) => process_classifier
            .executable_host_rule_scope(
                reason,
                host_rule_boundary,
                process_scope.as_ref().clone(),
                &classification.process_classifier,
            )
            .map(TransparentInterceptionActivationScope::host_rules),
        Ok(TransparentInterceptionSetupPlan::RequiresFlowClassifier {
            reason,
            host_rule_boundary,
            flow_scope,
        }) => flow_classifier_activation_scope(
            reason,
            host_rule_boundary,
            flow_scope,
            classification,
            proxy_mode,
        ),
        Err(error) => Err(TransparentInterceptionError::Setup(error.to_string())),
    }
}

fn flow_classifier_activation_scope(
    reason: String,
    host_rule_boundary: TransparentInterceptionHostRuleBoundary,
    flow_scope: TransparentInterceptionFlowClassifierScope,
    classification: &TransparentInterceptionClassificationPlan,
    proxy_mode: TransparentInterceptionProxyModeConfig,
) -> Result<TransparentInterceptionActivationScope, TransparentInterceptionError> {
    if classification.flow_classifier.mode == RuntimeMode::Unavailable {
        return Err(classifier_setup_error(
            reason,
            "flow classifier",
            &classification.flow_classifier,
        ));
    }
    if proxy_mode != TransparentInterceptionProxyModeConfig::ManagedTcpRelay {
        return Err(TransparentInterceptionError::Setup(format!(
            "{reason}; transparent flow classifier requires managed TCP relay proxy mode"
        )));
    }
    let TransparentInterceptionHostRuleBoundary::HostRules(setup_rules) = host_rule_boundary else {
        return Err(TransparentInterceptionError::Setup(format!(
            "{reason}; transparent flow classifier requires a finite host-rule boundary before rule installation"
        )));
    };
    let flow_classifier = TransparentInterceptionFlowClassifier::from_scope(flow_scope)?;
    Ok(TransparentInterceptionActivationScope::with_flow_classifier(setup_rules, flow_classifier))
}

fn classifier_setup_error(
    reason: String,
    classifier_name: &'static str,
    capability: &CapabilityState,
) -> TransparentInterceptionError {
    let readiness = match capability.mode {
        RuntimeMode::Available => {
            "capability is available, but no executable classifier backend is wired into this lifecycle".to_string()
        }
        RuntimeMode::Degraded => format!(
            "capability is degraded: {}",
            capability
                .reason
                .as_deref()
                .unwrap_or("no degradation reason reported")
        ),
        RuntimeMode::Unavailable => format!(
            "capability is unavailable: {}",
            capability
                .reason
                .as_deref()
                .unwrap_or("no unavailable reason reported")
        ),
    };
    TransparentInterceptionError::Setup(format!(
        "{reason}; transparent {classifier_name} {} {readiness}",
        capability.kind.wire_name(),
    ))
}

#[cfg(test)]
mod tests {
    use ::runtime::TransparentInterceptionClassificationPlan;
    use interception::TransparentInterceptionSetupSelectorSources;
    use probe_config::{
        EnforcementInterceptionConfig, TransparentInterceptionProxyConfig,
        TransparentInterceptionStrategyConfig,
    };
    use probe_core::{
        CapabilityKind, CapabilityState, Direction, ProcessSelector, ResolvedSelector, Selector,
        TrafficSelector,
    };

    use super::*;

    #[test]
    fn manifest_only_setup_scope_fails_closed() {
        let config = EnforcementInterceptionConfig {
            strategy: TransparentInterceptionStrategyConfig::InboundTproxy,
            selector: None,
            proxy: TransparentInterceptionProxyConfig {
                listen_port: Some(15001),
                ..TransparentInterceptionProxyConfig::default()
            },
            ..EnforcementInterceptionConfig::default()
        };
        let manifest_selector = Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                local_ports: vec![8443],
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        );
        let manifest_selector =
            ResolvedSelector::new(manifest_selector).expect("test selector should be valid");

        let selectors = TransparentInterceptionSetupSelectors::from_sources(
            TransparentInterceptionSetupSelectorSources {
                local_enforcement_selector: None,
                effective_enforcement_selector: Some(&manifest_selector),
                interception_selector: None,
            },
        );
        let execution_plan = TransparentInterceptionExecutionPlan::try_from_config(&config)
            .expect("test transparent interception config should be valid");
        let error = effective_setup_scope(
            &execution_plan,
            &unavailable_classifiers(),
            &mut TransparentInterceptionProcessClassifier::new(),
            selectors,
        )
        .expect_err("remote manifest must not be the only transparent setup scope");

        assert!(error.to_string().contains("explicit local selector"));
    }

    #[test]
    fn process_classifier_setup_scope_reports_capability_reason() {
        let config = EnforcementInterceptionConfig {
            strategy: TransparentInterceptionStrategyConfig::InboundTproxy,
            selector: None,
            proxy: TransparentInterceptionProxyConfig {
                listen_port: Some(15001),
                ..TransparentInterceptionProxyConfig::default()
            },
            ..EnforcementInterceptionConfig::default()
        };
        let selector = Selector::term(
            ProcessSelector {
                names: vec!["curl".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector {
                local_ports: vec![8443],
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        );
        let selector = ResolvedSelector::new(selector).expect("test selector should be valid");
        let selectors = TransparentInterceptionSetupSelectors::from_sources(
            TransparentInterceptionSetupSelectorSources {
                local_enforcement_selector: Some(&selector),
                effective_enforcement_selector: Some(&selector),
                interception_selector: None,
            },
        );
        let execution_plan = TransparentInterceptionExecutionPlan::try_from_config(&config)
            .expect("test transparent interception config should be valid");

        let error = effective_setup_scope(
            &execution_plan,
            &unavailable_classifiers(),
            &mut TransparentInterceptionProcessClassifier::new(),
            selectors,
        )
        .expect_err("process-scoped setup should require a classifier");
        let message = error.to_string();

        assert!(message.contains("transparent_process_classifier"));
        assert!(message.contains("not built"));
    }

    #[test]
    fn outbound_transparent_proxy_valid_host_scope_returns_executable_scope() {
        let config = outbound_transparent_proxy_config();
        let selector = Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                remote_ports: vec![443],
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
        );
        let selectors = setup_selectors(&selector, &config);
        let execution_plan = TransparentInterceptionExecutionPlan::try_from_config(&config)
            .expect("test transparent interception config should be valid");

        let scope = effective_setup_scope(
            &execution_plan,
            &unavailable_classifiers(),
            &mut TransparentInterceptionProcessClassifier::new(),
            selectors,
        )
        .expect("outbound transparent proxy host scope should be executable");

        assert!(scope.is_some());
    }

    #[test]
    fn outbound_transparent_proxy_wildcard_remote_ports_fail_before_runtime_boundary() {
        let config = outbound_transparent_proxy_config();
        let selector = Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                directions: vec![Direction::Outbound],
                remote_addresses: vec!["203.0.113.10".to_string()],
                ..TrafficSelector::default()
            },
        );
        let selectors = setup_selectors(&selector, &config);
        let execution_plan = TransparentInterceptionExecutionPlan::try_from_config(&config)
            .expect("test transparent interception config should be valid");

        let error = effective_setup_scope(
            &execution_plan,
            &unavailable_classifiers(),
            &mut TransparentInterceptionProcessClassifier::new(),
            selectors,
        )
        .expect_err("wildcard outbound remote ports should fail before runtime activation");
        let message = error.to_string();

        assert!(message.contains("explicit remote port scope"));
        assert!(!message.contains("transparent-linux artifact planning"));
        assert!(!message.contains("proxy self-bypass"));
        assert!(!message.contains("target recovery"));
    }

    #[test]
    fn flow_classifier_setup_scope_preserves_host_boundary_for_managed_proxy() {
        let config = EnforcementInterceptionConfig {
            strategy: TransparentInterceptionStrategyConfig::InboundTproxy,
            selector: None,
            proxy: TransparentInterceptionProxyConfig {
                mode: probe_config::TransparentInterceptionProxyModeConfig::ManagedTcpRelay,
                listen_port: Some(15001),
                ..TransparentInterceptionProxyConfig::default()
            },
            ..EnforcementInterceptionConfig::default()
        };
        let selector = correlated_process_any_selector(Direction::Inbound);
        let selectors = setup_selectors(&selector, &config);
        let execution_plan = TransparentInterceptionExecutionPlan::try_from_config(&config)
            .expect("test transparent interception config should be valid");

        let scope = effective_setup_scope(
            &execution_plan,
            &degraded_flow_classifier(),
            &mut TransparentInterceptionProcessClassifier::new(),
            selectors,
        )
        .expect("flow-classified setup should be executable")
        .expect("inbound TPROXY setup should produce activation scope");

        assert!(scope.has_flow_classifier());
        assert_eq!(
            scope.setup_rules().explicit_local_ports(),
            Some(vec![8443, 9443])
        );
    }

    #[test]
    fn flow_classifier_setup_scope_rejects_external_proxy() {
        let config = EnforcementInterceptionConfig {
            strategy: TransparentInterceptionStrategyConfig::InboundTproxy,
            selector: None,
            proxy: TransparentInterceptionProxyConfig {
                mode: probe_config::TransparentInterceptionProxyModeConfig::External,
                listen_port: Some(15001),
                ..TransparentInterceptionProxyConfig::default()
            },
            ..EnforcementInterceptionConfig::default()
        };
        let selector = correlated_process_any_selector(Direction::Inbound);
        let selectors = setup_selectors(&selector, &config);
        let execution_plan = TransparentInterceptionExecutionPlan::try_from_config(&config)
            .expect("test transparent interception config should be valid");

        let error = effective_setup_scope(
            &execution_plan,
            &degraded_flow_classifier(),
            &mut TransparentInterceptionProcessClassifier::new(),
            selectors,
        )
        .expect_err("external proxy cannot execute proxy-side flow classifier");

        assert!(error.to_string().contains("requires managed TCP relay"));
    }

    fn correlated_process_any_selector(direction: Direction) -> Selector {
        Selector::Any {
            selectors: vec![
                Selector::term(
                    ProcessSelector {
                        names: vec!["curl".to_string()],
                        ..ProcessSelector::default()
                    },
                    TrafficSelector {
                        local_ports: vec![8443],
                        directions: vec![direction],
                        ..TrafficSelector::default()
                    },
                ),
                Selector::term(
                    ProcessSelector {
                        names: vec!["wget".to_string()],
                        ..ProcessSelector::default()
                    },
                    TrafficSelector {
                        local_ports: vec![9443],
                        directions: vec![direction],
                        ..TrafficSelector::default()
                    },
                ),
            ],
        }
    }

    fn outbound_transparent_proxy_config() -> EnforcementInterceptionConfig {
        EnforcementInterceptionConfig {
            strategy: TransparentInterceptionStrategyConfig::OutboundTransparentProxy,
            selector: None,
            proxy: TransparentInterceptionProxyConfig {
                mode: probe_config::TransparentInterceptionProxyModeConfig::ManagedTcpRelay,
                listen_port: Some(15001),
                ..TransparentInterceptionProxyConfig::default()
            },
            ..EnforcementInterceptionConfig::default()
        }
    }

    fn setup_selectors(
        selector: &Selector,
        config: &EnforcementInterceptionConfig,
    ) -> TransparentInterceptionSetupSelectors {
        let selector =
            ResolvedSelector::new(selector.clone()).expect("test selector should be valid");
        let interception_selector = config.selector.clone().map(|selector| {
            ResolvedSelector::new(selector).expect("test selector should be valid")
        });
        TransparentInterceptionSetupSelectors::from_sources(
            TransparentInterceptionSetupSelectorSources {
                local_enforcement_selector: Some(&selector),
                effective_enforcement_selector: Some(&selector),
                interception_selector: interception_selector.as_ref(),
            },
        )
    }

    fn unavailable_classifiers() -> TransparentInterceptionClassificationPlan {
        TransparentInterceptionClassificationPlan {
            process_classifier: CapabilityState::unavailable(
                CapabilityKind::TransparentProcessClassifier,
                "not built",
            ),
            flow_classifier: CapabilityState::unavailable(
                CapabilityKind::TransparentFlowClassifier,
                "not built",
            ),
        }
    }

    fn degraded_flow_classifier() -> TransparentInterceptionClassificationPlan {
        TransparentInterceptionClassificationPlan {
            process_classifier: CapabilityState::unavailable(
                CapabilityKind::TransparentProcessClassifier,
                "not built",
            ),
            flow_classifier: CapabilityState::degraded(
                CapabilityKind::TransparentFlowClassifier,
                "procfs flow classification",
            ),
        }
    }
}
