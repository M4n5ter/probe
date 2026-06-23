mod error;
mod ip_family;
mod nftables;
mod process_classifier;
mod proxy;
mod runtime;

use ::runtime::{
    TransparentInterceptionClassificationPlan, TransparentInterceptionExecutionPlan,
    TransparentInterceptionOutboundRedirectPlan,
};
use interception::{
    TransparentInterceptionHostRuleScope, TransparentInterceptionSetupDirection,
    TransparentInterceptionSetupPlan, TransparentInterceptionSetupProjectionError,
    TransparentInterceptionSetupSelectors,
};
use probe_config::TransparentInterceptionStrategyConfig;
use probe_core::{CapabilityState, RuntimeMode};

pub(crate) use error::TransparentInterceptionError;
pub(crate) use ip_family::TransparentInterceptionIpFamily;
pub(crate) use process_classifier::TransparentInterceptionProcessClassifier;
use proxy::TransparentProxyRuntime;
pub(crate) use proxy::{
    TransparentProxyHealthProbeMode, TransparentProxyRuntimeHandle, TransparentProxyRuntimeMode,
    TransparentProxyRuntimeSnapshot,
};
pub(crate) use runtime::{TransparentInterceptionGuard, TransparentInterceptionRuntime};

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
        TransparentInterceptionExecutionPlan::OutboundMitm(_) => {
            TransparentInterceptionRuntime::unavailable(outbound_mitm_unavailable(), proxy_runtime)
        }
    }
}

pub(crate) fn effective_setup_scope(
    execution_plan: &TransparentInterceptionExecutionPlan,
    outbound_redirect: &TransparentInterceptionOutboundRedirectPlan,
    classification: &TransparentInterceptionClassificationPlan,
    process_classifier: &mut TransparentInterceptionProcessClassifier,
    selectors: TransparentInterceptionSetupSelectors,
) -> Result<Option<TransparentInterceptionHostRuleScope>, TransparentInterceptionError> {
    if execution_plan.strategy() == TransparentInterceptionStrategyConfig::None {
        return Ok(None);
    }
    if selectors.local_config_scope().is_none() {
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
        TransparentInterceptionExecutionPlan::OutboundMitm(_) => {
            validate_outbound_redirect_setup_scope(outbound_redirect, selectors)?;
            Err(TransparentInterceptionError::Setup(
                outbound_mitm_unavailable(),
            ))
        }
    }
}

fn inbound_tproxy_effective_setup_scope(
    inbound_plan: &::runtime::TransparentInterceptionInboundTproxyPlan,
    classification: &TransparentInterceptionClassificationPlan,
    process_classifier: &mut TransparentInterceptionProcessClassifier,
    selectors: TransparentInterceptionSetupSelectors,
) -> Result<Option<TransparentInterceptionHostRuleScope>, TransparentInterceptionError> {
    validate_local_setup_plan(
        selectors.local_setup_plan(TransparentInterceptionSetupDirection::Inbound),
    )?;
    let scope = executable_host_rule_scope(
        selectors.final_setup_plan(TransparentInterceptionSetupDirection::Inbound),
        classification,
        process_classifier,
    )?;
    nftables::validate_inbound_tproxy_setup_scope(inbound_plan, &scope)?;
    Ok(Some(scope))
}

fn validate_outbound_redirect_setup_scope(
    outbound_redirect: &TransparentInterceptionOutboundRedirectPlan,
    selectors: TransparentInterceptionSetupSelectors,
) -> Result<(), TransparentInterceptionError> {
    validate_local_setup_plan(
        selectors.local_setup_plan(TransparentInterceptionSetupDirection::Outbound),
    )?;
    match selectors.final_setup_plan(TransparentInterceptionSetupDirection::Outbound) {
        Ok(TransparentInterceptionSetupPlan::HostRules(scope)) => {
            nftables::validate_outbound_redirect_setup_scope(outbound_redirect, &scope)
        }
        Ok(
            TransparentInterceptionSetupPlan::RequiresProcessClassifier { reason, .. }
            | TransparentInterceptionSetupPlan::RequiresFlowClassifier { reason, .. },
        ) => Err(TransparentInterceptionError::Setup(format!(
            "{reason}; {}",
            outbound_mitm_unavailable()
        ))),
        Err(error) => Err(TransparentInterceptionError::Setup(error.to_string())),
    }
}

fn outbound_mitm_unavailable() -> String {
    format!(
        "outbound transparent MITM has a typed redirect plan, agent-side nft artifact rendering, existing {}, and proxy pre-connect SO_MARK primitive, but requires wiring them into an executable output redirect lifecycle for activation/install and MITM lifecycle before rules can be installed",
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
) -> Result<TransparentInterceptionHostRuleScope, TransparentInterceptionError> {
    match plan {
        Ok(TransparentInterceptionSetupPlan::HostRules(scope)) => Ok(scope),
        Ok(TransparentInterceptionSetupPlan::RequiresProcessClassifier {
            host_rule_boundary,
            process_scope,
            reason,
        }) => process_classifier.executable_host_rule_scope(
            reason,
            host_rule_boundary,
            process_scope,
            &classification.process_classifier,
        ),
        Ok(TransparentInterceptionSetupPlan::RequiresFlowClassifier { reason, .. }) => Err(
            classifier_setup_error(reason, "flow classifier", &classification.flow_classifier),
        ),
        Err(error) => Err(TransparentInterceptionError::Setup(error.to_string())),
    }
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
        CapabilityKind, CapabilityState, Direction, ProcessSelector, Selector, TrafficSelector,
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
        };
        let manifest_selector = Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                local_ports: vec![8443],
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        );

        let selectors = TransparentInterceptionSetupSelectors::from_sources(
            TransparentInterceptionSetupSelectorSources {
                local_enforcement_selector: None,
                effective_enforcement_selector: Some(&manifest_selector),
                interception_selector: config.selector.as_ref(),
            },
        );
        let execution_plan = TransparentInterceptionExecutionPlan::try_from_config(&config)
            .expect("test transparent interception config should be valid");
        let error = effective_setup_scope(
            &execution_plan,
            &TransparentInterceptionOutboundRedirectPlan::NotConfigured,
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
        let selectors = TransparentInterceptionSetupSelectors::from_sources(
            TransparentInterceptionSetupSelectorSources {
                local_enforcement_selector: Some(&selector),
                effective_enforcement_selector: Some(&selector),
                interception_selector: config.selector.as_ref(),
            },
        );
        let execution_plan = TransparentInterceptionExecutionPlan::try_from_config(&config)
            .expect("test transparent interception config should be valid");

        let error = effective_setup_scope(
            &execution_plan,
            &TransparentInterceptionOutboundRedirectPlan::NotConfigured,
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
    fn outbound_mitm_valid_host_scope_reaches_fail_closed_runtime_boundary() {
        let config = outbound_mitm_config();
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

        let error = effective_setup_scope(
            &execution_plan,
            &outbound_redirect_plan(),
            &unavailable_classifiers(),
            &mut TransparentInterceptionProcessClassifier::new(),
            selectors,
        )
        .expect_err("outbound MITM should remain fail closed after artifact validation");
        let message = error.to_string();

        assert!(message.contains("agent-side nft artifact rendering"));
        assert!(message.contains("activation/install"));
    }

    #[test]
    fn outbound_mitm_wildcard_remote_ports_fail_before_runtime_boundary() {
        let config = outbound_mitm_config();
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
            &outbound_redirect_plan(),
            &unavailable_classifiers(),
            &mut TransparentInterceptionProcessClassifier::new(),
            selectors,
        )
        .expect_err("wildcard outbound remote ports should fail before runtime activation");
        let message = error.to_string();

        assert!(message.contains("explicit remote port scope"));
        assert!(!message.contains("activation/install"));
    }

    fn outbound_mitm_config() -> EnforcementInterceptionConfig {
        EnforcementInterceptionConfig {
            strategy: TransparentInterceptionStrategyConfig::OutboundMitm,
            selector: None,
            proxy: TransparentInterceptionProxyConfig {
                listen_port: Some(15001),
                ..TransparentInterceptionProxyConfig::default()
            },
        }
    }

    fn outbound_redirect_plan() -> TransparentInterceptionOutboundRedirectPlan {
        let host_resources = ::runtime::TransparentInterceptionNftablesPlan::reserved();
        TransparentInterceptionOutboundRedirectPlan::Planned {
            table_name: host_resources.table_name,
            chain_name: "outbound_mitm".to_string(),
            hook: "output".to_string(),
            priority: "dstnat".to_string(),
            proxy_port: 15001,
            proxy_bypass_mark: host_resources.outbound_proxy_bypass_mark,
            install: ::runtime::TransparentInterceptionOutboundRedirectInstallPlan::Blocked {
                reason: "test blocked".to_string(),
            },
        }
    }

    fn setup_selectors(
        selector: &Selector,
        config: &EnforcementInterceptionConfig,
    ) -> TransparentInterceptionSetupSelectors {
        TransparentInterceptionSetupSelectors::from_sources(
            TransparentInterceptionSetupSelectorSources {
                local_enforcement_selector: Some(selector),
                effective_enforcement_selector: Some(selector),
                interception_selector: config.selector.as_ref(),
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
}
