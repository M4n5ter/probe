use exporter::WebhookConnectionOptions;
use probe_http::HttpConnectionOptions;
use runtime::{RuntimePlan, TransparentInterceptionExecutionPlan};

use crate::{
    configured_enforcement::EnforcementPolicySourceLoadContext,
    configured_policy::PolicySourceLoadContext,
};

pub(crate) fn webhook_connection_options_from_plan(plan: &RuntimePlan) -> WebhookConnectionOptions {
    agent_owned_connection_options_from_plan(plan, WebhookConnectionOptions::default())
}

pub(crate) fn policy_source_load_context_from_plan(plan: &RuntimePlan) -> PolicySourceLoadContext {
    PolicySourceLoadContext::with_remote_http_connection(agent_owned_connection_options_from_plan(
        plan,
        PolicySourceLoadContext::default().remote_http_connection(),
    ))
}

pub(crate) fn enforcement_policy_source_load_context_from_plan(
    plan: &RuntimePlan,
) -> EnforcementPolicySourceLoadContext {
    EnforcementPolicySourceLoadContext::with_remote_http_connection(
        agent_owned_connection_options_from_plan(
            plan,
            EnforcementPolicySourceLoadContext::default().remote_http_connection(),
        ),
    )
}

fn agent_owned_connection_options_from_plan(
    plan: &RuntimePlan,
    connection: HttpConnectionOptions,
) -> HttpConnectionOptions {
    match &plan.enforcement.interception.execution {
        TransparentInterceptionExecutionPlan::OutboundTransparentProxy(outbound) => {
            connection.with_socket_mark(outbound.outbound_redirect_artifact().proxy_bypass_mark)
        }
        TransparentInterceptionExecutionPlan::Disabled
        | TransparentInterceptionExecutionPlan::InboundTproxy(_) => connection,
    }
}

#[cfg(test)]
mod tests {
    use probe_config::{AgentConfig, CaptureBackend, CaptureSelection};
    use probe_core::{CapabilityKind, CapabilityState};
    use runtime::{
        CaptureProviderBuilder, CaptureProviderDescriptor, ProviderRegistry,
        TransparentInterceptionExecutionPlan,
    };

    use super::*;

    #[test]
    fn policy_source_context_inherits_outbound_proxy_bypass_mark()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = outbound_transparent_proxy_plan()?;

        let context = policy_source_load_context_from_plan(&plan);
        let TransparentInterceptionExecutionPlan::OutboundTransparentProxy(outbound) =
            &plan.enforcement.interception.execution
        else {
            panic!("outbound transparent proxy plan");
        };

        assert_eq!(
            context.remote_http_connection(),
            PolicySourceLoadContext::default()
                .remote_http_connection()
                .with_socket_mark(outbound.outbound_redirect_artifact().proxy_bypass_mark)
        );
        Ok(())
    }

    #[test]
    fn enforcement_source_context_inherits_outbound_proxy_bypass_mark()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = outbound_transparent_proxy_plan()?;

        let context = enforcement_policy_source_load_context_from_plan(&plan);
        let TransparentInterceptionExecutionPlan::OutboundTransparentProxy(outbound) =
            &plan.enforcement.interception.execution
        else {
            panic!("outbound transparent proxy plan");
        };

        assert_eq!(
            context.remote_http_connection(),
            EnforcementPolicySourceLoadContext::default()
                .remote_http_connection()
                .with_socket_mark(outbound.outbound_redirect_artifact().proxy_bypass_mark)
        );
        Ok(())
    }

    fn outbound_transparent_proxy_plan() -> Result<RuntimePlan, runtime::RuntimeError> {
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Libpcap;
        config.enforcement.mode = probe_core::EnforcementMode::Enforce;
        config.enforcement.interception.strategy =
            probe_config::TransparentInterceptionStrategyConfig::OutboundTransparentProxy;
        config.enforcement.interception.proxy.listen_port = Some(15001);
        config.enforcement.interception.proxy.self_bypass =
            probe_config::TransparentInterceptionProxySelfBypassConfig::UsesReservedMark;
        config.enforcement.interception.selector = Some(probe_core::Selector::term(
            probe_core::ProcessSelector {
                uids: vec![1000],
                ..probe_core::ProcessSelector::default()
            },
            probe_core::TrafficSelector {
                remote_ports: vec![443],
                directions: vec![probe_core::Direction::Outbound],
                ..probe_core::TrafficSelector::default()
            },
        ));
        RuntimePlan::build(config, &libpcap_registry())
    }

    fn libpcap_registry() -> ProviderRegistry {
        ProviderRegistry::new(
            vec![CaptureProviderDescriptor::available(
                CaptureBackend::Libpcap,
                CaptureProviderBuilder::Libpcap,
            )],
            vec![
                CapabilityState::available(CapabilityKind::Libpcap),
                CapabilityState::available(CapabilityKind::Http1),
                CapabilityState::available(CapabilityKind::Sse),
                CapabilityState::available(CapabilityKind::WebSocketHandoff),
                CapabilityState::available(CapabilityKind::WebSocketFrame),
                CapabilityState::available(CapabilityKind::DryRunEnforcement),
                CapabilityState::available(CapabilityKind::TransparentInterception),
            ],
        )
    }
}
