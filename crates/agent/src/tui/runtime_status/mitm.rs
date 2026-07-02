use probe_config::TransparentInterceptionStrategyConfig;
use probe_core::{CapabilityKind, RuntimeMode};
use runtime::{
    RequiredCapabilityPlan, TransparentInterceptionMitmBackendPlan,
    TransparentInterceptionMitmBackendReadinessProbePlan,
    TransparentInterceptionMitmClientTrustPlan, TransparentInterceptionMitmPlaintextBridgePlan,
};

use crate::{
    l7_mitm::{L7MitmPlaintextBridgeMode, L7MitmRuntimeSnapshot},
    status::{EnforcementStatusMode, EnforcementStatusSnapshot},
    tcp_health::{TcpHealthMode, TcpHealthSnapshot},
    transparent_interception::{TransparentProxyRuntimeMode, TransparentProxyRuntimeSnapshot},
    tui::copy::{
        MITM_HTTP_PATH_LABEL, MITM_PLAINTEXT_COVERAGE, MITM_TLS_PATH_LABEL, MITM_TLS_TRUST_ACTION,
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MitmDiagnostics {
    enforcement_status: EnforcementStatusMode,
    strategy: TransparentInterceptionStrategyConfig,
    selector_configured: bool,
    backend: TransparentInterceptionMitmBackendPlan,
    client_trust: TransparentInterceptionMitmClientTrustPlan,
    plaintext_bridge: TransparentInterceptionMitmPlaintextBridgePlan,
    capabilities: Vec<RequiredCapabilityPlan>,
    runtime_l7_mitm: Option<L7MitmRuntimeSnapshot>,
    runtime_proxy: Option<TransparentProxyRuntimeSnapshot>,
}

impl MitmDiagnostics {
    pub(super) fn from_enforcement(enforcement: EnforcementStatusSnapshot) -> Option<Self> {
        let interception = enforcement.interception;
        let mitm = interception.mitm;
        let diagnostics = Self {
            enforcement_status: enforcement.status,
            strategy: interception.strategy,
            selector_configured: interception.selector_configured,
            backend: mitm.backend,
            client_trust: mitm.client_trust,
            plaintext_bridge: mitm.plaintext_bridge,
            capabilities: interception.capabilities,
            runtime_l7_mitm: interception.runtime_l7_mitm,
            runtime_proxy: interception.runtime_proxy,
        };
        diagnostics.is_relevant().then_some(diagnostics)
    }

    pub(super) fn next_step(&self) -> String {
        if !self.selector_configured {
            return "MITM path is configured but has no scoped interception selector".to_string();
        }
        if let Some(capability) = self.first_unavailable_capability() {
            return format!(
                "MITM path is blocked by {}: {}",
                capability_kind_name(capability.capability),
                capability
                    .reason
                    .as_deref()
                    .unwrap_or("required capability is unavailable")
            );
        }
        if self
            .runtime_l7_mitm
            .as_ref()
            .is_some_and(l7_mitm_runtime_is_unhealthy)
        {
            return self
                .runtime_l7_mitm
                .as_ref()
                .and_then(l7_mitm_runtime_unhealthy_reason)
                .map(|reason| format!("MITM backend is unhealthy: {reason}"))
                .unwrap_or_else(|| "MITM backend is unhealthy".to_string());
        }
        if matches!(
            self.plaintext_bridge,
            TransparentInterceptionMitmPlaintextBridgePlan::Disabled
        ) {
            return format!(
                "MITM path needs a plaintext bridge to feed captured {MITM_PLAINTEXT_COVERAGE} into traffic events"
            );
        }
        mitm_client_trust_next_step(&self.client_trust)
    }

    pub(super) fn detail_lines(&self) -> Vec<String> {
        let mut lines = vec![
            "MITM diagnostics".to_string(),
            format!("strategy: {}", interception_strategy_name(self.strategy)),
            format!(
                "enforcement: {}",
                enforcement_status_name(self.enforcement_status)
            ),
            format!(
                "selector: {}",
                if self.selector_configured {
                    "configured"
                } else {
                    "missing"
                }
            ),
            format!("coverage: {MITM_PLAINTEXT_COVERAGE}"),
            format!(
                "backend: {}{}",
                mitm_backend_name(&self.backend),
                mitm_backend_readiness_target(&self.backend)
                    .map(|target| format!(" readiness={target}"))
                    .unwrap_or_default()
            ),
            format!(
                "client trust: {}",
                mitm_client_trust_name(&self.client_trust)
            ),
            format!(
                "tls trust action: {}",
                mitm_client_trust_action(&self.client_trust)
            ),
            self.plaintext_bridge_line(),
        ];
        lines.extend(self.mitm_visibility_lines());
        if !self.capabilities.is_empty() {
            lines.push("required capabilities:".to_string());
            lines.extend(
                self.capabilities
                    .iter()
                    .map(required_capability_detail_line),
            );
        }
        if let Some(runtime) = &self.runtime_l7_mitm {
            lines.extend(l7_mitm_runtime_detail_lines(runtime));
        }
        if let Some(runtime) = &self.runtime_proxy {
            lines.extend(transparent_proxy_runtime_detail_lines(runtime));
        }
        lines.push(format!("next action: {}", self.next_step()));
        lines
    }

    fn is_relevant(&self) -> bool {
        self.strategy.is_mitm()
            || !matches!(
                self.backend,
                TransparentInterceptionMitmBackendPlan::Disabled
            )
            || !matches!(
                self.plaintext_bridge,
                TransparentInterceptionMitmPlaintextBridgePlan::Disabled
            )
            || self.runtime_l7_mitm.is_some()
    }

    fn plaintext_bridge_line(&self) -> String {
        let mut line = format!(
            "plaintext bridge: {}",
            mitm_plaintext_bridge_name(&self.plaintext_bridge)
        );
        if let Some(path) = mitm_plaintext_bridge_path(&self.plaintext_bridge) {
            line.push_str(&format!(" path={path}"));
        }
        if let Some(follow) = mitm_plaintext_bridge_follow(&self.plaintext_bridge) {
            line.push_str(&format!(" follow={follow}"));
        }
        line
    }

    fn mitm_visibility_lines(&self) -> Vec<String> {
        match self.plaintext_bridge {
            TransparentInterceptionMitmPlaintextBridgePlan::Disabled => vec![
                "path labels: disabled until MITM plaintext bridge feeds traffic events"
                    .to_string(),
                "plain HTTP: unavailable until MITM plaintext bridge is enabled".to_string(),
                "TLS-decrypted HTTP: unavailable until MITM plaintext bridge is enabled"
                    .to_string(),
            ],
            TransparentInterceptionMitmPlaintextBridgePlan::CaptureEventFeed { .. } => {
                if let Some(reason) = self.runtime_plaintext_bridge_disabled_reason() {
                    return vec![
                        format!(
                            "path labels: {MITM_HTTP_PATH_LABEL}=plain HTTP, {MITM_TLS_PATH_LABEL}=TLS-decrypted HTTP"
                        ),
                        format!(
                            "plain HTTP: blocked because MITM plaintext bridge runtime is disabled: {reason}"
                        ),
                        format!(
                            "TLS-decrypted HTTP: blocked because MITM plaintext bridge runtime is disabled: {reason}"
                        ),
                    ];
                }
                let tls_line = match self.client_trust {
                    TransparentInterceptionMitmClientTrustPlan::Disabled => {
                        "TLS-decrypted HTTP: blocked until MITM client trust is configured"
                            .to_string()
                    }
                    TransparentInterceptionMitmClientTrustPlan::OperatorManaged => format!(
                        "TLS-decrypted HTTP: visible as {MITM_TLS_PATH_LABEL} after {MITM_TLS_TRUST_ACTION}"
                    ),
                };
                vec![
                    format!(
                        "path labels: {MITM_HTTP_PATH_LABEL}=plain HTTP, {MITM_TLS_PATH_LABEL}=TLS-decrypted HTTP"
                    ),
                    format!(
                        "plain HTTP: visible as {MITM_HTTP_PATH_LABEL} without TLS client trust"
                    ),
                    tls_line,
                ]
            }
        }
    }

    fn runtime_plaintext_bridge_disabled_reason(&self) -> Option<&str> {
        let runtime = self.runtime_l7_mitm.as_ref()?;
        (runtime.plaintext_bridge.mode == L7MitmPlaintextBridgeMode::DisabledAfterError).then_some(
            runtime
                .plaintext_bridge
                .disable_reason
                .as_deref()
                .unwrap_or("disabled after runtime error"),
        )
    }

    fn first_unavailable_capability(&self) -> Option<&RequiredCapabilityPlan> {
        self.capabilities
            .iter()
            .find(|capability| capability.mode == RuntimeMode::Unavailable)
    }
}

fn required_capability_detail_line(capability: &RequiredCapabilityPlan) -> String {
    let mut line = format!(
        "{}: {}",
        capability_kind_name(capability.capability),
        runtime_mode_name(capability.mode)
    );
    if let Some(reason) = &capability.reason {
        line.push_str(&format!(" reason={reason}"));
    }
    line
}

fn l7_mitm_runtime_is_unhealthy(runtime: &L7MitmRuntimeSnapshot) -> bool {
    runtime.backend_health.mode == TcpHealthMode::Unhealthy
        || runtime.plaintext_bridge.mode == L7MitmPlaintextBridgeMode::DisabledAfterError
}

fn l7_mitm_runtime_unhealthy_reason(runtime: &L7MitmRuntimeSnapshot) -> Option<&str> {
    runtime
        .backend_health
        .last_failure_reason
        .as_deref()
        .or(runtime.plaintext_bridge.disable_reason.as_deref())
}

fn l7_mitm_runtime_detail_lines(runtime: &L7MitmRuntimeSnapshot) -> Vec<String> {
    let mut lines = vec![
        format!(
            "l7 mitm backend health: {} successes={} failures={} consecutive_failures={}",
            tcp_health_mode_name(runtime.backend_health.mode),
            runtime.backend_health.check_successes,
            runtime.backend_health.check_failures,
            runtime.backend_health.consecutive_failures
        ),
        format!(
            "l7 mitm client trust runtime: {} material={}",
            runtime.client_trust.mode.wire_name(),
            runtime.client_trust.material.wire_name()
        ),
        format!(
            "l7 mitm plaintext bridge runtime: {}",
            runtime.plaintext_bridge.mode.wire_name()
        ),
    ];
    if let Some(reason) = &runtime.backend_health.last_failure_reason {
        lines.push(format!("l7 mitm backend failure: {reason}"));
    }
    if let Some(reason) = &runtime.plaintext_bridge.disable_reason {
        lines.push(format!("l7 mitm bridge disabled: {reason}"));
    }
    lines
}

fn transparent_proxy_runtime_detail_lines(
    runtime: &TransparentProxyRuntimeSnapshot,
) -> Vec<String> {
    let mut lines = vec![format!(
        "transparent proxy runtime: {} active_relays={} accepted={} rejected={} relay_failures={} listener_failures={}",
        transparent_proxy_runtime_mode_name(runtime.mode),
        runtime.active_relays,
        runtime.accepted_relays,
        runtime.rejected_relays,
        runtime.relay_failures,
        runtime.listener_failures
    )];
    lines.push(tcp_health_detail_line(
        "transparent proxy health",
        &runtime.health_probe,
    ));
    if let Some(reason) = &runtime.health_probe.last_failure_reason {
        lines.push(format!("transparent proxy failure: {reason}"));
    }
    lines
}

fn tcp_health_detail_line(label: &str, health: &TcpHealthSnapshot) -> String {
    format!(
        "{label}: {} successes={} failures={} consecutive_failures={}",
        tcp_health_mode_name(health.mode),
        health.check_successes,
        health.check_failures,
        health.consecutive_failures
    )
}

fn interception_strategy_name(strategy: TransparentInterceptionStrategyConfig) -> &'static str {
    match strategy {
        TransparentInterceptionStrategyConfig::None => "none",
        TransparentInterceptionStrategyConfig::InboundTproxy => "inbound_tproxy",
        TransparentInterceptionStrategyConfig::OutboundTransparentProxy => {
            "outbound_transparent_proxy"
        }
        TransparentInterceptionStrategyConfig::InboundTproxyMitm => "inbound_tproxy_mitm",
        TransparentInterceptionStrategyConfig::OutboundTransparentMitm => {
            "outbound_transparent_mitm"
        }
    }
}

fn enforcement_status_name(status: EnforcementStatusMode) -> &'static str {
    match status {
        EnforcementStatusMode::Disabled => "disabled",
        EnforcementStatusMode::AuditOnly => "audit_only",
        EnforcementStatusMode::DryRun => "dry_run",
        EnforcementStatusMode::Enforce => "enforce",
    }
}

fn mitm_backend_name(backend: &TransparentInterceptionMitmBackendPlan) -> &'static str {
    match backend {
        TransparentInterceptionMitmBackendPlan::Disabled => "disabled",
        TransparentInterceptionMitmBackendPlan::External { .. } => "external",
        TransparentInterceptionMitmBackendPlan::ManagedProcess { .. } => "managed_process",
        TransparentInterceptionMitmBackendPlan::ProductProxy { .. } => "product_proxy",
    }
}

fn mitm_backend_readiness_target(
    backend: &TransparentInterceptionMitmBackendPlan,
) -> Option<String> {
    match backend {
        TransparentInterceptionMitmBackendPlan::Disabled => None,
        TransparentInterceptionMitmBackendPlan::External { readiness_probe }
        | TransparentInterceptionMitmBackendPlan::ManagedProcess {
            readiness_probe, ..
        }
        | TransparentInterceptionMitmBackendPlan::ProductProxy {
            readiness_probe, ..
        } => Some(mitm_readiness_probe_target(readiness_probe)),
    }
}

fn mitm_readiness_probe_target(
    readiness_probe: &TransparentInterceptionMitmBackendReadinessProbePlan,
) -> String {
    match readiness_probe {
        TransparentInterceptionMitmBackendReadinessProbePlan::TcpConnect { target, .. } => {
            target.to_string()
        }
    }
}

fn mitm_client_trust_name(
    client_trust: &TransparentInterceptionMitmClientTrustPlan,
) -> &'static str {
    match client_trust {
        TransparentInterceptionMitmClientTrustPlan::Disabled => "disabled",
        TransparentInterceptionMitmClientTrustPlan::OperatorManaged => "operator_managed",
    }
}

fn mitm_client_trust_next_step(
    client_trust: &TransparentInterceptionMitmClientTrustPlan,
) -> String {
    format!(
        "MITM TLS trust needs attention: {}",
        mitm_client_trust_action(client_trust)
    )
}

fn mitm_client_trust_action(client_trust: &TransparentInterceptionMitmClientTrustPlan) -> String {
    match client_trust {
        TransparentInterceptionMitmClientTrustPlan::Disabled => {
            "configure MITM client trust before expecting TLS-decrypted HTTP".to_string()
        }
        TransparentInterceptionMitmClientTrustPlan::OperatorManaged => {
            MITM_TLS_TRUST_ACTION.to_string()
        }
    }
}

fn mitm_plaintext_bridge_name(
    bridge: &TransparentInterceptionMitmPlaintextBridgePlan,
) -> &'static str {
    match bridge {
        TransparentInterceptionMitmPlaintextBridgePlan::Disabled => "disabled",
        TransparentInterceptionMitmPlaintextBridgePlan::CaptureEventFeed { .. } => {
            "capture_event_feed"
        }
    }
}

fn mitm_plaintext_bridge_path(
    bridge: &TransparentInterceptionMitmPlaintextBridgePlan,
) -> Option<String> {
    match bridge {
        TransparentInterceptionMitmPlaintextBridgePlan::Disabled => None,
        TransparentInterceptionMitmPlaintextBridgePlan::CaptureEventFeed { path, .. } => {
            Some(path.display().to_string())
        }
    }
}

fn mitm_plaintext_bridge_follow(
    bridge: &TransparentInterceptionMitmPlaintextBridgePlan,
) -> Option<bool> {
    match bridge {
        TransparentInterceptionMitmPlaintextBridgePlan::Disabled => None,
        TransparentInterceptionMitmPlaintextBridgePlan::CaptureEventFeed { follow, .. } => {
            Some(*follow)
        }
    }
}

fn capability_kind_name(kind: CapabilityKind) -> &'static str {
    kind.wire_name()
}

fn runtime_mode_name(mode: RuntimeMode) -> &'static str {
    match mode {
        RuntimeMode::Available => "available",
        RuntimeMode::Degraded => "degraded",
        RuntimeMode::Unavailable => "unavailable",
    }
}

fn tcp_health_mode_name(mode: TcpHealthMode) -> &'static str {
    mode.wire_name()
}

fn transparent_proxy_runtime_mode_name(mode: TransparentProxyRuntimeMode) -> &'static str {
    mode.wire_name()
}
