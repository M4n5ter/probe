use std::path::PathBuf;

use probe_config::{TlsMaterialKind, TransparentInterceptionStrategyConfig};
use probe_core::{CapabilityKind, RuntimeMode};
use runtime::{
    RequiredCapabilityPlan, TlsMaterialPlan, TransparentInterceptionMitmBackendPlan,
    TransparentInterceptionMitmBackendReadinessProbePlan,
    TransparentInterceptionMitmClientTrustPlan, TransparentInterceptionMitmPlaintextBridgePlan,
    TransparentInterceptionMitmPlan,
};
use serde::Deserialize;

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
    trust_materials: MitmTrustMaterialDiagnostics,
}

impl MitmDiagnostics {
    pub(super) fn from_enforcement(
        enforcement: EnforcementStatusSnapshot,
        tls_materials: Option<&MitmTlsMaterialDiagnostics>,
    ) -> Option<Self> {
        let interception = enforcement.interception;
        let TransparentInterceptionMitmPlan {
            backend,
            client_trust,
            plaintext_bridge,
            ca_certificate,
            ca_private_key,
            leaf_certificate_chain,
            leaf_private_key,
            ..
        } = interception.mitm;
        let trust_materials = MitmTrustMaterialDiagnostics::from_materials(
            ca_certificate,
            ca_private_key,
            leaf_certificate_chain,
            leaf_private_key,
            tls_materials,
        );
        let diagnostics = Self {
            enforcement_status: enforcement.status,
            strategy: interception.strategy,
            selector_configured: interception.selector_configured,
            backend,
            client_trust,
            plaintext_bridge,
            capabilities: interception.capabilities,
            runtime_l7_mitm: interception.runtime_l7_mitm,
            runtime_proxy: interception.runtime_proxy,
            trust_materials,
        };
        diagnostics.is_relevant().then_some(diagnostics)
    }

    pub(super) fn next_step(&self) -> String {
        self.data_path_diagnosis().next_action
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
            format!("tls trust action: {}", self.client_trust_action()),
            self.plaintext_bridge_line(),
        ];
        lines.extend(self.trust_materials.detail_lines());
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
        let diagnosis = self.data_path_diagnosis();
        vec![
            diagnosis.path_labels,
            diagnosis.plain_http,
            diagnosis.tls_http,
        ]
    }

    fn data_path_diagnosis(&self) -> MitmDataPathDiagnosis {
        if !self.selector_configured {
            return MitmDataPathDiagnosis::disabled(
                "path labels: disabled until scoped MITM interception selector is configured",
                "plain HTTP: unavailable until scoped MITM interception selector is configured",
                "TLS-decrypted HTTP: unavailable until scoped MITM interception selector is configured",
                "MITM path is configured but has no scoped interception selector",
            );
        }

        if let Some(capability) = self.first_unavailable_capability() {
            let reason = capability
                .reason
                .as_deref()
                .unwrap_or("required capability is unavailable");
            let blocker = format!(
                "MITM path is blocked by {}: {reason}",
                capability_kind_name(capability.capability)
            );
            return MitmDataPathDiagnosis::disabled(
                format!("path labels: disabled because {blocker}"),
                format!("plain HTTP: blocked because {blocker}"),
                format!("TLS-decrypted HTTP: blocked because {blocker}"),
                blocker,
            );
        }

        match self.plaintext_bridge {
            TransparentInterceptionMitmPlaintextBridgePlan::Disabled => {
                MitmDataPathDiagnosis::disabled(
                    "path labels: disabled until MITM plaintext bridge feeds traffic events",
                    "plain HTTP: unavailable until MITM plaintext bridge is enabled",
                    "TLS-decrypted HTTP: unavailable until MITM plaintext bridge is enabled",
                    format!(
                        "MITM path needs a plaintext bridge to feed captured {MITM_PLAINTEXT_COVERAGE} into traffic events"
                    ),
                )
            }
            TransparentInterceptionMitmPlaintextBridgePlan::CaptureEventFeed { .. } => {
                if let Some(reason) = self.runtime_plaintext_bridge_disabled_reason() {
                    return MitmDataPathDiagnosis::labeled(
                        format!(
                            "plain HTTP: blocked because MITM plaintext bridge runtime is disabled: {reason}"
                        ),
                        format!(
                            "TLS-decrypted HTTP: blocked because MITM plaintext bridge runtime is disabled: {reason}"
                        ),
                        format!("MITM backend is unhealthy: {reason}"),
                    );
                }

                if let Some(reason) = self.runtime_backend_unhealthy_reason() {
                    return MitmDataPathDiagnosis::labeled(
                        format!("plain HTTP: blocked because MITM backend is unhealthy: {reason}"),
                        format!(
                            "TLS-decrypted HTTP: blocked because MITM backend is unhealthy: {reason}"
                        ),
                        format!("MITM backend is unhealthy: {reason}"),
                    );
                }

                let plain_http = format!(
                    "plain HTTP: visible as {MITM_HTTP_PATH_LABEL} without TLS client trust"
                );
                let tls_line = match self.client_trust {
                    TransparentInterceptionMitmClientTrustPlan::Disabled => {
                        "TLS-decrypted HTTP: blocked until MITM client trust is configured"
                            .to_string()
                    }
                    TransparentInterceptionMitmClientTrustPlan::OperatorManaged => {
                        self.operator_managed_tls_line()
                    }
                };
                MitmDataPathDiagnosis::labeled(plain_http, tls_line, self.tls_next_action())
            }
        }
    }

    fn operator_managed_tls_line(&self) -> String {
        if let Some(blocker) = self.trust_materials.first_unavailable_summary() {
            return format!("TLS-decrypted HTTP: blocked because {blocker}");
        }
        if let Some(unknown) = self.trust_materials.first_unknown_summary() {
            return format!("TLS-decrypted HTTP: unknown because {unknown}");
        }
        format!(
            "TLS-decrypted HTTP: visible as {MITM_TLS_PATH_LABEL} after {}",
            self.client_trust_action()
        )
    }

    fn tls_next_action(&self) -> String {
        match self.client_trust {
            TransparentInterceptionMitmClientTrustPlan::Disabled => {
                mitm_client_trust_next_step(self.client_trust_action())
            }
            TransparentInterceptionMitmClientTrustPlan::OperatorManaged => {
                if let Some(blocker) = self.trust_materials.first_unavailable_summary() {
                    return format!("MITM TLS material needs attention: {blocker}");
                }
                if let Some(unknown) = self.trust_materials.first_unknown_summary() {
                    return format!("MITM TLS material status is unknown: {unknown}");
                }
                mitm_client_trust_next_step(self.client_trust_action())
            }
        }
    }

    fn client_trust_action(&self) -> String {
        mitm_client_trust_action(&self.client_trust, &self.trust_materials)
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

    fn runtime_backend_unhealthy_reason(&self) -> Option<&str> {
        let runtime = self.runtime_l7_mitm.as_ref()?;
        (runtime.backend_health.mode == TcpHealthMode::Unhealthy).then_some(
            runtime
                .backend_health
                .last_failure_reason
                .as_deref()
                .unwrap_or("health probe is unhealthy"),
        )
    }

    fn first_unavailable_capability(&self) -> Option<&RequiredCapabilityPlan> {
        self.capabilities
            .iter()
            .find(|capability| capability.mode == RuntimeMode::Unavailable)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MitmDataPathDiagnosis {
    path_labels: String,
    plain_http: String,
    tls_http: String,
    next_action: String,
}

impl MitmDataPathDiagnosis {
    fn disabled(
        path_labels: impl Into<String>,
        plain_http: impl Into<String>,
        tls_http: impl Into<String>,
        next_action: impl Into<String>,
    ) -> Self {
        Self {
            path_labels: path_labels.into(),
            plain_http: plain_http.into(),
            tls_http: tls_http.into(),
            next_action: next_action.into(),
        }
    }

    fn labeled(
        plain_http: impl Into<String>,
        tls_http: impl Into<String>,
        next_action: impl Into<String>,
    ) -> Self {
        Self {
            path_labels: format!(
                "path labels: {MITM_HTTP_PATH_LABEL}=plain HTTP, {MITM_TLS_PATH_LABEL}=TLS-decrypted HTTP"
            ),
            plain_http: plain_http.into(),
            tls_http: tls_http.into(),
            next_action: next_action.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MitmTlsMaterialDiagnostics {
    materials: Vec<MitmTlsMaterialSource>,
}

impl MitmTlsMaterialDiagnostics {
    pub(super) fn from_tls_status(value: serde_json::Value) -> Result<Self, serde_json::Error> {
        let status = serde_json::from_value::<TlsStatusWire>(value)?;
        Ok(Self {
            materials: status
                .materials
                .into_iter()
                .map(|material| MitmTlsMaterialSource {
                    kind: material.kind,
                    path: material.path,
                    mode: material.source.mode,
                    reason: material.source.reason,
                })
                .collect(),
        })
    }

    fn source_for(&self, material: &TlsMaterialPlan) -> Option<MitmTlsMaterialSourceStatus> {
        self.materials
            .iter()
            .find(|source| source.kind == material.kind && source.path == material.path)
            .map(|source| MitmTlsMaterialSourceStatus::Known {
                mode: source.mode,
                reason: source.reason.clone(),
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MitmTrustMaterialDiagnostics {
    termination_source: MitmTlsTerminationSource,
}

impl MitmTrustMaterialDiagnostics {
    fn from_materials(
        ca_certificate: Option<TlsMaterialPlan>,
        ca_private_key: Option<TlsMaterialPlan>,
        leaf_certificate_chain: Vec<TlsMaterialPlan>,
        leaf_private_key: Option<TlsMaterialPlan>,
        tls_materials: Option<&MitmTlsMaterialDiagnostics>,
    ) -> Self {
        let ca_pair = ca_certificate
            .zip(ca_private_key)
            .map(|(certificate, private_key)| {
                (
                    MitmTrustMaterial::new("MITM CA certificate", certificate, tls_materials),
                    MitmTrustMaterial::new("MITM CA private key", private_key, tls_materials),
                )
            });
        let leaf_pair = (!leaf_certificate_chain.is_empty())
            .then_some(leaf_certificate_chain)
            .zip(leaf_private_key)
            .map(|(certificate_chain, private_key)| {
                (
                    leaf_certificate_chain_materials(certificate_chain, tls_materials),
                    MitmTrustMaterial::new("MITM leaf private key", private_key, tls_materials),
                )
            });
        let termination_source = match (ca_pair, leaf_pair) {
            (
                Some((ca_certificate, ca_private_key)),
                Some((leaf_certificate_chain, leaf_private_key)),
            ) => MitmTlsTerminationSource::CaAndLeaf {
                ca_certificate,
                ca_private_key,
                leaf_certificate_chain,
                leaf_private_key,
            },
            (Some((certificate, private_key)), None) => MitmTlsTerminationSource::DynamicCa {
                certificate,
                private_key,
            },
            (None, Some((certificate_chain, private_key))) => {
                MitmTlsTerminationSource::StaticLeaf {
                    certificate_chain,
                    private_key,
                }
            }
            _ => MitmTlsTerminationSource::NotConfigured,
        };
        Self { termination_source }
    }

    fn client_trust_action(&self) -> &'static str {
        match &self.termination_source {
            MitmTlsTerminationSource::DynamicCa { .. } => MITM_TLS_TRUST_ACTION,
            MitmTlsTerminationSource::CaAndLeaf { .. } => {
                "install the generated MITM CA and trust the configured MITM leaf certificate chain or issuing CA to see TLS-decrypted HTTP"
            }
            MitmTlsTerminationSource::StaticLeaf { .. } => {
                "trust the configured MITM leaf certificate chain or issuing CA to see TLS-decrypted HTTP"
            }
            MitmTlsTerminationSource::NotConfigured => {
                "configure MITM TLS termination material before expecting TLS-decrypted HTTP"
            }
        }
    }

    fn detail_lines(&self) -> Vec<String> {
        match &self.termination_source {
            MitmTlsTerminationSource::DynamicCa {
                certificate,
                private_key,
            } => vec![
                mitm_trust_material_line(certificate),
                mitm_trust_material_line(private_key),
            ],
            MitmTlsTerminationSource::CaAndLeaf {
                ca_certificate,
                ca_private_key,
                leaf_certificate_chain,
                leaf_private_key,
            } => [ca_certificate, ca_private_key]
                .into_iter()
                .chain(leaf_certificate_chain.iter())
                .chain(std::iter::once(leaf_private_key))
                .map(mitm_trust_material_line)
                .collect(),
            MitmTlsTerminationSource::StaticLeaf {
                certificate_chain,
                private_key,
            } => certificate_chain
                .iter()
                .chain(std::iter::once(private_key))
                .map(mitm_trust_material_line)
                .collect(),
            MitmTlsTerminationSource::NotConfigured => {
                vec!["mitm TLS termination material: not configured".to_string()]
            }
        }
    }

    fn first_unavailable_summary(&self) -> Option<String> {
        self.termination_materials()
            .into_iter()
            .find_map(mitm_trust_material_unavailable_summary)
    }

    fn first_unknown_summary(&self) -> Option<String> {
        self.termination_materials()
            .into_iter()
            .find_map(mitm_trust_material_unknown_summary)
            .or_else(|| {
                matches!(
                    &self.termination_source,
                    MitmTlsTerminationSource::NotConfigured
                )
                .then_some("MITM TLS termination material is not configured".to_string())
            })
    }

    fn termination_materials(&self) -> Vec<&MitmTrustMaterial> {
        match &self.termination_source {
            MitmTlsTerminationSource::DynamicCa {
                certificate,
                private_key,
            } => vec![certificate, private_key],
            MitmTlsTerminationSource::CaAndLeaf {
                ca_certificate,
                ca_private_key,
                leaf_certificate_chain,
                leaf_private_key,
            } => vec![ca_certificate, ca_private_key]
                .into_iter()
                .chain(leaf_certificate_chain.iter())
                .chain(std::iter::once(leaf_private_key))
                .collect(),
            MitmTlsTerminationSource::StaticLeaf {
                certificate_chain,
                private_key,
            } => certificate_chain
                .iter()
                .chain(std::iter::once(private_key))
                .collect(),
            MitmTlsTerminationSource::NotConfigured => Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MitmTrustMaterial {
    label: String,
    material: TlsMaterialPlan,
    source: MitmTlsMaterialSourceStatus,
}

impl MitmTrustMaterial {
    fn new(
        label: impl Into<String>,
        material: TlsMaterialPlan,
        tls_materials: Option<&MitmTlsMaterialDiagnostics>,
    ) -> Self {
        let source = tls_materials
            .and_then(|tls_materials| tls_materials.source_for(&material))
            .unwrap_or(MitmTlsMaterialSourceStatus::Unknown);
        Self {
            label: label.into(),
            material,
            source,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MitmTlsTerminationSource {
    DynamicCa {
        certificate: MitmTrustMaterial,
        private_key: MitmTrustMaterial,
    },
    CaAndLeaf {
        ca_certificate: MitmTrustMaterial,
        ca_private_key: MitmTrustMaterial,
        leaf_certificate_chain: Vec<MitmTrustMaterial>,
        leaf_private_key: MitmTrustMaterial,
    },
    StaticLeaf {
        certificate_chain: Vec<MitmTrustMaterial>,
        private_key: MitmTrustMaterial,
    },
    NotConfigured,
}

fn leaf_certificate_chain_materials(
    certificate_chain: Vec<TlsMaterialPlan>,
    tls_materials: Option<&MitmTlsMaterialDiagnostics>,
) -> Vec<MitmTrustMaterial> {
    certificate_chain
        .into_iter()
        .enumerate()
        .map(|(index, material)| {
            MitmTrustMaterial::new(
                format!("MITM leaf certificate chain[{index}]"),
                material,
                tls_materials,
            )
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MitmTlsMaterialSource {
    kind: TlsMaterialKind,
    path: PathBuf,
    mode: RuntimeMode,
    reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MitmTlsMaterialSourceStatus {
    Known {
        mode: RuntimeMode,
        reason: Option<String>,
    },
    Unknown,
}

#[derive(Deserialize)]
struct TlsStatusWire {
    #[serde(default)]
    materials: Vec<TlsMaterialStatusWire>,
}

#[derive(Deserialize)]
struct TlsMaterialStatusWire {
    kind: TlsMaterialKind,
    path: PathBuf,
    source: TlsMaterialSourceWire,
}

#[derive(Deserialize)]
struct TlsMaterialSourceWire {
    mode: RuntimeMode,
    reason: Option<String>,
}

fn mitm_trust_material_line(material: &MitmTrustMaterial) -> String {
    let mut line = format!("{}: {}", material.label, material.material.path.display());
    match &material.source {
        MitmTlsMaterialSourceStatus::Known { mode, reason } => {
            line.push_str(&format!(" source={}", runtime_mode_name(*mode)));
            if let Some(reason) = reason {
                line.push_str(&format!(" reason={reason}"));
            }
        }
        MitmTlsMaterialSourceStatus::Unknown => line.push_str(" source=unknown"),
    }
    line
}

fn mitm_trust_material_unavailable_summary(material: &MitmTrustMaterial) -> Option<String> {
    match &material.source {
        MitmTlsMaterialSourceStatus::Known {
            mode: RuntimeMode::Unavailable,
            reason,
        } => {
            let mut summary = format!("{} source is unavailable", material.label);
            if let Some(reason) = reason {
                summary.push_str(&format!(": {reason}"));
            }
            Some(summary)
        }
        MitmTlsMaterialSourceStatus::Known { .. } | MitmTlsMaterialSourceStatus::Unknown => None,
    }
}

fn mitm_trust_material_unknown_summary(material: &MitmTrustMaterial) -> Option<String> {
    matches!(material.source, MitmTlsMaterialSourceStatus::Unknown)
        .then(|| format!("{} source status is unknown", material.label))
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

fn mitm_client_trust_next_step(action: String) -> String {
    format!("MITM TLS trust needs attention: {action}")
}

fn mitm_client_trust_action(
    client_trust: &TransparentInterceptionMitmClientTrustPlan,
    trust_materials: &MitmTrustMaterialDiagnostics,
) -> String {
    match client_trust {
        TransparentInterceptionMitmClientTrustPlan::Disabled => {
            "configure MITM client trust before expecting TLS-decrypted HTTP".to_string()
        }
        TransparentInterceptionMitmClientTrustPlan::OperatorManaged => {
            trust_materials.client_trust_action().to_string()
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
