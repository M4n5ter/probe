use std::{
    net::{IpAddr, SocketAddr},
    num::NonZeroU16,
    path::PathBuf,
};

use probe_core::{EnforcementMode, ProtectiveActionProfile, Selector};
use serde::{Deserialize, Serialize};

pub const DEFAULT_TRANSPARENT_PROXY_HEALTH_PROBE_INTERVAL_MS: u64 = 1_000;
pub const DEFAULT_TRANSPARENT_PROXY_HEALTH_PROBE_TIMEOUT_MS: u64 = 200;
pub const DEFAULT_TRANSPARENT_PROXY_HEALTH_PROBE_FAILURE_THRESHOLD: u32 = 3;
pub const MIN_TRANSPARENT_PROXY_HEALTH_PROBE_INTERVAL_MS: u64 = 100;
pub const MAX_TRANSPARENT_PROXY_HEALTH_PROBE_INTERVAL_MS: u64 = 60_000;
pub const MIN_TRANSPARENT_PROXY_HEALTH_PROBE_TIMEOUT_MS: u64 = 10;
pub const MAX_TRANSPARENT_PROXY_HEALTH_PROBE_TIMEOUT_MS: u64 = 5_000;
pub const MIN_TRANSPARENT_PROXY_HEALTH_PROBE_FAILURE_THRESHOLD: u32 = 1;
pub const MAX_TRANSPARENT_PROXY_HEALTH_PROBE_FAILURE_THRESHOLD: u32 = 100;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnforcementConfig {
    pub mode: EnforcementMode,
    pub backend: ConnectionEnforcementBackendConfig,
    pub selector: Option<Selector>,
    pub interception: EnforcementInterceptionConfig,
    pub policy: EnforcementPolicyConfig,
}

impl Default for EnforcementConfig {
    fn default() -> Self {
        Self {
            mode: EnforcementMode::AuditOnly,
            backend: ConnectionEnforcementBackendConfig::None,
            selector: None,
            interception: EnforcementInterceptionConfig::default(),
            policy: EnforcementPolicyConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionEnforcementBackendConfig {
    #[default]
    None,
    LinuxSocketDestroy,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnforcementInterceptionConfig {
    pub strategy: TransparentInterceptionStrategyConfig,
    pub selector: Option<Selector>,
    pub proxy: TransparentInterceptionProxyConfig,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransparentInterceptionStrategyConfig {
    #[default]
    None,
    InboundTproxy,
    OutboundTransparentProxy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransparentInterceptionProxyIntent {
    Disabled(TransparentInterceptionDisabledProxyIntent),
    InboundTproxy(TransparentInterceptionEnabledProxyIntent),
    OutboundTransparentProxy(TransparentInterceptionOutboundProxyIntent),
}

impl TransparentInterceptionProxyIntent {
    pub fn strategy(&self) -> TransparentInterceptionStrategyConfig {
        match self {
            Self::Disabled(_) => TransparentInterceptionStrategyConfig::None,
            Self::InboundTproxy(_) => TransparentInterceptionStrategyConfig::InboundTproxy,
            Self::OutboundTransparentProxy(_) => {
                TransparentInterceptionStrategyConfig::OutboundTransparentProxy
            }
        }
    }

    pub fn mode(&self) -> TransparentInterceptionProxyModeConfig {
        match self {
            Self::Disabled(proxy) => proxy.mode,
            Self::InboundTproxy(proxy) => proxy.mode,
            Self::OutboundTransparentProxy(proxy) => proxy.mode(),
        }
    }

    pub fn listen_port(&self) -> Option<NonZeroU16> {
        match self {
            Self::Disabled(proxy) => proxy.listen_port,
            Self::InboundTproxy(proxy) => Some(proxy.listen_port),
            Self::OutboundTransparentProxy(proxy) => Some(proxy.listen_port()),
        }
    }

    pub fn health_probe(&self) -> TransparentInterceptionProxyHealthProbeIntent {
        match self {
            Self::Disabled(proxy) => proxy.health_probe.clone(),
            Self::InboundTproxy(proxy) => proxy.health_probe.clone(),
            Self::OutboundTransparentProxy(_) => {
                TransparentInterceptionProxyHealthProbeIntent::Disabled
            }
        }
    }

    pub fn self_bypass(&self) -> TransparentInterceptionProxySelfBypassConfig {
        match self {
            Self::Disabled(_) | Self::InboundTproxy(_) => {
                TransparentInterceptionProxySelfBypassConfig::None
            }
            Self::OutboundTransparentProxy(proxy) => proxy.self_bypass(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentInterceptionDisabledProxyIntent {
    mode: TransparentInterceptionProxyModeConfig,
    listen_port: Option<NonZeroU16>,
    health_probe: TransparentInterceptionProxyHealthProbeIntent,
}

impl TransparentInterceptionDisabledProxyIntent {
    pub fn mode(&self) -> TransparentInterceptionProxyModeConfig {
        self.mode
    }

    pub fn listen_port(&self) -> Option<NonZeroU16> {
        self.listen_port
    }

    pub fn health_probe(&self) -> &TransparentInterceptionProxyHealthProbeIntent {
        &self.health_probe
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentInterceptionEnabledProxyIntent {
    mode: TransparentInterceptionProxyModeConfig,
    listen_port: NonZeroU16,
    health_probe: TransparentInterceptionProxyHealthProbeIntent,
}

impl TransparentInterceptionEnabledProxyIntent {
    pub fn mode(&self) -> TransparentInterceptionProxyModeConfig {
        self.mode
    }

    pub fn listen_port(&self) -> NonZeroU16 {
        self.listen_port
    }

    pub fn health_probe(&self) -> &TransparentInterceptionProxyHealthProbeIntent {
        &self.health_probe
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentInterceptionOutboundProxyIntent {
    mode: TransparentInterceptionOutboundProxyModeIntent,
    listen_port: NonZeroU16,
}

impl TransparentInterceptionOutboundProxyIntent {
    pub fn mode(&self) -> TransparentInterceptionProxyModeConfig {
        self.mode.mode()
    }

    pub fn lifecycle(&self) -> &TransparentInterceptionOutboundProxyModeIntent {
        &self.mode
    }

    pub fn listen_port(&self) -> NonZeroU16 {
        self.listen_port
    }

    pub fn self_bypass(&self) -> TransparentInterceptionProxySelfBypassConfig {
        self.mode.self_bypass()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransparentInterceptionOutboundProxyModeIntent {
    ManagedTcpRelay,
    External {
        self_bypass: TransparentInterceptionOutboundProxySelfBypassIntent,
    },
}

impl TransparentInterceptionOutboundProxyModeIntent {
    pub fn mode(self) -> TransparentInterceptionProxyModeConfig {
        match self {
            Self::ManagedTcpRelay => TransparentInterceptionProxyModeConfig::ManagedTcpRelay,
            Self::External { .. } => TransparentInterceptionProxyModeConfig::External,
        }
    }

    pub fn self_bypass(self) -> TransparentInterceptionProxySelfBypassConfig {
        match self {
            Self::ManagedTcpRelay => TransparentInterceptionProxySelfBypassConfig::None,
            Self::External { self_bypass } => self_bypass.config(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransparentInterceptionOutboundProxySelfBypassIntent {
    UsesReservedMark,
}

impl TransparentInterceptionOutboundProxySelfBypassIntent {
    pub fn config(self) -> TransparentInterceptionProxySelfBypassConfig {
        match self {
            Self::UsesReservedMark => {
                TransparentInterceptionProxySelfBypassConfig::UsesReservedMark
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransparentInterceptionProxyHealthProbeIntent {
    Disabled,
    Enabled {
        target: SocketAddr,
        interval_ms: u64,
        timeout_ms: u64,
        failure_threshold: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentInterceptionProxyIntentViolation {
    field: &'static str,
    reason: String,
}

impl TransparentInterceptionProxyIntentViolation {
    pub fn field(&self) -> &'static str {
        self.field
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }
}

impl TransparentInterceptionStrategyConfig {
    pub fn is_enabled(self) -> bool {
        !matches!(self, Self::None)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TransparentInterceptionProxyConfig {
    pub mode: TransparentInterceptionProxyModeConfig,
    pub self_bypass: TransparentInterceptionProxySelfBypassConfig,
    pub listen_port: Option<u16>,
    pub health_probe: TransparentInterceptionProxyHealthProbeConfig,
}

impl EnforcementInterceptionConfig {
    pub fn transparent_proxy_intent(
        &self,
    ) -> Result<TransparentInterceptionProxyIntent, Vec<TransparentInterceptionProxyIntentViolation>>
    {
        let mut violations = Vec::new();

        if self.proxy.mode == TransparentInterceptionProxyModeConfig::ManagedTcpRelay
            && self.strategy == TransparentInterceptionStrategyConfig::None
        {
            violations.push(intent_violation(
                "enforcement.interception.proxy.mode",
                "managed TCP relay proxy mode requires an enabled transparent interception strategy",
            ));
        }
        let self_bypass_contract = resolve_self_bypass_contract(self);
        self_bypass_contract.record_violation(&mut violations);

        let listen_port = self.proxy.listen_port.and_then(NonZeroU16::new);
        if self.strategy.is_enabled() && listen_port.is_none() {
            violations.push(intent_violation(
                "enforcement.interception.proxy.listen_port",
                "transparent interception requires a non-zero proxy listen port",
            ));
        }

        let parsed_health_probe_target =
            validate_transparent_proxy_health_probe(self, &mut violations);

        if !violations.is_empty() {
            return Err(violations);
        }

        let health_probe = match parsed_health_probe_target {
            Some(target) => TransparentInterceptionProxyHealthProbeIntent::Enabled {
                target,
                interval_ms: self.proxy.health_probe.interval_ms,
                timeout_ms: self.proxy.health_probe.timeout_ms,
                failure_threshold: self.proxy.health_probe.failure_threshold,
            },
            None => TransparentInterceptionProxyHealthProbeIntent::Disabled,
        };
        let intent = match self.strategy {
            TransparentInterceptionStrategyConfig::None => {
                TransparentInterceptionProxyIntent::Disabled(
                    TransparentInterceptionDisabledProxyIntent {
                        mode: self.proxy.mode,
                        listen_port,
                        health_probe,
                    },
                )
            }
            TransparentInterceptionStrategyConfig::InboundTproxy => {
                let Some(listen_port) = listen_port else {
                    return Err(vec![intent_violation(
                        "enforcement.interception.proxy.listen_port",
                        "transparent interception requires a non-zero proxy listen port",
                    )]);
                };
                TransparentInterceptionProxyIntent::InboundTproxy(
                    TransparentInterceptionEnabledProxyIntent {
                        mode: self.proxy.mode,
                        listen_port,
                        health_probe,
                    },
                )
            }
            TransparentInterceptionStrategyConfig::OutboundTransparentProxy => {
                let Some(listen_port) = listen_port else {
                    return Err(vec![intent_violation(
                        "enforcement.interception.proxy.listen_port",
                        "transparent interception requires a non-zero proxy listen port",
                    )]);
                };
                let TransparentProxySelfBypassContract::Outbound(mode) = self_bypass_contract
                else {
                    return Err(vec![intent_violation(
                        "enforcement.interception.proxy.self_bypass",
                        "outbound transparent proxy requires a valid proxy lifecycle",
                    )]);
                };
                TransparentInterceptionProxyIntent::OutboundTransparentProxy(
                    TransparentInterceptionOutboundProxyIntent { mode, listen_port },
                )
            }
        };
        Ok(intent)
    }
}

enum TransparentProxySelfBypassContract {
    NotOutbound,
    Outbound(TransparentInterceptionOutboundProxyModeIntent),
    Violation(TransparentInterceptionProxyIntentViolation),
}

impl TransparentProxySelfBypassContract {
    fn record_violation(&self, violations: &mut Vec<TransparentInterceptionProxyIntentViolation>) {
        if let Self::Violation(violation) = self {
            violations.push(violation.clone());
        }
    }
}

fn validate_transparent_proxy_health_probe(
    interception: &EnforcementInterceptionConfig,
    violations: &mut Vec<TransparentInterceptionProxyIntentViolation>,
) -> Option<SocketAddr> {
    let health_probe = &interception.proxy.health_probe;
    let Some(target) = &health_probe.target else {
        return None;
    };
    if interception.strategy == TransparentInterceptionStrategyConfig::None {
        violations.push(intent_violation(
            "enforcement.interception.proxy.health_probe.target",
            "transparent proxy health probe requires an enabled interception strategy",
        ));
    }
    if interception.strategy == TransparentInterceptionStrategyConfig::OutboundTransparentProxy {
        violations.push(intent_violation(
            "enforcement.interception.proxy.health_probe.target",
            "transparent proxy health probe is currently executable for inbound TPROXY only",
        ));
    }
    let parsed_target = match target.parse::<SocketAddr>() {
        Ok(address) if address.port() == 0 => {
            violations.push(intent_violation(
                "enforcement.interception.proxy.health_probe.target",
                "transparent proxy health probe target must use a non-zero port",
            ));
            None
        }
        Ok(address) => Some(address),
        Err(_) => {
            violations.push(intent_violation(
                "enforcement.interception.proxy.health_probe.target",
                "transparent proxy health probe target must be an IP socket address",
            ));
            None
        }
    };
    if let (
        Some(target),
        TransparentInterceptionProxyModeConfig::ManagedTcpRelay,
        Some(listen_port),
    ) = (
        parsed_target,
        interception.proxy.mode,
        interception.proxy.listen_port,
    ) && health_probe_target_matches_managed_relay_listener(target, listen_port)
    {
        violations.push(intent_violation(
            "enforcement.interception.proxy.health_probe.target",
            "managed TCP relay health probe target must not point at the local relay listener",
        ));
    }
    validate_health_probe_range(
        "enforcement.interception.proxy.health_probe.interval_ms",
        health_probe.interval_ms,
        MIN_TRANSPARENT_PROXY_HEALTH_PROBE_INTERVAL_MS,
        MAX_TRANSPARENT_PROXY_HEALTH_PROBE_INTERVAL_MS,
        "transparent proxy health probe interval",
        violations,
    );
    validate_health_probe_range(
        "enforcement.interception.proxy.health_probe.timeout_ms",
        health_probe.timeout_ms,
        MIN_TRANSPARENT_PROXY_HEALTH_PROBE_TIMEOUT_MS,
        MAX_TRANSPARENT_PROXY_HEALTH_PROBE_TIMEOUT_MS,
        "transparent proxy health probe timeout",
        violations,
    );
    validate_health_probe_range(
        "enforcement.interception.proxy.health_probe.failure_threshold",
        u64::from(health_probe.failure_threshold),
        u64::from(MIN_TRANSPARENT_PROXY_HEALTH_PROBE_FAILURE_THRESHOLD),
        u64::from(MAX_TRANSPARENT_PROXY_HEALTH_PROBE_FAILURE_THRESHOLD),
        "transparent proxy health probe failure threshold",
        violations,
    );
    if health_probe.timeout_ms > health_probe.interval_ms {
        violations.push(intent_violation(
            "enforcement.interception.proxy.health_probe.timeout_ms",
            "transparent proxy health probe timeout must not exceed interval",
        ));
    }
    parsed_target
}

fn resolve_self_bypass_contract(
    interception: &EnforcementInterceptionConfig,
) -> TransparentProxySelfBypassContract {
    let self_bypass = interception.proxy.self_bypass;

    if interception.strategy != TransparentInterceptionStrategyConfig::OutboundTransparentProxy {
        if self_bypass == TransparentInterceptionProxySelfBypassConfig::UsesReservedMark {
            return TransparentProxySelfBypassContract::Violation(intent_violation(
                "enforcement.interception.proxy.self_bypass",
                "reserved-mark self-bypass is only valid for external outbound transparent proxy",
            ));
        }
        return TransparentProxySelfBypassContract::NotOutbound;
    }

    match (interception.proxy.mode, self_bypass) {
        (
            TransparentInterceptionProxyModeConfig::ManagedTcpRelay,
            TransparentInterceptionProxySelfBypassConfig::None,
        ) => TransparentProxySelfBypassContract::Outbound(
            TransparentInterceptionOutboundProxyModeIntent::ManagedTcpRelay,
        ),
        (
            TransparentInterceptionProxyModeConfig::ManagedTcpRelay,
            TransparentInterceptionProxySelfBypassConfig::UsesReservedMark,
        ) => TransparentProxySelfBypassContract::Violation(intent_violation(
            "enforcement.interception.proxy.self_bypass",
            "reserved-mark self-bypass is only valid for external outbound transparent proxy",
        )),
        (
            TransparentInterceptionProxyModeConfig::External,
            TransparentInterceptionProxySelfBypassConfig::UsesReservedMark,
        ) => TransparentProxySelfBypassContract::Outbound(
            TransparentInterceptionOutboundProxyModeIntent::External {
                self_bypass: TransparentInterceptionOutboundProxySelfBypassIntent::UsesReservedMark,
            },
        ),
        (
            TransparentInterceptionProxyModeConfig::External,
            TransparentInterceptionProxySelfBypassConfig::None,
        ) => TransparentProxySelfBypassContract::Violation(intent_violation(
            "enforcement.interception.proxy.self_bypass",
            "external outbound transparent proxy requires self_bypass = \"uses_reserved_mark\" so its upstream and control-plane sockets can bypass the agent-owned OUTPUT redirect",
        )),
    }
}

fn validate_health_probe_range(
    field: &'static str,
    value: u64,
    min: u64,
    max: u64,
    label: &str,
    violations: &mut Vec<TransparentInterceptionProxyIntentViolation>,
) {
    if !(min..=max).contains(&value) {
        violations.push(intent_violation(
            field,
            format!("{label} must be between {min} and {max}"),
        ));
    }
}

fn health_probe_target_matches_managed_relay_listener(
    target: SocketAddr,
    listen_port: u16,
) -> bool {
    target.port() == listen_port && is_local_listener_address(target.ip())
}

fn is_local_listener_address(address: IpAddr) -> bool {
    match normalized_ip_address(address) {
        IpAddr::V4(address) => address.is_loopback() || address.is_unspecified(),
        IpAddr::V6(address) => address.is_loopback() || address.is_unspecified(),
    }
}

fn normalized_ip_address(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V4(_) => address,
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
    }
}

fn intent_violation(
    field: &'static str,
    reason: impl Into<String>,
) -> TransparentInterceptionProxyIntentViolation {
    TransparentInterceptionProxyIntentViolation {
        field,
        reason: reason.into(),
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransparentInterceptionProxyModeConfig {
    #[default]
    External,
    ManagedTcpRelay,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransparentInterceptionProxySelfBypassConfig {
    #[default]
    None,
    UsesReservedMark,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TransparentInterceptionProxyHealthProbeConfig {
    pub target: Option<String>,
    pub interval_ms: u64,
    pub timeout_ms: u64,
    pub failure_threshold: u32,
}

impl Default for TransparentInterceptionProxyHealthProbeConfig {
    fn default() -> Self {
        Self {
            target: None,
            interval_ms: DEFAULT_TRANSPARENT_PROXY_HEALTH_PROBE_INTERVAL_MS,
            timeout_ms: DEFAULT_TRANSPARENT_PROXY_HEALTH_PROBE_TIMEOUT_MS,
            failure_threshold: DEFAULT_TRANSPARENT_PROXY_HEALTH_PROBE_FAILURE_THRESHOLD,
        }
    }
}

impl TransparentInterceptionProxyHealthProbeConfig {
    pub fn is_enabled(&self) -> bool {
        self.target.is_some()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnforcementPolicyConfig {
    pub source: EnforcementPolicySourceConfig,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum EnforcementPolicySourceConfig {
    #[default]
    None,
    File {
        path: PathBuf,
    },
    Directory {
        path: PathBuf,
    },
    Remote {
        endpoint: String,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnforcementPolicyManifest {
    pub id: String,
    pub version: String,
    pub selector: Option<Selector>,
    pub protective_actions: ProtectiveActionProfile,
}
