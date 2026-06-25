use std::{
    net::{IpAddr, SocketAddr},
    num::NonZeroU16,
    path::PathBuf,
};

use serde::{Deserialize, Serialize};

use super::{
    EnforcementInterceptionConfig, TransparentInterceptionIntentViolation,
    health_probe::{
        DEFAULT_TCP_HEALTH_PROBE_FAILURE_THRESHOLD, DEFAULT_TCP_HEALTH_PROBE_INTERVAL_MS,
        DEFAULT_TCP_HEALTH_PROBE_TIMEOUT_MS, MAX_TCP_HEALTH_PROBE_FAILURE_THRESHOLD,
        MAX_TCP_HEALTH_PROBE_INTERVAL_MS, MAX_TCP_HEALTH_PROBE_TIMEOUT_MS,
        MIN_TCP_HEALTH_PROBE_FAILURE_THRESHOLD, MIN_TCP_HEALTH_PROBE_INTERVAL_MS,
        MIN_TCP_HEALTH_PROBE_TIMEOUT_MS, TcpHealthProbeTimingFields,
        validate_tcp_health_probe_timing,
    },
    intent_violation, normalized_ip_address,
};

pub const DEFAULT_TRANSPARENT_MITM_BACKEND_READINESS_TIMEOUT_MS: u64 =
    DEFAULT_TCP_HEALTH_PROBE_TIMEOUT_MS;
pub const DEFAULT_TRANSPARENT_MITM_BACKEND_READINESS_INTERVAL_MS: u64 =
    DEFAULT_TCP_HEALTH_PROBE_INTERVAL_MS;
pub const DEFAULT_TRANSPARENT_MITM_BACKEND_READINESS_FAILURE_THRESHOLD: u32 =
    DEFAULT_TCP_HEALTH_PROBE_FAILURE_THRESHOLD;
pub const MIN_TRANSPARENT_MITM_BACKEND_READINESS_TIMEOUT_MS: u64 = MIN_TCP_HEALTH_PROBE_TIMEOUT_MS;
pub const MAX_TRANSPARENT_MITM_BACKEND_READINESS_TIMEOUT_MS: u64 = MAX_TCP_HEALTH_PROBE_TIMEOUT_MS;
pub const MIN_TRANSPARENT_MITM_BACKEND_READINESS_INTERVAL_MS: u64 =
    MIN_TCP_HEALTH_PROBE_INTERVAL_MS;
pub const MAX_TRANSPARENT_MITM_BACKEND_READINESS_INTERVAL_MS: u64 =
    MAX_TCP_HEALTH_PROBE_INTERVAL_MS;
pub const MIN_TRANSPARENT_MITM_BACKEND_READINESS_FAILURE_THRESHOLD: u32 =
    MIN_TCP_HEALTH_PROBE_FAILURE_THRESHOLD;
pub const MAX_TRANSPARENT_MITM_BACKEND_READINESS_FAILURE_THRESHOLD: u32 =
    MAX_TCP_HEALTH_PROBE_FAILURE_THRESHOLD;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TransparentInterceptionMitmConfig {
    pub backend: TransparentInterceptionMitmBackendConfig,
    pub backend_readiness_probe: TransparentInterceptionMitmBackendReadinessProbeConfig,
    pub plaintext_bridge: TransparentInterceptionMitmPlaintextBridgeConfig,
    pub ca_certificate_ref: Option<String>,
    pub ca_private_key_ref: Option<String>,
    pub leaf_certificate_chain_refs: Vec<String>,
    pub leaf_private_key_ref: Option<String>,
    pub upstream_trust_anchor_refs: Vec<String>,
}

impl TransparentInterceptionMitmConfig {
    pub fn is_configured(&self) -> bool {
        self.backend != TransparentInterceptionMitmBackendConfig::None
            || self.backend_readiness_probe.is_configured()
            || self.plaintext_bridge.is_configured()
            || self.ca_certificate_ref.is_some()
            || self.ca_private_key_ref.is_some()
            || !self.leaf_certificate_chain_refs.is_empty()
            || self.leaf_private_key_ref.is_some()
            || !self.upstream_trust_anchor_refs.is_empty()
    }

    pub fn has_ca_material_pair(&self) -> bool {
        self.ca_certificate_ref.is_some() && self.ca_private_key_ref.is_some()
    }

    pub fn has_leaf_material_pair(&self) -> bool {
        !self.leaf_certificate_chain_refs.is_empty() && self.leaf_private_key_ref.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TransparentInterceptionMitmBackendReadinessProbeConfig {
    pub target: Option<String>,
    pub interval_ms: u64,
    pub timeout_ms: u64,
    pub failure_threshold: u32,
}

impl TransparentInterceptionMitmBackendReadinessProbeConfig {
    pub fn is_configured(&self) -> bool {
        self.target.is_some()
            || self.interval_ms != DEFAULT_TRANSPARENT_MITM_BACKEND_READINESS_INTERVAL_MS
            || self.timeout_ms != DEFAULT_TRANSPARENT_MITM_BACKEND_READINESS_TIMEOUT_MS
            || self.failure_threshold
                != DEFAULT_TRANSPARENT_MITM_BACKEND_READINESS_FAILURE_THRESHOLD
    }
}

impl Default for TransparentInterceptionMitmBackendReadinessProbeConfig {
    fn default() -> Self {
        Self {
            target: None,
            interval_ms: DEFAULT_TRANSPARENT_MITM_BACKEND_READINESS_INTERVAL_MS,
            timeout_ms: DEFAULT_TRANSPARENT_MITM_BACKEND_READINESS_TIMEOUT_MS,
            failure_threshold: DEFAULT_TRANSPARENT_MITM_BACKEND_READINESS_FAILURE_THRESHOLD,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransparentInterceptionMitmBackendConfig {
    #[default]
    None,
    External,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TransparentInterceptionMitmPlaintextBridgeConfig {
    pub mode: TransparentInterceptionMitmPlaintextBridgeModeConfig,
    pub path: Option<PathBuf>,
    pub follow: Option<bool>,
}

impl TransparentInterceptionMitmPlaintextBridgeConfig {
    pub fn is_configured(&self) -> bool {
        self.mode != TransparentInterceptionMitmPlaintextBridgeModeConfig::None
            || self.path.is_some()
            || self.follow.is_some()
    }

    pub fn follow_enabled(&self) -> bool {
        self.follow.unwrap_or(true)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransparentInterceptionMitmPlaintextBridgeModeConfig {
    #[default]
    None,
    CaptureEventFeed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransparentInterceptionMitmBackendIntent {
    Disabled,
    External {
        readiness_probe: TransparentInterceptionMitmBackendReadinessProbeIntent,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransparentInterceptionMitmBackendReadinessProbeIntent {
    TcpConnect {
        target: SocketAddr,
        interval_ms: u64,
        timeout_ms: u64,
        failure_threshold: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransparentInterceptionMitmPlaintextBridgeIntent {
    Disabled,
    CaptureEventFeed { path: PathBuf, follow: bool },
}

pub type TransparentInterceptionMitmIntentViolation = TransparentInterceptionIntentViolation;

impl EnforcementInterceptionConfig {
    pub fn mitm_backend_intent(
        &self,
    ) -> Result<
        TransparentInterceptionMitmBackendIntent,
        Vec<TransparentInterceptionMitmIntentViolation>,
    > {
        if !self.strategy.is_mitm() {
            return Ok(TransparentInterceptionMitmBackendIntent::Disabled);
        }

        let mut violations = Vec::new();
        if self.mitm.backend != TransparentInterceptionMitmBackendConfig::External {
            violations.push(intent_violation(
                "enforcement.interception.mitm.backend",
                "MITM interception requires enforcement.interception.mitm.backend = \"external\" until a managed L7 backend exists",
            ));
        }
        let readiness_probe = validate_mitm_backend_readiness_probe(
            self.proxy.listen_port.and_then(NonZeroU16::new),
            &self.mitm.backend_readiness_probe,
            &mut violations,
        );

        if !violations.is_empty() {
            return Err(violations);
        }

        Ok(TransparentInterceptionMitmBackendIntent::External {
            readiness_probe: readiness_probe.expect(
                "external MITM backend readiness probe should be present when validation succeeds",
            ),
        })
    }

    pub fn mitm_plaintext_bridge_intent(
        &self,
    ) -> Result<
        TransparentInterceptionMitmPlaintextBridgeIntent,
        Vec<TransparentInterceptionMitmIntentViolation>,
    > {
        if !self.strategy.is_mitm() {
            return Ok(TransparentInterceptionMitmPlaintextBridgeIntent::Disabled);
        }

        let mut violations = Vec::new();
        let intent = validate_mitm_plaintext_bridge(&self.mitm.plaintext_bridge, &mut violations);
        if !violations.is_empty() {
            return Err(violations);
        }
        Ok(intent)
    }
}

fn validate_mitm_backend_readiness_probe(
    proxy_listen_port: Option<NonZeroU16>,
    probe: &TransparentInterceptionMitmBackendReadinessProbeConfig,
    violations: &mut Vec<TransparentInterceptionMitmIntentViolation>,
) -> Option<TransparentInterceptionMitmBackendReadinessProbeIntent> {
    let target = validate_mitm_backend_readiness_probe_target(proxy_listen_port, probe, violations);
    validate_mitm_backend_readiness_probe_ranges(probe, violations);
    target.map(
        |target| TransparentInterceptionMitmBackendReadinessProbeIntent::TcpConnect {
            target,
            interval_ms: probe.interval_ms,
            timeout_ms: probe.timeout_ms,
            failure_threshold: probe.failure_threshold,
        },
    )
}

fn validate_mitm_backend_readiness_probe_target(
    proxy_listen_port: Option<NonZeroU16>,
    probe: &TransparentInterceptionMitmBackendReadinessProbeConfig,
    violations: &mut Vec<TransparentInterceptionMitmIntentViolation>,
) -> Option<SocketAddr> {
    let Some(target) = &probe.target else {
        violations.push(intent_violation(
            "enforcement.interception.mitm.backend_readiness_probe.target",
            "external MITM backend requires a TCP readiness probe target",
        ));
        return None;
    };

    let parsed_target = match target.parse::<SocketAddr>() {
        Ok(address) if address.port() == 0 => {
            violations.push(intent_violation(
                "enforcement.interception.mitm.backend_readiness_probe.target",
                "external MITM backend readiness probe target must use a non-zero port",
            ));
            None
        }
        Ok(address) if !is_loopback_address(address.ip()) => {
            violations.push(intent_violation(
                "enforcement.interception.mitm.backend_readiness_probe.target",
                "external MITM backend readiness probe target must use a loopback IP address",
            ));
            Some(address)
        }
        Ok(address) => Some(address),
        Err(_) => {
            violations.push(intent_violation(
                "enforcement.interception.mitm.backend_readiness_probe.target",
                "external MITM backend readiness probe target must be an IP socket address",
            ));
            None
        }
    };

    if let (Some(target), Some(listen_port)) = (parsed_target, proxy_listen_port)
        && target.port() != listen_port.get()
    {
        violations.push(intent_violation(
            "enforcement.interception.mitm.backend_readiness_probe.target",
            "external MITM backend readiness probe target port must match proxy listen_port",
        ));
    }

    parsed_target
}

fn validate_mitm_backend_readiness_probe_ranges(
    probe: &TransparentInterceptionMitmBackendReadinessProbeConfig,
    violations: &mut Vec<TransparentInterceptionMitmIntentViolation>,
) {
    validate_tcp_health_probe_timing(
        TcpHealthProbeTimingFields {
            interval_ms: "enforcement.interception.mitm.backend_readiness_probe.interval_ms",
            timeout_ms: "enforcement.interception.mitm.backend_readiness_probe.timeout_ms",
            failure_threshold: "enforcement.interception.mitm.backend_readiness_probe.failure_threshold",
        },
        "external MITM backend readiness probe",
        probe.interval_ms,
        probe.timeout_ms,
        probe.failure_threshold,
        violations,
    );
}

fn validate_mitm_plaintext_bridge(
    bridge: &TransparentInterceptionMitmPlaintextBridgeConfig,
    violations: &mut Vec<TransparentInterceptionMitmIntentViolation>,
) -> TransparentInterceptionMitmPlaintextBridgeIntent {
    match bridge.mode {
        TransparentInterceptionMitmPlaintextBridgeModeConfig::None => {
            if bridge.path.is_some() {
                violations.push(intent_violation(
                    "enforcement.interception.mitm.plaintext_bridge.path",
                    "MITM plaintext bridge path requires plaintext_bridge.mode = \"capture_event_feed\"",
                ));
            }
            if bridge.follow.is_some() {
                violations.push(intent_violation(
                    "enforcement.interception.mitm.plaintext_bridge.follow",
                    "MITM plaintext bridge follow mode requires plaintext_bridge.mode = \"capture_event_feed\"",
                ));
            }
            TransparentInterceptionMitmPlaintextBridgeIntent::Disabled
        }
        TransparentInterceptionMitmPlaintextBridgeModeConfig::CaptureEventFeed => {
            let Some(path) = &bridge.path else {
                violations.push(intent_violation(
                    "enforcement.interception.mitm.plaintext_bridge.path",
                    "capture-event MITM plaintext bridge requires a JSON-lines capture event path",
                ));
                return TransparentInterceptionMitmPlaintextBridgeIntent::Disabled;
            };
            if path.as_os_str().is_empty() {
                violations.push(intent_violation(
                    "enforcement.interception.mitm.plaintext_bridge.path",
                    "capture-event MITM plaintext bridge path must not be empty",
                ));
            }
            TransparentInterceptionMitmPlaintextBridgeIntent::CaptureEventFeed {
                path: path.clone(),
                follow: bridge.follow_enabled(),
            }
        }
    }
}

fn is_loopback_address(address: IpAddr) -> bool {
    match normalized_ip_address(address) {
        IpAddr::V4(address) => address.is_loopback(),
        IpAddr::V6(address) => address.is_loopback(),
    }
}
