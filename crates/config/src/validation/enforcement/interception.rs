use std::collections::HashSet;

use crate::{
    ConfigViolation, EnforcementInterceptionConfig, TlsConfig, TlsMaterialKind,
    TransparentInterceptionMitmBackendConfig, TransparentInterceptionMitmConfig,
};

pub(super) fn validate(
    interception: &EnforcementInterceptionConfig,
    tls: &TlsConfig,
    violations: &mut Vec<ConfigViolation>,
) {
    validate_transparent_proxy_intent(interception, violations);
    validate_mitm_config(interception, tls, violations);
}

pub(super) fn validate_l7_mitm_contract(
    interception: &EnforcementInterceptionConfig,
    tls: &TlsConfig,
    violations: &mut Vec<ConfigViolation>,
) {
    validate_transparent_proxy_intent(interception, violations);
    validate_mitm_config(interception, tls, violations);
}

fn validate_transparent_proxy_intent(
    interception: &EnforcementInterceptionConfig,
    violations: &mut Vec<ConfigViolation>,
) {
    if let Err(intent_violations) = interception.transparent_proxy_intent() {
        violations.extend(
            intent_violations
                .into_iter()
                .map(|violation| ConfigViolation {
                    field: violation.field().to_string(),
                    reason: violation.reason().to_string(),
                }),
        );
    }
}

fn validate_mitm_config(
    interception: &EnforcementInterceptionConfig,
    tls: &TlsConfig,
    violations: &mut Vec<ConfigViolation>,
) {
    let mitm = &interception.mitm;
    if !interception.strategy.is_mitm() {
        if mitm.is_configured() {
            violations.push(ConfigViolation {
                field: "enforcement.interception.mitm".to_string(),
                reason: "MITM backend config requires a MITM interception strategy".to_string(),
            });
        }
        return;
    }

    if mitm.backend != TransparentInterceptionMitmBackendConfig::External {
        violations.push(ConfigViolation {
            field: "enforcement.interception.mitm.backend".to_string(),
            reason: "MITM interception requires enforcement.interception.mitm.backend = \"external\" until a managed L7 backend exists".to_string(),
        });
    }

    validate_mitm_material_shape(mitm, violations);
    validate_mitm_material_refs(mitm, tls, violations);
}

fn validate_mitm_material_shape(
    mitm: &TransparentInterceptionMitmConfig,
    violations: &mut Vec<ConfigViolation>,
) {
    if mitm.ca_certificate_ref.is_some() != mitm.ca_private_key_ref.is_some() {
        violations.push(ConfigViolation {
            field: "enforcement.interception.mitm.ca_certificate_ref".to_string(),
            reason: "MITM CA certificate and private key refs must be configured together"
                .to_string(),
        });
    }
    let has_leaf_certificates = !mitm.leaf_certificate_chain_refs.is_empty();
    let has_leaf_private_key = mitm.leaf_private_key_ref.is_some();
    if has_leaf_certificates != has_leaf_private_key {
        violations.push(ConfigViolation {
            field: "enforcement.interception.mitm.leaf_certificate_chain_refs".to_string(),
            reason:
                "MITM leaf certificate chain refs and private key ref must be configured together"
                    .to_string(),
        });
    }
    if !mitm.has_ca_material_pair() && !mitm.has_leaf_material_pair() {
        violations.push(ConfigViolation {
            field: "enforcement.interception.mitm".to_string(),
            reason: "MITM interception requires either a CA certificate/private key pair or a leaf certificate/private key pair".to_string(),
        });
    }
}

fn validate_mitm_material_refs(
    mitm: &TransparentInterceptionMitmConfig,
    tls: &TlsConfig,
    violations: &mut Vec<ConfigViolation>,
) {
    let materials_by_id = crate::tls::materials_by_id(tls);
    if let Some(reference) = &mitm.ca_certificate_ref {
        crate::tls::validate_material_ref(
            "enforcement.interception.mitm.ca_certificate_ref",
            reference,
            TlsMaterialKind::MitmCaCertificate,
            &materials_by_id,
            violations,
            "MITM material",
        );
    }
    if let Some(reference) = &mitm.ca_private_key_ref {
        crate::tls::validate_material_ref(
            "enforcement.interception.mitm.ca_private_key_ref",
            reference,
            TlsMaterialKind::MitmCaPrivateKey,
            &materials_by_id,
            violations,
            "MITM material",
        );
    }
    validate_mitm_material_ref_list(
        &mitm.leaf_certificate_chain_refs,
        "enforcement.interception.mitm.leaf_certificate_chain_refs",
        TlsMaterialKind::MitmLeafCertificate,
        &materials_by_id,
        violations,
    );
    if let Some(reference) = &mitm.leaf_private_key_ref {
        crate::tls::validate_material_ref(
            "enforcement.interception.mitm.leaf_private_key_ref",
            reference,
            TlsMaterialKind::MitmLeafPrivateKey,
            &materials_by_id,
            violations,
            "MITM material",
        );
    }
    validate_mitm_material_ref_list(
        &mitm.upstream_trust_anchor_refs,
        "enforcement.interception.mitm.upstream_trust_anchor_refs",
        TlsMaterialKind::MitmUpstreamTrustAnchor,
        &materials_by_id,
        violations,
    );
}

fn validate_mitm_material_ref_list(
    refs: &[String],
    field: &'static str,
    expected_kind: TlsMaterialKind,
    materials_by_id: &std::collections::BTreeMap<&str, TlsMaterialKind>,
    violations: &mut Vec<ConfigViolation>,
) {
    let mut seen_refs = HashSet::new();
    for reference in refs {
        crate::tls::validate_material_ref(
            field,
            reference,
            expected_kind,
            materials_by_id,
            violations,
            "MITM material",
        );
        if !reference.trim().is_empty() && !seen_refs.insert(reference.as_str()) {
            violations.push(ConfigViolation {
                field: field.to_string(),
                reason: format!("MITM material ref {reference} is duplicated"),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        EnforcementInterceptionConfig, MAX_TRANSPARENT_PROXY_HEALTH_PROBE_FAILURE_THRESHOLD,
        MAX_TRANSPARENT_PROXY_HEALTH_PROBE_TIMEOUT_MS,
        MIN_TRANSPARENT_PROXY_HEALTH_PROBE_INTERVAL_MS, TransparentInterceptionProxyConfig,
        TransparentInterceptionProxyHealthProbeConfig, TransparentInterceptionProxyModeConfig,
        TransparentInterceptionProxySelfBypassConfig, TransparentInterceptionStrategyConfig,
    };

    use super::*;

    #[test]
    fn enabled_strategy_requires_proxy_port() {
        let mut violations = Vec::new();
        validate_interception(
            &EnforcementInterceptionConfig {
                strategy: TransparentInterceptionStrategyConfig::InboundTproxy,
                selector: None,
                proxy: TransparentInterceptionProxyConfig {
                    listen_port: Some(0),
                    ..TransparentInterceptionProxyConfig::default()
                },
                ..EnforcementInterceptionConfig::default()
            },
            &mut violations,
        );

        assert_eq!(violations.len(), 1);
        assert!(
            violations
                .iter()
                .any(|violation| violation.field == "enforcement.interception.proxy.listen_port")
        );
    }

    #[test]
    fn disabled_strategy_does_not_require_proxy_config() {
        let mut violations = Vec::new();
        validate_interception(&EnforcementInterceptionConfig::default(), &mut violations);

        assert!(violations.is_empty());
    }

    #[test]
    fn managed_tcp_relay_is_not_valid_when_interception_is_disabled() {
        let mut violations = Vec::new();
        validate_interception(
            &EnforcementInterceptionConfig {
                proxy: TransparentInterceptionProxyConfig {
                    mode: TransparentInterceptionProxyModeConfig::ManagedTcpRelay,
                    ..TransparentInterceptionProxyConfig::default()
                },
                ..EnforcementInterceptionConfig::default()
            },
            &mut violations,
        );

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].field, "enforcement.interception.proxy.mode");
    }

    #[test]
    fn managed_tcp_relay_is_valid_for_outbound_transparent_proxy() {
        let mut violations = Vec::new();
        validate_interception(
            &EnforcementInterceptionConfig {
                strategy: TransparentInterceptionStrategyConfig::OutboundTransparentProxy,
                selector: None,
                proxy: TransparentInterceptionProxyConfig {
                    mode: TransparentInterceptionProxyModeConfig::ManagedTcpRelay,
                    listen_port: Some(15001),
                    ..TransparentInterceptionProxyConfig::default()
                },
                ..EnforcementInterceptionConfig::default()
            },
            &mut violations,
        );

        assert!(violations.is_empty());
    }

    #[test]
    fn mitm_strategy_rejects_managed_tcp_relay() {
        for strategy in [
            TransparentInterceptionStrategyConfig::InboundTproxyMitm,
            TransparentInterceptionStrategyConfig::OutboundTransparentMitm,
        ] {
            let mut violations = Vec::new();
            validate_interception(
                &EnforcementInterceptionConfig {
                    strategy,
                    selector: None,
                    proxy: TransparentInterceptionProxyConfig {
                        mode: TransparentInterceptionProxyModeConfig::ManagedTcpRelay,
                        listen_port: Some(15001),
                        ..TransparentInterceptionProxyConfig::default()
                    },
                    ..EnforcementInterceptionConfig::default()
                },
                &mut violations,
            );

            assert!(violations.iter().any(|violation| violation.field
                == "enforcement.interception.proxy.mode"
                && violation.reason.contains("plain TCP relay")));
        }
    }

    #[test]
    fn health_probe_requires_enabled_strategy_and_valid_target() {
        let mut violations = Vec::new();
        validate_interception(
            &EnforcementInterceptionConfig {
                proxy: TransparentInterceptionProxyConfig {
                    health_probe: TransparentInterceptionProxyHealthProbeConfig {
                        target: Some("localhost:15001".to_string()),
                        interval_ms: 0,
                        timeout_ms: 0,
                        failure_threshold: 0,
                    },
                    ..TransparentInterceptionProxyConfig::default()
                },
                ..EnforcementInterceptionConfig::default()
            },
            &mut violations,
        );

        assert!(violations.iter().any(|violation| violation.field
            == "enforcement.interception.proxy.health_probe.target"
            && violation.reason.contains("enabled interception strategy")));
        assert!(violations.iter().any(|violation| violation.field
            == "enforcement.interception.proxy.health_probe.target"
            && violation.reason.contains("IP socket address")));
        assert!(violations.iter().any(|violation| violation.field
            == "enforcement.interception.proxy.health_probe.interval_ms"));
        assert!(
            violations.iter().any(|violation| violation.field
                == "enforcement.interception.proxy.health_probe.timeout_ms")
        );
        assert!(violations.iter().any(|violation| violation.field
            == "enforcement.interception.proxy.health_probe.failure_threshold"));
    }

    #[test]
    fn managed_health_probe_cannot_target_relay_listen_port() {
        let mut violations = Vec::new();
        validate_interception(
            &EnforcementInterceptionConfig {
                strategy: TransparentInterceptionStrategyConfig::InboundTproxy,
                proxy: TransparentInterceptionProxyConfig {
                    mode: TransparentInterceptionProxyModeConfig::ManagedTcpRelay,
                    self_bypass: TransparentInterceptionProxySelfBypassConfig::None,
                    listen_port: Some(15001),
                    health_probe: TransparentInterceptionProxyHealthProbeConfig {
                        target: Some("127.0.0.1:15001".to_string()),
                        interval_ms: 500,
                        timeout_ms: 100,
                        failure_threshold: 1,
                    },
                },
                ..EnforcementInterceptionConfig::default()
            },
            &mut violations,
        );

        assert!(violations.iter().any(|violation| violation.field
            == "enforcement.interception.proxy.health_probe.target"
            && violation.reason.contains("local relay listener")));
    }

    #[test]
    fn managed_health_probe_allows_remote_target_on_relay_port() {
        let mut violations = Vec::new();
        validate_interception(
            &EnforcementInterceptionConfig {
                strategy: TransparentInterceptionStrategyConfig::InboundTproxy,
                proxy: TransparentInterceptionProxyConfig {
                    mode: TransparentInterceptionProxyModeConfig::ManagedTcpRelay,
                    self_bypass: TransparentInterceptionProxySelfBypassConfig::None,
                    listen_port: Some(15001),
                    health_probe: TransparentInterceptionProxyHealthProbeConfig {
                        target: Some("203.0.113.10:15001".to_string()),
                        interval_ms: 500,
                        timeout_ms: 100,
                        failure_threshold: 1,
                    },
                },
                ..EnforcementInterceptionConfig::default()
            },
            &mut violations,
        );

        assert!(violations.is_empty());
    }

    #[test]
    fn health_probe_is_currently_inbound_tproxy_only() {
        let mut violations = Vec::new();
        validate_interception(
            &EnforcementInterceptionConfig {
                strategy: TransparentInterceptionStrategyConfig::OutboundTransparentProxy,
                proxy: TransparentInterceptionProxyConfig {
                    listen_port: Some(15001),
                    health_probe: TransparentInterceptionProxyHealthProbeConfig {
                        target: Some("127.0.0.1:18080".to_string()),
                        interval_ms: 500,
                        timeout_ms: 100,
                        failure_threshold: 1,
                    },
                    ..TransparentInterceptionProxyConfig::default()
                },
                ..EnforcementInterceptionConfig::default()
            },
            &mut violations,
        );

        assert!(violations.iter().any(|violation| violation.field
            == "enforcement.interception.proxy.health_probe.target"
            && violation.reason.contains("inbound TPROXY only")));
    }

    #[test]
    fn health_probe_timing_uses_bounded_runtime_values() {
        let mut violations = Vec::new();
        validate_interception(
            &EnforcementInterceptionConfig {
                strategy: TransparentInterceptionStrategyConfig::InboundTproxy,
                proxy: TransparentInterceptionProxyConfig {
                    listen_port: Some(15001),
                    health_probe: TransparentInterceptionProxyHealthProbeConfig {
                        target: Some("127.0.0.1:18080".to_string()),
                        interval_ms: MIN_TRANSPARENT_PROXY_HEALTH_PROBE_INTERVAL_MS - 1,
                        timeout_ms: MAX_TRANSPARENT_PROXY_HEALTH_PROBE_TIMEOUT_MS + 1,
                        failure_threshold: MAX_TRANSPARENT_PROXY_HEALTH_PROBE_FAILURE_THRESHOLD + 1,
                    },
                    ..TransparentInterceptionProxyConfig::default()
                },
                ..EnforcementInterceptionConfig::default()
            },
            &mut violations,
        );

        assert!(violations.iter().any(|violation| violation.field
            == "enforcement.interception.proxy.health_probe.interval_ms"));
        assert!(
            violations.iter().any(|violation| violation.field
                == "enforcement.interception.proxy.health_probe.timeout_ms")
        );
        assert!(violations.iter().any(|violation| violation.field
            == "enforcement.interception.proxy.health_probe.failure_threshold"));
    }

    fn validate_interception(
        interception: &EnforcementInterceptionConfig,
        violations: &mut Vec<ConfigViolation>,
    ) {
        validate(interception, &TlsConfig::default(), violations);
    }
}
