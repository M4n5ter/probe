use std::collections::HashSet;

use crate::{
    ConfigViolation, EnforcementInterceptionConfig, TlsConfig, TlsMaterialKind,
    TransparentInterceptionIntentViolation, TransparentInterceptionMitmBackendConfig,
    TransparentInterceptionMitmConfig, TransparentInterceptionMitmPlaintextBridgeModeConfig,
    TransparentInterceptionMitmPolicyHookModeConfig,
    TransparentInterceptionMitmProductProxyUpstreamTlsModeConfig,
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
    validate_mitm_config(interception, tls, violations);
}

fn validate_transparent_proxy_intent(
    interception: &EnforcementInterceptionConfig,
    violations: &mut Vec<ConfigViolation>,
) {
    if let Err(intent_violations) = interception.transparent_proxy_intent() {
        extend_intent_violations(violations, intent_violations);
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

    validate_mitm_backend_intent(interception, violations);
    validate_mitm_client_trust_intent(interception, violations);
    validate_mitm_plaintext_bridge_intent(interception, violations);
    validate_mitm_policy_hook_intent(interception, violations);
    validate_mitm_material_shape(mitm, violations);
    validate_product_proxy_contract(mitm, violations);
    validate_mitm_material_refs(mitm, tls, violations);
}

fn validate_mitm_backend_intent(
    interception: &EnforcementInterceptionConfig,
    violations: &mut Vec<ConfigViolation>,
) {
    if let Err(intent_violations) = interception.mitm_backend_intent() {
        extend_intent_violations(violations, intent_violations);
    }
}

fn validate_mitm_plaintext_bridge_intent(
    interception: &EnforcementInterceptionConfig,
    violations: &mut Vec<ConfigViolation>,
) {
    if let Err(intent_violations) = interception.mitm_plaintext_bridge_intent() {
        extend_intent_violations(violations, intent_violations);
    }
}

fn validate_mitm_client_trust_intent(
    interception: &EnforcementInterceptionConfig,
    violations: &mut Vec<ConfigViolation>,
) {
    if let Err(intent_violations) = interception.mitm_client_trust_intent() {
        extend_intent_violations(violations, intent_violations);
    }
}

fn validate_mitm_policy_hook_intent(
    interception: &EnforcementInterceptionConfig,
    violations: &mut Vec<ConfigViolation>,
) {
    if let Err(intent_violations) = interception.mitm_policy_hook_intent() {
        extend_intent_violations(violations, intent_violations);
    }
}

fn extend_intent_violations(
    violations: &mut Vec<ConfigViolation>,
    intent_violations: Vec<TransparentInterceptionIntentViolation>,
) {
    violations.extend(
        intent_violations
            .into_iter()
            .map(|violation| ConfigViolation {
                field: violation.field().to_string(),
                reason: violation.reason().to_string(),
            }),
    );
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

fn validate_product_proxy_contract(
    mitm: &TransparentInterceptionMitmConfig,
    violations: &mut Vec<ConfigViolation>,
) {
    let TransparentInterceptionMitmBackendConfig::ProductProxy { process, .. } = &mitm.backend
    else {
        return;
    };

    if mitm.plaintext_bridge.mode
        != TransparentInterceptionMitmPlaintextBridgeModeConfig::CaptureEventFeed
    {
        violations.push(ConfigViolation {
            field: "enforcement.interception.mitm.plaintext_bridge.mode".to_string(),
            reason: "product MITM proxy backend requires plaintext_bridge.mode = \"capture_event_feed\" so the generated proxy feed is the typed bridge source".to_string(),
        });
    }
    if let Some(path) = &mitm.plaintext_bridge.path
        && !path.is_absolute()
    {
        violations.push(ConfigViolation {
            field: "enforcement.interception.mitm.plaintext_bridge.path".to_string(),
            reason: "product MITM proxy backend requires an absolute plaintext bridge path so the agent and spawned proxy share the same feed file".to_string(),
        });
    }
    if mitm.policy_hook.mode != TransparentInterceptionMitmPolicyHookModeConfig::HttpJson {
        violations.push(ConfigViolation {
            field: "enforcement.interception.mitm.policy_hook.mode".to_string(),
            reason: "product MITM proxy backend requires policy_hook.mode = \"http_json\" so proxy-side protective actions use the typed hook contract".to_string(),
        });
    }
    let has_ca_pair = mitm.has_ca_material_pair();
    let has_leaf_material =
        !mitm.leaf_certificate_chain_refs.is_empty() || mitm.leaf_private_key_ref.is_some();
    let has_static_leaf =
        mitm.leaf_certificate_chain_refs.len() == 1 && mitm.leaf_private_key_ref.is_some();
    let has_exactly_one_tls_source = matches!(
        (has_ca_pair, has_leaf_material, has_static_leaf),
        (true, false, false) | (false, true, true)
    );
    if !has_exactly_one_tls_source {
        violations.push(ConfigViolation {
            field: "enforcement.interception.mitm.leaf_certificate_chain_refs".to_string(),
            reason: "product MITM proxy backend requires exactly one TLS termination source: a CA certificate/private key pair for dynamic SNI certificates or one leaf certificate/private key pair for static TLS termination".to_string(),
        });
    }
    if process.upstream_tls_mode
        == TransparentInterceptionMitmProductProxyUpstreamTlsModeConfig::Never
        && !mitm.upstream_trust_anchor_refs.is_empty()
    {
        violations.push(ConfigViolation {
            field: "enforcement.interception.mitm.upstream_trust_anchor_refs".to_string(),
            reason: "product MITM proxy upstream trust anchors require backend.process.upstream_tls_mode = \"auto\" or \"always\"".to_string(),
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
        EnforcementInterceptionConfig, MAX_TRANSPARENT_MITM_BACKEND_READINESS_FAILURE_THRESHOLD,
        MAX_TRANSPARENT_MITM_BACKEND_READINESS_TIMEOUT_MS,
        MAX_TRANSPARENT_PROXY_HEALTH_PROBE_FAILURE_THRESHOLD,
        MAX_TRANSPARENT_PROXY_HEALTH_PROBE_TIMEOUT_MS,
        MIN_TRANSPARENT_MITM_BACKEND_READINESS_INTERVAL_MS,
        MIN_TRANSPARENT_PROXY_HEALTH_PROBE_INTERVAL_MS, TlsMaterialConfig, TlsMaterialKind,
        TransparentInterceptionMitmBackendConfig,
        TransparentInterceptionMitmBackendReadinessProbeConfig, TransparentInterceptionMitmConfig,
        TransparentInterceptionMitmPlaintextBridgeConfig,
        TransparentInterceptionMitmPlaintextBridgeModeConfig,
        TransparentInterceptionMitmPolicyHookConfig,
        TransparentInterceptionMitmPolicyHookModeConfig, TransparentInterceptionProxyConfig,
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

    #[test]
    fn health_probe_timeout_must_not_exceed_interval() {
        let mut violations = Vec::new();
        validate_interception(
            &EnforcementInterceptionConfig {
                strategy: TransparentInterceptionStrategyConfig::InboundTproxy,
                proxy: TransparentInterceptionProxyConfig {
                    listen_port: Some(15001),
                    health_probe: TransparentInterceptionProxyHealthProbeConfig {
                        target: Some("127.0.0.1:18080".to_string()),
                        interval_ms: 500,
                        timeout_ms: 600,
                        failure_threshold: 1,
                    },
                    ..TransparentInterceptionProxyConfig::default()
                },
                ..EnforcementInterceptionConfig::default()
            },
            &mut violations,
        );

        assert!(violations.iter().any(|violation| violation.field
            == "enforcement.interception.proxy.health_probe.timeout_ms"
            && violation.reason.contains("must not exceed interval")));
    }

    #[test]
    fn mitm_backend_readiness_probe_timing_uses_bounded_runtime_values() {
        let mut violations = Vec::new();
        let interception = EnforcementInterceptionConfig {
            strategy: TransparentInterceptionStrategyConfig::InboundTproxyMitm,
            proxy: TransparentInterceptionProxyConfig {
                listen_port: Some(15002),
                ..TransparentInterceptionProxyConfig::default()
            },
            mitm: TransparentInterceptionMitmConfig {
                backend: TransparentInterceptionMitmBackendConfig::external(
                    TransparentInterceptionMitmBackendReadinessProbeConfig {
                        target: Some("127.0.0.1:15002".to_string()),
                        interval_ms: MIN_TRANSPARENT_MITM_BACKEND_READINESS_INTERVAL_MS - 1,
                        timeout_ms: MAX_TRANSPARENT_MITM_BACKEND_READINESS_TIMEOUT_MS + 1,
                        failure_threshold: MAX_TRANSPARENT_MITM_BACKEND_READINESS_FAILURE_THRESHOLD
                            + 1,
                    },
                ),
                ca_certificate_ref: Some("mitm-ca".to_string()),
                ca_private_key_ref: Some("mitm-ca-key".to_string()),
                ..TransparentInterceptionMitmConfig::default()
            },
            ..EnforcementInterceptionConfig::default()
        };
        validate(&interception, &tls_config_with_mitm_ca(), &mut violations);

        assert!(violations.iter().any(|violation| violation.field
            == "enforcement.interception.mitm.backend.readiness_probe.interval_ms"));
        assert!(violations.iter().any(|violation| violation.field
            == "enforcement.interception.mitm.backend.readiness_probe.timeout_ms"));
        assert!(violations.iter().any(|violation| violation.field
            == "enforcement.interception.mitm.backend.readiness_probe.failure_threshold"));
    }

    #[test]
    fn mitm_backend_readiness_probe_timeout_must_not_exceed_interval() {
        let mut violations = Vec::new();
        let interception = EnforcementInterceptionConfig {
            strategy: TransparentInterceptionStrategyConfig::InboundTproxyMitm,
            proxy: TransparentInterceptionProxyConfig {
                listen_port: Some(15002),
                ..TransparentInterceptionProxyConfig::default()
            },
            mitm: TransparentInterceptionMitmConfig {
                backend: TransparentInterceptionMitmBackendConfig::external(
                    TransparentInterceptionMitmBackendReadinessProbeConfig {
                        target: Some("127.0.0.1:15002".to_string()),
                        interval_ms: 500,
                        timeout_ms: 600,
                        failure_threshold: 1,
                    },
                ),
                ca_certificate_ref: Some("mitm-ca".to_string()),
                ca_private_key_ref: Some("mitm-ca-key".to_string()),
                ..TransparentInterceptionMitmConfig::default()
            },
            ..EnforcementInterceptionConfig::default()
        };
        validate(&interception, &tls_config_with_mitm_ca(), &mut violations);

        assert!(violations.iter().any(|violation| violation.field
            == "enforcement.interception.mitm.backend.readiness_probe.timeout_ms"
            && violation.reason.contains("must not exceed interval")));
    }

    #[test]
    fn mitm_policy_hook_requires_loopback_http_endpoint() {
        let mut violations = Vec::new();
        let interception = EnforcementInterceptionConfig {
            strategy: TransparentInterceptionStrategyConfig::InboundTproxyMitm,
            proxy: TransparentInterceptionProxyConfig {
                listen_port: Some(15002),
                ..TransparentInterceptionProxyConfig::default()
            },
            mitm: TransparentInterceptionMitmConfig {
                backend: TransparentInterceptionMitmBackendConfig::external(
                    TransparentInterceptionMitmBackendReadinessProbeConfig {
                        target: Some("127.0.0.1:15002".to_string()),
                        ..TransparentInterceptionMitmBackendReadinessProbeConfig::default()
                    },
                ),
                policy_hook: TransparentInterceptionMitmPolicyHookConfig {
                    mode: TransparentInterceptionMitmPolicyHookModeConfig::HttpJson,
                    endpoint: Some("https://192.0.2.10:15002/enforce".to_string()),
                    ..TransparentInterceptionMitmPolicyHookConfig::default()
                },
                ca_certificate_ref: Some("mitm-ca".to_string()),
                ca_private_key_ref: Some("mitm-ca-key".to_string()),
                ..TransparentInterceptionMitmConfig::default()
            },
            ..EnforcementInterceptionConfig::default()
        };
        validate(&interception, &tls_config_with_mitm_ca(), &mut violations);

        assert!(violations.iter().any(|violation| violation.field
            == "enforcement.interception.mitm.policy_hook.endpoint"
            && violation.reason.contains("http scheme")));
        assert!(violations.iter().any(|violation| violation.field
            == "enforcement.interception.mitm.policy_hook.endpoint"
            && violation.reason.contains("loopback IP")));
    }

    #[test]
    fn disabled_mitm_policy_hook_rejects_endpoint_overrides() {
        let mut violations = Vec::new();
        let interception = EnforcementInterceptionConfig {
            strategy: TransparentInterceptionStrategyConfig::InboundTproxyMitm,
            proxy: TransparentInterceptionProxyConfig {
                listen_port: Some(15002),
                ..TransparentInterceptionProxyConfig::default()
            },
            mitm: TransparentInterceptionMitmConfig {
                backend: TransparentInterceptionMitmBackendConfig::external(
                    TransparentInterceptionMitmBackendReadinessProbeConfig {
                        target: Some("127.0.0.1:15002".to_string()),
                        ..TransparentInterceptionMitmBackendReadinessProbeConfig::default()
                    },
                ),
                policy_hook: TransparentInterceptionMitmPolicyHookConfig {
                    endpoint: Some("http://127.0.0.1:15002/enforce".to_string()),
                    ..TransparentInterceptionMitmPolicyHookConfig::default()
                },
                ca_certificate_ref: Some("mitm-ca".to_string()),
                ca_private_key_ref: Some("mitm-ca-key".to_string()),
                ..TransparentInterceptionMitmConfig::default()
            },
            ..EnforcementInterceptionConfig::default()
        };
        validate(&interception, &tls_config_with_mitm_ca(), &mut violations);

        assert!(violations.iter().any(|violation| violation.field
            == "enforcement.interception.mitm.policy_hook.endpoint"
            && violation.reason.contains("policy_hook.mode")));
    }

    #[test]
    fn product_proxy_requires_absolute_plaintext_bridge_path() {
        let mut violations = Vec::new();
        let mut interception = product_proxy_interception();
        interception.mitm.plaintext_bridge.path = Some("relative/mitm-feed.jsonl".into());

        validate(&interception, &tls_config_with_mitm_leaf(), &mut violations);

        assert!(violations.iter().any(|violation| violation.field
            == "enforcement.interception.mitm.plaintext_bridge.path"
            && violation.reason.contains("absolute plaintext bridge path")));
    }

    #[test]
    fn product_proxy_accepts_ca_tls_termination_source() {
        let mut violations = Vec::new();
        let mut interception = product_proxy_interception();
        interception.mitm.leaf_certificate_chain_refs.clear();
        interception.mitm.leaf_private_key_ref = None;
        interception.mitm.ca_certificate_ref = Some("mitm-ca".to_string());
        interception.mitm.ca_private_key_ref = Some("mitm-ca-key".to_string());

        validate(&interception, &tls_config_with_mitm_ca(), &mut violations);

        assert!(violations.is_empty(), "{violations:?}");
    }

    #[test]
    fn product_proxy_accepts_upstream_routes() {
        let mut violations = Vec::new();
        let mut interception = product_proxy_interception();
        let TransparentInterceptionMitmBackendConfig::ProductProxy { process, .. } =
            &mut interception.mitm.backend
        else {
            panic!("test fixture should use product proxy");
        };
        process.upstream_routes = vec![
            crate::TransparentInterceptionMitmProductProxyUpstreamRouteConfig {
                host: "Route.Example".to_string(),
                target: "127.0.0.1:18443".to_string(),
            },
            crate::TransparentInterceptionMitmProductProxyUpstreamRouteConfig {
                host: "*.Route.Example".to_string(),
                target: "127.0.0.1:18444".to_string(),
            },
        ];

        validate(&interception, &tls_config_with_mitm_leaf(), &mut violations);
        let intent = interception
            .mitm_backend_intent()
            .expect("valid product proxy route should produce an intent");

        let crate::TransparentInterceptionMitmBackendIntent::ProductProxy { process, .. } = intent
        else {
            panic!("expected product proxy intent");
        };
        assert!(violations.is_empty(), "{violations:?}");
        assert_eq!(
            process.upstream_routes[0].host_pattern().to_string(),
            "route.example"
        );
        assert_eq!(
            process.upstream_routes[0].target(),
            "127.0.0.1:18443".parse().expect("test target")
        );
        assert_eq!(
            process.upstream_routes[1].host_pattern().to_string(),
            "*.route.example"
        );
        assert_eq!(
            process.upstream_routes[1].target(),
            "127.0.0.1:18444".parse().expect("test target")
        );
    }

    #[test]
    fn product_proxy_defaults_application_protocols_to_http1() {
        let mut violations = Vec::new();
        let interception = product_proxy_interception();

        validate(&interception, &tls_config_with_mitm_leaf(), &mut violations);
        let intent = interception
            .mitm_backend_intent()
            .expect("valid product proxy should produce an intent");

        let crate::TransparentInterceptionMitmBackendIntent::ProductProxy { process, .. } = intent
        else {
            panic!("expected product proxy intent");
        };
        assert!(violations.is_empty(), "{violations:?}");
        assert_eq!(
            process.application_protocols.protocols(),
            [probe_core::ApplicationProtocol::Http1]
        );
    }

    #[test]
    fn product_proxy_accepts_upstream_dns_discovery() {
        let mut violations = Vec::new();
        let mut interception = product_proxy_interception();
        let TransparentInterceptionMitmBackendConfig::ProductProxy { process, .. } =
            &mut interception.mitm.backend
        else {
            panic!("test fixture should use product proxy");
        };
        process.upstream_discovery =
            crate::TransparentInterceptionMitmProductProxyUpstreamDiscoveryConfig {
                mode:
                    crate::TransparentInterceptionMitmProductProxyUpstreamDiscoveryModeConfig::Dns,
                default_port: std::num::NonZeroU16::new(443),
                allow_special_use_addresses: true,
            };

        validate(&interception, &tls_config_with_mitm_leaf(), &mut violations);
        let intent = interception
            .mitm_backend_intent()
            .expect("valid product proxy DNS discovery should produce an intent");

        let crate::TransparentInterceptionMitmBackendIntent::ProductProxy { process, .. } = intent
        else {
            panic!("expected product proxy intent");
        };
        assert!(violations.is_empty(), "{violations:?}");
        assert_eq!(
            process.upstream_discovery,
            crate::TransparentInterceptionMitmProductProxyUpstreamDiscoveryIntent::Dns {
                default_port: std::num::NonZeroU16::new(443),
                allow_special_use_addresses: true
            }
        );
    }

    #[test]
    fn product_proxy_rejects_upstream_trust_anchors_when_upstream_tls_is_disabled() {
        let mut violations = Vec::new();
        let mut interception = product_proxy_interception();
        interception.mitm.upstream_trust_anchor_refs = vec!["upstream-ca".to_string()];
        let TransparentInterceptionMitmBackendConfig::ProductProxy { process, .. } =
            &mut interception.mitm.backend
        else {
            panic!("test fixture should use product proxy");
        };
        process.upstream_tls_mode =
            crate::TransparentInterceptionMitmProductProxyUpstreamTlsModeConfig::Never;

        validate(
            &interception,
            &tls_config_with_mitm_leaf_and_upstream_ca(),
            &mut violations,
        );

        assert!(violations.iter().any(|violation| violation.field
            == "enforcement.interception.mitm.upstream_trust_anchor_refs"
            && violation.reason.contains("upstream_tls_mode")));
    }

    #[test]
    fn product_proxy_rejects_dangling_upstream_dns_default_port() {
        let mut violations = Vec::new();
        let mut interception = product_proxy_interception();
        let TransparentInterceptionMitmBackendConfig::ProductProxy { process, .. } =
            &mut interception.mitm.backend
        else {
            panic!("test fixture should use product proxy");
        };
        process.upstream_discovery =
            crate::TransparentInterceptionMitmProductProxyUpstreamDiscoveryConfig {
                mode:
                    crate::TransparentInterceptionMitmProductProxyUpstreamDiscoveryModeConfig::None,
                default_port: std::num::NonZeroU16::new(443),
                allow_special_use_addresses: false,
            };

        validate(&interception, &tls_config_with_mitm_leaf(), &mut violations);

        assert!(violations.iter().any(|violation| {
            violation.field == "enforcement.interception.mitm.backend.process.upstream_discovery"
                && violation.reason.contains("mode = \"dns\"")
        }));
    }

    #[test]
    fn product_proxy_rejects_empty_application_protocols() {
        let mut violations = Vec::new();
        let mut interception = product_proxy_interception();
        let TransparentInterceptionMitmBackendConfig::ProductProxy { process, .. } =
            &mut interception.mitm.backend
        else {
            panic!("test fixture should use product proxy");
        };
        process.application_protocols = Some(Vec::new());

        validate(&interception, &tls_config_with_mitm_leaf(), &mut violations);

        assert!(violations.iter().any(|violation| {
            violation.field == "enforcement.interception.mitm.backend.process.application_protocols"
                && violation
                    .reason
                    .contains("must include at least one protocol")
        }));
    }

    #[test]
    fn product_proxy_rejects_invalid_upstream_routes() {
        let mut violations = Vec::new();
        let mut interception = product_proxy_interception();
        let TransparentInterceptionMitmBackendConfig::ProductProxy { process, .. } =
            &mut interception.mitm.backend
        else {
            panic!("test fixture should use product proxy");
        };
        process.upstream_routes = vec![
            crate::TransparentInterceptionMitmProductProxyUpstreamRouteConfig {
                host: "example.test".to_string(),
                target: "127.0.0.1:18443".to_string(),
            },
            crate::TransparentInterceptionMitmProductProxyUpstreamRouteConfig {
                host: "EXAMPLE.TEST".to_string(),
                target: "not-a-socket".to_string(),
            },
            crate::TransparentInterceptionMitmProductProxyUpstreamRouteConfig {
                host: "bad_host".to_string(),
                target: "127.0.0.1:0".to_string(),
            },
        ];

        validate(&interception, &tls_config_with_mitm_leaf(), &mut violations);

        assert!(violations.iter().any(|violation| {
            violation.field == "enforcement.interception.mitm.backend.process.upstream_routes"
                && violation.reason.contains("duplicated")
        }));
        assert!(violations.iter().any(|violation| {
            violation.field == "enforcement.interception.mitm.backend.process.upstream_routes"
                && violation.reason.contains("IP socket address")
        }));
        assert!(violations.iter().any(|violation| {
            violation.field == "enforcement.interception.mitm.backend.process.upstream_routes"
                && violation.reason.contains("ASCII letters")
        }));
        assert!(violations.iter().any(|violation| {
            violation.field == "enforcement.interception.mitm.backend.process.upstream_routes"
                && violation.reason.contains("port must be non-zero")
        }));
    }

    #[test]
    fn product_proxy_rejects_bare_wildcard_upstream_route() {
        let mut violations = Vec::new();
        let mut interception = product_proxy_interception();
        let TransparentInterceptionMitmBackendConfig::ProductProxy { process, .. } =
            &mut interception.mitm.backend
        else {
            panic!("test fixture should use product proxy");
        };
        process.upstream_routes = vec![
            crate::TransparentInterceptionMitmProductProxyUpstreamRouteConfig {
                host: "*".to_string(),
                target: "127.0.0.1:18443".to_string(),
            },
        ];

        validate(&interception, &tls_config_with_mitm_leaf(), &mut violations);

        assert!(violations.iter().any(|violation| {
            violation.field == "enforcement.interception.mitm.backend.process.upstream_routes"
                && violation.reason.contains("*.suffix")
        }));
    }

    #[test]
    fn product_proxy_rejects_upstream_routes_that_target_proxy_listener() {
        let mut violations = Vec::new();
        let mut interception = product_proxy_interception();
        let TransparentInterceptionMitmBackendConfig::ProductProxy { process, .. } =
            &mut interception.mitm.backend
        else {
            panic!("test fixture should use product proxy");
        };
        process.upstream_routes = vec![
            crate::TransparentInterceptionMitmProductProxyUpstreamRouteConfig {
                host: "loop.example".to_string(),
                target: "127.0.0.1:15002".to_string(),
            },
            crate::TransparentInterceptionMitmProductProxyUpstreamRouteConfig {
                host: "wildcard.example".to_string(),
                target: "[::]:15002".to_string(),
            },
        ];

        validate(&interception, &tls_config_with_mitm_leaf(), &mut violations);

        assert!(violations.iter().any(|violation| {
            violation.field == "enforcement.interception.mitm.backend.process.upstream_routes"
                && violation.reason.contains("must not point back")
        }));
    }

    #[test]
    fn product_proxy_rejects_ambiguous_tls_termination_sources() {
        let mut violations = Vec::new();
        let mut interception = product_proxy_interception();
        interception.mitm.ca_certificate_ref = Some("mitm-ca".to_string());
        interception.mitm.ca_private_key_ref = Some("mitm-ca-key".to_string());

        validate(
            &interception,
            &tls_config_with_mitm_ca_and_leaf(),
            &mut violations,
        );

        assert!(violations.iter().any(|violation| {
            violation.field == "enforcement.interception.mitm.leaf_certificate_chain_refs"
                && violation
                    .reason
                    .contains("exactly one TLS termination source")
        }));
    }

    fn validate_interception(
        interception: &EnforcementInterceptionConfig,
        violations: &mut Vec<ConfigViolation>,
    ) {
        validate(interception, &TlsConfig::default(), violations);
    }

    fn product_proxy_interception() -> EnforcementInterceptionConfig {
        EnforcementInterceptionConfig {
            strategy: TransparentInterceptionStrategyConfig::InboundTproxyMitm,
            proxy: TransparentInterceptionProxyConfig {
                listen_port: Some(15002),
                ..TransparentInterceptionProxyConfig::default()
            },
            mitm: TransparentInterceptionMitmConfig {
                backend: TransparentInterceptionMitmBackendConfig::product_proxy(
                    TransparentInterceptionMitmBackendReadinessProbeConfig {
                        target: Some("127.0.0.1:15002".to_string()),
                        ..TransparentInterceptionMitmBackendReadinessProbeConfig::default()
                    },
                    crate::TransparentInterceptionMitmProductProxyConfig {
                        launcher:
                            crate::TransparentInterceptionMitmProductProxyLauncherConfig::ExternalBinary {
                                program: Some("/usr/local/bin/traffic-probe-mitm-proxy".into()),
                                working_dir: Some("/run/traffic-probe".into()),
                            },
                        application_protocols: None,
                        upstream_tls_mode:
                            crate::TransparentInterceptionMitmProductProxyUpstreamTlsModeConfig::Auto,
                        upstream_discovery:
                            crate::TransparentInterceptionMitmProductProxyUpstreamDiscoveryConfig::default(),
                        upstream_routes: Vec::new(),
                    },
                ),
                client_trust: crate::TransparentInterceptionMitmClientTrustConfig {
                    mode: crate::TransparentInterceptionMitmClientTrustModeConfig::OperatorManaged,
                },
                plaintext_bridge: TransparentInterceptionMitmPlaintextBridgeConfig {
                    mode: TransparentInterceptionMitmPlaintextBridgeModeConfig::CaptureEventFeed,
                    path: Some("/run/traffic-probe/mitm-feed.jsonl".into()),
                    follow: Some(true),
                },
                policy_hook: TransparentInterceptionMitmPolicyHookConfig {
                    mode: TransparentInterceptionMitmPolicyHookModeConfig::HttpJson,
                    endpoint: Some("http://127.0.0.1:15003/mitm-policy-hook".to_string()),
                    ..TransparentInterceptionMitmPolicyHookConfig::default()
                },
                leaf_certificate_chain_refs: vec!["mitm-leaf".to_string()],
                leaf_private_key_ref: Some("mitm-leaf-key".to_string()),
                ..TransparentInterceptionMitmConfig::default()
            },
            ..EnforcementInterceptionConfig::default()
        }
    }

    fn tls_config_with_mitm_ca() -> TlsConfig {
        TlsConfig {
            materials: vec![
                TlsMaterialConfig {
                    id: Some("mitm-ca".to_string()),
                    kind: TlsMaterialKind::MitmCaCertificate,
                    path: "/etc/traffic-probe/mitm-ca.pem".into(),
                },
                TlsMaterialConfig {
                    id: Some("mitm-ca-key".to_string()),
                    kind: TlsMaterialKind::MitmCaPrivateKey,
                    path: "/etc/traffic-probe/mitm-ca.key".into(),
                },
            ],
            ..TlsConfig::default()
        }
    }

    fn tls_config_with_mitm_leaf() -> TlsConfig {
        TlsConfig {
            materials: vec![
                TlsMaterialConfig {
                    id: Some("mitm-leaf".to_string()),
                    kind: TlsMaterialKind::MitmLeafCertificate,
                    path: "/etc/traffic-probe/mitm-leaf.pem".into(),
                },
                TlsMaterialConfig {
                    id: Some("mitm-leaf-key".to_string()),
                    kind: TlsMaterialKind::MitmLeafPrivateKey,
                    path: "/etc/traffic-probe/mitm-leaf.key".into(),
                },
            ],
            ..TlsConfig::default()
        }
    }

    fn tls_config_with_mitm_ca_and_leaf() -> TlsConfig {
        let mut config = tls_config_with_mitm_ca();
        config
            .materials
            .extend(tls_config_with_mitm_leaf().materials);
        config
    }

    fn tls_config_with_mitm_leaf_and_upstream_ca() -> TlsConfig {
        let mut config = tls_config_with_mitm_leaf();
        config.materials.push(TlsMaterialConfig {
            id: Some("upstream-ca".to_string()),
            kind: TlsMaterialKind::MitmUpstreamTrustAnchor,
            path: "/etc/traffic-probe/upstream-ca.pem".into(),
        });
        config
    }
}
