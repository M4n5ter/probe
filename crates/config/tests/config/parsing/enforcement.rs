use probe_config::*;
use probe_core::Action;

#[test]
fn parses_transparent_interception_strategy() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[enforcement.interception]
strategy = "outbound_transparent_proxy"

[enforcement.interception.proxy]
mode = "managed_tcp_relay"
listen_port = 15001

[enforcement.interception.selector]
op = "match"

[enforcement.interception.selector.term.process]
pids = []
names = []
exe_path_globs = ["/usr/bin/curl"]
cmdline_regexes = []
systemd_services = []
container_ids = []

[enforcement.interception.selector.term.traffic]
local_ports = []
remote_ports = [443]
directions = []
remote_addresses = []
"#,
    )?;

    assert_eq!(
        config.enforcement.interception.strategy,
        TransparentInterceptionStrategyConfig::OutboundTransparentProxy
    );
    assert_eq!(
        config.enforcement.interception.proxy.listen_port,
        Some(15001)
    );
    assert_eq!(
        config.enforcement.interception.proxy.mode,
        TransparentInterceptionProxyModeConfig::ManagedTcpRelay
    );
    assert!(config.enforcement.interception.selector.is_some());
    Ok(())
}

#[test]
fn parses_outbound_transparent_mitm_strategy() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[enforcement.interception]
strategy = "outbound_transparent_mitm"

[enforcement.interception.proxy]
mode = "external"
self_bypass = "uses_reserved_mark"
listen_port = 15002
"#,
    )?;

    assert_eq!(
        config.enforcement.interception.strategy,
        TransparentInterceptionStrategyConfig::OutboundTransparentMitm
    );
    assert_eq!(
        config.enforcement.interception.proxy.mode,
        TransparentInterceptionProxyModeConfig::External
    );
    assert_eq!(
        config.enforcement.interception.proxy.self_bypass,
        TransparentInterceptionProxySelfBypassConfig::UsesReservedMark
    );
    assert_eq!(
        config.enforcement.interception.proxy.listen_port,
        Some(15002)
    );
    Ok(())
}

#[test]
fn parses_inbound_tproxy_mitm_strategy() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[enforcement.interception]
strategy = "inbound_tproxy_mitm"

[enforcement.interception.proxy]
mode = "external"
listen_port = 15003
"#,
    )?;

    assert_eq!(
        config.enforcement.interception.strategy,
        TransparentInterceptionStrategyConfig::InboundTproxyMitm
    );
    assert_eq!(
        config.enforcement.interception.proxy.mode,
        TransparentInterceptionProxyModeConfig::External
    );
    assert_eq!(
        config.enforcement.interception.proxy.listen_port,
        Some(15003)
    );
    Ok(())
}

#[test]
fn parses_external_mitm_backend_material_contract() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[enforcement.interception]
strategy = "outbound_transparent_mitm"

[enforcement.interception.proxy]
mode = "external"
self_bypass = "uses_reserved_mark"
listen_port = 15002

[enforcement.interception.mitm]
backend = "external"
ca_certificate_ref = "mitm-ca"
ca_private_key_ref = "mitm-ca-key"
leaf_certificate_chain_refs = ["leaf-cert"]
leaf_private_key_ref = "leaf-key"
upstream_trust_anchor_refs = ["upstream-ca"]

[[tls.materials]]
id = "mitm-ca"
kind = "mitm_ca_certificate"
path = "/etc/sssa/mitm-ca.pem"

[[tls.materials]]
id = "mitm-ca-key"
kind = "mitm_ca_private_key"
path = "/etc/sssa/mitm-ca.key"

[[tls.materials]]
id = "leaf-cert"
kind = "mitm_leaf_certificate"
path = "/etc/sssa/leaf.pem"

[[tls.materials]]
id = "leaf-key"
kind = "mitm_leaf_private_key"
path = "/etc/sssa/leaf.key"

[[tls.materials]]
id = "upstream-ca"
kind = "mitm_upstream_trust_anchor"
path = "/etc/sssa/upstream-ca.pem"
"#,
    )?;

    assert_eq!(
        config.enforcement.interception.mitm.backend,
        TransparentInterceptionMitmBackendConfig::External
    );
    assert_eq!(
        config.enforcement.interception.mitm.ca_certificate_ref,
        Some("mitm-ca".to_string())
    );
    assert_eq!(
        config.enforcement.interception.mitm.ca_private_key_ref,
        Some("mitm-ca-key".to_string())
    );
    assert_eq!(
        config
            .enforcement
            .interception
            .mitm
            .leaf_certificate_chain_refs,
        vec!["leaf-cert"]
    );
    assert_eq!(
        config.enforcement.interception.mitm.leaf_private_key_ref,
        Some("leaf-key".to_string())
    );
    assert_eq!(
        config
            .enforcement
            .interception
            .mitm
            .upstream_trust_anchor_refs,
        vec!["upstream-ca"]
    );
    assert_eq!(
        config.tls.materials[0].kind,
        TlsMaterialKind::MitmCaCertificate
    );
    assert_eq!(
        config.tls.materials[1].kind,
        TlsMaterialKind::MitmCaPrivateKey
    );
    assert_eq!(
        config.tls.materials[2].kind,
        TlsMaterialKind::MitmLeafCertificate
    );
    assert_eq!(
        config.tls.materials[3].kind,
        TlsMaterialKind::MitmLeafPrivateKey
    );
    assert_eq!(
        config.tls.materials[4].kind,
        TlsMaterialKind::MitmUpstreamTrustAnchor
    );
    Ok(())
}

#[test]
fn parses_external_outbound_proxy_self_bypass_contract() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[enforcement.interception]
strategy = "outbound_transparent_proxy"

[enforcement.interception.proxy]
mode = "external"
self_bypass = "uses_reserved_mark"
listen_port = 15001
"#,
    )?;

    assert_eq!(
        config.enforcement.interception.proxy.mode,
        TransparentInterceptionProxyModeConfig::External
    );
    assert_eq!(
        config.enforcement.interception.proxy.self_bypass,
        TransparentInterceptionProxySelfBypassConfig::UsesReservedMark
    );
    Ok(())
}

#[test]
fn parses_managed_transparent_interception_proxy_mode() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[enforcement.interception]
strategy = "inbound_tproxy"

[enforcement.interception.proxy]
mode = "managed_tcp_relay"
listen_port = 15001
"#,
    )?;

    assert_eq!(
        config.enforcement.interception.proxy.mode,
        TransparentInterceptionProxyModeConfig::ManagedTcpRelay
    );
    assert_eq!(
        config.enforcement.interception.proxy.listen_port,
        Some(15001)
    );
    Ok(())
}

#[test]
fn parses_transparent_proxy_health_probe() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[enforcement.interception]
strategy = "inbound_tproxy"

[enforcement.interception.proxy]
mode = "managed_tcp_relay"
listen_port = 15001

[enforcement.interception.proxy.health_probe]
target = "127.0.0.1:18080"
interval_ms = 500
timeout_ms = 100
failure_threshold = 2
"#,
    )?;

    assert_eq!(
        config.enforcement.interception.proxy.health_probe.target,
        Some("127.0.0.1:18080".to_string())
    );
    assert_eq!(
        config
            .enforcement
            .interception
            .proxy
            .health_probe
            .interval_ms,
        500
    );
    assert_eq!(
        config
            .enforcement
            .interception
            .proxy
            .health_probe
            .timeout_ms,
        100
    );
    assert_eq!(
        config
            .enforcement
            .interception
            .proxy
            .health_probe
            .failure_threshold,
        2
    );
    Ok(())
}

#[test]
fn rejects_transparent_interception_host_resource_overrides() {
    let error = AgentConfig::from_toml_str(
        r#"
[enforcement.interception]
strategy = "inbound_tproxy"

[enforcement.interception.proxy]
listen_port = 15001

[enforcement.interception.nftables]
table_name = "filter"
mark = 0
route_table = 0
"#,
    )
    .expect_err("transparent interception host resources are internal reserved resources");

    assert!(error.to_string().contains("nftables"));
}

#[test]
fn parses_enforcement_policy_manifest_defaults() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = toml::from_str::<EnforcementPolicyManifest>(
        r#"
id = "managed-apps"
version = "2026-06-12"
"#,
    )?;

    assert_eq!(manifest.id, "managed-apps");
    assert_eq!(manifest.version, "2026-06-12");
    assert_eq!(
        manifest.protective_actions.actions(),
        &[Action::Deny, Action::Reset, Action::Quarantine]
    );
    assert!(manifest.selector.is_none());
    Ok(())
}
