use probe_config::*;
use probe_core::{Action, ApplicationProtocol};

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
ca_certificate_ref = "mitm-ca"
ca_private_key_ref = "mitm-ca-key"
leaf_certificate_chain_refs = ["leaf-cert"]
leaf_private_key_ref = "leaf-key"
upstream_trust_anchor_refs = ["upstream-ca"]

[enforcement.interception.mitm.client_trust]
mode = "operator_managed"

[enforcement.interception.mitm.backend]
mode = "external"

[enforcement.interception.mitm.backend.readiness_probe]
target = "127.0.0.1:15002"
timeout_ms = 250

[[tls.materials]]
id = "mitm-ca"
kind = "mitm_ca_certificate"
path = "/etc/traffic-probe/mitm-ca.pem"

[[tls.materials]]
id = "mitm-ca-key"
kind = "mitm_ca_private_key"
path = "/etc/traffic-probe/mitm-ca.key"

[[tls.materials]]
id = "leaf-cert"
kind = "mitm_leaf_certificate"
path = "/etc/traffic-probe/leaf.pem"

[[tls.materials]]
id = "leaf-key"
kind = "mitm_leaf_private_key"
path = "/etc/traffic-probe/leaf.key"

[[tls.materials]]
id = "upstream-ca"
kind = "mitm_upstream_trust_anchor"
path = "/etc/traffic-probe/upstream-ca.pem"
"#,
    )?;

    let TransparentInterceptionMitmBackendConfig::External { readiness_probe } =
        &config.enforcement.interception.mitm.backend
    else {
        panic!("expected external MITM backend");
    };
    assert_eq!(
        config.enforcement.interception.mitm.ca_certificate_ref,
        Some("mitm-ca".to_string())
    );
    assert_eq!(
        config.enforcement.interception.mitm.ca_private_key_ref,
        Some("mitm-ca-key".to_string())
    );
    assert_eq!(
        config.enforcement.interception.mitm.client_trust.mode,
        TransparentInterceptionMitmClientTrustModeConfig::OperatorManaged
    );
    assert_eq!(readiness_probe.target.as_deref(), Some("127.0.0.1:15002"));
    assert_eq!(readiness_probe.timeout_ms, 250);
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
fn parses_managed_process_mitm_backend_contract() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[enforcement.interception]
strategy = "inbound_tproxy_mitm"

[enforcement.interception.proxy]
mode = "external"
listen_port = 15002

[enforcement.interception.mitm]
ca_certificate_ref = "mitm-ca"
ca_private_key_ref = "mitm-ca-key"

[enforcement.interception.mitm.client_trust]
mode = "operator_managed"

[enforcement.interception.mitm.backend]
mode = "managed_process"

[enforcement.interception.mitm.backend.readiness_probe]
target = "127.0.0.1:15002"
timeout_ms = 250

[enforcement.interception.mitm.backend.process]
program = "/usr/local/bin/traffic-probe-mitm-proxy"
args = ["--listen", "127.0.0.1:15002"]
working_dir = "/run/traffic-probe"

[[tls.materials]]
id = "mitm-ca"
kind = "mitm_ca_certificate"
path = "/etc/traffic-probe/mitm-ca.pem"

[[tls.materials]]
id = "mitm-ca-key"
kind = "mitm_ca_private_key"
path = "/etc/traffic-probe/mitm-ca.key"
"#,
    )?;

    let TransparentInterceptionMitmBackendConfig::ManagedProcess { process, .. } =
        &config.enforcement.interception.mitm.backend
    else {
        panic!("expected managed-process MITM backend");
    };
    assert_eq!(
        config.enforcement.interception.mitm.client_trust.mode,
        TransparentInterceptionMitmClientTrustModeConfig::OperatorManaged
    );
    assert_eq!(
        process.program.as_deref(),
        Some(std::path::Path::new(
            "/usr/local/bin/traffic-probe-mitm-proxy"
        ))
    );
    assert_eq!(
        process.args,
        vec!["--listen".to_string(), "127.0.0.1:15002".to_string()]
    );
    assert_eq!(
        process.working_dir.as_deref(),
        Some(std::path::Path::new("/run/traffic-probe"))
    );
    Ok(())
}

#[test]
fn parses_product_proxy_mitm_backend_contract() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[enforcement.interception]
strategy = "inbound_tproxy_mitm"

[enforcement.interception.proxy]
mode = "external"
listen_port = 15002

[enforcement.interception.mitm]
leaf_certificate_chain_refs = ["mitm-leaf"]
leaf_private_key_ref = "mitm-leaf-key"

[enforcement.interception.mitm.client_trust]
mode = "operator_managed"

[enforcement.interception.mitm.plaintext_bridge]
mode = "capture_event_feed"
path = "/run/traffic-probe/mitm-feed.jsonl"

[enforcement.interception.mitm.policy_hook]
mode = "http_json"
endpoint = "http://127.0.0.1:15003/mitm-policy-hook"

[enforcement.interception.mitm.backend]
mode = "product_proxy"

[enforcement.interception.mitm.backend.readiness_probe]
target = "127.0.0.1:15002"

	[enforcement.interception.mitm.backend.process]
	application_protocols = ["http1"]
	upstream_tls_mode = "always"

	[enforcement.interception.mitm.backend.process.launcher]
	mode = "external_binary"
	program = "/usr/local/bin/traffic-probe-mitm-proxy"
	working_dir = "/run/traffic-probe"

	[enforcement.interception.mitm.backend.process.upstream_discovery]
	mode = "dns"
	default_port = 443
	allow_special_use_addresses = true

	[[enforcement.interception.mitm.backend.process.upstream_routes]]
	host = "Route.Example"
target = "127.0.0.1:18443"

[[tls.materials]]
id = "mitm-leaf"
kind = "mitm_leaf_certificate"
path = "/etc/traffic-probe/mitm-leaf.pem"

[[tls.materials]]
id = "mitm-leaf-key"
kind = "mitm_leaf_private_key"
path = "/etc/traffic-probe/mitm-leaf.key"
"#,
    )?;

    let TransparentInterceptionMitmBackendConfig::ProductProxy { process, .. } =
        &config.enforcement.interception.mitm.backend
    else {
        panic!("expected product-proxy MITM backend");
    };
    let TransparentInterceptionMitmProductProxyLauncherConfig::ExternalBinary {
        program,
        working_dir,
    } = &process.launcher
    else {
        panic!("expected external binary launcher");
    };
    assert_eq!(
        program.as_deref(),
        Some(std::path::Path::new(
            "/usr/local/bin/traffic-probe-mitm-proxy"
        ))
    );
    assert_eq!(
        working_dir.as_deref(),
        Some(std::path::Path::new("/run/traffic-probe"))
    );
    assert_eq!(
        process.application_protocols,
        Some(vec![ApplicationProtocol::Http1])
    );
    assert_eq!(
        process.upstream_tls_mode,
        TransparentInterceptionMitmProductProxyUpstreamTlsModeConfig::Always
    );
    assert_eq!(
        process.upstream_discovery.mode,
        TransparentInterceptionMitmProductProxyUpstreamDiscoveryModeConfig::Dns
    );
    assert_eq!(
        process.upstream_discovery.default_port,
        std::num::NonZeroU16::new(443)
    );
    assert!(process.upstream_discovery.allow_special_use_addresses);
    assert_eq!(process.upstream_routes.len(), 1);
    assert_eq!(process.upstream_routes[0].host, "Route.Example");
    assert_eq!(process.upstream_routes[0].target, "127.0.0.1:18443");
    Ok(())
}

#[test]
fn parses_external_mitm_plaintext_bridge() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[enforcement.interception]
strategy = "inbound_tproxy_mitm"

[enforcement.interception.mitm.plaintext_bridge]
mode = "capture_event_feed"
path = "/run/traffic-probe/mitm-capture-events.jsonl"
follow = true
"#,
    )?;

    assert_eq!(
        config.enforcement.interception.mitm.plaintext_bridge.mode,
        TransparentInterceptionMitmPlaintextBridgeModeConfig::CaptureEventFeed
    );
    assert_eq!(
        config
            .enforcement
            .interception
            .mitm
            .plaintext_bridge
            .path
            .as_deref(),
        Some(std::path::Path::new(
            "/run/traffic-probe/mitm-capture-events.jsonl"
        ))
    );
    assert_eq!(
        config.enforcement.interception.mitm.plaintext_bridge.follow,
        Some(true)
    );
    Ok(())
}

#[test]
fn parses_external_mitm_policy_hook() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[enforcement.interception]
strategy = "outbound_transparent_mitm"

[enforcement.interception.mitm.policy_hook]
mode = "http_json"
endpoint = "http://127.0.0.1:15002/enforce"
timeout_ms = 500
max_response_bytes = 32768
"#,
    )?;

    assert_eq!(
        config.enforcement.interception.mitm.policy_hook.mode,
        TransparentInterceptionMitmPolicyHookModeConfig::HttpJson
    );
    assert_eq!(
        config
            .enforcement
            .interception
            .mitm
            .policy_hook
            .endpoint
            .as_deref(),
        Some("http://127.0.0.1:15002/enforce")
    );
    assert_eq!(
        config.enforcement.interception.mitm.policy_hook.timeout_ms,
        500
    );
    assert_eq!(
        config
            .enforcement
            .interception
            .mitm
            .policy_hook
            .max_response_bytes,
        32768
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
