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
