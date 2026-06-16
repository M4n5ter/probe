use probe_config::*;
use probe_core::Action;

#[test]
fn parses_transparent_interception_strategy() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[enforcement.interception]
strategy = "outbound_mitm"

[enforcement.interception.proxy]
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
        TransparentInterceptionStrategyConfig::OutboundMitm
    );
    assert_eq!(
        config.enforcement.interception.proxy.listen_port,
        Some(15001)
    );
    assert!(config.enforcement.interception.selector.is_some());
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
