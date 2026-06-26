use probe_config::*;

#[test]
fn validation_rejects_invalid_enforcement_policy_source_config()
-> Result<(), Box<dyn std::error::Error>> {
    let empty_file = AgentConfig::from_toml_str(
        r#"
[enforcement.policy.source]
kind = "file"
path = ""
"#,
    )?;

    let error = empty_file
        .validate_basic()
        .expect_err("enforcement policy source path must be validated");

    assert!(
        error
            .to_string()
            .contains("enforcement policy file path cannot be empty")
    );

    for endpoint in [
        "https://control.example/enforcement",
        "http://127.0.0.1:8080/enforcement",
        "http://[::1]:8080/enforcement",
        "http://localhost:8080/enforcement",
    ] {
        let config = AgentConfig::from_toml_str(&format!(
            r#"
[enforcement.policy.source]
kind = "remote"
endpoint = "{endpoint}"
"#
        ))?;
        config.validate_basic()?;
    }

    let config = AgentConfig::from_toml_str(
        r#"
[enforcement.policy.source]
kind = "remote"
endpoint = "https://control.example/enforcement"
max_body_bytes = 33554432
"#,
    )?;
    config.validate_basic()?;

    for (endpoint, reason) in [
        (
            "http://control.example/enforcement",
            "remote enforcement policy endpoint must use HTTPS",
        ),
        (
            "ftp://control.example/enforcement",
            "remote enforcement policy endpoint must use HTTPS",
        ),
        (
            "control.example/enforcement",
            "remote enforcement policy endpoint must be an absolute URL",
        ),
        (
            "https://user:password@control.example/enforcement",
            "remote enforcement policy endpoint must not contain credentials",
        ),
    ] {
        let config = AgentConfig::from_toml_str(&format!(
            r#"
[enforcement.policy.source]
kind = "remote"
endpoint = "{endpoint}"
"#
        ))?;
        let error = config
            .validate_basic()
            .expect_err("invalid remote enforcement endpoint must be rejected");
        assert!(
            error.to_string().contains(reason),
            "expected {reason:?} in {error}"
        );
    }

    for (max_body_bytes, reason) in [
        (
            0,
            "remote enforcement policy max_body_bytes must be greater than zero",
        ),
        (
            MAX_REMOTE_ENFORCEMENT_POLICY_BODY_LIMIT_BYTES + 1,
            "remote enforcement policy max_body_bytes cannot exceed",
        ),
    ] {
        let config = AgentConfig::from_toml_str(&format!(
            r#"
[enforcement.policy.source]
kind = "remote"
endpoint = "https://control.example/enforcement"
max_body_bytes = {max_body_bytes}
"#
        ))?;
        let error = config
            .validate_basic()
            .expect_err("invalid remote enforcement body limit must be rejected");
        assert!(
            error.to_string().contains(reason),
            "expected {reason:?} in {error}"
        );
    }
    Ok(())
}

#[test]
fn validation_rejects_incomplete_transparent_interception_config()
-> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[enforcement.interception]
strategy = "inbound_tproxy"
"#,
    )?;

    let error = config
        .validate_basic()
        .expect_err("invalid transparent interception config must be rejected");

    assert!(
        error
            .to_string()
            .contains("transparent interception requires a non-zero proxy listen port")
    );
    Ok(())
}

#[test]
fn validation_rejects_external_outbound_proxy_without_self_bypass_contract()
-> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[enforcement.interception]
strategy = "outbound_transparent_proxy"

[enforcement.interception.proxy]
listen_port = 15001
"#,
    )?;

    let error = config
        .validate_basic()
        .expect_err("external outbound transparent proxy must declare self-bypass contract");

    assert!(
        error
            .to_string()
            .contains("external outbound transparent proxy requires self_bypass")
    );
    Ok(())
}

#[test]
fn validation_accepts_external_outbound_proxy_with_reserved_mark_self_bypass()
-> Result<(), Box<dyn std::error::Error>> {
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

    config.validate_basic()?;
    Ok(())
}

#[test]
fn validation_accepts_external_mitm_backend_material_contract()
-> Result<(), Box<dyn std::error::Error>> {
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
upstream_trust_anchor_refs = ["upstream-ca"]

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
id = "upstream-ca"
kind = "mitm_upstream_trust_anchor"
path = "/etc/traffic-probe/upstream-ca.pem"
"#,
    )?;

    config.validate_basic()?;
    Ok(())
}

#[test]
fn validation_accepts_managed_process_mitm_backend_contract()
-> Result<(), Box<dyn std::error::Error>> {
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

[enforcement.interception.mitm.backend]
mode = "managed_process"

[enforcement.interception.mitm.backend.readiness_probe]
target = "127.0.0.1:15002"
timeout_ms = 250

[enforcement.interception.mitm.backend.process]
program = "/usr/local/bin/traffic-probe-mitm-proxy"
args = ["--listen", "127.0.0.1:15002"]

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

    config.validate_basic()?;
    Ok(())
}

#[test]
fn validation_rejects_incomplete_managed_process_mitm_backend_contract()
-> Result<(), Box<dyn std::error::Error>> {
    let missing_program = AgentConfig::from_toml_str(
        r#"
[enforcement.interception]
strategy = "inbound_tproxy_mitm"

[enforcement.interception.proxy]
mode = "external"
listen_port = 15002

[enforcement.interception.mitm]
ca_certificate_ref = "mitm-ca"
ca_private_key_ref = "mitm-ca-key"

[enforcement.interception.mitm.backend]
mode = "managed_process"

[enforcement.interception.mitm.backend.readiness_probe]
target = "127.0.0.1:15002"

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
    let error = missing_program
        .validate_basic()
        .expect_err("managed MITM backend must require a program");
    let violations = validation_violations(&error);

    assert!(violations.iter().any(|violation| violation.field
        == "enforcement.interception.mitm.backend.process.program"
        && violation.reason.contains("requires a program path")));

    let external_with_managed_process = AgentConfig::from_toml_str(
        r#"
[enforcement.interception]
strategy = "inbound_tproxy_mitm"

[enforcement.interception.proxy]
mode = "external"
listen_port = 15002

[enforcement.interception.mitm]
ca_certificate_ref = "mitm-ca"
ca_private_key_ref = "mitm-ca-key"

[enforcement.interception.mitm.backend]
mode = "external"

[enforcement.interception.mitm.backend.readiness_probe]
target = "127.0.0.1:15002"

[enforcement.interception.mitm.backend.process]
program = "/usr/local/bin/traffic-probe-mitm-proxy"

[[tls.materials]]
id = "mitm-ca"
kind = "mitm_ca_certificate"
path = "/etc/traffic-probe/mitm-ca.pem"

[[tls.materials]]
id = "mitm-ca-key"
kind = "mitm_ca_private_key"
path = "/etc/traffic-probe/mitm-ca.key"
"#,
    )
    .expect_err("external MITM backend must not accept managed process payload");

    assert!(
        external_with_managed_process
            .to_string()
            .contains("unknown field")
    );

    let relative_paths = AgentConfig::from_toml_str(
        r#"
[enforcement.interception]
strategy = "inbound_tproxy_mitm"

[enforcement.interception.proxy]
mode = "external"
listen_port = 15002

[enforcement.interception.mitm]
ca_certificate_ref = "mitm-ca"
ca_private_key_ref = "mitm-ca-key"

[enforcement.interception.mitm.backend]
mode = "managed_process"

[enforcement.interception.mitm.backend.readiness_probe]
target = "127.0.0.1:15002"

[enforcement.interception.mitm.backend.process]
program = "traffic-probe-mitm-proxy"
working_dir = "run/traffic-probe"

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
    let error = relative_paths
        .validate_basic()
        .expect_err("managed MITM backend paths must be absolute");
    let violations = validation_violations(&error);

    assert!(violations.iter().any(|violation| violation.field
        == "enforcement.interception.mitm.backend.process.program"
        && violation.reason.contains("must be absolute")));
    assert!(violations.iter().any(|violation| violation.field
        == "enforcement.interception.mitm.backend.process.working_dir"
        && violation.reason.contains("must be absolute")));
    Ok(())
}

#[test]
fn validation_accepts_external_mitm_plaintext_bridge() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(&external_mitm_bridge_fixture(
        r#"
[enforcement.interception.mitm.plaintext_bridge]
mode = "capture_event_feed"
path = "/run/traffic-probe/mitm-capture-events.jsonl"
follow = true
"#,
    ))?;

    config.validate_basic()?;
    Ok(())
}

#[test]
fn validation_rejects_incomplete_external_mitm_plaintext_bridge()
-> Result<(), Box<dyn std::error::Error>> {
    let missing_path = AgentConfig::from_toml_str(&external_mitm_bridge_fixture(
        r#"
[enforcement.interception.mitm.plaintext_bridge]
mode = "capture_event_feed"
"#,
    ))?;
    let error = missing_path
        .validate_basic()
        .expect_err("capture-event MITM plaintext bridge must have a path");
    let violations = validation_violations(&error);

    assert!(violations.iter().any(|violation| {
        violation.field == "enforcement.interception.mitm.plaintext_bridge.path"
            && violation
                .reason
                .contains("requires a JSON-lines capture event path")
    }));

    let path_without_mode = AgentConfig::from_toml_str(&external_mitm_bridge_fixture(
        r#"
[enforcement.interception.mitm.plaintext_bridge]
path = "/run/traffic-probe/mitm-capture-events.jsonl"
"#,
    ))?;
    let error = path_without_mode
        .validate_basic()
        .expect_err("MITM plaintext bridge path must require explicit mode");
    let violations = validation_violations(&error);

    assert!(violations.iter().any(|violation| violation.field
        == "enforcement.interception.mitm.plaintext_bridge.path"
        && violation.reason.contains("plaintext_bridge.mode")));

    let follow_without_mode = AgentConfig::from_toml_str(&external_mitm_bridge_fixture(
        r#"
[enforcement.interception.mitm.plaintext_bridge]
follow = true
"#,
    ))?;
    let error = follow_without_mode
        .validate_basic()
        .expect_err("MITM plaintext bridge follow mode must require explicit mode");
    let violations = validation_violations(&error);

    assert!(violations.iter().any(|violation| violation.field
        == "enforcement.interception.mitm.plaintext_bridge.follow"
        && violation.reason.contains("plaintext_bridge.mode")));

    let empty_path = AgentConfig::from_toml_str(&external_mitm_bridge_fixture(
        r#"
[enforcement.interception.mitm.plaintext_bridge]
mode = "capture_event_feed"
path = ""
"#,
    ))?;
    let error = empty_path
        .validate_basic()
        .expect_err("MITM plaintext bridge path must not be empty");
    let violations = validation_violations(&error);

    assert!(violations.iter().any(|violation| violation.field
        == "enforcement.interception.mitm.plaintext_bridge.path"
        && violation.reason.contains("must not be empty")));
    Ok(())
}

#[test]
fn validation_rejects_external_mitm_without_readiness_target()
-> Result<(), Box<dyn std::error::Error>> {
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

[enforcement.interception.mitm.backend]
mode = "external"

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

    let error = config
        .validate_basic()
        .expect_err("external MITM backend must have a readiness target");
    let violations = validation_violations(&error);

    assert!(violations.iter().any(|violation| violation.field
        == "enforcement.interception.mitm.backend.readiness_probe.target"));
    Ok(())
}

#[test]
fn validation_rejects_invalid_external_mitm_readiness_probe()
-> Result<(), Box<dyn std::error::Error>> {
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

[enforcement.interception.mitm.backend]
mode = "external"

[enforcement.interception.mitm.backend.readiness_probe]
target = "localhost:15002"
timeout_ms = 0

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

    let error = config
        .validate_basic()
        .expect_err("external MITM readiness probe must be an IP socket target");
    let violations = validation_violations(&error);

    assert!(violations.iter().any(|violation| violation.field
        == "enforcement.interception.mitm.backend.readiness_probe.target"
        && violation.reason.contains("IP socket address")));
    assert!(violations.iter().any(|violation| violation.field
        == "enforcement.interception.mitm.backend.readiness_probe.timeout_ms"));
    Ok(())
}

#[test]
fn validation_rejects_external_mitm_readiness_target_that_does_not_match_redirect_listener()
-> Result<(), Box<dyn std::error::Error>> {
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

[enforcement.interception.mitm.backend]
mode = "external"

[enforcement.interception.mitm.backend.readiness_probe]
target = "192.0.2.10:15003"

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

    let error = config
        .validate_basic()
        .expect_err("external MITM readiness probe must target the local redirect listener");
    let violations = validation_violations(&error);

    assert!(violations.iter().any(|violation| violation.field
        == "enforcement.interception.mitm.backend.readiness_probe.target"
        && violation.reason.contains("loopback IP address")));
    assert!(violations.iter().any(|violation| {
        violation.field == "enforcement.interception.mitm.backend.readiness_probe.target"
            && violation
                .reason
                .contains("target port must match proxy listen_port")
    }));
    Ok(())
}

#[test]
fn validation_rejects_incomplete_external_mitm_backend_contract()
-> Result<(), Box<dyn std::error::Error>> {
    let missing_backend = AgentConfig::from_toml_str(
        r#"
[enforcement.interception]
strategy = "inbound_tproxy_mitm"

[enforcement.interception.proxy]
mode = "external"
listen_port = 15002
"#,
    )?;
    let error = missing_backend
        .validate_basic()
        .expect_err("MITM strategy must require explicit backend and certificate material");
    assert!(
        error
            .to_string()
            .contains("enforcement.interception.mitm.backend")
    );
    assert!(
        error
            .to_string()
            .contains("requires either a CA certificate/private key pair")
    );

    let wrong_kind = AgentConfig::from_toml_str(
        r#"
[enforcement.interception]
strategy = "inbound_tproxy_mitm"

[enforcement.interception.proxy]
mode = "external"
listen_port = 15002

[enforcement.interception.mitm]
ca_certificate_ref = "collector-ca"
ca_private_key_ref = "mitm-ca-key"

[enforcement.interception.mitm.backend]
mode = "external"

[enforcement.interception.mitm.backend.readiness_probe]
target = "127.0.0.1:15002"

[[tls.materials]]
id = "collector-ca"
kind = "trust_anchor"
path = "/etc/traffic-probe/collector-ca.pem"

[[tls.materials]]
id = "mitm-ca-key"
kind = "mitm_ca_private_key"
path = "/etc/traffic-probe/mitm-ca.key"
"#,
    )?;
    let error = wrong_kind
        .validate_basic()
        .expect_err("MITM material refs must point at MITM material kinds");
    assert!(error.to_string().contains("expected MitmCaCertificate"));

    Ok(())
}

#[test]
fn validation_rejects_reserved_mark_self_bypass_outside_external_outbound_proxy()
-> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[enforcement.interception]
strategy = "inbound_tproxy"

[enforcement.interception.proxy]
mode = "external"
self_bypass = "uses_reserved_mark"
listen_port = 15001
"#,
    )?;

    let error = config
        .validate_basic()
        .expect_err("reserved mark self-bypass must be scoped to external outbound proxy");

    assert!(
        error
            .to_string()
            .contains("reserved-mark self-bypass is only valid")
    );
    Ok(())
}

#[test]
fn validation_rejects_reserved_mark_self_bypass_for_managed_outbound_proxy()
-> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[enforcement.interception]
strategy = "outbound_transparent_proxy"

[enforcement.interception.proxy]
mode = "managed_tcp_relay"
self_bypass = "uses_reserved_mark"
listen_port = 15001
"#,
    )?;

    let error = config
        .validate_basic()
        .expect_err("managed outbound proxy must not accept reserved mark self-bypass");

    assert!(
        error
            .to_string()
            .contains("reserved-mark self-bypass is only valid")
    );
    Ok(())
}

#[test]
fn validation_rejects_ipv4_mapped_managed_relay_health_probe_self_target()
-> Result<(), Box<dyn std::error::Error>> {
    for target in ["[::ffff:127.0.0.1]:15001", "[::ffff:0.0.0.0]:15001"] {
        let config = AgentConfig::from_toml_str(&format!(
            r#"
[enforcement.interception]
strategy = "inbound_tproxy"

[enforcement.interception.proxy]
mode = "managed_tcp_relay"
listen_port = 15001

[enforcement.interception.proxy.health_probe]
target = "{target}"
"#
        ))?;

        let error = config
            .validate_basic()
            .expect_err("IPv4-mapped self-target health probe must be rejected");

        assert!(
            error.to_string().contains(
                "managed TCP relay health probe target must not point at the local relay listener"
            ),
            "expected self-target rejection for {target}: {error}"
        );
    }
    Ok(())
}

fn validation_violations(error: &ConfigError) -> &[ConfigViolation] {
    let ConfigError::Validation(error) = error else {
        panic!("expected validation error, got {error}");
    };
    error.violations()
}

fn external_mitm_bridge_fixture(bridge: &str) -> String {
    format!(
        r#"
[enforcement.interception]
strategy = "inbound_tproxy_mitm"

[enforcement.interception.proxy]
mode = "external"
listen_port = 15002

[enforcement.interception.mitm]
ca_certificate_ref = "mitm-ca"
ca_private_key_ref = "mitm-ca-key"

[enforcement.interception.mitm.backend]
mode = "external"

[enforcement.interception.mitm.backend.readiness_probe]
target = "127.0.0.1:15002"

{bridge}

[[tls.materials]]
id = "mitm-ca"
kind = "mitm_ca_certificate"
path = "/etc/traffic-probe/mitm-ca.pem"

[[tls.materials]]
id = "mitm-ca-key"
kind = "mitm_ca_private_key"
path = "/etc/traffic-probe/mitm-ca.key"
"#
    )
}
