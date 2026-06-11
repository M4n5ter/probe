use super::*;
use probe_core::Action;

#[test]
fn minimal_config_uses_defaults() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str("")?;

    assert_eq!(config.agent_id, "sssa-probe");
    assert_eq!(config.capture.selection, CaptureSelection::Auto);
    assert_eq!(
        config.capture.fallback_backends,
        vec![LiveCaptureBackend::Ebpf, LiveCaptureBackend::Libpcap]
    );
    assert_eq!(config.capture.libpcap.interface, None);
    assert_eq!(config.capture.libpcap.bpf_filter, "tcp");
    assert_eq!(config.capture.libpcap.snaplen, 65_535);
    assert!(!config.capture.libpcap.promisc);
    assert!(config.capture.libpcap.immediate_mode);
    assert_eq!(config.capture.libpcap.read_timeout_ms, 1_000);
    assert!(config.export.worker.enabled);
    assert_eq!(
        config.export.worker.schedule,
        ExportWorkerScheduleConfig::FixedIntervalBounded {
            interval_ms: 1_000,
            batches_per_sink_per_tick: 1,
            sink_timeout_ms: 10_000,
            failure_backoff_ms: 30_000,
        }
    );
    assert_eq!(config.exporters, Vec::<ExporterConfig>::new());
    assert_eq!(config.enforcement.mode, EnforcementMode::AuditOnly);
    assert_eq!(
        config.enforcement.policy.source,
        EnforcementPolicySourceConfig::None
    );
    config.validate_basic()?;
    Ok(())
}

#[test]
fn parses_runtime_sections() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
agent_id = "node-a"
config_version = "cfg-1"

[capture]
selection = "ebpf"
fallback_backends = ["libpcap"]

[capture.libpcap]
interface = "lo"
bpf_filter = "tcp port 8080"
snaplen = 4096
promisc = true
immediate_mode = false
read_timeout_ms = 250
buffer_size = 1048576

[storage]
path = "/tmp/sssa-spool"
ingress_retention_bytes = 1048576

[export.worker]
enabled = true

[export.worker.schedule]
mode = "fixed_interval_bounded"
interval_ms = 250
batches_per_sink_per_tick = 3
sink_timeout_ms = 2000
failure_backoff_ms = 5000

[[exporters]]
id = "primary"
transport = "webhook"
endpoint = "https://collector.example/batches"
codec = "zstd"
headers = { x_probe = "node-a" }

[exporters.worker]
batches_per_tick = 2

[exporters.tls]
trust_anchor_refs = ["collector-ca"]

[[tls.materials]]
id = "collector-ca"
kind = "trust_anchor"
path = "/etc/ssl/certs/ca.pem"

[tls.plaintext]
enabled = true
provider = "libssl_uprobe"

[enforcement]
mode = "dry_run"

[enforcement.policy.source]
kind = "file"
path = "/etc/sssa-probe/enforcement.toml"

[admin]
enabled = true
socket_path = "/run/sssa-probe/admin.sock"
"#,
    )?;

    assert_eq!(config.agent_id, "node-a");
    assert_eq!(config.config_version, "cfg-1");
    assert_eq!(config.capture.selection, CaptureSelection::Ebpf);
    assert_eq!(config.capture.libpcap.interface.as_deref(), Some("lo"));
    assert_eq!(config.capture.libpcap.bpf_filter, "tcp port 8080");
    assert_eq!(config.capture.libpcap.snaplen, 4096);
    assert!(config.capture.libpcap.promisc);
    assert!(!config.capture.libpcap.immediate_mode);
    assert_eq!(config.capture.libpcap.read_timeout_ms, 250);
    assert_eq!(config.capture.libpcap.buffer_size, Some(1_048_576));
    assert_eq!(config.storage.path, PathBuf::from("/tmp/sssa-spool"));
    assert!(config.export.worker.enabled);
    assert_eq!(
        config.export.worker.schedule,
        ExportWorkerScheduleConfig::FixedIntervalBounded {
            interval_ms: 250,
            batches_per_sink_per_tick: 3,
            sink_timeout_ms: 2_000,
            failure_backoff_ms: 5_000,
        }
    );
    assert_eq!(config.exporters[0].codec, CompressionCodecName::Zstd);
    assert_eq!(config.exporters[0].worker.batches_per_tick, Some(2));
    assert_eq!(
        config.exporters[0].tls.trust_anchor_refs,
        vec!["collector-ca"]
    );
    assert_eq!(config.tls.materials[0].id.as_deref(), Some("collector-ca"));
    assert_eq!(config.tls.materials[0].kind, TlsMaterialKind::TrustAnchor);
    assert!(config.tls.plaintext.enabled);
    assert_eq!(config.capture.plaintext_feed.path, None);
    assert_eq!(config.enforcement.mode, EnforcementMode::DryRun);
    assert_eq!(
        config.enforcement.policy.source,
        EnforcementPolicySourceConfig::File {
            path: PathBuf::from("/etc/sssa-probe/enforcement.toml"),
        }
    );
    assert!(config.admin.enabled);
    assert_eq!(
        config.admin.socket_path,
        PathBuf::from("/run/sssa-probe/admin.sock")
    );
    Ok(())
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
    Ok(())
}

#[test]
fn export_worker_schedule_uses_defaults_for_omitted_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[export.worker]
enabled = true

[export.worker.schedule]
mode = "fixed_interval_bounded"
interval_ms = 250
"#,
    )?;

    assert_eq!(
        config.export.worker.schedule,
        ExportWorkerScheduleConfig::FixedIntervalBounded {
            interval_ms: 250,
            batches_per_sink_per_tick: 1,
            sink_timeout_ms: 10_000,
            failure_backoff_ms: 30_000,
        }
    );
    config.validate_basic()?;
    Ok(())
}

#[test]
fn parses_external_plaintext_feed_config() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[capture]
selection = "plaintext_feed"

[capture.plaintext_feed]
path = "/tmp/sssa-plaintext-feed.jsonl"
"#,
    )?;

    assert_eq!(config.capture.selection, CaptureSelection::PlaintextFeed);
    assert_eq!(
        config.capture.plaintext_feed.path,
        Some(PathBuf::from("/tmp/sssa-plaintext-feed.jsonl"))
    );
    config.validate_basic()?;
    Ok(())
}

#[test]
fn config_rejects_unknown_fields() {
    let result = AgentConfig::from_toml_str("unknown = true");

    assert!(result.is_err());
}

#[test]
fn validation_rejects_invalid_capture_runtime_fields() -> Result<(), Box<dyn std::error::Error>> {
    let empty_fallback = AgentConfig::from_toml_str(
        r#"
[capture]
fallback_backends = []
"#,
    )?;

    let empty_fallback_error = empty_fallback
        .validate_basic()
        .expect_err("auto capture requires a live backend");
    assert!(
        empty_fallback_error
            .to_string()
            .contains("auto capture selection requires at least one live fallback backend")
    );

    let config = AgentConfig::from_toml_str(
        r#"
[capture]
selection = "libpcap"

[capture.libpcap]
bpf_filter = " "
snaplen = 0
read_timeout_ms = -1
buffer_size = 0
"#,
    )?;

    let error = config
        .validate_basic()
        .expect_err("capture fields must be validated");

    assert!(
        error
            .to_string()
            .contains("libpcap BPF filter cannot be empty")
    );
    assert!(
        error
            .to_string()
            .contains("libpcap snaplen must be positive")
    );
    assert!(
        error
            .to_string()
            .contains("libpcap read timeout cannot be negative")
    );
    assert!(
        error
            .to_string()
            .contains("libpcap buffer size must be positive")
    );
    Ok(())
}

#[test]
fn validation_rejects_invalid_plaintext_feed_config() -> Result<(), Box<dyn std::error::Error>> {
    let unused_path = AgentConfig::from_toml_str(
        r#"
[capture.plaintext_feed]
path = "/tmp/feed.jsonl"
"#,
    )?;
    let error = unused_path
        .validate_basic()
        .expect_err("plaintext feed path must belong to the selected backend");
    assert!(error.to_string().contains("capture.plaintext_feed.path"));

    let missing_path = AgentConfig::from_toml_str(
        r#"
[capture]
selection = "plaintext_feed"
"#,
    )?;
    let error = missing_path
        .validate_basic()
        .expect_err("external feed must set a path");
    assert!(error.to_string().contains("capture.plaintext_feed.path"));

    let conflicting_tls_provider = AgentConfig::from_toml_str(
        r#"
[capture]
selection = "plaintext_feed"

[capture.plaintext_feed]
path = "/tmp/feed.jsonl"

[tls.plaintext]
enabled = true
provider = "libssl_uprobe"
"#,
    )?;
    let error = conflicting_tls_provider
        .validate_basic()
        .expect_err("plaintext feed selection must not also enable TLS instrumentation");
    assert!(error.to_string().contains("tls.plaintext.enabled"));
    Ok(())
}

#[test]
fn validation_rejects_empty_tls_material_path() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[[tls.materials]]
kind = "trust_anchor"
path = ""
"#,
    )?;

    let error = config
        .validate_basic()
        .expect_err("TLS material paths must be explicit");

    assert!(error.to_string().contains("tls.materials[0].path"));
    assert!(
        error
            .to_string()
            .contains("TLS material path cannot be empty")
    );
    Ok(())
}

#[test]
fn validation_rejects_invalid_tls_material_registry_refs() -> Result<(), Box<dyn std::error::Error>>
{
    let duplicate_ids = AgentConfig::from_toml_str(
        r#"
[[tls.materials]]
id = "collector-ca"
kind = "trust_anchor"
path = "/tmp/ca-1.pem"

[[tls.materials]]
id = "collector-ca"
kind = "trust_anchor"
path = "/tmp/ca-2.pem"
"#,
    )?;
    let duplicate_error = duplicate_ids
        .validate_basic()
        .expect_err("TLS material ids must be unique");
    assert!(
        duplicate_error
            .to_string()
            .contains("TLS material id must be unique")
    );

    let missing_ref = AgentConfig::from_toml_str(
        r#"
[[exporters]]
id = "primary"
transport = "webhook"
endpoint = "https://collector.example/batches"

[exporters.tls]
trust_anchor_refs = ["missing-ca"]
"#,
    )?;
    let missing_ref_error = missing_ref
        .validate_basic()
        .expect_err("exporter TLS refs must point at registered material ids");
    assert!(
        missing_ref_error
            .to_string()
            .contains("TLS material ref missing-ca does not exist")
    );
    Ok(())
}

#[test]
fn validation_rejects_incomplete_client_tls_identity() -> Result<(), Box<dyn std::error::Error>> {
    let missing_key = AgentConfig::from_toml_str(
        r#"
[[exporters]]
id = "primary"
transport = "webhook"
endpoint = "https://collector.example/batches"

[exporters.tls]
client_certificate_refs = ["client-cert"]

[[tls.materials]]
id = "client-cert"
kind = "client_certificate"
path = "/tmp/client.pem"
"#,
    )?;
    let missing_key_error = missing_key
        .validate_basic()
        .expect_err("client certificate must require a private key");
    assert!(
        missing_key_error
            .to_string()
            .contains("client certificate refs require a client private key ref")
    );

    let missing_certificate = AgentConfig::from_toml_str(
        r#"
[[exporters]]
id = "primary"
transport = "webhook"
endpoint = "https://collector.example/batches"

[exporters.tls]
client_private_key_ref = "client-key"

[[tls.materials]]
id = "client-key"
kind = "client_private_key"
path = "/tmp/client.key"
"#,
    )?;
    let missing_certificate_error = missing_certificate
        .validate_basic()
        .expect_err("client private key must require a certificate");
    assert!(
        missing_certificate_error
            .to_string()
            .contains("client private key ref requires at least one client certificate ref")
    );

    let wrong_kind = AgentConfig::from_toml_str(
        r#"
[[exporters]]
id = "primary"
transport = "webhook"
endpoint = "https://collector.example/batches"

[exporters.tls]
trust_anchor_refs = ["client-cert"]

[[tls.materials]]
id = "client-cert"
kind = "client_certificate"
path = "/tmp/client.pem"
"#,
    )?;
    let wrong_kind_error = wrong_kind
        .validate_basic()
        .expect_err("trust anchor ref must point at a trust anchor material");
    assert!(
        wrong_kind_error
            .to_string()
            .contains("expected TrustAnchor")
    );

    let http_tls = AgentConfig::from_toml_str(
        r#"
[[exporters]]
id = "primary"
transport = "webhook"
endpoint = "http://collector.example/batches"

[exporters.tls]
trust_anchor_refs = ["collector-ca"]

[[tls.materials]]
id = "collector-ca"
kind = "trust_anchor"
path = "/tmp/ca.pem"
"#,
    )?;
    let http_tls_error = http_tls
        .validate_basic()
        .expect_err("TLS refs on plain HTTP webhook must be rejected");
    assert!(
        http_tls_error
            .to_string()
            .contains("exporter TLS material refs require an HTTPS webhook endpoint")
    );
    Ok(())
}

#[test]
fn validation_rejects_invalid_admin_socket_path() -> Result<(), Box<dyn std::error::Error>> {
    let empty = AgentConfig::from_toml_str(
        r#"
[admin]
enabled = true
socket_path = ""
"#,
    )?;
    let error = empty
        .validate_basic()
        .expect_err("enabled admin socket requires a path");
    assert!(
        error
            .to_string()
            .contains("enabled admin socket requires a socket path")
    );

    let relative = AgentConfig::from_toml_str(
        r#"
[admin]
enabled = true
socket_path = "admin.sock"
"#,
    )?;
    let error = relative
        .validate_basic()
        .expect_err("admin socket path must be absolute");
    assert!(
        error
            .to_string()
            .contains("admin socket path must be absolute")
    );
    Ok(())
}

#[test]
fn validation_rejects_zero_enabled_export_worker_knobs() -> Result<(), Box<dyn std::error::Error>> {
    let enabled = AgentConfig::from_toml_str(
        r#"
[export.worker]
enabled = true

[export.worker.schedule]
mode = "fixed_interval_bounded"
interval_ms = 0
batches_per_sink_per_tick = 0
sink_timeout_ms = 0
failure_backoff_ms = 0
"#,
    )?;

    let error = enabled
        .validate_basic()
        .expect_err("enabled export worker must have a positive interval");
    assert!(
        error
            .to_string()
            .contains("export worker interval must be positive")
    );
    assert!(
        error
            .to_string()
            .contains("export worker per-sink batch budget must be positive")
    );
    assert!(
        error
            .to_string()
            .contains("export worker sink timeout must be positive")
    );
    assert!(
        error
            .to_string()
            .contains("export worker failure backoff must be positive")
    );

    let disabled = AgentConfig::from_toml_str(
        r#"
[export.worker]
enabled = false

[export.worker.schedule]
mode = "fixed_interval_bounded"
interval_ms = 0
batches_per_sink_per_tick = 0
sink_timeout_ms = 0
failure_backoff_ms = 0
"#,
    )?;
    disabled.validate_basic()?;
    Ok(())
}

#[test]
fn validation_rejects_zero_exporter_worker_batch_quota() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[[exporters]]
id = "primary"
transport = "webhook"
endpoint = "https://collector.example/batches"

[exporters.worker]
batches_per_tick = 0
"#,
    )?;

    let error = config
        .validate_basic()
        .expect_err("per-sink exporter batch quota must be positive");
    assert!(
        error
            .to_string()
            .contains("exporter worker batches_per_tick must be positive")
    );
    Ok(())
}

#[test]
fn validation_rejects_reserved_exporter_headers() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[[exporters]]
id = "primary"
transport = "webhook"
endpoint = "https://collector.example/batches"
headers = { idempotency-key = "override" }
"#,
    )?;

    let error = config
        .validate_basic()
        .expect_err("reserved webhook header must be rejected");

    assert!(error.to_string().contains("exporter header is reserved"));
    Ok(())
}

#[test]
fn validation_rejects_duplicate_and_reserved_exporter_ids() -> Result<(), Box<dyn std::error::Error>>
{
    let duplicate = AgentConfig::from_toml_str(
        r#"
[[exporters]]
id = "primary"
transport = "webhook"
endpoint = "https://collector.example/one"

[[exporters]]
id = "primary"
transport = "webhook"
endpoint = "https://collector.example/two"
"#,
    )?;
    let duplicate_error = duplicate
        .validate_basic()
        .expect_err("duplicate exporter ids must be rejected");
    assert!(
        duplicate_error
            .to_string()
            .contains("exporter id must be unique")
    );

    let reserved = AgentConfig::from_toml_str(
        r#"
[[exporters]]
id = "replay-webhook"
transport = "webhook"
endpoint = "https://collector.example/replay"
"#,
    )?;
    let reserved_error = reserved
        .validate_basic()
        .expect_err("replay-webhook sink id must be reserved");
    assert!(
        reserved_error
            .to_string()
            .contains("reserved for replay CLI")
    );
    Ok(())
}

#[test]
fn validation_rejects_invalid_exporter_headers() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[[exporters]]
id = "primary"
transport = "webhook"
endpoint = "https://collector.example/batches"
headers = { "bad header" = "value", good = "bad\nvalue" }
"#,
    )?;

    let error = config
        .validate_basic()
        .expect_err("invalid webhook headers must be rejected");

    assert!(
        error
            .to_string()
            .contains("exporter header name is not a valid HTTP token")
    );
    assert!(
        error
            .to_string()
            .contains("exporter header value cannot contain CR or LF")
    );
    Ok(())
}

#[test]
fn validation_ignores_unused_libpcap_fields() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[capture]
selection = "replay"

[capture.libpcap]
bpf_filter = " "
snaplen = 0
"#,
    )?;

    config.validate_basic()?;
    Ok(())
}

#[test]
fn validation_rejects_multiple_enabled_policies() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[[policies]]
id = "a"
enabled = true
path = "/tmp/a.lua"

[[policies]]
id = "b"
enabled = true
path = "/tmp/b.lua"
"#,
    )?;

    let error = config
        .validate_basic()
        .expect_err("multiple enabled policies must be rejected before run");

    assert!(
        error
            .to_string()
            .contains("at most one enabled policy bundle")
    );
    Ok(())
}
