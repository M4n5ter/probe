use std::{collections::BTreeMap, path::PathBuf};

use probe_config::*;
use probe_core::EnforcementMode;

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
path = "/tmp/traffic-probe-spool"

[storage.retention.export]
max_age_ms = 60000
max_records = 50000
sweep_interval_ms = 5000
prune_batch_limit = 128

[storage.retention.ingress]
max_age_ms = 120000
max_records = 10000
sweep_interval_ms = 7000
prune_batch_limit = 256

[export.worker]
enabled = true

[export.worker.schedule]
mode = "fixed_interval_bounded"
interval_ms = 250
batches_per_sink_per_tick = 3
sink_timeout_ms = 2000

[export.worker.schedule.failure_backoff]
initial_ms = 5000
max_ms = 20000
multiplier = 3

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

[tls.plaintext.instrumentation]
enabled = true
libssl_uprobe_object_path = "/opt/traffic-probe/ebpf-tls-plaintext.bpf.o"

[tls.plaintext.instrumentation.selector]
op = "match"

[tls.plaintext.instrumentation.selector.term.process]
pids = [4242]
names = []
exe_path_globs = []
cmdline_regexes = []
systemd_services = []
container_ids = []

[tls.plaintext.instrumentation.selector.term.traffic]
local_ports = [443]
remote_ports = []
directions = []
remote_addresses = []

[enforcement]
mode = "dry_run"
backend = "linux_socket_destroy"

[enforcement.policy.source]
kind = "file"
path = "/etc/traffic-probe/enforcement.toml"

[admin]
enabled = true
socket_path = "/run/traffic-probe/admin.sock"
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
    assert_eq!(
        config.storage.path,
        PathBuf::from("/tmp/traffic-probe-spool")
    );
    assert_eq!(config.storage.retention.ingress.max_age_ms, Some(120_000));
    assert_eq!(config.storage.retention.ingress.max_records, Some(10_000));
    assert_eq!(config.storage.retention.ingress.sweep_interval_ms, 7_000);
    assert_eq!(config.storage.retention.ingress.prune_batch_limit, 256);
    assert_eq!(config.storage.retention.export.max_age_ms, Some(60_000));
    assert_eq!(config.storage.retention.export.max_records, Some(50_000));
    assert_eq!(config.storage.retention.export.sweep_interval_ms, 5_000);
    assert_eq!(config.storage.retention.export.prune_batch_limit, 128);
    assert!(config.export.worker.enabled);
    assert_eq!(
        config.export.worker.schedule,
        ExportWorkerScheduleConfig::FixedIntervalBounded {
            interval_ms: 250,
            batches_per_sink_per_tick: 3,
            sink_timeout_ms: 2_000,
            failure_backoff: ExportFailureBackoffConfig {
                initial_ms: 5_000,
                max_ms: 20_000,
                multiplier: 3,
            },
        }
    );
    assert_eq!(config.exporters[0].codec, CompressionCodecName::Zstd);
    assert_eq!(config.exporters[0].worker.batches_per_tick, Some(2));
    let ExporterTransportConfig::Webhook { tls, .. } = &config.exporters[0].transport else {
        panic!("expected webhook exporter");
    };
    assert_eq!(tls.trust_anchor_refs, vec!["collector-ca"]);
    assert_eq!(config.tls.materials[0].id.as_deref(), Some("collector-ca"));
    assert_eq!(config.tls.materials[0].kind, TlsMaterialKind::TrustAnchor);
    assert!(config.tls.plaintext.instrumentation.enabled);
    assert_eq!(
        config
            .tls
            .plaintext
            .instrumentation
            .libssl_uprobe_object_path,
        Some(PathBuf::from("/opt/traffic-probe/ebpf-tls-plaintext.bpf.o"))
    );
    assert!(config.tls.plaintext.instrumentation.selector.is_some());
    assert_eq!(config.capture.plaintext_feed.path, None);
    assert_eq!(config.enforcement.mode, EnforcementMode::DryRun);
    assert_eq!(
        config.enforcement.backend,
        ConnectionEnforcementBackendConfig::LinuxSocketDestroy
    );
    assert_eq!(
        config.enforcement.policy.source,
        EnforcementPolicySourceConfig::File {
            path: PathBuf::from("/etc/traffic-probe/enforcement.toml"),
        }
    );
    assert!(config.admin.enabled);
    assert_eq!(
        config.admin.socket_path,
        PathBuf::from("/run/traffic-probe/admin.sock")
    );
    Ok(())
}

#[test]
fn parses_file_exporter_transport() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[[exporters]]
id = "local-file"
transport = "file"
path = "/tmp/traffic-probe-export.jsonl"
codec = "gzip"
"#,
    )?;

    assert_eq!(config.exporters[0].id, "local-file");
    assert_eq!(config.exporters[0].codec, CompressionCodecName::Gzip);
    assert_eq!(
        config.exporters[0].transport,
        ExporterTransportConfig::File {
            path: PathBuf::from("/tmp/traffic-probe-export.jsonl"),
        }
    );
    config.validate_basic()?;
    Ok(())
}

#[test]
fn exporter_config_serializes_to_parseable_flat_toml() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig {
        exporters: vec![
            ExporterConfig {
                id: "webhook".to_string(),
                transport: ExporterTransportConfig::Webhook {
                    endpoint: "https://collector.example/batches".to_string(),
                    headers: BTreeMap::from([("x-probe-node".to_string(), "node-a".to_string())]),
                    tls: ExporterTlsConfig {
                        trust_anchor_refs: vec!["collector-ca".to_string()],
                        client_certificate_refs: Vec::new(),
                        client_private_key_ref: None,
                    },
                },
                codec: CompressionCodecName::Gzip,
                worker: ExporterWorkerConfig {
                    batches_per_tick: Some(2),
                },
            },
            ExporterConfig {
                id: "local-file".to_string(),
                transport: ExporterTransportConfig::File {
                    path: PathBuf::from("/tmp/traffic-probe-export.jsonl"),
                },
                codec: CompressionCodecName::None,
                worker: ExporterWorkerConfig::default(),
            },
        ],
        tls: TlsConfig {
            materials: vec![TlsMaterialConfig {
                id: Some("collector-ca".to_string()),
                kind: TlsMaterialKind::TrustAnchor,
                path: PathBuf::from("/etc/ssl/certs/collector-ca.pem"),
            }],
            ..TlsConfig::default()
        },
        ..AgentConfig::default()
    };

    let rendered = toml::to_string(&config)?;
    assert!(rendered.contains("transport = \"webhook\""));
    assert!(rendered.contains("endpoint = \"https://collector.example/batches\""));
    assert!(rendered.contains("transport = \"file\""));
    assert!(rendered.contains("path = \"/tmp/traffic-probe-export.jsonl\""));

    let roundtrip = AgentConfig::from_toml_str(&rendered)?;

    assert_eq!(roundtrip.exporters, config.exporters);
    roundtrip.validate_basic()?;
    Ok(())
}
