use std::path::PathBuf;

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
path = "/tmp/sssa-spool"

[storage.retention.export]
max_age_ms = 60000
sweep_interval_ms = 5000
prune_batch_limit = 128

[storage.retention.ingress]
max_age_ms = 120000
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

[tls.plaintext]
enabled = true
provider = "libssl_uprobe"
libssl_uprobe_object_path = "/opt/sssa/ebpf-tls-plaintext.bpf.o"

[tls.plaintext.selector]
op = "match"

[tls.plaintext.selector.term.process]
pids = [4242]
names = []
exe_path_globs = []
cmdline_regexes = []
systemd_services = []
container_ids = []

[tls.plaintext.selector.term.traffic]
local_ports = [443]
remote_ports = []
directions = []
remote_addresses = []

[enforcement]
mode = "dry_run"
backend = "linux_socket_destroy"

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
    assert_eq!(config.storage.retention.ingress.max_age_ms, Some(120_000));
    assert_eq!(config.storage.retention.ingress.sweep_interval_ms, 7_000);
    assert_eq!(config.storage.retention.ingress.prune_batch_limit, 256);
    assert_eq!(config.storage.retention.export.max_age_ms, Some(60_000));
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
    assert_eq!(
        config.exporters[0].tls.trust_anchor_refs,
        vec!["collector-ca"]
    );
    assert_eq!(config.tls.materials[0].id.as_deref(), Some("collector-ca"));
    assert_eq!(config.tls.materials[0].kind, TlsMaterialKind::TrustAnchor);
    assert!(config.tls.plaintext.enabled);
    assert_eq!(
        config.tls.plaintext.provider,
        TlsPlaintextProvider::LibsslUprobe
    );
    assert_eq!(
        config.tls.plaintext.libssl_uprobe_object_path,
        Some(PathBuf::from("/opt/sssa/ebpf-tls-plaintext.bpf.o"))
    );
    assert!(config.tls.plaintext.selector.is_some());
    assert_eq!(config.capture.plaintext_feed.path, None);
    assert_eq!(config.enforcement.mode, EnforcementMode::DryRun);
    assert_eq!(
        config.enforcement.backend,
        ConnectionEnforcementBackendConfig::LinuxSocketDestroy
    );
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
