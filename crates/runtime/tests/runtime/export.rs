use std::{num::NonZeroU64, path::PathBuf};

use probe_config::{AgentConfig, CompressionCodecName, ExporterTransport};
use runtime::{
    ExportFailureBackoffPlan, ExportRetentionPlan, ExportSinkPlan, ExportSinkTlsPlan,
    ExportSinkWorkerPlan, ExportWorkerPlan, ProviderRegistry, RuntimePlan,
};

use super::fixture::{export_tls_material, test_platform_capabilities};

#[test]
fn export_plan_disables_worker_without_sinks() -> Result<(), Box<dyn std::error::Error>> {
    let registry = ProviderRegistry::new(vec![], test_platform_capabilities());

    let plan = RuntimePlan::build(AgentConfig::default(), &registry)?;

    assert_eq!(
        plan.export.worker,
        ExportWorkerPlan::Disabled {
            reason: "export worker has no planned sinks".to_string(),
        }
    );
    assert_eq!(plan.export.sinks, Vec::<ExportSinkPlan>::new());
    Ok(())
}

#[test]
fn export_plan_normalizes_worker_plan_and_sinks() -> Result<(), Box<dyn std::error::Error>> {
    let registry = ProviderRegistry::new(vec![], test_platform_capabilities());
    let mut config = AgentConfig::default();
    config.export.worker.schedule =
        probe_config::ExportWorkerScheduleConfig::FixedIntervalBounded {
            interval_ms: 250,
            batches_per_sink_per_tick: 3,
            sink_timeout_ms: 2_000,
            failure_backoff: probe_config::ExportFailureBackoffConfig {
                initial_ms: 5_000,
                max_ms: 20_000,
                multiplier: 3,
            },
        };
    config.storage.retention.export.max_age_ms = Some(60_000);
    config.storage.retention.export.sweep_interval_ms = 5_000;
    config.storage.retention.export.prune_batch_limit = 128;
    config.exporters = vec![probe_config::ExporterConfig {
        id: "primary".to_string(),
        transport: ExporterTransport::Webhook,
        endpoint: "https://collector.example/batches".to_string(),
        codec: CompressionCodecName::None,
        headers: Default::default(),
        tls: probe_config::ExporterTlsConfig {
            trust_anchor_refs: vec!["collector-ca".to_string()],
            client_certificate_refs: vec!["client-cert".to_string()],
            client_private_key_ref: Some("client-key".to_string()),
        },
        worker: probe_config::ExporterWorkerConfig {
            batches_per_tick: Some(2),
        },
    }];
    config.tls.materials = vec![
        probe_config::TlsMaterialConfig {
            id: Some("collector-ca".to_string()),
            kind: probe_config::TlsMaterialKind::TrustAnchor,
            path: PathBuf::from("/etc/ssl/private/collector-ca.pem"),
        },
        probe_config::TlsMaterialConfig {
            id: Some("client-cert".to_string()),
            kind: probe_config::TlsMaterialKind::ClientCertificate,
            path: PathBuf::from("/etc/sssa/client.pem"),
        },
        probe_config::TlsMaterialConfig {
            id: Some("client-key".to_string()),
            kind: probe_config::TlsMaterialKind::ClientPrivateKey,
            path: PathBuf::from("/etc/sssa/client.key"),
        },
        probe_config::TlsMaterialConfig {
            id: Some("keylog".to_string()),
            kind: probe_config::TlsMaterialKind::KeyLogFile,
            path: PathBuf::from("/tmp/ssl-keylog.log"),
        },
    ];

    let plan = RuntimePlan::build(config, &registry)?;

    assert_eq!(
        plan.export.worker,
        ExportWorkerPlan::FixedIntervalBounded {
            interval_ms: 250,
            batches_per_sink_per_tick: 3,
            sink_timeout_ms: 2_000,
            failure_backoff: ExportFailureBackoffPlan {
                initial_ms: 5_000,
                max_ms: 20_000,
                multiplier: 3,
            },
        }
    );
    assert_eq!(
        plan.storage.retention.export,
        ExportRetentionPlan {
            max_age_ms: Some(60_000),
            sweep_interval_ms: NonZeroU64::new(5_000).expect("positive retention sweep interval"),
            prune_batch_limit: NonZeroU64::new(128).expect("positive retention prune limit"),
        }
    );
    assert_eq!(
        plan.export.sinks,
        vec![ExportSinkPlan {
            id: "primary".to_string(),
            transport: ExporterTransport::Webhook,
            endpoint: "https://collector.example/batches".to_string(),
            codec: CompressionCodecName::None,
            headers: Default::default(),
            tls: ExportSinkTlsPlan {
                trust_anchors: vec![export_tls_material(
                    "collector-ca",
                    probe_config::TlsMaterialKind::TrustAnchor,
                    "/etc/ssl/private/collector-ca.pem",
                )],
                client_certificates: vec![export_tls_material(
                    "client-cert",
                    probe_config::TlsMaterialKind::ClientCertificate,
                    "/etc/sssa/client.pem",
                )],
                client_private_key: Some(export_tls_material(
                    "client-key",
                    probe_config::TlsMaterialKind::ClientPrivateKey,
                    "/etc/sssa/client.key",
                )),
            },
            worker: ExportSinkWorkerPlan {
                batches_per_tick_override: Some(2),
                effective_batches_per_tick: NonZeroU64::new(2).expect("positive batch quota"),
            },
        }]
    );
    Ok(())
}
