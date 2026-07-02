use probe_config::*;
use probe_core::EnforcementMode;

#[test]
fn minimal_config_uses_defaults() -> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str("")?;

    assert_eq!(config.agent_id, "traffic-probe");
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
            failure_backoff: ExportFailureBackoffConfig {
                initial_ms: 30_000,
                max_ms: 300_000,
                multiplier: 2,
            },
        }
    );
    assert_eq!(config.exporters, Vec::<ExporterConfig>::new());
    assert_eq!(config.enforcement.mode, EnforcementMode::AuditOnly);
    assert_eq!(
        config.enforcement.backend,
        ConnectionEnforcementBackendConfig::None
    );
    assert_eq!(
        config.enforcement.interception.strategy,
        TransparentInterceptionStrategyConfig::None
    );
    assert_eq!(config.enforcement.interception.selector, None);
    assert_eq!(
        config.enforcement.policy.source,
        EnforcementPolicySourceConfig::None
    );
    assert!(!config.admin.enabled);
    assert_eq!(config.admin.socket_path, default_admin_socket_path());
    assert!(!config.tls.plaintext.instrumentation.enabled);
    assert_eq!(config.tls.plaintext.instrumentation.selector, None);
    assert_eq!(
        config.tls.plaintext.decrypt_hints.key_log_refs,
        Vec::<String>::new()
    );
    assert_eq!(
        config.tls.plaintext.decrypt_hints.session_secret_refs,
        Vec::<String>::new()
    );
    config.validate_basic()?;
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
            failure_backoff: ExportFailureBackoffConfig {
                initial_ms: 30_000,
                max_ms: 300_000,
                multiplier: 2,
            },
        }
    );
    config.validate_basic()?;
    Ok(())
}

#[test]
fn export_worker_failure_backoff_uses_defaults_for_omitted_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let config = AgentConfig::from_toml_str(
        r#"
[export.worker.schedule]
mode = "fixed_interval_bounded"

[export.worker.schedule.failure_backoff]
initial_ms = 5000
"#,
    )?;

    assert_eq!(
        config.export.worker.schedule,
        ExportWorkerScheduleConfig::FixedIntervalBounded {
            interval_ms: 1_000,
            batches_per_sink_per_tick: 1,
            sink_timeout_ms: 10_000,
            failure_backoff: ExportFailureBackoffConfig {
                initial_ms: 5_000,
                max_ms: 300_000,
                multiplier: 2,
            },
        }
    );
    config.validate_basic()?;
    Ok(())
}

#[test]
fn config_rejects_unknown_fields() {
    let result = AgentConfig::from_toml_str("unknown = true");

    assert!(result.is_err());
}
