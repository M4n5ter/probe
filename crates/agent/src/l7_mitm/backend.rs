use std::{
    fs, io,
    net::{SocketAddr, TcpStream},
    os::unix::fs::PermissionsExt,
    time::Duration,
};

use probe_config::{AgentConfig, TransparentInterceptionMitmPlaintextBridgeIntent};
use probe_core::{CapabilityKind, CapabilityState, RuntimeMode};
use runtime::{
    TransparentInterceptionMitmBackendPlan, TransparentInterceptionMitmBackendReadinessProbePlan,
    TransparentInterceptionMitmManagedProcessPlan, TransparentInterceptionMitmPlan,
};

use super::{
    L7MitmBackendHealthSnapshot, L7MitmPlaintextBridgeSnapshot, L7MitmRuntime, state::unavailable,
};
use crate::tcp_health::TcpHealthProbePlan;

pub(super) fn resolve(config: &AgentConfig) -> L7MitmRuntime {
    resolve_with_probe(config, connect_tcp)
}

pub(super) fn resolve_with_probe(
    config: &AgentConfig,
    tcp_probe: impl FnOnce(SocketAddr, Duration) -> io::Result<()>,
) -> L7MitmRuntime {
    let interception = &config.enforcement.interception;
    if !interception.strategy.is_mitm() {
        return unavailable(
            "L7 MITM backend is not configured; select a MITM interception strategy to require it",
            L7MitmPlaintextBridgeSnapshot::not_configured(),
        );
    }
    let plaintext_bridge = match resolve_plaintext_bridge(config) {
        Ok(snapshot) => snapshot,
        Err(error) => return unavailable(error, L7MitmPlaintextBridgeSnapshot::not_configured()),
    };
    let mitm = match TransparentInterceptionMitmPlan::try_from_config(config) {
        Ok(plan) => plan,
        Err(error) => {
            return unavailable(
                format!("L7 MITM backend contract is invalid: {error}"),
                plaintext_bridge,
            );
        }
    };
    if let Err(error) = preflight_backend(&mitm.backend, tcp_probe) {
        return unavailable(error, plaintext_bridge);
    }
    let backend = &mitm.backend;
    let initial_backend_health = initial_health(backend);
    let failure_threshold = backend_health_probe(backend)
        .expect("available L7 MITM backend should have a health probe")
        .failure_threshold;
    let capability_reason = capability_reason(backend);

    L7MitmRuntime {
        capability: CapabilityState {
            kind: CapabilityKind::L7Mitm,
            mode: RuntimeMode::Available,
            reason: Some(capability_reason.to_string()),
        },
        handle: super::state::L7MitmRuntimeHandle::new(
            initial_backend_health,
            plaintext_bridge,
            failure_threshold,
        ),
    }
}

pub(super) fn connect_tcp(target: SocketAddr, timeout: Duration) -> io::Result<()> {
    TcpStream::connect_timeout(&target, timeout).map(|_| ())
}

fn preflight_backend(
    backend: &TransparentInterceptionMitmBackendPlan,
    tcp_probe: impl FnOnce(SocketAddr, Duration) -> io::Result<()>,
) -> Result<(), String> {
    match backend {
        TransparentInterceptionMitmBackendPlan::External { readiness_probe } => {
            resolve_external_backend(readiness_probe, tcp_probe)?;
        }
        TransparentInterceptionMitmBackendPlan::ManagedProcess { process, .. } => {
            verify_managed_process_preflight(process)?;
        }
        TransparentInterceptionMitmBackendPlan::Disabled => {
            return Err("L7 MITM backend contract is missing".to_string());
        }
    }
    Ok(())
}

fn resolve_external_backend(
    readiness_probe: &TransparentInterceptionMitmBackendReadinessProbePlan,
    tcp_probe: impl FnOnce(SocketAddr, Duration) -> io::Result<()>,
) -> Result<(), String> {
    let health_probe = backend_health_probe_from_readiness(readiness_probe);
    let timeout = health_probe.timeout;
    let target = health_probe.target;
    tcp_probe(target, timeout).map_err(|error| {
        format!("external L7 MITM backend readiness probe failed for {target}: {error}")
    })
}

pub(super) fn backend_health_probe(
    backend: &TransparentInterceptionMitmBackendPlan,
) -> Option<L7MitmBackendHealthProbe> {
    match backend {
        TransparentInterceptionMitmBackendPlan::External { readiness_probe }
        | TransparentInterceptionMitmBackendPlan::ManagedProcess {
            readiness_probe, ..
        } => Some(backend_health_probe_from_readiness(readiness_probe)),
        TransparentInterceptionMitmBackendPlan::Disabled => None,
    }
}

fn backend_health_probe_from_readiness(
    readiness_probe: &TransparentInterceptionMitmBackendReadinessProbePlan,
) -> L7MitmBackendHealthProbe {
    let TransparentInterceptionMitmBackendReadinessProbePlan::TcpConnect {
        target,
        interval_ms,
        timeout_ms,
        failure_threshold,
    } = readiness_probe;
    L7MitmBackendHealthProbe {
        target: *target,
        interval: Duration::from_millis(*interval_ms),
        timeout: Duration::from_millis(*timeout_ms),
        failure_threshold: *failure_threshold,
    }
}

fn initial_health(backend: &TransparentInterceptionMitmBackendPlan) -> L7MitmBackendHealthSnapshot {
    match backend {
        TransparentInterceptionMitmBackendPlan::External { .. } => {
            L7MitmBackendHealthSnapshot::initial_success()
        }
        TransparentInterceptionMitmBackendPlan::ManagedProcess { .. } => {
            L7MitmBackendHealthSnapshot::pending()
        }
        TransparentInterceptionMitmBackendPlan::Disabled => L7MitmBackendHealthSnapshot::disabled(),
    }
}

fn capability_reason(backend: &TransparentInterceptionMitmBackendPlan) -> &'static str {
    match backend {
        TransparentInterceptionMitmBackendPlan::External { .. } => {
            "external selector-scoped L7 MITM backend contract is configured and its configured readiness endpoint is reachable; agent redirects matching flows to the configured listener port but does not manage the L7 proxy process or prove per-family transparent listener behavior yet"
        }
        TransparentInterceptionMitmBackendPlan::ManagedProcess { .. } => {
            "agent-managed selector-scoped L7 MITM backend process contract is configured and executable; run will spawn the process and require its configured readiness endpoint before installing transparent interception rules"
        }
        TransparentInterceptionMitmBackendPlan::Disabled => "L7 MITM backend is disabled",
    }
}

fn resolve_plaintext_bridge(config: &AgentConfig) -> Result<L7MitmPlaintextBridgeSnapshot, String> {
    let bridge = config
        .enforcement
        .interception
        .mitm_plaintext_bridge_intent()
        .map_err(|violations| {
            violations
                .into_iter()
                .map(|violation| format!("{}: {}", violation.field(), violation.reason()))
                .collect::<Vec<_>>()
                .join("; ")
        })?;
    match bridge {
        TransparentInterceptionMitmPlaintextBridgeIntent::Disabled => {
            Ok(L7MitmPlaintextBridgeSnapshot::not_configured())
        }
        TransparentInterceptionMitmPlaintextBridgeIntent::CaptureEventFeed { .. } => {
            Ok(L7MitmPlaintextBridgeSnapshot::configured())
        }
    }
}

fn verify_managed_process_preflight(
    process: &TransparentInterceptionMitmManagedProcessPlan,
) -> Result<(), String> {
    if !process.program.is_absolute() {
        return Err(format!(
            "managed L7 MITM backend program path must be absolute: {}",
            process.program.display()
        ));
    }
    let metadata = fs::symlink_metadata(&process.program).map_err(|error| {
        format!(
            "managed L7 MITM backend program {} is not accessible: {error}",
            process.program.display()
        )
    })?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "managed L7 MITM backend program {} must not be a symlink",
            process.program.display()
        ));
    }
    if !metadata.is_file() {
        return Err(format!(
            "managed L7 MITM backend program {} is not a regular file",
            process.program.display()
        ));
    }
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err(format!(
            "managed L7 MITM backend program {} is not executable",
            process.program.display()
        ));
    }
    if let Some(working_dir) = &process.working_dir {
        if !working_dir.is_absolute() {
            return Err(format!(
                "managed L7 MITM backend working_dir must be absolute: {}",
                working_dir.display()
            ));
        }
        let metadata = fs::symlink_metadata(working_dir).map_err(|error| {
            format!(
                "managed L7 MITM backend working_dir {} is not accessible: {error}",
                working_dir.display()
            )
        })?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "managed L7 MITM backend working_dir {} must not be a symlink",
                working_dir.display()
            ));
        }
        if !metadata.is_dir() {
            return Err(format!(
                "managed L7 MITM backend working_dir {} is not a directory",
                working_dir.display()
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(super) struct L7MitmBackendHealthProbe {
    pub(super) target: SocketAddr,
    pub(super) interval: Duration,
    pub(super) timeout: Duration,
    pub(super) failure_threshold: u32,
}

impl L7MitmBackendHealthProbe {
    pub(super) fn into_plan(self) -> TcpHealthProbePlan {
        TcpHealthProbePlan::new(self.target, self.interval, self.timeout)
            .with_initial_delay(self.interval)
    }
}

#[cfg(test)]
mod tests {
    use std::{io::ErrorKind, os::unix::fs::symlink, path::Path};

    use probe_config::{
        TlsMaterialConfig, TlsMaterialKind, TransparentInterceptionMitmBackendConfig,
        TransparentInterceptionMitmBackendReadinessProbeConfig,
        TransparentInterceptionMitmManagedProcessConfig,
        TransparentInterceptionMitmPlaintextBridgeModeConfig,
        TransparentInterceptionStrategyConfig,
    };
    use probe_core::RuntimeMode;
    use tempfile::tempdir;

    use super::*;
    use crate::l7_mitm::{L7MitmBackendHealthMode, L7MitmPlaintextBridgeMode};

    #[test]
    fn failed_readiness_probe_reports_l7_mitm_unavailable() {
        let config = external_mitm_config("127.0.0.1:15002");

        let runtime = resolve_with_probe(&config, |_target, _timeout| {
            Err(io::Error::new(ErrorKind::ConnectionRefused, "closed"))
        });

        let capability = runtime.capability();
        assert_eq!(capability.mode, RuntimeMode::Unavailable);
        assert!(
            capability
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("readiness probe failed")),
            "{capability:?}"
        );
    }

    #[test]
    fn configured_plaintext_bridge_waits_for_capture_preflight()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut config = external_mitm_config("127.0.0.1:15002");
        config.enforcement.interception.mitm.plaintext_bridge.mode =
            TransparentInterceptionMitmPlaintextBridgeModeConfig::CaptureEventFeed;
        config.enforcement.interception.mitm.plaintext_bridge.path = Some(missing_bridge_path()?);

        let runtime = resolve_with_probe(&config, |_target, _timeout| Ok(()));

        let capability = runtime.capability();
        assert_eq!(capability.mode, RuntimeMode::Available);
        let bridge = runtime.handle().snapshot().plaintext_bridge;
        assert_eq!(bridge.mode, L7MitmPlaintextBridgeMode::Configured);
        assert_eq!(bridge.disable_reason, None);
        Ok(())
    }

    #[test]
    fn unavailable_backend_preserves_configured_plaintext_bridge_intent()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut config = external_mitm_config("127.0.0.1:15002");
        config.enforcement.interception.mitm.plaintext_bridge.mode =
            TransparentInterceptionMitmPlaintextBridgeModeConfig::CaptureEventFeed;
        config.enforcement.interception.mitm.plaintext_bridge.path = Some(missing_bridge_path()?);

        let runtime = resolve_with_probe(&config, |_target, _timeout| {
            Err(io::Error::new(ErrorKind::ConnectionRefused, "closed"))
        });

        let capability = runtime.capability();
        assert_eq!(capability.mode, RuntimeMode::Unavailable);
        let bridge = runtime.handle().snapshot().plaintext_bridge;
        assert_eq!(bridge.mode, L7MitmPlaintextBridgeMode::Configured);
        assert_eq!(bridge.disable_reason, None);
        Ok(())
    }

    #[test]
    fn successful_readiness_probe_initializes_backend_health_runtime() {
        let config = external_mitm_config("127.0.0.1:15002");

        let runtime = resolve_with_probe(&config, |target, timeout| {
            assert_eq!(
                target,
                "127.0.0.1:15002"
                    .parse()
                    .expect("test MITM target should parse")
            );
            assert_eq!(timeout, Duration::from_millis(200));
            Ok(())
        });

        let capability = runtime.capability();
        assert_eq!(capability.mode, RuntimeMode::Available);
        let mitm = TransparentInterceptionMitmPlan::try_from_config(&config)
            .expect("test MITM plan should resolve");
        let probe = backend_health_probe(&mitm.backend)
            .expect("available external MITM backend should have a health probe");
        assert_eq!(probe.interval, Duration::from_millis(1_000));
        assert_eq!(probe.timeout, Duration::from_millis(200));
        let health = runtime.handle().snapshot().backend_health;
        assert_eq!(health.mode, L7MitmBackendHealthMode::Healthy);
        assert_eq!(health.check_successes, 1);
        assert_eq!(health.check_failures, 0);
        let bridge = runtime.handle().snapshot().plaintext_bridge;
        assert_eq!(bridge.mode, L7MitmPlaintextBridgeMode::NotConfigured);
        assert_eq!(bridge.disable_reason, None);
    }

    #[test]
    fn managed_process_backend_reports_available_without_pre_spawn_probe()
    -> Result<(), Box<dyn std::error::Error>> {
        let config = managed_mitm_config("127.0.0.1:15002", std::env::current_exe()?, []);

        let runtime = resolve_with_probe(&config, |_target, _timeout| {
            panic!("managed backend readiness must run after the process is spawned")
        });

        let capability = runtime.capability();
        assert_eq!(capability.mode, RuntimeMode::Available);
        assert!(
            capability
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("agent-managed selector-scoped")),
            "{capability:?}"
        );
        let health = runtime.handle().snapshot().backend_health;
        assert_eq!(health.mode, L7MitmBackendHealthMode::Pending);
        assert_eq!(health.check_successes, 0);
        assert_eq!(health.check_failures, 0);
        Ok(())
    }

    #[test]
    fn managed_process_backend_requires_accessible_executable()
    -> Result<(), Box<dyn std::error::Error>> {
        let missing_program = tempdir()?.path().join("missing-mitm-backend");
        let config = managed_mitm_config("127.0.0.1:15002", missing_program, []);

        let runtime = resolve_with_probe(&config, |_target, _timeout| {
            panic!("managed backend readiness must run after executable preflight")
        });

        let capability = runtime.capability();
        assert_eq!(capability.mode, RuntimeMode::Unavailable);
        assert!(
            capability
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("not accessible")),
            "{capability:?}"
        );
        Ok(())
    }

    #[test]
    fn managed_process_backend_rejects_symlinked_executable()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempdir()?;
        let symlinked_program = dir.path().join("mitm-backend");
        symlink("/bin/true", &symlinked_program)?;
        let config = managed_mitm_config("127.0.0.1:15002", symlinked_program, []);

        let runtime = resolve_with_probe(&config, |_target, _timeout| {
            panic!("managed backend readiness must run after executable preflight")
        });

        let capability = runtime.capability();
        assert_eq!(capability.mode, RuntimeMode::Unavailable);
        assert!(
            capability
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("must not be a symlink")),
            "{capability:?}"
        );
        Ok(())
    }

    fn external_mitm_config(target: &str) -> AgentConfig {
        let mut config = AgentConfig::default();
        let target: SocketAddr = target
            .parse()
            .expect("test MITM readiness target should parse");
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::InboundTproxyMitm;
        config.enforcement.interception.proxy.listen_port = Some(target.port());
        config.enforcement.interception.mitm.backend =
            TransparentInterceptionMitmBackendConfig::external(
                TransparentInterceptionMitmBackendReadinessProbeConfig {
                    target: Some(target.to_string()),
                    ..TransparentInterceptionMitmBackendReadinessProbeConfig::default()
                },
            );
        config.enforcement.interception.mitm.ca_certificate_ref = Some("mitm-ca".to_string());
        config.enforcement.interception.mitm.ca_private_key_ref = Some("mitm-ca-key".to_string());
        config.tls.materials = vec![
            TlsMaterialConfig {
                id: Some("mitm-ca".to_string()),
                kind: TlsMaterialKind::MitmCaCertificate,
                path: "/etc/traffic-probe/mitm-ca.pem".into(),
            },
            TlsMaterialConfig {
                id: Some("mitm-ca-key".to_string()),
                kind: TlsMaterialKind::MitmCaPrivateKey,
                path: "/etc/traffic-probe/mitm-ca.key".into(),
            },
        ];
        config
    }

    fn managed_mitm_config(
        target: impl ToString,
        program: impl AsRef<Path>,
        args: impl IntoIterator<Item = &'static str>,
    ) -> AgentConfig {
        let mut config = external_mitm_config(&target.to_string());
        let readiness_probe = TransparentInterceptionMitmBackendReadinessProbeConfig {
            target: Some(target.to_string()),
            ..TransparentInterceptionMitmBackendReadinessProbeConfig::default()
        };
        let process = TransparentInterceptionMitmManagedProcessConfig {
            program: Some(program.as_ref().into()),
            args: args.into_iter().map(str::to_string).collect(),
            working_dir: None,
        };
        config.enforcement.interception.mitm.backend =
            TransparentInterceptionMitmBackendConfig::managed_process(readiness_probe, process);
        config
    }

    fn missing_bridge_path() -> Result<std::path::PathBuf, std::io::Error> {
        Ok(tempdir()?.path().join("missing-mitm-bridge.jsonl"))
    }
}
