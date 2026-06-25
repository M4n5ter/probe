use std::{
    io,
    net::{SocketAddr, TcpStream},
    sync::{Arc, Mutex},
    time::Duration,
};

use probe_config::{
    AgentConfig, TransparentInterceptionMitmBackendIntent,
    TransparentInterceptionMitmBackendReadinessProbeIntent,
    TransparentInterceptionMitmPlaintextBridgeIntent,
};
use probe_core::{CapabilityKind, CapabilityState, RuntimeMode};
use serde::{Deserialize, Serialize};

use crate::tcp_health::{TcpHealthProbeObserver, TcpHealthProbePlan, start_tcp_health_probe};

pub(crate) use crate::tcp_health::{
    TcpHealthMode as L7MitmBackendHealthMode, TcpHealthProbeGuard as L7MitmBackendHealthProbeGuard,
    TcpHealthSnapshot as L7MitmBackendHealthSnapshot,
};

#[derive(Clone)]
pub(crate) struct L7MitmRuntime {
    capability: CapabilityState,
    backend_health_probe: Option<L7MitmBackendHealthProbePlan>,
    handle: L7MitmRuntimeHandle,
}

impl L7MitmRuntime {
    pub(crate) fn capability(&self) -> CapabilityState {
        self.capability.clone()
    }

    pub(crate) fn handle(&self) -> L7MitmRuntimeHandle {
        self.handle.clone()
    }

    pub(crate) fn start_backend_health_probe(&self) -> Option<L7MitmBackendHealthProbeGuard> {
        start_tcp_health_probe(
            self.backend_health_probe,
            self.handle.clone(),
            || Ok(()),
            "L7 MITM backend health probe thread panicked",
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct L7MitmRuntimeSnapshot {
    pub backend_health: L7MitmBackendHealthSnapshot,
    pub plaintext_bridge: L7MitmPlaintextBridgeSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct L7MitmPlaintextBridgeSnapshot {
    pub mode: L7MitmPlaintextBridgeMode,
    pub disable_reason: Option<String>,
}

impl L7MitmPlaintextBridgeSnapshot {
    fn not_configured() -> Self {
        Self {
            mode: L7MitmPlaintextBridgeMode::NotConfigured,
            disable_reason: None,
        }
    }

    fn configured() -> Self {
        Self {
            mode: L7MitmPlaintextBridgeMode::Configured,
            disable_reason: None,
        }
    }

    fn record_ready(&mut self) {
        self.mode = L7MitmPlaintextBridgeMode::Ready;
        self.disable_reason = None;
    }

    fn record_active(&mut self) {
        self.mode = L7MitmPlaintextBridgeMode::Active;
        self.disable_reason = None;
    }

    fn record_disabled_after_error(&mut self, reason: impl Into<String>) {
        self.mode = L7MitmPlaintextBridgeMode::DisabledAfterError;
        self.disable_reason = Some(reason.into());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum L7MitmPlaintextBridgeMode {
    NotConfigured,
    Configured,
    Ready,
    Active,
    DisabledAfterError,
}

impl L7MitmPlaintextBridgeMode {
    pub(crate) fn wire_name(self) -> &'static str {
        match self {
            Self::NotConfigured => "not_configured",
            Self::Configured => "configured",
            Self::Ready => "ready",
            Self::Active => "active",
            Self::DisabledAfterError => "disabled_after_error",
        }
    }
}

#[derive(Clone)]
pub(crate) struct L7MitmRuntimeHandle {
    inner: Arc<Mutex<L7MitmRuntimeState>>,
}

struct L7MitmRuntimeState {
    snapshot: L7MitmRuntimeSnapshot,
    backend_health_failure_threshold: u32,
}

type L7MitmBackendHealthProbePlan = TcpHealthProbePlan;

pub(crate) fn resolve(config: &AgentConfig) -> L7MitmRuntime {
    resolve_with_probe(config, connect_tcp)
}

fn resolve_with_probe(
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
    if let Err(error) = config.validate_l7_mitm_contract() {
        return unavailable(
            format!("L7 MITM backend contract is invalid: {error}"),
            plaintext_bridge,
        );
    };
    let backend_health_probe = match probe_external_backend(config, tcp_probe) {
        Ok(plan) => plan,
        Err(error) => return unavailable(error, plaintext_bridge),
    };

    L7MitmRuntime {
        capability: CapabilityState {
            kind: CapabilityKind::L7Mitm,
            mode: RuntimeMode::Available,
            reason: Some(
                "external selector-scoped L7 MITM backend contract is configured and its configured readiness endpoint is reachable; agent redirects matching flows to the configured listener port but does not manage the L7 proxy process or prove per-family transparent listener behavior yet"
                    .to_string(),
            ),
        },
        handle: L7MitmRuntimeHandle::new(
            L7MitmBackendHealthSnapshot::initial_success(),
            plaintext_bridge,
            backend_health_probe.failure_threshold,
        ),
        backend_health_probe: Some(backend_health_probe.into_plan()),
    }
}

fn connect_tcp(target: SocketAddr, timeout: Duration) -> io::Result<()> {
    TcpStream::connect_timeout(&target, timeout).map(|_| ())
}

fn probe_external_backend(
    config: &AgentConfig,
    tcp_probe: impl FnOnce(SocketAddr, Duration) -> io::Result<()>,
) -> Result<ResolvedL7MitmBackendHealthProbe, String> {
    let readiness_probe = config
        .enforcement
        .interception
        .mitm_backend_intent()
        .map_err(|violations| {
            violations
                .into_iter()
                .map(|violation| format!("{}: {}", violation.field(), violation.reason()))
                .collect::<Vec<_>>()
                .join("; ")
        })?;
    let TransparentInterceptionMitmBackendIntent::External { readiness_probe } = readiness_probe
    else {
        return Err("external L7 MITM backend contract is missing".to_string());
    };
    let TransparentInterceptionMitmBackendReadinessProbeIntent::TcpConnect {
        target,
        interval_ms,
        timeout_ms,
        failure_threshold,
    } = readiness_probe;
    let timeout = Duration::from_millis(timeout_ms);
    tcp_probe(target, timeout).map_err(|error| {
        format!("external L7 MITM backend readiness probe failed for {target}: {error}")
    })?;
    Ok(ResolvedL7MitmBackendHealthProbe {
        target,
        interval: Duration::from_millis(interval_ms),
        timeout,
        failure_threshold,
    })
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

fn unavailable(
    reason: impl Into<String>,
    plaintext_bridge: L7MitmPlaintextBridgeSnapshot,
) -> L7MitmRuntime {
    L7MitmRuntime {
        capability: CapabilityState::unavailable(CapabilityKind::L7Mitm, reason),
        backend_health_probe: None,
        handle: L7MitmRuntimeHandle::new(
            L7MitmBackendHealthSnapshot::disabled(),
            plaintext_bridge,
            1,
        ),
    }
}

struct ResolvedL7MitmBackendHealthProbe {
    target: SocketAddr,
    interval: Duration,
    timeout: Duration,
    failure_threshold: u32,
}

impl ResolvedL7MitmBackendHealthProbe {
    fn into_plan(self) -> L7MitmBackendHealthProbePlan {
        TcpHealthProbePlan::new(self.target, self.interval, self.timeout)
            .with_initial_delay(self.interval)
    }
}

impl L7MitmRuntimeHandle {
    fn new(
        backend_health: L7MitmBackendHealthSnapshot,
        plaintext_bridge: L7MitmPlaintextBridgeSnapshot,
        backend_health_failure_threshold: u32,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(L7MitmRuntimeState {
                snapshot: L7MitmRuntimeSnapshot {
                    backend_health,
                    plaintext_bridge,
                },
                backend_health_failure_threshold,
            })),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        backend_health: L7MitmBackendHealthSnapshot,
        plaintext_bridge: L7MitmPlaintextBridgeSnapshot,
        backend_health_failure_threshold: u32,
    ) -> Self {
        Self::new(
            backend_health,
            plaintext_bridge,
            backend_health_failure_threshold,
        )
    }

    pub(crate) fn snapshot(&self) -> L7MitmRuntimeSnapshot {
        self.lock().snapshot.clone()
    }

    fn record_backend_health_success(&self) {
        let mut state = self.lock();
        state.snapshot.backend_health.record_success();
    }

    fn record_backend_health_failure(&self, reason: impl Into<String>) {
        let mut state = self.lock();
        let failure_threshold = state.backend_health_failure_threshold;
        state
            .snapshot
            .backend_health
            .record_failure(failure_threshold, reason);
    }

    pub(crate) fn record_plaintext_bridge_disabled(&self, reason: impl Into<String>) {
        let mut state = self.lock();
        state
            .snapshot
            .plaintext_bridge
            .record_disabled_after_error(reason);
    }

    pub(crate) fn record_plaintext_bridge_ready(&self) {
        let mut state = self.lock();
        state.snapshot.plaintext_bridge.record_ready();
    }

    pub(crate) fn record_plaintext_bridge_active(&self) {
        let mut state = self.lock();
        state.snapshot.plaintext_bridge.record_active();
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, L7MitmRuntimeState> {
        self.inner
            .lock()
            .expect("L7 MITM runtime state should not be poisoned")
    }
}

impl TcpHealthProbeObserver for L7MitmRuntimeHandle {
    fn record_tcp_health_success(&self) {
        self.record_backend_health_success();
    }

    fn record_tcp_health_failure(&self, reason: String) {
        self.record_backend_health_failure(reason);
    }
}

#[cfg(test)]
mod tests {
    use std::{io::ErrorKind, net::TcpListener, thread, time::Instant};

    use probe_config::{
        AgentConfig, TlsMaterialConfig, TlsMaterialKind, TransparentInterceptionMitmBackendConfig,
        TransparentInterceptionMitmPlaintextBridgeModeConfig,
        TransparentInterceptionStrategyConfig,
    };
    use probe_core::RuntimeMode;
    use tempfile::tempdir;

    use super::*;

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
        let probe = runtime
            .backend_health_probe
            .as_ref()
            .expect("available external MITM runtime should start backend health probe");
        assert_eq!(probe.interval(), Duration::from_millis(1_000));
        assert_eq!(probe.timeout(), Duration::from_millis(200));
        let health = runtime.handle().snapshot().backend_health;
        assert_eq!(health.mode, L7MitmBackendHealthMode::Healthy);
        assert_eq!(health.check_successes, 1);
        assert_eq!(health.check_failures, 0);
        let bridge = runtime.handle().snapshot().plaintext_bridge;
        assert_eq!(bridge.mode, L7MitmPlaintextBridgeMode::NotConfigured);
        assert_eq!(bridge.disable_reason, None);
    }

    #[test]
    fn backend_health_probe_marks_unhealthy_after_failure_threshold() {
        let handle = L7MitmRuntimeHandle::new(
            L7MitmBackendHealthSnapshot::initial_success(),
            L7MitmPlaintextBridgeSnapshot::not_configured(),
            2,
        );

        handle.record_backend_health_failure("connection refused");
        let health = handle.snapshot().backend_health;
        assert_eq!(health.mode, L7MitmBackendHealthMode::Healthy);
        assert_eq!(health.check_failures, 1);
        assert_eq!(health.consecutive_failures, 1);

        handle.record_backend_health_failure("connection refused");
        let health = handle.snapshot().backend_health;
        assert_eq!(health.mode, L7MitmBackendHealthMode::Unhealthy);
        assert_eq!(health.check_failures, 2);
        assert_eq!(health.consecutive_failures, 2);
        assert_eq!(
            health.last_failure_reason.as_deref(),
            Some("connection refused")
        );
    }

    #[test]
    fn backend_health_probe_success_clears_unhealthy_state() {
        let handle = L7MitmRuntimeHandle::new(
            L7MitmBackendHealthSnapshot::initial_success(),
            L7MitmPlaintextBridgeSnapshot::not_configured(),
            1,
        );

        handle.record_backend_health_failure("connection refused");
        assert_eq!(
            handle.snapshot().backend_health.mode,
            L7MitmBackendHealthMode::Unhealthy
        );

        handle.record_backend_health_success();

        let health = handle.snapshot().backend_health;
        assert_eq!(health.mode, L7MitmBackendHealthMode::Healthy);
        assert_eq!(health.check_successes, 2);
        assert_eq!(health.check_failures, 1);
        assert_eq!(health.consecutive_failures, 0);
        assert_eq!(health.last_failure_reason, None);
    }

    #[test]
    fn backend_health_probe_thread_records_checks_and_stops()
    -> Result<(), Box<dyn std::error::Error>> {
        let target = closed_loopback_target()?;
        let handle = L7MitmRuntimeHandle::new(
            L7MitmBackendHealthSnapshot::initial_success(),
            L7MitmPlaintextBridgeSnapshot::not_configured(),
            1,
        );
        let runtime = L7MitmRuntime {
            capability: CapabilityState {
                kind: CapabilityKind::L7Mitm,
                mode: RuntimeMode::Available,
                reason: None,
            },
            backend_health_probe: Some(TcpHealthProbePlan::new(
                target,
                Duration::from_millis(5),
                Duration::from_millis(10),
            )),
            handle: handle.clone(),
        };
        let guard = runtime
            .start_backend_health_probe()
            .expect("configured backend health probe should start");

        wait_until(Duration::from_secs(1), || {
            handle.snapshot().backend_health.check_failures > 0
        })?;
        guard.stop()?;

        let health = handle.snapshot().backend_health;
        assert_eq!(health.mode, L7MitmBackendHealthMode::Unhealthy);
        assert!(health.check_failures > 0);
        assert!(health.consecutive_failures > 0);
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
            TransparentInterceptionMitmBackendConfig::External;
        config
            .enforcement
            .interception
            .mitm
            .backend_readiness_probe
            .target = Some(target.to_string());
        config.enforcement.interception.mitm.ca_certificate_ref = Some("mitm-ca".to_string());
        config.enforcement.interception.mitm.ca_private_key_ref = Some("mitm-ca-key".to_string());
        config.tls.materials = vec![
            TlsMaterialConfig {
                id: Some("mitm-ca".to_string()),
                kind: TlsMaterialKind::MitmCaCertificate,
                path: "/etc/sssa/mitm-ca.pem".into(),
            },
            TlsMaterialConfig {
                id: Some("mitm-ca-key".to_string()),
                kind: TlsMaterialKind::MitmCaPrivateKey,
                path: "/etc/sssa/mitm-ca.key".into(),
            },
        ];
        config
    }

    fn missing_bridge_path() -> Result<std::path::PathBuf, std::io::Error> {
        Ok(tempdir()?.path().join("missing-mitm-bridge.jsonl"))
    }

    fn closed_loopback_target() -> Result<SocketAddr, std::io::Error> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let target = listener.local_addr()?;
        drop(listener);
        Ok(target)
    }

    fn wait_until(
        timeout: Duration,
        mut condition: impl FnMut() -> bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if condition() {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(10));
        }
        Err("condition did not become true before timeout".into())
    }
}
