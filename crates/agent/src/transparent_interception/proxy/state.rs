use std::sync::{Arc, Mutex};

use ::runtime::{
    TransparentInterceptionExecutionPlan, TransparentInterceptionProxyHealthProbePlan,
};
use probe_config::TransparentInterceptionProxyModeConfig;
use serde::Serialize;

use crate::transparent_interception::TransparentInterceptionIpFamily;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct TransparentProxyRuntimeSnapshot {
    pub mode: TransparentProxyRuntimeMode,
    pub listener_families: Vec<TransparentInterceptionIpFamily>,
    pub health_probe: TransparentProxyHealthProbeSnapshot,
    pub upstream_connects: TransparentProxyConnectMetricsSnapshot,
    pub active_relays: u64,
    pub accepted_relays: u64,
    pub rejected_relays: u64,
    pub relay_failures: u64,
    pub listener_failures: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TransparentProxyRuntimeMode {
    Disabled,
    External,
    Configured,
    Running,
    Degraded,
    Failed,
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TransparentProxyHealthProbeMode {
    Disabled,
    Pending,
    Healthy,
    Unhealthy,
}

impl TransparentProxyHealthProbeMode {
    pub(crate) fn wire_name(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Pending => "pending",
            Self::Healthy => "healthy",
            Self::Unhealthy => "unhealthy",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct TransparentProxyHealthProbeSnapshot {
    pub mode: TransparentProxyHealthProbeMode,
    pub check_successes: u64,
    pub check_failures: u64,
    pub consecutive_failures: u64,
    pub last_failure_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct TransparentProxyConnectMetricsSnapshot {
    pub connect_successes: u64,
    pub connect_failures: u64,
    pub last_failure_reason: Option<String>,
}

#[derive(Clone)]
pub(in crate::transparent_interception) struct TransparentProxyRuntime {
    handle: TransparentProxyRuntimeHandle,
}

#[derive(Clone)]
pub(crate) struct TransparentProxyRuntimeHandle {
    inner: Arc<Mutex<TransparentProxyRuntimeState>>,
}

struct TransparentProxyRuntimeState {
    snapshot: TransparentProxyRuntimeSnapshot,
    health_probe_failure_threshold: u32,
}

impl TransparentProxyRuntime {
    pub(crate) fn disabled() -> Self {
        Self::new(
            TransparentProxyRuntimeMode::Disabled,
            TransparentProxyHealthProbeSnapshot::disabled(),
            1,
        )
    }

    pub(crate) fn for_execution_plan(plan: &TransparentInterceptionExecutionPlan) -> Self {
        let (mode, health_probe_plan) = match plan {
            TransparentInterceptionExecutionPlan::Disabled => {
                (TransparentProxyRuntimeMode::Disabled, None)
            }
            TransparentInterceptionExecutionPlan::InboundTproxy(inbound_plan) => {
                let mode = match inbound_plan.proxy_mode() {
                    TransparentInterceptionProxyModeConfig::External => {
                        TransparentProxyRuntimeMode::External
                    }
                    TransparentInterceptionProxyModeConfig::ManagedTcpRelay => {
                        TransparentProxyRuntimeMode::Configured
                    }
                };
                (mode, Some(inbound_plan.health_probe()))
            }
            TransparentInterceptionExecutionPlan::OutboundTransparentProxy(_) => {
                (TransparentProxyRuntimeMode::Configured, None)
            }
        };
        let health_probe = health_probe_plan
            .map_or_else(TransparentProxyHealthProbeSnapshot::disabled, |plan| {
                TransparentProxyHealthProbeSnapshot::from_plan(plan)
            });
        let health_probe_failure_threshold =
            health_probe_plan.map_or(1, health_probe_failure_threshold);
        Self::new(mode, health_probe, health_probe_failure_threshold)
    }

    #[cfg(test)]
    pub(crate) fn for_test_config(config: &probe_config::EnforcementInterceptionConfig) -> Self {
        let plan = TransparentInterceptionExecutionPlan::try_from_config(config)
            .expect("test transparent interception config should be valid");
        Self::for_execution_plan(&plan)
    }

    fn new(
        mode: TransparentProxyRuntimeMode,
        health_probe: TransparentProxyHealthProbeSnapshot,
        health_probe_failure_threshold: u32,
    ) -> Self {
        Self {
            handle: TransparentProxyRuntimeHandle {
                inner: Arc::new(Mutex::new(TransparentProxyRuntimeState {
                    snapshot: TransparentProxyRuntimeSnapshot {
                        mode,
                        listener_families: Vec::new(),
                        health_probe,
                        upstream_connects: TransparentProxyConnectMetricsSnapshot {
                            connect_successes: 0,
                            connect_failures: 0,
                            last_failure_reason: None,
                        },
                        active_relays: 0,
                        accepted_relays: 0,
                        rejected_relays: 0,
                        relay_failures: 0,
                        listener_failures: 0,
                    },
                    health_probe_failure_threshold,
                })),
            },
        }
    }

    pub(crate) fn handle(&self) -> TransparentProxyRuntimeHandle {
        self.handle.clone()
    }

    pub(super) fn mark_running(&self, listener_families: Vec<TransparentInterceptionIpFamily>) {
        let mut state = self.handle.lock();
        state.snapshot.mode = TransparentProxyRuntimeMode::Running;
        state.snapshot.listener_families = listener_families;
    }

    pub(super) fn mark_stopped(&self) {
        let mut state = self.handle.lock();
        state.snapshot.mode = match state.snapshot.mode {
            TransparentProxyRuntimeMode::Degraded | TransparentProxyRuntimeMode::Failed => {
                state.snapshot.mode
            }
            _ => TransparentProxyRuntimeMode::Stopped,
        };
        state.snapshot.listener_families.clear();
    }

    pub(super) fn record_accepted_relay(&self) {
        let mut state = self.handle.lock();
        state.snapshot.accepted_relays = state.snapshot.accepted_relays.saturating_add(1);
    }

    pub(super) fn record_rejected_relay(&self) {
        let mut state = self.handle.lock();
        state.snapshot.rejected_relays = state.snapshot.rejected_relays.saturating_add(1);
    }

    pub(super) fn record_relay_failure(&self) {
        let mut state = self.handle.lock();
        state.snapshot.relay_failures = state.snapshot.relay_failures.saturating_add(1);
    }

    pub(super) fn record_upstream_connect_success(&self) {
        let mut state = self.handle.lock();
        state.snapshot.upstream_connects.connect_successes = state
            .snapshot
            .upstream_connects
            .connect_successes
            .saturating_add(1);
    }

    pub(super) fn record_upstream_connect_failure(&self, reason: impl Into<String>) {
        let mut state = self.handle.lock();
        state.snapshot.upstream_connects.connect_failures = state
            .snapshot
            .upstream_connects
            .connect_failures
            .saturating_add(1);
        state.snapshot.upstream_connects.last_failure_reason = Some(reason.into());
    }

    pub(super) fn record_health_probe_success(&self) {
        let mut state = self.handle.lock();
        if state.snapshot.health_probe.mode == TransparentProxyHealthProbeMode::Disabled {
            return;
        }
        state.snapshot.health_probe.check_successes = state
            .snapshot
            .health_probe
            .check_successes
            .saturating_add(1);
        state.snapshot.health_probe.consecutive_failures = 0;
        state.snapshot.health_probe.last_failure_reason = None;
        state.snapshot.health_probe.mode = TransparentProxyHealthProbeMode::Healthy;
    }

    pub(super) fn record_health_probe_failure(&self, reason: impl Into<String>) {
        let mut state = self.handle.lock();
        if state.snapshot.health_probe.mode == TransparentProxyHealthProbeMode::Disabled {
            return;
        }
        state.snapshot.health_probe.check_failures =
            state.snapshot.health_probe.check_failures.saturating_add(1);
        state.snapshot.health_probe.consecutive_failures = state
            .snapshot
            .health_probe
            .consecutive_failures
            .saturating_add(1);
        state.snapshot.health_probe.last_failure_reason = Some(reason.into());
        if state.snapshot.health_probe.consecutive_failures
            >= u64::from(state.health_probe_failure_threshold)
        {
            state.snapshot.health_probe.mode = TransparentProxyHealthProbeMode::Unhealthy;
        }
    }

    pub(super) fn record_listener_failure(&self, family: TransparentInterceptionIpFamily) {
        let mut state = self.handle.lock();
        state.snapshot.listener_failures = state.snapshot.listener_failures.saturating_add(1);
        state
            .snapshot
            .listener_families
            .retain(|listener_family| *listener_family != family);
        state.snapshot.mode = match (
            state.snapshot.mode,
            state.snapshot.listener_families.is_empty(),
        ) {
            (TransparentProxyRuntimeMode::Running, true)
            | (TransparentProxyRuntimeMode::Degraded, true)
            | (TransparentProxyRuntimeMode::Configured, _) => TransparentProxyRuntimeMode::Failed,
            (TransparentProxyRuntimeMode::Running, false) => TransparentProxyRuntimeMode::Degraded,
            (mode, _) => mode,
        };
    }

    pub(super) fn try_record_relay_started(&self, max_active_relays: u64) -> bool {
        let mut state = self.handle.lock();
        if state.snapshot.active_relays >= max_active_relays {
            return false;
        }
        state.snapshot.active_relays = state.snapshot.active_relays.saturating_add(1);
        true
    }

    pub(super) fn record_relay_finished(&self) {
        let mut state = self.handle.lock();
        state.snapshot.active_relays = state.snapshot.active_relays.saturating_sub(1);
    }
}

impl TransparentProxyHealthProbeSnapshot {
    fn disabled() -> Self {
        Self {
            mode: TransparentProxyHealthProbeMode::Disabled,
            check_successes: 0,
            check_failures: 0,
            consecutive_failures: 0,
            last_failure_reason: None,
        }
    }

    fn from_plan(plan: &TransparentInterceptionProxyHealthProbePlan) -> Self {
        let mode = if plan.is_enabled() {
            TransparentProxyHealthProbeMode::Pending
        } else {
            TransparentProxyHealthProbeMode::Disabled
        };
        Self {
            mode,
            ..Self::disabled()
        }
    }
}

fn health_probe_failure_threshold(plan: &TransparentInterceptionProxyHealthProbePlan) -> u32 {
    match plan {
        TransparentInterceptionProxyHealthProbePlan::Disabled => 1,
        TransparentInterceptionProxyHealthProbePlan::Enabled {
            failure_threshold, ..
        } => *failure_threshold,
    }
}

impl TransparentProxyRuntimeHandle {
    pub(crate) fn snapshot(&self) -> TransparentProxyRuntimeSnapshot {
        self.lock().snapshot.clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, TransparentProxyRuntimeState> {
        self.inner
            .lock()
            .expect("transparent proxy runtime state should not be poisoned")
    }
}

#[cfg(test)]
impl TransparentProxyRuntimeSnapshot {
    pub(crate) fn for_test(mode: TransparentProxyRuntimeMode) -> Self {
        Self {
            mode,
            listener_families: Vec::new(),
            health_probe: TransparentProxyHealthProbeSnapshot {
                mode: TransparentProxyHealthProbeMode::Disabled,
                check_successes: 0,
                check_failures: 0,
                consecutive_failures: 0,
                last_failure_reason: None,
            },
            upstream_connects: TransparentProxyConnectMetricsSnapshot {
                connect_successes: 0,
                connect_failures: 0,
                last_failure_reason: None,
            },
            active_relays: 0,
            accepted_relays: 0,
            rejected_relays: 0,
            relay_failures: 0,
            listener_failures: 0,
        }
    }

    pub(crate) fn with_relay_counts(
        mut self,
        active_relays: u64,
        accepted_relays: u64,
        rejected_relays: u64,
        relay_failures: u64,
        listener_failures: u64,
    ) -> Self {
        self.active_relays = active_relays;
        self.accepted_relays = accepted_relays;
        self.rejected_relays = rejected_relays;
        self.relay_failures = relay_failures;
        self.listener_failures = listener_failures;
        self
    }

    pub(crate) fn with_upstream_connects(
        mut self,
        connect_successes: u64,
        connect_failures: u64,
        last_failure_reason: Option<&str>,
    ) -> Self {
        self.upstream_connects.connect_successes = connect_successes;
        self.upstream_connects.connect_failures = connect_failures;
        self.upstream_connects.last_failure_reason = last_failure_reason.map(ToString::to_string);
        self
    }

    pub(crate) fn with_health_probe(
        mut self,
        mode: TransparentProxyHealthProbeMode,
        check_successes: u64,
        check_failures: u64,
        consecutive_failures: u64,
        last_failure_reason: Option<&str>,
    ) -> Self {
        self.health_probe.mode = mode;
        self.health_probe.check_successes = check_successes;
        self.health_probe.check_failures = check_failures;
        self.health_probe.consecutive_failures = consecutive_failures;
        self.health_probe.last_failure_reason = last_failure_reason.map(ToString::to_string);
        self
    }
}

#[cfg(test)]
mod tests {
    use probe_config::{
        EnforcementInterceptionConfig, TransparentInterceptionProxyConfig,
        TransparentInterceptionProxyHealthProbeConfig, TransparentInterceptionStrategyConfig,
    };

    use super::*;

    #[test]
    fn runtime_mode_follows_interception_config() {
        let disabled =
            TransparentProxyRuntime::for_test_config(&EnforcementInterceptionConfig::default())
                .handle()
                .snapshot();
        assert_eq!(disabled.mode, TransparentProxyRuntimeMode::Disabled);

        let inbound_external = TransparentProxyRuntime::for_test_config(&interception_config(
            TransparentInterceptionStrategyConfig::InboundTproxy,
            TransparentInterceptionProxyModeConfig::External,
        ))
        .handle()
        .snapshot();
        assert_eq!(inbound_external.mode, TransparentProxyRuntimeMode::External);

        let inbound_managed = TransparentProxyRuntime::for_test_config(&interception_config(
            TransparentInterceptionStrategyConfig::InboundTproxy,
            TransparentInterceptionProxyModeConfig::ManagedTcpRelay,
        ))
        .handle()
        .snapshot();
        assert_eq!(
            inbound_managed.mode,
            TransparentProxyRuntimeMode::Configured
        );

        let outbound_transparent_proxy =
            TransparentProxyRuntime::for_test_config(&interception_config(
                TransparentInterceptionStrategyConfig::OutboundTransparentProxy,
                TransparentInterceptionProxyModeConfig::ManagedTcpRelay,
            ))
            .handle()
            .snapshot();
        assert_eq!(
            outbound_transparent_proxy.mode,
            TransparentProxyRuntimeMode::Configured
        );
    }

    #[test]
    fn health_probe_state_follows_configured_checks() {
        let state =
            TransparentProxyRuntime::for_test_config(&interception_config_with_health_probe());
        let handle = state.handle();

        let snapshot = handle.snapshot();
        assert_eq!(
            snapshot.health_probe.mode,
            TransparentProxyHealthProbeMode::Pending
        );

        state.record_health_probe_failure("connection refused");

        let snapshot = handle.snapshot();
        assert_eq!(
            snapshot.health_probe.mode,
            TransparentProxyHealthProbeMode::Pending
        );
        assert_eq!(snapshot.health_probe.check_failures, 1);
        assert_eq!(snapshot.health_probe.consecutive_failures, 1);

        state.record_health_probe_failure("timed out");

        let snapshot = handle.snapshot();
        assert_eq!(
            snapshot.health_probe.mode,
            TransparentProxyHealthProbeMode::Unhealthy
        );
        assert_eq!(snapshot.health_probe.check_failures, 2);
        assert_eq!(snapshot.health_probe.consecutive_failures, 2);
        assert_eq!(
            snapshot.health_probe.last_failure_reason.as_deref(),
            Some("timed out")
        );

        state.record_health_probe_success();

        let snapshot = handle.snapshot();
        assert_eq!(
            snapshot.health_probe.mode,
            TransparentProxyHealthProbeMode::Healthy
        );
        assert_eq!(snapshot.health_probe.check_successes, 1);
        assert_eq!(snapshot.health_probe.consecutive_failures, 0);
        assert_eq!(snapshot.health_probe.last_failure_reason, None);
    }

    #[test]
    fn runtime_counters_follow_relay_lifecycle() {
        let state = TransparentProxyRuntime::for_test_config(&interception_config(
            TransparentInterceptionStrategyConfig::InboundTproxy,
            TransparentInterceptionProxyModeConfig::ManagedTcpRelay,
        ));
        let handle = state.handle();

        state.mark_running(vec![
            TransparentInterceptionIpFamily::Ipv4,
            TransparentInterceptionIpFamily::Ipv6,
        ]);
        assert!(state.try_record_relay_started(2));
        assert!(state.try_record_relay_started(2));
        assert!(!state.try_record_relay_started(2));
        state.record_accepted_relay();
        state.record_rejected_relay();
        state.record_relay_failure();
        state.record_listener_failure(TransparentInterceptionIpFamily::Ipv6);
        state.record_relay_finished();

        let snapshot = handle.snapshot();
        assert_eq!(snapshot.mode, TransparentProxyRuntimeMode::Degraded);
        assert_eq!(
            snapshot.listener_families,
            vec![TransparentInterceptionIpFamily::Ipv4]
        );
        assert_eq!(snapshot.active_relays, 1);
        assert_eq!(snapshot.accepted_relays, 1);
        assert_eq!(snapshot.rejected_relays, 1);
        assert_eq!(snapshot.relay_failures, 1);
        assert_eq!(snapshot.listener_failures, 1);
        assert_eq!(snapshot.upstream_connects.connect_successes, 0);
        assert_eq!(snapshot.upstream_connects.connect_failures, 0);

        state.record_listener_failure(TransparentInterceptionIpFamily::Ipv4);
        let snapshot = handle.snapshot();
        assert_eq!(snapshot.mode, TransparentProxyRuntimeMode::Failed);
        assert!(snapshot.listener_families.is_empty());
        assert_eq!(snapshot.active_relays, 1);
        assert_eq!(snapshot.listener_failures, 2);

        state.mark_stopped();
        assert_eq!(handle.snapshot().active_relays, 1);
        state.record_relay_finished();

        let snapshot = handle.snapshot();
        assert_eq!(snapshot.mode, TransparentProxyRuntimeMode::Failed);
        assert!(snapshot.listener_families.is_empty());
        assert_eq!(snapshot.active_relays, 0);
        assert_eq!(snapshot.accepted_relays, 1);
        assert_eq!(snapshot.rejected_relays, 1);
        assert_eq!(snapshot.relay_failures, 1);
        assert_eq!(snapshot.listener_failures, 2);
    }

    #[test]
    fn upstream_connect_metrics_follow_connect_results() {
        let state = TransparentProxyRuntime::for_test_config(&interception_config(
            TransparentInterceptionStrategyConfig::InboundTproxy,
            TransparentInterceptionProxyModeConfig::ManagedTcpRelay,
        ));
        let handle = state.handle();

        state.record_upstream_connect_success();

        let snapshot = handle.snapshot();
        assert_eq!(snapshot.upstream_connects.connect_successes, 1);
        assert_eq!(snapshot.upstream_connects.connect_failures, 0);
        assert_eq!(snapshot.upstream_connects.last_failure_reason, None);

        state.record_upstream_connect_failure("connection refused");

        let snapshot = handle.snapshot();
        assert_eq!(snapshot.upstream_connects.connect_successes, 1);
        assert_eq!(snapshot.upstream_connects.connect_failures, 1);
        assert_eq!(
            snapshot.upstream_connects.last_failure_reason.as_deref(),
            Some("connection refused")
        );

        state.record_upstream_connect_success();

        let snapshot = handle.snapshot();
        assert_eq!(snapshot.upstream_connects.connect_successes, 2);
        assert_eq!(snapshot.upstream_connects.connect_failures, 1);
        assert_eq!(
            snapshot.upstream_connects.last_failure_reason.as_deref(),
            Some("connection refused")
        );
    }

    #[test]
    fn clean_stop_marks_proxy_stopped_without_forging_relay_lifecycle() {
        let state = TransparentProxyRuntime::for_test_config(&interception_config(
            TransparentInterceptionStrategyConfig::InboundTproxy,
            TransparentInterceptionProxyModeConfig::ManagedTcpRelay,
        ));
        let handle = state.handle();

        state.mark_running(vec![TransparentInterceptionIpFamily::Ipv4]);
        assert!(state.try_record_relay_started(2));
        state.mark_stopped();

        let snapshot = handle.snapshot();
        assert_eq!(snapshot.mode, TransparentProxyRuntimeMode::Stopped);
        assert!(snapshot.listener_families.is_empty());
        assert_eq!(snapshot.active_relays, 1);

        state.record_relay_finished();

        assert_eq!(handle.snapshot().active_relays, 0);
    }

    fn interception_config(
        strategy: TransparentInterceptionStrategyConfig,
        proxy_mode: TransparentInterceptionProxyModeConfig,
    ) -> EnforcementInterceptionConfig {
        EnforcementInterceptionConfig {
            strategy,
            proxy: TransparentInterceptionProxyConfig {
                mode: proxy_mode,
                listen_port: Some(15001),
                ..TransparentInterceptionProxyConfig::default()
            },
            ..EnforcementInterceptionConfig::default()
        }
    }

    fn interception_config_with_health_probe() -> EnforcementInterceptionConfig {
        EnforcementInterceptionConfig {
            strategy: TransparentInterceptionStrategyConfig::InboundTproxy,
            proxy: TransparentInterceptionProxyConfig {
                mode: TransparentInterceptionProxyModeConfig::ManagedTcpRelay,
                listen_port: Some(15001),
                health_probe: TransparentInterceptionProxyHealthProbeConfig {
                    target: Some("127.0.0.1:18080".to_string()),
                    interval_ms: 500,
                    timeout_ms: 100,
                    failure_threshold: 2,
                },
            },
            ..EnforcementInterceptionConfig::default()
        }
    }
}
