use std::sync::{Arc, Mutex};

use probe_config::{
    EnforcementInterceptionConfig, TransparentInterceptionProxyModeConfig,
    TransparentInterceptionStrategyConfig,
};
use serde::Serialize;

use crate::transparent_interception::TransparentInterceptionIpFamily;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct TransparentProxyRuntimeSnapshot {
    pub mode: TransparentProxyRuntimeMode,
    pub listener_families: Vec<TransparentInterceptionIpFamily>,
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

#[derive(Clone)]
pub(in crate::transparent_interception) struct TransparentProxyRuntime {
    handle: TransparentProxyRuntimeHandle,
}

#[derive(Clone)]
pub(crate) struct TransparentProxyRuntimeHandle {
    inner: Arc<Mutex<TransparentProxyRuntimeSnapshot>>,
}

impl TransparentProxyRuntime {
    pub(crate) fn for_config(config: &EnforcementInterceptionConfig) -> Self {
        let mode = match (config.strategy, config.proxy.mode) {
            (TransparentInterceptionStrategyConfig::None, _) => {
                TransparentProxyRuntimeMode::Disabled
            }
            (_, TransparentInterceptionProxyModeConfig::External) => {
                TransparentProxyRuntimeMode::External
            }
            (_, TransparentInterceptionProxyModeConfig::ManagedTcpRelay) => {
                TransparentProxyRuntimeMode::Configured
            }
        };
        Self {
            handle: TransparentProxyRuntimeHandle {
                inner: Arc::new(Mutex::new(TransparentProxyRuntimeSnapshot {
                    mode,
                    listener_families: Vec::new(),
                    active_relays: 0,
                    accepted_relays: 0,
                    rejected_relays: 0,
                    relay_failures: 0,
                    listener_failures: 0,
                })),
            },
        }
    }

    pub(crate) fn handle(&self) -> TransparentProxyRuntimeHandle {
        self.handle.clone()
    }

    pub(super) fn mark_running(&self, listener_families: Vec<TransparentInterceptionIpFamily>) {
        let mut state = self.handle.lock();
        state.mode = TransparentProxyRuntimeMode::Running;
        state.listener_families = listener_families;
    }

    pub(super) fn mark_stopped(&self) {
        let mut state = self.handle.lock();
        state.mode = match state.mode {
            TransparentProxyRuntimeMode::Degraded | TransparentProxyRuntimeMode::Failed => {
                state.mode
            }
            _ => TransparentProxyRuntimeMode::Stopped,
        };
        state.listener_families.clear();
    }

    pub(super) fn record_accepted_relay(&self) {
        let mut state = self.handle.lock();
        state.accepted_relays = state.accepted_relays.saturating_add(1);
    }

    pub(super) fn record_rejected_relay(&self) {
        let mut state = self.handle.lock();
        state.rejected_relays = state.rejected_relays.saturating_add(1);
    }

    pub(super) fn record_relay_failure(&self) {
        let mut state = self.handle.lock();
        state.relay_failures = state.relay_failures.saturating_add(1);
    }

    pub(super) fn record_listener_failure(&self, family: TransparentInterceptionIpFamily) {
        let mut state = self.handle.lock();
        state.listener_failures = state.listener_failures.saturating_add(1);
        state
            .listener_families
            .retain(|listener_family| *listener_family != family);
        state.mode = match (state.mode, state.listener_families.is_empty()) {
            (TransparentProxyRuntimeMode::Running, true)
            | (TransparentProxyRuntimeMode::Degraded, true)
            | (TransparentProxyRuntimeMode::Configured, _) => TransparentProxyRuntimeMode::Failed,
            (TransparentProxyRuntimeMode::Running, false) => TransparentProxyRuntimeMode::Degraded,
            (mode, _) => mode,
        };
    }

    pub(super) fn try_record_relay_started(&self, max_active_relays: u64) -> bool {
        let mut state = self.handle.lock();
        if state.active_relays >= max_active_relays {
            return false;
        }
        state.active_relays = state.active_relays.saturating_add(1);
        true
    }

    pub(super) fn record_relay_finished(&self) {
        let mut state = self.handle.lock();
        state.active_relays = state.active_relays.saturating_sub(1);
    }
}

impl TransparentProxyRuntimeHandle {
    pub(crate) fn snapshot(&self) -> TransparentProxyRuntimeSnapshot {
        self.lock().clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, TransparentProxyRuntimeSnapshot> {
        self.inner
            .lock()
            .expect("transparent proxy runtime state should not be poisoned")
    }
}

#[cfg(test)]
mod tests {
    use probe_config::TransparentInterceptionProxyConfig;

    use super::*;

    #[test]
    fn runtime_mode_follows_interception_config() {
        assert_eq!(
            TransparentProxyRuntime::for_config(&EnforcementInterceptionConfig::default())
                .handle()
                .snapshot()
                .mode,
            TransparentProxyRuntimeMode::Disabled
        );

        assert_eq!(
            TransparentProxyRuntime::for_config(&interception_config(
                TransparentInterceptionStrategyConfig::InboundTproxy,
                TransparentInterceptionProxyModeConfig::External,
            ))
            .handle()
            .snapshot()
            .mode,
            TransparentProxyRuntimeMode::External
        );

        assert_eq!(
            TransparentProxyRuntime::for_config(&interception_config(
                TransparentInterceptionStrategyConfig::InboundTproxy,
                TransparentInterceptionProxyModeConfig::ManagedTcpRelay,
            ))
            .handle()
            .snapshot()
            .mode,
            TransparentProxyRuntimeMode::Configured
        );
    }

    #[test]
    fn runtime_counters_follow_relay_lifecycle() {
        let state = TransparentProxyRuntime::for_config(&interception_config(
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
    fn clean_stop_marks_proxy_stopped_without_forging_relay_lifecycle() {
        let state = TransparentProxyRuntime::for_config(&interception_config(
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
            },
            ..EnforcementInterceptionConfig::default()
        }
    }
}
