use std::{
    io,
    net::{Shutdown, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use super::state::TransparentProxyRuntime;

const MAX_ACTIVE_RELAYS: usize = 256;

#[derive(Clone)]
pub(super) struct RelayRegistry {
    next_id: Arc<AtomicU64>,
    relays: Arc<Mutex<Vec<TrackedRelay>>>,
    runtime: TransparentProxyRuntime,
}

struct TrackedRelay {
    id: u64,
    downstream: TcpStream,
    upstream: TcpStream,
}

pub(super) struct RelayRegistration {
    id: u64,
    registry: RelayRegistry,
}

pub(super) struct RelaySlot {
    registry: RelayRegistry,
}

impl RelayRegistry {
    pub(super) fn new(runtime: TransparentProxyRuntime) -> Self {
        Self {
            next_id: Arc::new(AtomicU64::new(0)),
            relays: Arc::new(Mutex::new(Vec::new())),
            runtime,
        }
    }

    pub(super) fn try_acquire_slot(&self) -> Option<RelaySlot> {
        if self
            .runtime
            .try_record_relay_started(MAX_ACTIVE_RELAYS as u64)
        {
            Some(RelaySlot {
                registry: self.clone(),
            })
        } else {
            None
        }
    }

    fn release_slot(&self) {
        self.runtime.record_relay_finished();
    }

    pub(super) fn register(
        &self,
        downstream: &TcpStream,
        upstream: &TcpStream,
    ) -> io::Result<RelayRegistration> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let relay = TrackedRelay {
            id,
            downstream: downstream.try_clone()?,
            upstream: upstream.try_clone()?,
        };
        self.relays
            .lock()
            .expect("active relay registry should not be poisoned")
            .push(relay);
        Ok(RelayRegistration {
            id,
            registry: self.clone(),
        })
    }

    fn unregister(&self, id: u64) {
        self.relays
            .lock()
            .expect("active relay registry should not be poisoned")
            .retain(|relay| relay.id != id);
    }

    pub(super) fn shutdown_all(&self) {
        for relay in self
            .relays
            .lock()
            .expect("active relay registry should not be poisoned")
            .iter()
        {
            shutdown_streams(&relay.downstream, &relay.upstream);
        }
    }
}

#[cfg(test)]
impl Default for RelayRegistry {
    fn default() -> Self {
        Self {
            next_id: Arc::new(AtomicU64::new(0)),
            relays: Arc::new(Mutex::new(Vec::new())),
            runtime: TransparentProxyRuntime::for_test_config(
                &probe_config::EnforcementInterceptionConfig::default(),
            ),
        }
    }
}

impl Drop for RelayRegistration {
    fn drop(&mut self) {
        self.registry.unregister(self.id);
    }
}

impl Drop for RelaySlot {
    fn drop(&mut self) {
        self.registry.release_slot();
    }
}

pub(super) fn shutdown_streams(downstream: &TcpStream, upstream: &TcpStream) {
    let _ = downstream.shutdown(Shutdown::Both);
    let _ = upstream.shutdown(Shutdown::Both);
}

#[cfg(test)]
mod tests {
    use probe_config::{
        EnforcementInterceptionConfig, TransparentInterceptionProxyConfig,
        TransparentInterceptionProxyModeConfig, TransparentInterceptionStrategyConfig,
    };

    use super::*;

    #[test]
    fn active_relay_slots_are_bounded_and_released() {
        let registry = RelayRegistry::default();
        let slots = (0..MAX_ACTIVE_RELAYS)
            .map(|_| {
                registry
                    .try_acquire_slot()
                    .expect("slot should be available")
            })
            .collect::<Vec<_>>();

        assert!(registry.try_acquire_slot().is_none());

        drop(slots);
        assert!(registry.try_acquire_slot().is_some());
    }

    #[test]
    fn relay_slots_update_runtime_active_count() {
        let runtime = TransparentProxyRuntime::for_test_config(&managed_interception_config());
        let handle = runtime.handle();
        let registry = RelayRegistry::new(runtime);

        let first = registry
            .try_acquire_slot()
            .expect("first slot should be available");
        let second = registry
            .try_acquire_slot()
            .expect("second slot should be available");
        assert_eq!(handle.snapshot().active_relays, 2);

        drop(first);
        assert_eq!(handle.snapshot().active_relays, 1);

        drop(second);
        assert_eq!(handle.snapshot().active_relays, 0);
    }

    #[test]
    fn stopped_runtime_does_not_forge_active_relay_count() {
        let runtime = TransparentProxyRuntime::for_test_config(&managed_interception_config());
        let handle = runtime.handle();
        let registry = RelayRegistry::new(runtime.clone());
        let slot = registry
            .try_acquire_slot()
            .expect("slot should be available");

        runtime.mark_stopped();

        assert_eq!(handle.snapshot().active_relays, 1);

        drop(slot);

        assert_eq!(handle.snapshot().active_relays, 0);
    }

    fn managed_interception_config() -> EnforcementInterceptionConfig {
        EnforcementInterceptionConfig {
            strategy: TransparentInterceptionStrategyConfig::InboundTproxy,
            proxy: TransparentInterceptionProxyConfig {
                mode: TransparentInterceptionProxyModeConfig::ManagedTcpRelay,
                listen_port: Some(15001),
                ..TransparentInterceptionProxyConfig::default()
            },
            ..EnforcementInterceptionConfig::default()
        }
    }
}
