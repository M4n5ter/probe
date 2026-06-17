use std::{
    io,
    net::{Shutdown, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

const MAX_ACTIVE_RELAYS: usize = 256;

#[derive(Clone, Default)]
pub(super) struct RelayRegistry {
    next_id: Arc<AtomicU64>,
    active_slots: Arc<AtomicU64>,
    relays: Arc<Mutex<Vec<TrackedRelay>>>,
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
    pub(super) fn try_acquire_slot(&self) -> Option<RelaySlot> {
        let mut current = self.active_slots.load(Ordering::SeqCst);
        loop {
            if current >= MAX_ACTIVE_RELAYS as u64 {
                return None;
            }
            match self.active_slots.compare_exchange(
                current,
                current + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    return Some(RelaySlot {
                        registry: self.clone(),
                    });
                }
                Err(next) => current = next,
            }
        }
    }

    fn release_slot(&self) {
        self.active_slots.fetch_sub(1, Ordering::SeqCst);
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
}
