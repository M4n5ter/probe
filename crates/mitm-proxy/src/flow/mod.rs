use std::{
    collections::{HashMap, hash_map::DefaultHasher},
    fs,
    hash::{Hash, Hasher},
    net::SocketAddr,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
        mpsc::{self, Receiver, Sender},
    },
    time::Instant,
};

use probe_core::{
    AddressPort, Direction, FlowContext, FlowIdentity, ProcessContext, ProcessIdentity,
    TransportProtocol,
};

#[derive(Debug)]
pub(crate) enum ProxyAction {
    Deny { reason: Option<String> },
}

#[derive(Default)]
pub(crate) struct FlowRegistry {
    flows: Mutex<HashMap<String, Sender<ProxyAction>>>,
}

impl FlowRegistry {
    pub(crate) fn register(self: &Arc<Self>, flow_id: FlowIdentity) -> FlowRegistration {
        let (sender, receiver) = mpsc::channel();
        self.flows
            .lock()
            .expect("flow registry mutex should not be poisoned")
            .insert(flow_id.0.clone(), sender);
        FlowRegistration {
            registry: Arc::clone(self),
            flow_id,
            receiver,
        }
    }

    pub(crate) fn deny(&self, flow_id: &str, reason: Option<String>) -> bool {
        let mut flows = self
            .flows
            .lock()
            .expect("flow registry mutex should not be poisoned");
        let Some(sender) = flows.remove(flow_id) else {
            return false;
        };
        sender.send(ProxyAction::Deny { reason }).is_ok()
    }

    fn remove(&self, flow_id: &FlowIdentity) {
        self.flows
            .lock()
            .expect("flow registry mutex should not be poisoned")
            .remove(&flow_id.0);
    }
}

pub(crate) struct FlowRegistration {
    registry: Arc<FlowRegistry>,
    flow_id: FlowIdentity,
    receiver: Receiver<ProxyAction>,
}

impl FlowRegistration {
    pub(crate) fn recv_timeout(self, timeout: std::time::Duration) -> Option<ProxyAction> {
        match self.receiver.recv_timeout(timeout) {
            Ok(action) => Some(action),
            Err(_) => {
                self.registry.remove(&self.flow_id);
                self.receiver.try_recv().ok()
            }
        }
    }
}

impl Drop for FlowRegistration {
    fn drop(&mut self) {
        self.registry.remove(&self.flow_id);
    }
}

pub(crate) struct FlowFactory {
    process: ProcessContext,
    started: Instant,
    next_flow: AtomicU64,
}

impl FlowFactory {
    pub(crate) fn new() -> Self {
        Self {
            process: current_process_context(),
            started: Instant::now(),
            next_flow: AtomicU64::new(1),
        }
    }

    pub(crate) fn flow(
        &self,
        peer: SocketAddr,
        target: SocketAddr,
        request_direction: Direction,
    ) -> FlowContext {
        let sequence = self.next_flow.fetch_add(1, Ordering::Relaxed);
        let (local, remote) = match request_direction {
            Direction::Inbound => (target, peer),
            Direction::Outbound => (peer, target),
        };
        FlowContext {
            id: FlowIdentity(format!("l7_mitm:{sequence}")),
            process: self.process.clone(),
            local: address_port(local),
            remote: address_port(remote),
            protocol: TransportProtocol::Tcp,
            start_monotonic_ns: monotonic_ns(self.started),
            socket_cookie: None,
            attribution_confidence: 0,
        }
    }
}

fn current_process_context() -> ProcessContext {
    let pid = std::process::id();
    let cmdline = std::env::args().collect::<Vec<_>>();
    let executable = std::env::current_exe().unwrap_or_else(|_| Path::new("").to_path_buf());
    let name = executable
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("traffic-probe-mitm-proxy")
        .to_string();
    ProcessContext {
        identity: ProcessIdentity {
            pid,
            tgid: pid,
            start_time_ticks: 0,
            boot_id: boot_id(),
            exe_path: executable.display().to_string(),
            cmdline_hash: cmdline_hash(&cmdline),
            uid: rustix::process::getuid().as_raw(),
            gid: rustix::process::getgid().as_raw(),
            cgroup: None,
            systemd_service: None,
            container_id: None,
            runtime_hint: Some("l7_mitm_proxy".to_string()),
        },
        name,
        cmdline,
    }
}

fn address_port(address: SocketAddr) -> AddressPort {
    AddressPort {
        address: address.ip().to_string(),
        port: address.port(),
    }
}

fn monotonic_ns(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

fn boot_id() -> String {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|value| value.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

fn cmdline_hash(cmdline: &[String]) -> String {
    let mut hasher = DefaultHasher::new();
    cmdline.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use super::*;

    #[test]
    fn timeout_closes_pending_flow() {
        let registry = Arc::new(FlowRegistry::default());
        let registration = Arc::clone(&registry).register(FlowIdentity("flow-1".to_string()));

        assert!(registration.recv_timeout(Duration::ZERO).is_none());
        assert!(!registry.deny("flow-1", Some("too late".to_string())));
    }

    #[test]
    fn deny_before_timeout_is_delivered() {
        let registry = Arc::new(FlowRegistry::default());
        let registration = Arc::clone(&registry).register(FlowIdentity("flow-1".to_string()));

        assert!(registry.deny("flow-1", Some("blocked".to_string())));
        assert!(matches!(
            registration.recv_timeout(Duration::from_secs(1)),
            Some(ProxyAction::Deny { reason }) if reason.as_deref() == Some("blocked")
        ));
    }
}
