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

use attribution::{AttributionError, ProcfsSocketResolver, SocketProcessContext};
use probe_core::{
    AddressPort, Direction, EventEnvelope, EventKind, FlowContext, FlowIdentity, ProcessContext,
    ProcessIdentity, TcpConnection, TcpEndpoint, TransportProtocol,
};

#[derive(Debug)]
pub(crate) enum ProxyAction {
    Deny { reason: Option<String> },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct PendingActionKey {
    flow_id: FlowIdentity,
    direction: Direction,
    stream_sequence: u64,
}

impl PendingActionKey {
    pub(crate) fn request(
        flow_id: FlowIdentity,
        direction: Direction,
        stream_sequence: u64,
    ) -> Self {
        Self {
            flow_id,
            direction,
            stream_sequence,
        }
    }

    pub(crate) fn from_trigger(trigger: &EventEnvelope) -> Option<Self> {
        let flow = trigger.flow()?;
        match trigger.kind() {
            EventKind::HttpRequestHeaders(headers) => Some(Self::request(
                flow.id.clone(),
                headers.direction,
                headers.stream_sequence,
            )),
            _ => None,
        }
    }

    pub(crate) fn describe(&self) -> String {
        format!(
            "{} {:?} stream {}",
            self.flow_id.0, self.direction, self.stream_sequence
        )
    }
}

#[derive(Default)]
pub(crate) struct FlowRegistry {
    pending: Mutex<HashMap<PendingActionKey, Sender<ProxyAction>>>,
}

impl FlowRegistry {
    pub(crate) fn register(self: &Arc<Self>, key: PendingActionKey) -> FlowRegistration {
        let (sender, receiver) = mpsc::channel();
        self.pending
            .lock()
            .expect("flow registry mutex should not be poisoned")
            .insert(key.clone(), sender);
        FlowRegistration {
            registry: Arc::clone(self),
            key,
            receiver,
        }
    }

    pub(crate) fn deny(&self, key: &PendingActionKey, reason: Option<String>) -> bool {
        let mut pending = self
            .pending
            .lock()
            .expect("flow registry mutex should not be poisoned");
        let Some(sender) = pending.remove(key) else {
            return false;
        };
        sender.send(ProxyAction::Deny { reason }).is_ok()
    }

    fn remove(&self, key: &PendingActionKey) {
        self.pending
            .lock()
            .expect("flow registry mutex should not be poisoned")
            .remove(key);
    }
}

pub(crate) struct FlowRegistration {
    registry: Arc<FlowRegistry>,
    key: PendingActionKey,
    receiver: Receiver<ProxyAction>,
}

impl FlowRegistration {
    pub(crate) fn recv_timeout(self, timeout: std::time::Duration) -> Option<ProxyAction> {
        match self.receiver.recv_timeout(timeout) {
            Ok(action) => Some(action),
            Err(_) => {
                self.registry.remove(&self.key);
                self.receiver.try_recv().ok()
            }
        }
    }
}

impl Drop for FlowRegistration {
    fn drop(&mut self) {
        self.registry.remove(&self.key);
    }
}

pub(crate) struct FlowFactory {
    fallback_process: ProcessContext,
    attribution: FlowAttribution,
    request_direction: Direction,
    started: Instant,
    next_flow: AtomicU64,
}

impl FlowFactory {
    pub(crate) fn new(request_direction: Direction) -> Self {
        Self {
            fallback_process: current_process_context(),
            attribution: FlowAttribution::for_direction(request_direction),
            request_direction,
            started: Instant::now(),
            next_flow: AtomicU64::new(1),
        }
    }

    #[cfg(test)]
    fn with_attributor(
        request_direction: Direction,
        attributor: impl FlowProcessAttributor + 'static,
    ) -> Self {
        Self {
            fallback_process: current_process_context(),
            attribution: FlowAttribution::OutboundProcfs(Mutex::new(Box::new(attributor))),
            request_direction,
            started: Instant::now(),
            next_flow: AtomicU64::new(1),
        }
    }

    pub(crate) fn flow(&self, peer: SocketAddr, target: SocketAddr) -> FlowContext {
        let sequence = self.next_flow.fetch_add(1, Ordering::Relaxed);
        let endpoints = FlowEndpoints::from_direction(self.request_direction, peer, target);
        let local = address_port(endpoints.local);
        let remote = address_port(endpoints.remote);
        let started = monotonic_ns(self.started);
        let resolved = self.attribution.resolve(endpoints);
        let (process, attribution_confidence) = resolved
            .map(|resolved| (resolved.process, resolved.confidence))
            .unwrap_or_else(|| (self.fallback_process.clone(), 0));
        let socket_cookie = None;
        let id = if attribution_confidence > 0 {
            FlowIdentity::stable(
                &process.identity,
                &local,
                &remote,
                TransportProtocol::Tcp,
                started,
                socket_cookie,
            )
        } else {
            FlowIdentity(format!("l7_mitm:{sequence}"))
        };
        FlowContext {
            id,
            process,
            local,
            remote,
            protocol: TransportProtocol::Tcp,
            start_monotonic_ns: started,
            socket_cookie,
            attribution_confidence,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct FlowEndpoints {
    local: SocketAddr,
    remote: SocketAddr,
}

impl FlowEndpoints {
    fn from_direction(direction: Direction, peer: SocketAddr, target: SocketAddr) -> Self {
        let (local, remote) = match direction {
            Direction::Inbound => (target, peer),
            Direction::Outbound => (peer, target),
        };
        Self { local, remote }
    }

    fn connection(self) -> TcpConnection {
        tcp_connection(self.local, self.remote)
    }
}

enum FlowAttribution {
    ProxyOnly,
    OutboundProcfs(Mutex<Box<dyn FlowProcessAttributor>>),
}

impl FlowAttribution {
    fn for_direction(direction: Direction) -> Self {
        match direction {
            Direction::Inbound => Self::ProxyOnly,
            Direction::Outbound => {
                Self::OutboundProcfs(Mutex::new(Box::new(ProcfsFlowProcessAttributor::new())))
            }
        }
    }

    fn resolve(&self, endpoints: FlowEndpoints) -> Option<SocketProcessContext> {
        match self {
            Self::ProxyOnly => None,
            Self::OutboundProcfs(attributor) => attributor
                .lock()
                .expect("flow process attributor mutex should not be poisoned")
                .resolve(endpoints.connection())
                .ok()
                .flatten(),
        }
    }
}

trait FlowProcessAttributor: Send {
    fn resolve(
        &mut self,
        connection: TcpConnection,
    ) -> Result<Option<SocketProcessContext>, AttributionError>;
}

struct ProcfsFlowProcessAttributor {
    resolver: ProcfsSocketResolver,
}

impl ProcfsFlowProcessAttributor {
    fn new() -> Self {
        Self {
            resolver: ProcfsSocketResolver::new(),
        }
    }
}

impl FlowProcessAttributor for ProcfsFlowProcessAttributor {
    fn resolve(
        &mut self,
        connection: TcpConnection,
    ) -> Result<Option<SocketProcessContext>, AttributionError> {
        self.resolver.invalidate_snapshot();
        self.resolver.resolve_tcp_connection(connection)
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

fn tcp_connection(local: SocketAddr, remote: SocketAddr) -> TcpConnection {
    TcpConnection::new(tcp_endpoint(local), tcp_endpoint(remote))
}

fn tcp_endpoint(address: SocketAddr) -> TcpEndpoint {
    TcpEndpoint::new(address.ip(), address.port())
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
    use std::{
        net::{TcpListener, TcpStream},
        sync::Arc,
        time::Duration,
    };

    use super::*;

    #[test]
    fn timeout_closes_pending_flow() {
        let registry = Arc::new(FlowRegistry::default());
        let key =
            PendingActionKey::request(FlowIdentity("flow-1".to_string()), Direction::Outbound, 1);
        let registration = Arc::clone(&registry).register(key.clone());

        assert!(registration.recv_timeout(Duration::ZERO).is_none());
        assert!(!registry.deny(&key, Some("too late".to_string())));
    }

    #[test]
    fn deny_before_timeout_is_delivered() {
        let registry = Arc::new(FlowRegistry::default());
        let key =
            PendingActionKey::request(FlowIdentity("flow-1".to_string()), Direction::Outbound, 1);
        let registration = Arc::clone(&registry).register(key.clone());

        assert!(registry.deny(&key, Some("blocked".to_string())));
        assert!(matches!(
            registration.recv_timeout(Duration::from_secs(1)),
            Some(ProxyAction::Deny { reason }) if reason.as_deref() == Some("blocked")
        ));
    }

    #[test]
    fn request_pending_keys_do_not_alias_on_sequence() {
        let registry = Arc::new(FlowRegistry::default());
        let first =
            PendingActionKey::request(FlowIdentity("flow-1".to_string()), Direction::Outbound, 1);
        let second =
            PendingActionKey::request(FlowIdentity("flow-1".to_string()), Direction::Outbound, 2);
        let registration = Arc::clone(&registry).register(second.clone());

        assert!(!registry.deny(&first, Some("stale".to_string())));
        assert!(registry.deny(&second, Some("blocked".to_string())));
        assert!(matches!(
            registration.recv_timeout(Duration::from_secs(1)),
            Some(ProxyAction::Deny { reason }) if reason.as_deref() == Some("blocked")
        ));
    }

    #[test]
    fn outbound_flow_prefers_procfs_socket_process_context()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let target = listener.local_addr()?;
        let client = TcpStream::connect(target)?;
        let peer = client.local_addr()?;
        let (_accepted, _) = listener.accept()?;

        let flow = FlowFactory::new(Direction::Outbound).flow(peer, target);

        assert_eq!(flow.process.identity.pid, std::process::id());
        assert!(
            flow.attribution_confidence > 0,
            "outbound flow should use procfs socket attribution, got {flow:?}"
        );
        assert_eq!(flow.local, address_port(peer));
        assert_eq!(flow.remote, address_port(target));
        Ok(())
    }

    #[test]
    fn inbound_flow_keeps_proxy_process_fallback() {
        let peer = "127.0.0.1:40000".parse().expect("peer");
        let target = "127.0.0.1:50000".parse().expect("target");

        let flow = FlowFactory::new(Direction::Inbound).flow(peer, target);

        assert_eq!(flow.attribution_confidence, 0);
        assert_eq!(
            flow.process.identity.runtime_hint.as_deref(),
            Some("l7_mitm_proxy")
        );
    }

    #[test]
    fn outbound_flow_uses_configured_attributor_context() {
        let peer = "127.0.0.1:40000".parse().expect("peer");
        let target = "127.0.0.1:50000".parse().expect("target");
        let process = current_process_context();
        let factory = FlowFactory::with_attributor(
            Direction::Outbound,
            FixedAttributor::hit(SocketProcessContext {
                process: process.clone(),
                confidence: 77,
                socket_inode: 42,
            }),
        );

        let flow = factory.flow(peer, target);

        assert_eq!(flow.process, process);
        assert_eq!(flow.attribution_confidence, 77);
        assert_eq!(flow.local, address_port(peer));
        assert_eq!(flow.remote, address_port(target));
    }

    #[test]
    fn outbound_flow_falls_back_when_attributor_misses() {
        let peer = "127.0.0.1:40000".parse().expect("peer");
        let target = "127.0.0.1:50000".parse().expect("target");
        let factory = FlowFactory::with_attributor(Direction::Outbound, FixedAttributor::miss());

        let flow = factory.flow(peer, target);

        assert_eq!(flow.attribution_confidence, 0);
        assert_eq!(
            flow.process.identity.runtime_hint.as_deref(),
            Some("l7_mitm_proxy")
        );
    }

    #[test]
    fn outbound_flow_falls_back_when_attributor_errors() {
        let peer = "127.0.0.1:40000".parse().expect("peer");
        let target = "127.0.0.1:50000".parse().expect("target");
        let factory = FlowFactory::with_attributor(Direction::Outbound, FixedAttributor::error());

        let flow = factory.flow(peer, target);

        assert_eq!(flow.attribution_confidence, 0);
        assert_eq!(
            flow.process.identity.runtime_hint.as_deref(),
            Some("l7_mitm_proxy")
        );
    }

    struct FixedAttributor {
        result: Result<Option<SocketProcessContext>, AttributionError>,
    }

    impl FixedAttributor {
        fn hit(context: SocketProcessContext) -> Self {
            Self {
                result: Ok(Some(context)),
            }
        }

        fn miss() -> Self {
            Self { result: Ok(None) }
        }

        fn error() -> Self {
            Self {
                result: Err(AttributionError::IncompleteSocketOwnerScan {
                    reason: "fixed attribution error".to_string(),
                }),
            }
        }
    }

    impl FlowProcessAttributor for FixedAttributor {
        fn resolve(
            &mut self,
            _connection: TcpConnection,
        ) -> Result<Option<SocketProcessContext>, AttributionError> {
            self.result.clone()
        }
    }
}
