use std::{fmt, net::SocketAddr, sync::Arc};

use attribution::{
    AttributionError, ProcfsSocketResolver, SocketProcessContext, TcpListenerProcessLookup,
};
use interception::TransparentInterceptionFlowClassifierScope;
use probe_core::{
    AddressPort, CapabilityKind, CapabilityState, CompiledSelector, Direction, FlowContext,
    FlowIdentity, Selector, TcpConnection, TcpEndpoint, TransportProtocol,
};

use crate::transparent_interception::TransparentInterceptionError;

#[derive(Clone)]
pub(crate) struct TransparentInterceptionFlowClassifier {
    selector: Arc<CompiledSelector>,
    resolver_factory: Arc<dyn FlowOwnerResolverFactory>,
}

impl fmt::Debug for TransparentInterceptionFlowClassifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransparentInterceptionFlowClassifier")
            .finish_non_exhaustive()
    }
}

impl TransparentInterceptionFlowClassifier {
    pub(crate) fn from_scope(
        scope: TransparentInterceptionFlowClassifierScope,
    ) -> Result<Self, TransparentInterceptionError> {
        Self::new(scope.into_selector(), ProcfsFlowOwnerResolverFactory)
    }

    pub(crate) fn classify_proxy_flow(
        &self,
        peer: SocketAddr,
        target: SocketAddr,
        direction: Direction,
    ) -> Result<(), String> {
        let connection = proxy_tcp_connection(peer, target, direction);
        match direction {
            Direction::Inbound => self.classify_inbound_listener(target, connection),
            Direction::Outbound => self.classify_connection_owner(connection, direction),
        }
    }

    fn classify_connection_owner(
        &self,
        connection: TcpConnection,
        direction: Direction,
    ) -> Result<(), String> {
        let mut resolver = self.resolver_factory.create();
        let owner = resolver
            .resolve_tcp_connection(connection)
            .map_err(|error| format!("procfs owner lookup failed: {error}"))?
            .ok_or_else(|| {
                format!(
                    "procfs owner lookup found no live owner for {} -> {}",
                    format_tcp_endpoint(connection.local),
                    format_tcp_endpoint(connection.remote)
                )
            })?;

        let flow = flow_context(owner.process, owner.confidence, connection);
        if self.selector.matches_flow(&flow, direction) {
            Ok(())
        } else {
            Err(format!(
                "resolved process pid={} name={} did not match selector",
                flow.process.identity.pid, flow.process.name
            ))
        }
    }

    fn classify_inbound_listener(
        &self,
        target: SocketAddr,
        connection: TcpConnection,
    ) -> Result<(), String> {
        let mut resolver = self.resolver_factory.create();
        let target_endpoint = TcpEndpoint::new(target.ip(), target.port());
        let lookup = resolver
            .resolve_tcp_listeners_by_local_endpoint(target_endpoint)
            .map_err(|error| format!("procfs listener owner lookup failed: {error}"))?;
        if !lookup.unattributed_listeners.is_empty() {
            return Err(format!(
                "procfs listener owner lookup found unattributed listeners for target {target}: {:?}",
                lookup.unattributed_listeners
            ));
        }

        if lookup.listeners.is_empty() {
            return Err(format!(
                "procfs listener owner lookup found no attributed listener for target {target}"
            ));
        }

        for listener in lookup.listeners {
            let flow = flow_context(
                listener.observed.process,
                listener.observed.confidence,
                connection,
            );
            if !self.selector.matches_flow(&flow, Direction::Inbound) {
                return Err(format!(
                    "resolved listener process pid={} name={} did not match selector",
                    flow.process.identity.pid, flow.process.name
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn capability_from_resolver(resolver: &ProcfsSocketResolver) -> CapabilityState {
        match resolver.probe_tcp_listener_process_attribution() {
            Ok(()) => CapabilityState::degraded(
                CapabilityKind::TransparentFlowClassifier,
                "proxy-side transparent flow classification can fail closed after host-rule boundary interception by resolving the current TCP owner through procfs and applying the compiled selector before relay; procfs races, namespaces, PID reuse, and missing socket lifetime evidence remain possible, and no-host-boundary wildcard interception is still rejected",
            ),
            Err(error) => CapabilityState::unavailable(
                CapabilityKind::TransparentFlowClassifier,
                format!(
                    "proxy-side transparent flow classification requires complete procfs TCP table and fd owner attribution: {error}"
                ),
            ),
        }
    }

    fn new(
        selector: Selector,
        resolver_factory: impl FlowOwnerResolverFactory + 'static,
    ) -> Result<Self, TransparentInterceptionError> {
        Ok(Self {
            selector: Arc::new(selector.compile().map_err(|error| {
                TransparentInterceptionError::Setup(format!(
                    "transparent flow classifier selector is invalid: {error}"
                ))
            })?),
            resolver_factory: Arc::new(resolver_factory),
        })
    }
}

trait FlowOwnerResolverFactory: Send + Sync {
    fn create(&self) -> Box<dyn FlowOwnerResolver>;
}

trait FlowOwnerResolver: Send {
    fn resolve_tcp_connection(
        &mut self,
        connection: TcpConnection,
    ) -> Result<Option<SocketProcessContext>, AttributionError>;

    fn resolve_tcp_listeners_by_local_endpoint(
        &mut self,
        local_endpoint: TcpEndpoint,
    ) -> Result<TcpListenerProcessLookup, AttributionError>;
}

struct ProcfsFlowOwnerResolverFactory;

impl FlowOwnerResolverFactory for ProcfsFlowOwnerResolverFactory {
    fn create(&self) -> Box<dyn FlowOwnerResolver> {
        Box::<ProcfsFlowOwnerResolver>::default()
    }
}

#[derive(Default)]
struct ProcfsFlowOwnerResolver {
    resolver: ProcfsSocketResolver,
}

impl FlowOwnerResolver for ProcfsFlowOwnerResolver {
    fn resolve_tcp_connection(
        &mut self,
        connection: TcpConnection,
    ) -> Result<Option<SocketProcessContext>, AttributionError> {
        self.resolver.resolve_tcp_connection(connection)
    }

    fn resolve_tcp_listeners_by_local_endpoint(
        &mut self,
        local_endpoint: TcpEndpoint,
    ) -> Result<TcpListenerProcessLookup, AttributionError> {
        self.resolver
            .resolve_tcp_listeners_by_local_endpoint(local_endpoint)
    }
}

fn proxy_tcp_connection(
    peer: SocketAddr,
    target: SocketAddr,
    direction: Direction,
) -> TcpConnection {
    match direction {
        Direction::Inbound => TcpConnection::new(
            TcpEndpoint::new(target.ip(), target.port()),
            TcpEndpoint::new(peer.ip(), peer.port()),
        ),
        Direction::Outbound => TcpConnection::new(
            TcpEndpoint::new(peer.ip(), peer.port()),
            TcpEndpoint::new(target.ip(), target.port()),
        ),
    }
}

fn flow_context(
    process: probe_core::ProcessContext,
    attribution_confidence: u8,
    connection: TcpConnection,
) -> FlowContext {
    let local = AddressPort::from(connection.local);
    let remote = AddressPort::from(connection.remote);
    FlowContext {
        id: FlowIdentity::stable(
            &process.identity,
            &local,
            &remote,
            TransportProtocol::Tcp,
            0,
            None,
        ),
        process,
        local,
        remote,
        protocol: TransportProtocol::Tcp,
        start_monotonic_ns: 0,
        socket_cookie: None,
        attribution_confidence,
    }
}

fn format_tcp_endpoint(endpoint: TcpEndpoint) -> String {
    format!("{}:{}", endpoint.address, endpoint.port)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        io,
        net::{IpAddr, Ipv4Addr},
        sync::Mutex,
    };

    use attribution::{
        TcpListenerObservedSocket, TcpListenerOwnerContext, TcpListenerOwnerSource,
        TcpListenerProcessContext,
    };
    use probe_core::{ProcessContext, ProcessIdentity, ProcessSelector, TrafficSelector};

    use super::*;

    #[test]
    fn flow_classifier_allows_matching_outbound_flow() {
        let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 41000));
        let target = SocketAddr::from(([203, 0, 113, 10], 443));
        let connection = proxy_tcp_connection(peer, target, Direction::Outbound);
        let resolver = FakeFlowOwnerResolver::with_results([Ok(Some(socket_owner(
            process_context(42, "curl"),
        )))]);
        let classifier = classifier(
            ProcessSelector {
                names: vec!["curl".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector {
                remote_ports: vec![443],
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
            resolver.clone(),
        );

        classifier
            .classify_proxy_flow(peer, target, Direction::Outbound)
            .expect("matching flow should be allowed");

        assert_eq!(resolver.requests(), vec![connection]);
    }

    #[test]
    fn flow_classifier_rejects_non_matching_owner() {
        let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 41000));
        let target = SocketAddr::from(([203, 0, 113, 10], 443));
        let resolver = FakeFlowOwnerResolver::with_results([Ok(Some(socket_owner(
            process_context(42, "wget"),
        )))]);
        let classifier = classifier(
            ProcessSelector {
                names: vec!["curl".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector {
                remote_ports: vec![443],
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
            resolver,
        );

        let error = classifier
            .classify_proxy_flow(peer, target, Direction::Outbound)
            .expect_err("non-matching process should be rejected");

        assert!(error.contains("did not match selector"));
    }

    #[test]
    fn flow_classifier_rejects_unattributed_flow() {
        let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 41000));
        let target = SocketAddr::from(([203, 0, 113, 10], 443));
        let resolver = FakeFlowOwnerResolver::with_results([Ok(None)]);
        let classifier = classifier(
            ProcessSelector::default(),
            TrafficSelector {
                remote_ports: vec![443],
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
            resolver,
        );

        let error = classifier
            .classify_proxy_flow(peer, target, Direction::Outbound)
            .expect_err("unattributed flow should fail closed");

        assert!(error.contains("found no live owner"));
    }

    #[test]
    fn inbound_flow_classifier_allows_matching_listener_owner() {
        let peer = SocketAddr::from(([203, 0, 113, 10], 51000));
        let target = SocketAddr::from((Ipv4Addr::LOCALHOST, 8443));
        let resolver =
            FakeFlowOwnerResolver::with_listener_results([Ok(listener_lookup([listener_owner(
                process_context(42, "xtask"),
                Ipv4Addr::UNSPECIFIED,
                8443,
            )]))]);
        let classifier = classifier(
            ProcessSelector {
                names: vec!["xtask".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector {
                local_ports: vec![8443],
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
            resolver.clone(),
        );

        classifier
            .classify_proxy_flow(peer, target, Direction::Inbound)
            .expect("matching listener should be allowed");

        assert_eq!(
            resolver.listener_requests(),
            vec![TcpEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8443)]
        );
    }

    #[test]
    fn inbound_flow_classifier_rejects_non_matching_listener_owner() {
        let peer = SocketAddr::from(([203, 0, 113, 10], 51000));
        let target = SocketAddr::from((Ipv4Addr::LOCALHOST, 9443));
        let resolver =
            FakeFlowOwnerResolver::with_listener_results([Ok(listener_lookup([listener_owner(
                process_context(42, "xtask"),
                Ipv4Addr::UNSPECIFIED,
                9443,
            )]))]);
        let classifier = classifier(
            ProcessSelector {
                names: vec!["not-xtask".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector {
                local_ports: vec![9443],
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
            resolver,
        );

        let error = classifier
            .classify_proxy_flow(peer, target, Direction::Inbound)
            .expect_err("non-matching listener should be rejected");

        assert!(error.contains("listener process"));
        assert!(error.contains("did not match selector"));
    }

    #[test]
    fn inbound_flow_classifier_uses_observed_holder_not_logical_owner() {
        let peer = SocketAddr::from(([203, 0, 113, 10], 51000));
        let target = SocketAddr::from((Ipv4Addr::LOCALHOST, 8081));
        let resolver =
            FakeFlowOwnerResolver::with_listener_results([Ok(listener_lookup([listener_alias(
                process_context(7, "docker-proxy"),
                process_context(42, "sssa-backend"),
                Ipv4Addr::UNSPECIFIED,
                8081,
            )]))]);
        let classifier = classifier(
            ProcessSelector {
                names: vec!["sssa-backend".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector {
                local_ports: vec![8081],
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
            resolver,
        );

        let error = classifier
            .classify_proxy_flow(peer, target, Direction::Inbound)
            .expect_err("logical owner must not authorize transparent interception");

        assert!(error.contains("listener process"));
        assert!(error.contains("did not match selector"));
        assert!(error.contains("docker-proxy"));
    }

    #[test]
    fn inbound_proxy_connection_uses_target_as_local_endpoint() {
        let peer = SocketAddr::from(([203, 0, 113, 10], 51000));
        let target = SocketAddr::from((Ipv4Addr::LOCALHOST, 8443));

        let connection = proxy_tcp_connection(peer, target, Direction::Inbound);

        assert_eq!(
            connection,
            TcpConnection::new(
                TcpEndpoint::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8443),
                TcpEndpoint::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 51000),
            )
        );
    }

    #[derive(Clone)]
    struct FakeFlowOwnerResolver {
        state: Arc<Mutex<FakeFlowOwnerResolverState>>,
    }

    struct FakeFlowOwnerResolverState {
        requests: Vec<TcpConnection>,
        listener_requests: Vec<TcpEndpoint>,
        results: VecDeque<Result<Option<SocketProcessContext>, AttributionError>>,
        listener_results: VecDeque<Result<TcpListenerProcessLookup, AttributionError>>,
    }

    impl FakeFlowOwnerResolver {
        fn with_results(
            results: impl IntoIterator<Item = Result<Option<SocketProcessContext>, AttributionError>>,
        ) -> Self {
            Self {
                state: Arc::new(Mutex::new(FakeFlowOwnerResolverState {
                    requests: Vec::new(),
                    listener_requests: Vec::new(),
                    results: results.into_iter().collect(),
                    listener_results: VecDeque::new(),
                })),
            }
        }

        fn with_listener_results(
            results: impl IntoIterator<Item = Result<TcpListenerProcessLookup, AttributionError>>,
        ) -> Self {
            Self {
                state: Arc::new(Mutex::new(FakeFlowOwnerResolverState {
                    requests: Vec::new(),
                    listener_requests: Vec::new(),
                    results: VecDeque::new(),
                    listener_results: results.into_iter().collect(),
                })),
            }
        }

        fn requests(&self) -> Vec<TcpConnection> {
            self.state
                .lock()
                .expect("fake resolver state poisoned")
                .requests
                .clone()
        }

        fn listener_requests(&self) -> Vec<TcpEndpoint> {
            self.state
                .lock()
                .expect("fake resolver state poisoned")
                .listener_requests
                .clone()
        }
    }

    impl FlowOwnerResolverFactory for FakeFlowOwnerResolver {
        fn create(&self) -> Box<dyn FlowOwnerResolver> {
            Box::new(self.clone())
        }
    }

    impl FlowOwnerResolver for FakeFlowOwnerResolver {
        fn resolve_tcp_connection(
            &mut self,
            connection: TcpConnection,
        ) -> Result<Option<SocketProcessContext>, AttributionError> {
            let mut state = self.state.lock().expect("fake resolver state poisoned");
            state.requests.push(connection);
            state
                .results
                .pop_front()
                .unwrap_or_else(|| panic!("missing fake resolver result"))
        }

        fn resolve_tcp_listeners_by_local_endpoint(
            &mut self,
            local_endpoint: TcpEndpoint,
        ) -> Result<TcpListenerProcessLookup, AttributionError> {
            let mut state = self.state.lock().expect("fake resolver state poisoned");
            state.listener_requests.push(local_endpoint);
            state
                .listener_results
                .pop_front()
                .unwrap_or_else(|| panic!("missing fake listener resolver result"))
        }
    }

    fn classifier(
        process: ProcessSelector,
        traffic: TrafficSelector,
        resolver: FakeFlowOwnerResolver,
    ) -> TransparentInterceptionFlowClassifier {
        TransparentInterceptionFlowClassifier::new(Selector::term(process, traffic), resolver)
            .expect("test selector should compile")
    }

    fn socket_owner(process: ProcessContext) -> SocketProcessContext {
        SocketProcessContext {
            process,
            confidence: 60,
            socket_inode: 123,
        }
    }

    fn listener_lookup(
        listeners: impl IntoIterator<Item = TcpListenerProcessContext>,
    ) -> TcpListenerProcessLookup {
        TcpListenerProcessLookup {
            listeners: listeners.into_iter().collect(),
            unattributed_listeners: Vec::new(),
        }
    }

    fn listener_owner(
        process: ProcessContext,
        address: Ipv4Addr,
        port: u16,
    ) -> TcpListenerProcessContext {
        TcpListenerProcessContext::from_observed_socket(TcpListenerObservedSocket {
            process,
            confidence: 60,
            socket_inode: 123,
            local: TcpEndpoint::new(IpAddr::V4(address), port),
        })
    }

    fn listener_alias(
        observed_process: ProcessContext,
        logical_owner_process: ProcessContext,
        address: Ipv4Addr,
        port: u16,
    ) -> TcpListenerProcessContext {
        listener_owner(observed_process, address, port).with_owner(TcpListenerOwnerContext {
            process: logical_owner_process,
            confidence: 55,
            source: TcpListenerOwnerSource::DockerProxyTarget {
                target_local: TcpEndpoint::new(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 3)), 8080),
                target_socket_inode: 424_242,
            },
        })
    }

    fn process_context(pid: u32, name: &str) -> ProcessContext {
        ProcessContext {
            identity: ProcessIdentity {
                pid,
                tgid: pid,
                start_time_ticks: 7,
                boot_id: "boot".to_string(),
                exe_path: format!("/usr/bin/{name}"),
                cmdline_hash: "hash".to_string(),
                uid: 1000,
                gid: 1000,
                cgroup: None,
                systemd_service: None,
                container_id: None,
                runtime_hint: None,
            },
            name: name.to_string(),
            cmdline: vec![name.to_string()],
        }
    }

    #[test]
    fn resolver_error_is_reported() {
        let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 41000));
        let target = SocketAddr::from(([203, 0, 113, 10], 443));
        let resolver = FakeFlowOwnerResolver::with_results([Err(AttributionError::Read {
            path: "/proc/net/tcp".to_string(),
            source: io::Error::other("boom"),
        })]);
        let classifier = classifier(
            ProcessSelector::default(),
            TrafficSelector::default(),
            resolver,
        );

        let error = classifier
            .classify_proxy_flow(peer, target, Direction::Outbound)
            .expect_err("resolver error should reject the flow");

        assert!(error.contains("procfs owner lookup failed"));
        assert!(error.contains("/proc/net/tcp"));
    }
}
