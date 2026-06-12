use std::collections::{HashMap, VecDeque};

use probe_core::{
    AddressPort, Direction, FlowContext, FlowIdentity, ProcessContext, ProcessIdentity,
    TcpConnection, TcpEndpoint, Timestamp, TransportProtocol,
};

use crate::{CaptureError, ProcessResolver, ResolvedProcess};

use super::decoder::DecodedTcpSegment;

const MAX_FLOW_TRACKER_CONNECTIONS: usize = 16_384;
const FLOW_IDLE_TIMEOUT_UNIX_NS: i64 = 120_000_000_000;

#[derive(Debug, Default)]
pub(super) struct FlowTracker {
    flows: HashMap<ConnectionKey, FlowRecord>,
    order: VecDeque<ConnectionKey>,
}

impl FlowTracker {
    pub(super) fn observe(
        &mut self,
        decoded: &DecodedTcpSegment<'_>,
        timestamp: Timestamp,
        process_resolver: &mut Option<Box<dyn ProcessResolver>>,
    ) -> FlowObservation {
        let mut closed_before = self.evict_idle(timestamp.wall_time_unix_ns);
        let key = ConnectionKey::from_decoded(decoded);
        if decoded.has_syn()
            && let Some(flow) = self.remove_flow(&key)
        {
            closed_before.push(flow);
        }
        if !closed_before.is_empty() {
            invalidate_process_resolution(process_resolver);
        }
        if let Some(record) = self.flows.get_mut(&key) {
            let direction = if decoded.source_endpoint() == record.local_endpoint {
                Direction::Outbound
            } else {
                Direction::Inbound
            };
            record.last_seen_wall_time_unix_ns = timestamp.wall_time_unix_ns;
            let mut observation = FlowObservation::new(
                decoded,
                direction,
                record.process.clone(),
                record.confidence,
                record.flow.start_monotonic_ns,
                None,
            );
            record.observe_lifecycle(decoded);
            if record.closed() {
                observation.closed_after = self.remove_flow(&key);
            }
            observation.closed_before = closed_before;
            return observation;
        }

        let capacity_closed = self.evict_oldest_if_full();
        if !capacity_closed.is_empty() {
            invalidate_process_resolution(process_resolver);
        }
        closed_before.extend(capacity_closed);
        let primary = FlowCandidate::from_decoded(decoded, infer_initial_direction(decoded));
        let secondary = FlowCandidate::from_decoded(decoded, opposite_direction(primary.direction));
        let selected = select_flow_candidate(primary, secondary, process_resolver);
        self.order.push_back(key);
        let flow = flow_from_decoded(
            decoded,
            selected.direction,
            selected.process.clone(),
            selected.confidence,
            timestamp.monotonic_ns,
        );
        self.flows.insert(
            key,
            FlowRecord {
                local_endpoint: selected.local_endpoint,
                process: selected.process,
                confidence: selected.confidence,
                flow: flow.clone(),
                last_seen_wall_time_unix_ns: timestamp.wall_time_unix_ns,
                local_fin: false,
                remote_fin: false,
                reset: false,
            },
        );
        let mut observation = FlowObservation {
            direction: selected.direction,
            flow,
            attribution_confidence: selected.confidence,
            attribution_failure: selected.attribution_failure,
            closed_before,
            closed_after: None,
        };
        if let Some(record) = self.flows.get_mut(&key) {
            record.observe_lifecycle(decoded);
            if record.closed() {
                observation.closed_after = self.remove_flow(&key);
            }
        }
        if decoded.has_rst() {
            observation.closed_after = observation.closed_after.or_else(|| self.remove_flow(&key));
        }
        observation
    }

    pub(super) fn observe_lifecycle(
        &mut self,
        decoded: &DecodedTcpSegment<'_>,
        timestamp: Timestamp,
    ) -> Vec<FlowContext> {
        let mut closed = self.evict_idle(timestamp.wall_time_unix_ns);
        let key = ConnectionKey::from_decoded(decoded);
        if decoded.has_syn() {
            if let Some(flow) = self.remove_flow(&key) {
                closed.push(flow);
            }
            return closed;
        }
        if let Some(record) = self.flows.get_mut(&key) {
            record.last_seen_wall_time_unix_ns = timestamp.wall_time_unix_ns;
            record.observe_lifecycle(decoded);
            if record.closed()
                && let Some(flow) = self.remove_flow(&key)
            {
                closed.push(flow);
            }
        }
        closed
    }

    fn evict_oldest_if_full(&mut self) -> Vec<FlowContext> {
        let mut closed = Vec::new();
        while self.flows.len() >= MAX_FLOW_TRACKER_CONNECTIONS {
            let Some(oldest) = self.order.pop_front() else {
                return closed;
            };
            if let Some(flow) = self.remove_flow(&oldest) {
                closed.push(flow);
            }
        }
        closed
    }

    fn evict_idle(&mut self, wall_time_unix_ns: i64) -> Vec<FlowContext> {
        let idle_keys = self
            .flows
            .iter()
            .filter_map(|(key, record)| {
                (wall_time_unix_ns.saturating_sub(record.last_seen_wall_time_unix_ns)
                    > FLOW_IDLE_TIMEOUT_UNIX_NS)
                    .then_some(*key)
            })
            .collect::<Vec<_>>();
        idle_keys
            .iter()
            .filter_map(|key| self.remove_flow(key))
            .collect()
    }

    fn remove_flow(&mut self, key: &ConnectionKey) -> Option<FlowContext> {
        let removed = self.flows.remove(key);
        self.order.retain(|existing| existing != key);
        removed.map(|record| record.flow)
    }
}

fn invalidate_process_resolution(process_resolver: &mut Option<Box<dyn ProcessResolver>>) {
    if let Some(process_resolver) = process_resolver.as_deref_mut() {
        process_resolver.invalidate_cached_resolution();
    }
}

#[derive(Debug, Clone)]
struct FlowRecord {
    local_endpoint: TcpEndpoint,
    process: ProcessContext,
    confidence: u8,
    flow: FlowContext,
    last_seen_wall_time_unix_ns: i64,
    local_fin: bool,
    remote_fin: bool,
    reset: bool,
}

impl FlowRecord {
    fn observe_lifecycle(&mut self, decoded: &DecodedTcpSegment<'_>) {
        if decoded.has_rst() {
            self.reset = true;
            return;
        }
        if !decoded.has_fin() {
            return;
        }
        if decoded.source_endpoint() == self.local_endpoint {
            self.local_fin = true;
        } else {
            self.remote_fin = true;
        }
    }

    fn closed(&self) -> bool {
        self.reset || (self.local_fin && self.remote_fin)
    }
}

#[derive(Debug, Clone)]
struct SelectedFlowCandidate {
    direction: Direction,
    local_endpoint: TcpEndpoint,
    process: ProcessContext,
    confidence: u8,
    attribution_failure: Option<String>,
}

#[derive(Debug, Clone)]
pub(super) struct FlowObservation {
    pub(super) direction: Direction,
    pub(super) flow: FlowContext,
    pub(super) attribution_confidence: u8,
    pub(super) attribution_failure: Option<String>,
    pub(super) closed_before: Vec<FlowContext>,
    pub(super) closed_after: Option<FlowContext>,
}

impl FlowObservation {
    fn new(
        decoded: &DecodedTcpSegment<'_>,
        direction: Direction,
        process: ProcessContext,
        attribution_confidence: u8,
        start_monotonic_ns: u64,
        attribution_failure: Option<String>,
    ) -> Self {
        Self {
            direction,
            flow: flow_from_decoded(
                decoded,
                direction,
                process,
                attribution_confidence,
                start_monotonic_ns,
            ),
            attribution_confidence,
            attribution_failure,
            closed_before: Vec::new(),
            closed_after: None,
        }
    }
}

#[derive(Debug, Clone)]
struct FlowCandidate {
    direction: Direction,
    local_endpoint: TcpEndpoint,
    remote_endpoint: TcpEndpoint,
    local: AddressPort,
    remote: AddressPort,
}

impl FlowCandidate {
    fn from_decoded(decoded: &DecodedTcpSegment<'_>, direction: Direction) -> Self {
        let source = decoded.source_endpoint();
        let destination = decoded.destination_endpoint();
        match direction {
            Direction::Outbound => Self {
                direction,
                local_endpoint: source,
                remote_endpoint: destination,
                local: source.into(),
                remote: destination.into(),
            },
            Direction::Inbound => Self {
                direction,
                local_endpoint: destination,
                remote_endpoint: source,
                local: destination.into(),
                remote: source.into(),
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ConnectionKey {
    lower: TcpEndpoint,
    higher: TcpEndpoint,
}

impl ConnectionKey {
    fn from_decoded(decoded: &DecodedTcpSegment<'_>) -> Self {
        let source = decoded.source_endpoint();
        let destination = decoded.destination_endpoint();
        if source <= destination {
            Self {
                lower: source,
                higher: destination,
            }
        } else {
            Self {
                lower: destination,
                higher: source,
            }
        }
    }
}

fn infer_initial_direction(decoded: &DecodedTcpSegment<'_>) -> Direction {
    if decoded.payload.starts_with(b"HTTP/") {
        return Direction::Inbound;
    }
    if looks_like_http_request(decoded.payload) {
        return Direction::Outbound;
    }
    if looks_like_server_port(decoded.source_port)
        && !looks_like_server_port(decoded.destination_port)
    {
        return Direction::Inbound;
    }
    Direction::Outbound
}

fn opposite_direction(direction: Direction) -> Direction {
    match direction {
        Direction::Inbound => Direction::Outbound,
        Direction::Outbound => Direction::Inbound,
    }
}

fn select_flow_candidate(
    primary: FlowCandidate,
    secondary: FlowCandidate,
    process_resolver: &mut Option<Box<dyn ProcessResolver>>,
) -> SelectedFlowCandidate {
    let mut attribution_failure = None;
    match resolve_candidate_process(&primary, process_resolver) {
        Ok(Some(process)) => {
            return SelectedFlowCandidate {
                direction: primary.direction,
                local_endpoint: primary.local_endpoint,
                process: process.process,
                confidence: process.confidence,
                attribution_failure: None,
            };
        }
        Ok(None) => {}
        Err(error) => attribution_failure = Some(error.to_string()),
    }
    match resolve_candidate_process(&secondary, process_resolver) {
        Ok(Some(process)) => {
            return SelectedFlowCandidate {
                direction: secondary.direction,
                local_endpoint: secondary.local_endpoint,
                process: process.process,
                confidence: process.confidence,
                attribution_failure: None,
            };
        }
        Ok(None) => {}
        Err(error) => {
            if attribution_failure.is_none() {
                attribution_failure = Some(error.to_string());
            }
        }
    }
    SelectedFlowCandidate {
        direction: primary.direction,
        local_endpoint: primary.local_endpoint,
        process: synthetic_libpcap_process(),
        confidence: 0,
        attribution_failure,
    }
}

fn resolve_candidate_process(
    candidate: &FlowCandidate,
    process_resolver: &mut Option<Box<dyn ProcessResolver>>,
) -> Result<Option<ResolvedProcess>, CaptureError> {
    let Some(resolver) = process_resolver.as_deref_mut() else {
        return Ok(None);
    };
    resolver.resolve_tcp_process(TcpConnection::new(
        candidate.local_endpoint,
        candidate.remote_endpoint,
    ))
}

fn looks_like_http_request(payload: &[u8]) -> bool {
    const METHODS: [&[u8]; 9] = [
        b"GET ",
        b"POST ",
        b"PUT ",
        b"PATCH ",
        b"DELETE ",
        b"HEAD ",
        b"OPTIONS ",
        b"CONNECT ",
        b"TRACE ",
    ];
    METHODS.iter().any(|method| payload.starts_with(method))
}

fn looks_like_server_port(port: u16) -> bool {
    matches!(port, 80 | 443 | 8000 | 8080 | 8443)
}

fn flow_from_decoded(
    decoded: &DecodedTcpSegment<'_>,
    direction: Direction,
    process: ProcessContext,
    attribution_confidence: u8,
    start_monotonic_ns: u64,
) -> FlowContext {
    let candidate = FlowCandidate::from_decoded(decoded, direction);
    FlowContext {
        id: FlowIdentity::stable(
            &process.identity,
            &candidate.local,
            &candidate.remote,
            TransportProtocol::Tcp,
            start_monotonic_ns,
            None,
        ),
        process,
        local: candidate.local,
        remote: candidate.remote,
        protocol: TransportProtocol::Tcp,
        start_monotonic_ns,
        socket_cookie: None,
        attribution_confidence,
    }
}

fn synthetic_libpcap_process() -> ProcessContext {
    let identity = ProcessIdentity {
        pid: 0,
        tgid: 0,
        start_time_ticks: 0,
        boot_id: "libpcap".to_string(),
        exe_path: "unknown".to_string(),
        cmdline_hash: "unknown".to_string(),
        uid: 0,
        gid: 0,
        cgroup: None,
        systemd_service: None,
        container_id: None,
        runtime_hint: Some("libpcap_fallback".to_string()),
    };
    ProcessContext {
        identity,
        name: "unknown".to_string(),
        cmdline: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::RefCell,
        net::{IpAddr, Ipv4Addr},
        rc::Rc,
    };

    use super::*;

    #[test]
    fn builds_stable_flow_for_opposite_http_directions() {
        let request = DecodedTcpSegment {
            source: ipv4(10, 0, 0, 1),
            destination: ipv4(10, 0, 0, 2),
            source_port: 50_000,
            destination_port: 80,
            sequence: 100,
            flags: default_flags(),
            payload: b"GET / HTTP/1.1\r\n\r\n",
        };
        let response = DecodedTcpSegment {
            source: ipv4(10, 0, 0, 2),
            destination: ipv4(10, 0, 0, 1),
            source_port: 80,
            destination_port: 50_000,
            sequence: 200,
            flags: default_flags(),
            payload: b"HTTP/1.1 200 OK\r\n\r\n",
        };

        let process = synthetic_libpcap_process();
        let request_flow = flow_from_decoded(&request, Direction::Outbound, process.clone(), 0, 7);
        let response_flow = flow_from_decoded(&response, Direction::Inbound, process, 0, 7);

        assert_eq!(request_flow.id, response_flow.id);
        assert_eq!(request_flow.local.address, "10.0.0.1");
        assert_eq!(request_flow.remote.address, "10.0.0.2");
        assert_eq!(request_flow.attribution_confidence, 0);
        assert_eq!(request_flow.start_monotonic_ns, 7);
    }

    #[test]
    fn direction_tracker_keeps_response_body_inbound_after_response_headers() {
        let response_headers = DecodedTcpSegment {
            source: ipv4(10, 0, 0, 2),
            destination: ipv4(10, 0, 0, 1),
            source_port: 80,
            destination_port: 50_000,
            sequence: 200,
            flags: default_flags(),
            payload: b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n",
        };
        let response_body = DecodedTcpSegment {
            source: ipv4(10, 0, 0, 2),
            destination: ipv4(10, 0, 0, 1),
            source_port: 80,
            destination_port: 50_000,
            sequence: 240,
            flags: default_flags(),
            payload: b"hello",
        };
        let mut tracker = FlowTracker::default();
        let mut resolver = None;

        assert_eq!(
            tracker
                .observe(&response_headers, timestamp(1, 1), &mut resolver)
                .direction,
            Direction::Inbound
        );
        assert_eq!(
            tracker
                .observe(&response_body, timestamp(2, 2), &mut resolver)
                .direction,
            Direction::Inbound
        );
    }

    #[test]
    fn procfs_resolution_can_select_local_server_for_http_request() {
        let request = DecodedTcpSegment {
            source: ipv4(10, 0, 0, 1),
            destination: ipv4(10, 0, 0, 2),
            source_port: 50_000,
            destination_port: 80,
            sequence: 100,
            flags: default_flags(),
            payload: b"GET / HTTP/1.1\r\n\r\n",
        };
        let resolver = StaticProcessResolver {
            connection: TcpConnection::new(
                TcpEndpoint::new(Ipv4Addr::new(10, 0, 0, 2).into(), 80),
                TcpEndpoint::new(Ipv4Addr::new(10, 0, 0, 1).into(), 50_000),
            ),
            process: demo_process(42, "server"),
            confidence: 60,
        };
        let mut resolver: Option<Box<dyn ProcessResolver>> = Some(Box::new(resolver));
        let mut tracker = FlowTracker::default();

        let observed = tracker.observe(&request, timestamp(1, 1), &mut resolver);

        assert_eq!(observed.direction, Direction::Inbound);
        assert_eq!(observed.flow.local.address, "10.0.0.2");
        assert_eq!(observed.flow.remote.address, "10.0.0.1");
        assert_eq!(observed.flow.process.identity.pid, 42);
        assert_eq!(observed.flow.process.name, "server");
        assert_eq!(observed.attribution_confidence, 60);
    }

    #[test]
    fn closed_flow_re_resolves_reused_four_tuple() {
        let first = DecodedTcpSegment {
            source: ipv4(10, 0, 0, 1),
            destination: ipv4(10, 0, 0, 2),
            source_port: 50_000,
            destination_port: 80,
            sequence: 100,
            flags: default_flags(),
            payload: b"GET /first HTTP/1.1\r\n\r\n",
        };
        let close = DecodedTcpSegment {
            flags: closing_flags(),
            payload: b"",
            ..first
        };
        let peer_close = DecodedTcpSegment {
            source: first.destination,
            destination: first.source,
            source_port: first.destination_port,
            destination_port: first.source_port,
            sequence: 200,
            flags: closing_flags(),
            payload: b"",
        };
        let second = DecodedTcpSegment {
            sequence: 300,
            payload: b"GET /second HTTP/1.1\r\n\r\n",
            ..first
        };
        let mut resolver: Option<Box<dyn ProcessResolver>> = Some(Box::new(SequenceResolver {
            connection: TcpConnection::new(
                TcpEndpoint::new(Ipv4Addr::new(10, 0, 0, 1).into(), 50_000),
                TcpEndpoint::new(Ipv4Addr::new(10, 0, 0, 2).into(), 80),
            ),
            responses: VecDeque::from([
                ResolvedProcess {
                    process: demo_process(1, "first"),
                    confidence: 60,
                },
                ResolvedProcess {
                    process: demo_process(2, "second"),
                    confidence: 60,
                },
            ]),
        }));
        let mut tracker = FlowTracker::default();

        let first_observed = tracker.observe(&first, timestamp(10, 10), &mut resolver);
        tracker.observe_lifecycle(&close, timestamp(11, 11));
        tracker.observe_lifecycle(&peer_close, timestamp(12, 12));
        let second_observed = tracker.observe(&second, timestamp(12, 12), &mut resolver);

        assert_eq!(first_observed.flow.process.identity.pid, 1);
        assert_eq!(second_observed.flow.process.identity.pid, 2);
        assert_ne!(first_observed.flow.id, second_observed.flow.id);
    }

    #[test]
    fn half_closed_flow_keeps_peer_response_on_same_flow() {
        let request = DecodedTcpSegment {
            source: ipv4(10, 0, 0, 1),
            destination: ipv4(10, 0, 0, 2),
            source_port: 50_000,
            destination_port: 80,
            sequence: 100,
            flags: default_flags(),
            payload: b"GET / HTTP/1.1\r\n\r\n",
        };
        let client_fin = DecodedTcpSegment {
            flags: closing_flags(),
            payload: b"",
            ..request
        };
        let response = DecodedTcpSegment {
            source: ipv4(10, 0, 0, 2),
            destination: ipv4(10, 0, 0, 1),
            source_port: 80,
            destination_port: 50_000,
            sequence: 200,
            flags: default_flags(),
            payload: b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        };
        let mut resolver: Option<Box<dyn ProcessResolver>> = Some(Box::new(SequenceResolver {
            connection: TcpConnection::new(
                TcpEndpoint::new(Ipv4Addr::new(10, 0, 0, 1).into(), 50_000),
                TcpEndpoint::new(Ipv4Addr::new(10, 0, 0, 2).into(), 80),
            ),
            responses: VecDeque::from([ResolvedProcess {
                process: demo_process(1, "client"),
                confidence: 60,
            }]),
        }));
        let mut tracker = FlowTracker::default();

        let request_observed = tracker.observe(&request, timestamp(10, 10), &mut resolver);
        tracker.observe_lifecycle(&client_fin, timestamp(11, 11));
        let response_observed = tracker.observe(&response, timestamp(12, 12), &mut resolver);

        assert_eq!(request_observed.flow.id, response_observed.flow.id);
        assert_eq!(response_observed.flow.process.identity.pid, 1);
        assert_eq!(response_observed.direction, Direction::Inbound);
    }

    #[test]
    fn payload_fin_closes_current_flow_after_bytes() {
        let request = DecodedTcpSegment {
            source: ipv4(10, 0, 0, 1),
            destination: ipv4(10, 0, 0, 2),
            source_port: 50_000,
            destination_port: 80,
            sequence: 100,
            flags: default_flags(),
            payload: b"GET / HTTP/1.1\r\n\r\n",
        };
        let client_fin = DecodedTcpSegment {
            flags: closing_flags(),
            payload: b"",
            ..request
        };
        let response_fin = DecodedTcpSegment {
            source: ipv4(10, 0, 0, 2),
            destination: ipv4(10, 0, 0, 1),
            source_port: 80,
            destination_port: 50_000,
            sequence: 200,
            flags: closing_flags(),
            payload: b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        };
        let mut resolver: Option<Box<dyn ProcessResolver>> = Some(Box::new(SequenceResolver {
            connection: TcpConnection::new(
                TcpEndpoint::new(Ipv4Addr::new(10, 0, 0, 1).into(), 50_000),
                TcpEndpoint::new(Ipv4Addr::new(10, 0, 0, 2).into(), 80),
            ),
            responses: VecDeque::from([ResolvedProcess {
                process: demo_process(1, "client"),
                confidence: 60,
            }]),
        }));
        let mut tracker = FlowTracker::default();

        let request_observed = tracker.observe(&request, timestamp(10, 10), &mut resolver);
        assert!(
            tracker
                .observe_lifecycle(&client_fin, timestamp(11, 11))
                .is_empty()
        );
        let response_observed = tracker.observe(&response_fin, timestamp(12, 12), &mut resolver);

        assert_eq!(request_observed.flow.id, response_observed.flow.id);
        assert!(response_observed.closed_before.is_empty());
        assert_eq!(
            response_observed
                .closed_after
                .as_ref()
                .map(|flow| flow.id.clone()),
            Some(request_observed.flow.id)
        );
    }

    #[test]
    fn idle_flow_re_resolves_reused_four_tuple() {
        let first = DecodedTcpSegment {
            source: ipv4(10, 0, 0, 1),
            destination: ipv4(10, 0, 0, 2),
            source_port: 50_000,
            destination_port: 80,
            sequence: 100,
            flags: default_flags(),
            payload: b"GET /first HTTP/1.1\r\n\r\n",
        };
        let second = DecodedTcpSegment {
            sequence: 300,
            payload: b"GET /second HTTP/1.1\r\n\r\n",
            ..first
        };
        let mut resolver: Option<Box<dyn ProcessResolver>> = Some(Box::new(SequenceResolver {
            connection: TcpConnection::new(
                TcpEndpoint::new(Ipv4Addr::new(10, 0, 0, 1).into(), 50_000),
                TcpEndpoint::new(Ipv4Addr::new(10, 0, 0, 2).into(), 80),
            ),
            responses: VecDeque::from([
                ResolvedProcess {
                    process: demo_process(1, "first"),
                    confidence: 60,
                },
                ResolvedProcess {
                    process: demo_process(2, "second"),
                    confidence: 60,
                },
            ]),
        }));
        let mut tracker = FlowTracker::default();

        let first_observed = tracker.observe(&first, timestamp(10, 10), &mut resolver);
        let second_observed = tracker.observe(
            &second,
            timestamp(12, FLOW_IDLE_TIMEOUT_UNIX_NS + 11),
            &mut resolver,
        );

        assert_eq!(first_observed.flow.process.identity.pid, 1);
        assert_eq!(second_observed.closed_before.len(), 1);
        assert_eq!(second_observed.closed_before[0].id, first_observed.flow.id);
        assert_eq!(second_observed.flow.process.identity.pid, 2);
        assert_ne!(first_observed.flow.id, second_observed.flow.id);
    }

    #[test]
    fn idle_eviction_invalidates_resolver_snapshot_before_re_resolve() {
        let first = DecodedTcpSegment {
            source: ipv4(10, 0, 0, 1),
            destination: ipv4(10, 0, 0, 2),
            source_port: 50_000,
            destination_port: 80,
            sequence: 100,
            flags: default_flags(),
            payload: b"GET /first HTTP/1.1\r\n\r\n",
        };
        let second = DecodedTcpSegment {
            sequence: 300,
            payload: b"GET /second HTTP/1.1\r\n\r\n",
            ..first
        };
        let operations = Rc::new(RefCell::new(Vec::new()));
        let mut resolver: Option<Box<dyn ProcessResolver>> =
            Some(Box::new(InvalidationTrackingResolver {
                connection: TcpConnection::new(
                    TcpEndpoint::new(Ipv4Addr::new(10, 0, 0, 1).into(), 50_000),
                    TcpEndpoint::new(Ipv4Addr::new(10, 0, 0, 2).into(), 80),
                ),
                responses: VecDeque::from([
                    ResolvedProcess {
                        process: demo_process(1, "first"),
                        confidence: 60,
                    },
                    ResolvedProcess {
                        process: demo_process(2, "second"),
                        confidence: 60,
                    },
                ]),
                operations: Rc::clone(&operations),
            }));
        let mut tracker = FlowTracker::default();

        tracker.observe(&first, timestamp(10, 10), &mut resolver);
        tracker.observe(
            &second,
            timestamp(12, FLOW_IDLE_TIMEOUT_UNIX_NS + 11),
            &mut resolver,
        );

        assert_eq!(
            operations.borrow().as_slice(),
            ["resolve", "invalidate", "resolve"]
        );
    }

    #[test]
    fn syn_reuse_closes_stale_flow_and_re_resolves_four_tuple() {
        let first = DecodedTcpSegment {
            source: ipv4(10, 0, 0, 1),
            destination: ipv4(10, 0, 0, 2),
            source_port: 50_000,
            destination_port: 80,
            sequence: 100,
            flags: default_flags(),
            payload: b"GET /first HTTP/1.1\r\n\r\n",
        };
        let reused_syn = DecodedTcpSegment {
            sequence: 300,
            flags: syn_flags(),
            payload: b"",
            ..first
        };
        let second = DecodedTcpSegment {
            sequence: 301,
            payload: b"GET /second HTTP/1.1\r\n\r\n",
            ..first
        };
        let mut resolver: Option<Box<dyn ProcessResolver>> = Some(Box::new(SequenceResolver {
            connection: TcpConnection::new(
                TcpEndpoint::new(Ipv4Addr::new(10, 0, 0, 1).into(), 50_000),
                TcpEndpoint::new(Ipv4Addr::new(10, 0, 0, 2).into(), 80),
            ),
            responses: VecDeque::from([
                ResolvedProcess {
                    process: demo_process(1, "first"),
                    confidence: 60,
                },
                ResolvedProcess {
                    process: demo_process(2, "second"),
                    confidence: 60,
                },
            ]),
        }));
        let mut tracker = FlowTracker::default();

        let first_observed = tracker.observe(&first, timestamp(10, 10), &mut resolver);
        let closed = tracker
            .observe_lifecycle(&reused_syn, timestamp(11, 11))
            .into_iter()
            .next()
            .expect("syn reuse should close stale flow");
        let second_observed = tracker.observe(&second, timestamp(12, 12), &mut resolver);

        assert_eq!(closed.id, first_observed.flow.id);
        assert_eq!(second_observed.flow.process.identity.pid, 2);
        assert_ne!(first_observed.flow.id, second_observed.flow.id);
    }

    #[test]
    fn full_table_does_not_evict_when_observing_existing_flow() {
        let first = DecodedTcpSegment {
            source: ipv4(10, 0, 0, 1),
            destination: ipv4(10, 0, 0, 2),
            source_port: 50_000,
            destination_port: 80,
            sequence: 100,
            flags: default_flags(),
            payload: b"GET /first HTTP/1.1\r\n\r\n",
        };
        let first_followup = DecodedTcpSegment {
            sequence: 101,
            payload: b"GET /followup HTTP/1.1\r\n\r\n",
            ..first
        };
        let mut resolver = None;
        let mut tracker = FlowTracker::default();

        let first_observed = tracker.observe(&first, timestamp(1, 1), &mut resolver);
        for index in 1..MAX_FLOW_TRACKER_CONNECTIONS {
            let segment = DecodedTcpSegment {
                source: ipv4(10, 1, (index / 256) as u8, (index % 256) as u8),
                destination: ipv4(10, 2, (index / 256) as u8, (index % 256) as u8),
                source_port: 10_000 + (index % 50_000) as u16,
                destination_port: 80,
                sequence: index as u32,
                flags: default_flags(),
                payload: b"GET /fill HTTP/1.1\r\n\r\n",
            };
            tracker.observe(
                &segment,
                timestamp(index as u64 + 1, index as i64 + 1),
                &mut resolver,
            );
        }

        let observed = tracker.observe(
            &first_followup,
            timestamp((MAX_FLOW_TRACKER_CONNECTIONS + 2) as u64, 10_000_000),
            &mut resolver,
        );

        assert!(observed.closed_before.is_empty());
        assert_eq!(observed.flow.id, first_observed.flow.id);
    }

    struct StaticProcessResolver {
        connection: TcpConnection,
        process: ProcessContext,
        confidence: u8,
    }

    impl ProcessResolver for StaticProcessResolver {
        fn resolve_tcp_process(
            &mut self,
            connection: TcpConnection,
        ) -> Result<Option<ResolvedProcess>, crate::CaptureError> {
            Ok((connection == self.connection).then(|| ResolvedProcess {
                process: self.process.clone(),
                confidence: self.confidence,
            }))
        }
    }

    struct SequenceResolver {
        connection: TcpConnection,
        responses: VecDeque<ResolvedProcess>,
    }

    impl ProcessResolver for SequenceResolver {
        fn resolve_tcp_process(
            &mut self,
            connection: TcpConnection,
        ) -> Result<Option<ResolvedProcess>, crate::CaptureError> {
            Ok((connection == self.connection)
                .then(|| self.responses.pop_front())
                .flatten())
        }
    }

    struct InvalidationTrackingResolver {
        connection: TcpConnection,
        responses: VecDeque<ResolvedProcess>,
        operations: Rc<RefCell<Vec<&'static str>>>,
    }

    impl ProcessResolver for InvalidationTrackingResolver {
        fn resolve_tcp_process(
            &mut self,
            connection: TcpConnection,
        ) -> Result<Option<ResolvedProcess>, crate::CaptureError> {
            self.operations.borrow_mut().push("resolve");
            Ok((connection == self.connection)
                .then(|| self.responses.pop_front())
                .flatten())
        }

        fn invalidate_cached_resolution(&mut self) {
            self.operations.borrow_mut().push("invalidate");
        }
    }

    fn timestamp(monotonic_ns: u64, wall_time_unix_ns: i64) -> Timestamp {
        Timestamp {
            monotonic_ns,
            wall_time_unix_ns,
        }
    }

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn default_flags() -> super::super::decoder::TcpFlags {
        super::super::decoder::TcpFlags {
            syn: false,
            fin: false,
            rst: false,
        }
    }

    fn closing_flags() -> super::super::decoder::TcpFlags {
        super::super::decoder::TcpFlags {
            syn: false,
            fin: true,
            rst: false,
        }
    }

    fn syn_flags() -> super::super::decoder::TcpFlags {
        super::super::decoder::TcpFlags {
            syn: true,
            fin: false,
            rst: false,
        }
    }

    fn demo_process(pid: u32, name: &str) -> ProcessContext {
        ProcessContext {
            identity: ProcessIdentity {
                pid,
                tgid: pid,
                start_time_ticks: 1,
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
}
