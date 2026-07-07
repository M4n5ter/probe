use std::collections::{HashMap, VecDeque};

use probe_core::{Direction, Timestamp};

use crate::ProcessResolver;

use super::super::decoder::DecodedTcpSegment;
use super::candidate::{
    FlowCandidate, flow_from_decoded, infer_initial_direction, opposite_direction,
    select_flow_candidate,
};
use super::model::{
    FlowClosure, FlowEnd, FlowFinalization, FlowLifecycleObservation, FlowPayload,
    FlowPayloadObservation,
};
use super::record::{ConnectionKey, FlowRecord};

const MAX_FLOW_TRACKER_CONNECTIONS: usize = 16_384;
const FLOW_IDLE_TIMEOUT_UNIX_NS: i64 = 120_000_000_000;

#[derive(Debug, Default)]
pub(in crate::libpcap) struct FlowTracker {
    flows: HashMap<ConnectionKey, FlowRecord>,
    order: VecDeque<ConnectionKey>,
}

struct OpenedFlowRecord {
    direction: Direction,
    attribution_failure: Option<String>,
    record: FlowRecord,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SyntheticFlowPolicy {
    Allow,
    RequireResolved,
}

impl FlowTracker {
    pub(in crate::libpcap) fn observe(
        &mut self,
        decoded: &DecodedTcpSegment<'_>,
        timestamp: Timestamp,
        process_resolver: &mut Option<Box<dyn ProcessResolver>>,
    ) -> FlowPayloadObservation {
        let mut invalidated_resolution = false;
        invalidate_for_lifecycle_signal(decoded, process_resolver, &mut invalidated_resolution);
        let mut closed_before = self.evict_idle(timestamp.wall_time_unix_ns);
        let key = ConnectionKey::from_decoded(decoded);
        if decoded.has_syn()
            && !self.syn_belongs_to_existing_flow(&key, decoded)
            && let Some(closure) = self.remove_flow(&key)
        {
            closed_before.push(closure);
        }
        if let Some(record) = self.flows.get(&key) {
            let direction = record.direction_for(decoded);
            if record.payload_starts_after_close(direction, decoded)
                && let Some(closure) = self.remove_flow(&key)
            {
                closed_before.push(closure);
            }
        }
        if !closed_before.is_empty() {
            invalidate_process_resolution(process_resolver, &mut invalidated_resolution);
        }
        if let Some(record) = self.flows.get_mut(&key) {
            let direction = record.direction_for(decoded);
            record.last_seen_wall_time_unix_ns = timestamp.wall_time_unix_ns;
            let flow = record.flow.clone();
            record.observe_lifecycle(decoded);
            let payload = FlowPayload::new(direction, flow.clone(), record.confidence, None);
            let after_payload = self.flow_end_after_lifecycle(&key, direction);
            return FlowPayloadObservation::new(closed_before, payload, after_payload);
        }

        let capacity_closed = self.evict_oldest_if_full();
        if !capacity_closed.is_empty() {
            invalidate_process_resolution(process_resolver, &mut invalidated_resolution);
        }
        closed_before.extend(capacity_closed);
        let opened = open_flow_record(
            decoded,
            timestamp,
            process_resolver,
            SyntheticFlowPolicy::Allow,
        )
        .expect("payload flow opening allows synthetic libpcap attribution fallback");
        self.order.push_back(key);
        let flow = opened.record.flow.clone();
        let payload = FlowPayload::new(
            opened.direction,
            flow,
            opened.record.confidence,
            opened.attribution_failure,
        );
        let direction = opened.direction;
        self.flows.insert(key, opened.record);
        let after_payload = self.flow_end_after_lifecycle(&key, direction);
        FlowPayloadObservation::new(closed_before, payload, after_payload)
    }

    pub(in crate::libpcap) fn observe_lifecycle(
        &mut self,
        decoded: &DecodedTcpSegment<'_>,
        timestamp: Timestamp,
        process_resolver: &mut Option<Box<dyn ProcessResolver>>,
    ) -> FlowLifecycleObservation {
        let mut invalidated_resolution = false;
        invalidate_for_lifecycle_signal(decoded, process_resolver, &mut invalidated_resolution);
        let mut closed_before = self.evict_idle(timestamp.wall_time_unix_ns);
        let key = ConnectionKey::from_decoded(decoded);
        if decoded.has_syn() {
            if self.syn_belongs_to_existing_flow(&key, decoded) {
                if let Some(record) = self.flows.get_mut(&key) {
                    record.last_seen_wall_time_unix_ns = timestamp.wall_time_unix_ns;
                    record.observe_lifecycle(decoded);
                }
            } else if let Some(closure) = self.remove_flow(&key) {
                closed_before.push(closure);
            }
            if !closed_before.is_empty() {
                invalidate_process_resolution(process_resolver, &mut invalidated_resolution);
            }
            if !self.flows.contains_key(&key)
                && let Some(opened) = open_flow_record(
                    decoded,
                    timestamp,
                    process_resolver,
                    SyntheticFlowPolicy::RequireResolved,
                )
            {
                let capacity_closed = self.evict_oldest_if_full();
                if !capacity_closed.is_empty() {
                    invalidate_process_resolution(process_resolver, &mut invalidated_resolution);
                }
                closed_before.extend(capacity_closed);
                self.order.push_back(key);
                self.flows.insert(key, opened.record);
            }
            return FlowLifecycleObservation::new(closed_before, None);
        }
        if !closed_before.is_empty() {
            invalidate_process_resolution(process_resolver, &mut invalidated_resolution);
        }
        let mut finalization = None;
        let mut closed = false;
        if let Some(record) = self.flows.get_mut(&key) {
            let direction = record.direction_for(decoded);
            record.last_seen_wall_time_unix_ns = timestamp.wall_time_unix_ns;
            record.observe_lifecycle(decoded);
            closed = record.closed();
            if !closed && let Some(close_sequence) = record.close_sequence_for(direction) {
                finalization = Some(FlowFinalization::new(record.flow.clone(), close_sequence));
            }
        }
        let after_lifecycle = if closed {
            self.remove_flow(&key).map(FlowEnd::close)
        } else {
            finalization.map(FlowEnd::finalize)
        };
        FlowLifecycleObservation::new(closed_before, after_lifecycle)
    }

    fn syn_belongs_to_existing_flow(
        &self,
        key: &ConnectionKey,
        decoded: &DecodedTcpSegment<'_>,
    ) -> bool {
        decoded.has_syn()
            && self
                .flows
                .get(key)
                .is_some_and(|record| record.syn_belongs_to_existing_flow(decoded))
    }

    fn evict_oldest_if_full(&mut self) -> Vec<FlowClosure> {
        let mut closed = Vec::new();
        while self.flows.len() >= MAX_FLOW_TRACKER_CONNECTIONS {
            let Some(oldest) = self.order.pop_front() else {
                return closed;
            };
            if let Some(closure) = self.remove_flow(&oldest) {
                closed.push(closure);
            }
        }
        closed
    }

    fn evict_idle(&mut self, wall_time_unix_ns: i64) -> Vec<FlowClosure> {
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

    fn remove_flow(&mut self, key: &ConnectionKey) -> Option<FlowClosure> {
        let removed = self.flows.remove(key);
        self.order.retain(|existing| existing != key);
        removed.map(FlowRecord::into_closure)
    }

    fn flow_end_after_lifecycle(
        &mut self,
        key: &ConnectionKey,
        direction: Direction,
    ) -> Option<FlowEnd> {
        let (closed, finalization) = self
            .flows
            .get(key)
            .map(|record| {
                (
                    record.closed(),
                    (!record.closed())
                        .then(|| record.close_sequence_for(direction))
                        .flatten()
                        .map(|close_sequence| {
                            FlowFinalization::new(record.flow.clone(), close_sequence)
                        }),
                )
            })
            .unwrap_or_default();
        if closed {
            self.remove_flow(key).map(FlowEnd::close)
        } else {
            finalization.map(FlowEnd::finalize)
        }
    }
}

fn open_flow_record(
    decoded: &DecodedTcpSegment<'_>,
    timestamp: Timestamp,
    process_resolver: &mut Option<Box<dyn ProcessResolver>>,
    synthetic_policy: SyntheticFlowPolicy,
) -> Option<OpenedFlowRecord> {
    let primary = FlowCandidate::from_decoded(decoded, infer_initial_direction(decoded));
    let secondary = FlowCandidate::from_decoded(decoded, opposite_direction(primary.direction));
    let selected = select_flow_candidate(primary, secondary, process_resolver);
    if synthetic_policy == SyntheticFlowPolicy::RequireResolved && selected.confidence == 0 {
        return None;
    }
    let flow = flow_from_decoded(
        decoded,
        selected.direction,
        selected.process,
        selected.confidence,
        timestamp.monotonic_ns,
    );
    let mut record = FlowRecord::new(
        selected.local_endpoint,
        selected.confidence,
        flow,
        timestamp.wall_time_unix_ns,
    );
    record.observe_lifecycle(decoded);
    Some(OpenedFlowRecord {
        direction: selected.direction,
        attribution_failure: selected.attribution_failure,
        record,
    })
}

fn invalidate_for_lifecycle_signal(
    decoded: &DecodedTcpSegment<'_>,
    process_resolver: &mut Option<Box<dyn ProcessResolver>>,
    invalidated: &mut bool,
) {
    if decoded.has_lifecycle_signal() {
        invalidate_process_resolution(process_resolver, invalidated);
    }
}

fn invalidate_process_resolution(
    process_resolver: &mut Option<Box<dyn ProcessResolver>>,
    invalidated: &mut bool,
) {
    if !*invalidated && let Some(process_resolver) = process_resolver.as_deref_mut() {
        process_resolver.invalidate_cached_resolution();
        *invalidated = true;
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::RefCell,
        net::{IpAddr, Ipv4Addr},
        rc::Rc,
    };

    use probe_core::{Direction, ProcessContext, ProcessIdentity, TcpConnection, TcpEndpoint};

    use crate::ResolvedProcess;

    use super::super::super::tcp_seq;
    use super::super::candidate::synthetic_libpcap_process;
    use super::*;

    #[test]
    fn builds_stable_flow_for_opposite_http_directions() {
        let request = DecodedTcpSegment {
            source: ipv4(10, 0, 0, 1),
            destination: ipv4(10, 0, 0, 2),
            source_port: 50_000,
            destination_port: 80,
            sequence: 100,
            acknowledgment: 0,
            flags: default_flags(),
            payload: b"GET / HTTP/1.1\r\n\r\n",
        };
        let response = DecodedTcpSegment {
            source: ipv4(10, 0, 0, 2),
            destination: ipv4(10, 0, 0, 1),
            source_port: 80,
            destination_port: 50_000,
            sequence: 200,
            acknowledgment: 0,
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
            acknowledgment: 0,
            flags: default_flags(),
            payload: b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n",
        };
        let response_body = DecodedTcpSegment {
            source: ipv4(10, 0, 0, 2),
            destination: ipv4(10, 0, 0, 1),
            source_port: 80,
            destination_port: 50_000,
            sequence: 240,
            acknowledgment: 0,
            flags: default_flags(),
            payload: b"hello",
        };
        let mut tracker = FlowTracker::default();
        let mut resolver = None;

        assert_eq!(
            tracker
                .observe(&response_headers, timestamp(1, 1), &mut resolver)
                .payload
                .direction,
            Direction::Inbound
        );
        assert_eq!(
            tracker
                .observe(&response_body, timestamp(2, 2), &mut resolver)
                .payload
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
            acknowledgment: 0,
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

        let observed = tracker
            .observe(&request, timestamp(1, 1), &mut resolver)
            .payload;

        assert_eq!(observed.direction, Direction::Inbound);
        assert_eq!(observed.flow.local.address, "10.0.0.2");
        assert_eq!(observed.flow.remote.address, "10.0.0.1");
        assert_eq!(observed.flow.process.identity.pid, 42);
        assert_eq!(observed.flow.process.name, "server");
        assert_eq!(observed.attribution_confidence, 60);
    }

    #[test]
    fn listener_resolution_prefers_server_side_for_http_request() {
        let request = DecodedTcpSegment {
            source: ipv4(10, 0, 0, 1),
            destination: ipv4(10, 0, 0, 2),
            source_port: 50_000,
            destination_port: 80,
            sequence: 100,
            acknowledgment: 0,
            flags: default_flags(),
            payload: b"GET / HTTP/1.1\r\n\r\n",
        };
        let mut resolver: Option<Box<dyn ProcessResolver>> =
            Some(Box::new(EndpointOnlyListenerResolver {
                listener: TcpEndpoint::new(Ipv4Addr::new(10, 0, 0, 2).into(), 80),
                listener_process: demo_process(42, "server"),
            }));
        let mut tracker = FlowTracker::default();

        let observed = tracker
            .observe(&request, timestamp(1, 1), &mut resolver)
            .payload;

        assert_eq!(observed.direction, Direction::Inbound);
        assert_eq!(observed.flow.local.address, "10.0.0.2");
        assert_eq!(observed.flow.remote.address, "10.0.0.1");
        assert_eq!(observed.flow.process.identity.pid, 42);
        assert_eq!(observed.flow.process.name, "server");
        assert_eq!(observed.attribution_confidence, 60);
    }

    #[test]
    fn exact_connection_attribution_outranks_unrelated_port_listener() {
        let request = DecodedTcpSegment {
            source: ipv4(10, 0, 0, 2),
            destination: ipv4(93, 184, 216, 34),
            source_port: 50_000,
            destination_port: 80,
            sequence: 100,
            acknowledgment: 0,
            flags: default_flags(),
            payload: b"GET / HTTP/1.1\r\n\r\n",
        };
        let mut resolver: Option<Box<dyn ProcessResolver>> =
            Some(Box::new(ConnectionAndPortListenerResolver {
                connection: TcpConnection::new(
                    TcpEndpoint::new(Ipv4Addr::new(10, 0, 0, 2).into(), 50_000),
                    TcpEndpoint::new(Ipv4Addr::new(93, 184, 216, 34).into(), 80),
                ),
                port: 80,
                connection_process: demo_process(7, "client"),
                listener_process: demo_process(42, "local-server"),
            }));
        let mut tracker = FlowTracker::default();

        let observed = tracker
            .observe(&request, timestamp(1, 1), &mut resolver)
            .payload;

        assert_eq!(observed.direction, Direction::Outbound);
        assert_eq!(observed.flow.local.address, "10.0.0.2");
        assert_eq!(observed.flow.remote.address, "93.184.216.34");
        assert_eq!(observed.flow.process.identity.pid, 7);
        assert_eq!(observed.flow.process.name, "client");
        assert_eq!(observed.attribution_confidence, 65);
    }

    #[test]
    fn listener_port_resolution_handles_rewritten_listener_addresses() {
        let request = DecodedTcpSegment {
            source: ipv4(10, 0, 0, 1),
            destination: ipv4(10, 0, 0, 2),
            source_port: 50_000,
            destination_port: 80,
            sequence: 100,
            acknowledgment: 0,
            flags: default_flags(),
            payload: b"GET / HTTP/1.1\r\n\r\n",
        };
        let mut resolver: Option<Box<dyn ProcessResolver>> =
            Some(Box::new(PortOnlyListenerResolver {
                port: 80,
                listener_process: demo_process(42, "server"),
            }));
        let mut tracker = FlowTracker::default();

        let observed = tracker
            .observe(&request, timestamp(1, 1), &mut resolver)
            .payload;

        assert_eq!(observed.direction, Direction::Inbound);
        assert_eq!(observed.flow.local.address, "10.0.0.2");
        assert_eq!(observed.flow.remote.address, "10.0.0.1");
        assert_eq!(observed.flow.process.identity.pid, 42);
        assert_eq!(observed.flow.process.name, "server");
        assert_eq!(observed.attribution_confidence, 55);
    }

    #[test]
    fn syn_listener_resolution_preserves_process_for_late_payload() {
        let syn = DecodedTcpSegment {
            source: ipv4(10, 0, 0, 1),
            destination: ipv4(10, 0, 0, 2),
            source_port: 50_000,
            destination_port: 44_977,
            sequence: 100,
            acknowledgment: 0,
            flags: syn_flags(),
            payload: b"",
        };
        let request = DecodedTcpSegment {
            sequence: 101,
            acknowledgment: 0,
            flags: default_flags(),
            payload: b"GET / HTTP/1.1\r\n\r\n",
            ..syn
        };
        let mut resolver: Option<Box<dyn ProcessResolver>> =
            Some(Box::new(ConnectionAndListenerResolver {
                connection: TcpConnection::new(
                    TcpEndpoint::new(Ipv4Addr::new(10, 0, 0, 2).into(), 44_977),
                    TcpEndpoint::new(Ipv4Addr::new(10, 0, 0, 1).into(), 50_000),
                ),
                listener: TcpEndpoint::new(Ipv4Addr::new(10, 0, 0, 2).into(), 44_977),
                connection_process: demo_process(42, "server"),
                listener_process: demo_process(42, "server"),
            }));
        let mut tracker = FlowTracker::default();

        let syn_observation = tracker.observe_lifecycle(&syn, timestamp(1, 1), &mut resolver);
        resolver = None;
        let observed = tracker
            .observe(&request, timestamp(2, 2), &mut resolver)
            .payload;

        assert!(syn_observation.before_lifecycle_closures.is_empty());
        assert!(syn_observation.after_lifecycle.is_none());
        assert_eq!(observed.direction, Direction::Inbound);
        assert_eq!(observed.flow.local.address, "10.0.0.2");
        assert_eq!(observed.flow.remote.address, "10.0.0.1");
        assert_eq!(observed.flow.process.identity.pid, 42);
        assert_eq!(observed.flow.process.name, "server");
        assert_eq!(observed.attribution_confidence, 60);
    }

    #[test]
    fn syn_ack_listener_resolution_preserves_process_for_late_request_payload() {
        let syn_ack = DecodedTcpSegment {
            source: ipv4(10, 0, 0, 2),
            destination: ipv4(10, 0, 0, 1),
            source_port: 44_977,
            destination_port: 50_000,
            sequence: 200,
            acknowledgment: 101,
            flags: syn_ack_flags(),
            payload: b"",
        };
        let request = DecodedTcpSegment {
            source: syn_ack.destination,
            destination: syn_ack.source,
            source_port: syn_ack.destination_port,
            destination_port: syn_ack.source_port,
            sequence: 100,
            acknowledgment: 0,
            flags: default_flags(),
            payload: b"GET / HTTP/1.1\r\n\r\n",
        };
        let mut resolver: Option<Box<dyn ProcessResolver>> =
            Some(Box::new(ConnectionAndListenerResolver {
                connection: TcpConnection::new(
                    TcpEndpoint::new(Ipv4Addr::new(10, 0, 0, 2).into(), 44_977),
                    TcpEndpoint::new(Ipv4Addr::new(10, 0, 0, 1).into(), 50_000),
                ),
                listener: TcpEndpoint::new(Ipv4Addr::new(10, 0, 0, 2).into(), 44_977),
                connection_process: demo_process(42, "server"),
                listener_process: demo_process(42, "server"),
            }));
        let mut tracker = FlowTracker::default();

        let syn_observation = tracker.observe_lifecycle(&syn_ack, timestamp(1, 1), &mut resolver);
        resolver = None;
        let observed = tracker
            .observe(&request, timestamp(2, 2), &mut resolver)
            .payload;

        assert!(syn_observation.before_lifecycle_closures.is_empty());
        assert!(syn_observation.after_lifecycle.is_none());
        assert_eq!(observed.direction, Direction::Inbound);
        assert_eq!(observed.flow.local.address, "10.0.0.2");
        assert_eq!(observed.flow.remote.address, "10.0.0.1");
        assert_eq!(observed.flow.process.identity.pid, 42);
        assert_eq!(observed.flow.process.name, "server");
        assert_eq!(observed.attribution_confidence, 60);
    }

    #[test]
    fn syn_ack_after_syn_stays_on_existing_flow() {
        let syn = DecodedTcpSegment {
            source: ipv4(10, 0, 0, 1),
            destination: ipv4(10, 0, 0, 2),
            source_port: 50_000,
            destination_port: 44_977,
            sequence: 100,
            acknowledgment: 0,
            flags: syn_flags(),
            payload: b"",
        };
        let syn_ack = DecodedTcpSegment {
            source: syn.destination,
            destination: syn.source,
            source_port: syn.destination_port,
            destination_port: syn.source_port,
            sequence: 200,
            acknowledgment: 101,
            flags: syn_ack_flags(),
            payload: b"",
        };
        let request = DecodedTcpSegment {
            sequence: 101,
            acknowledgment: 0,
            flags: default_flags(),
            payload: b"GET / HTTP/1.1\r\n\r\n",
            ..syn
        };
        let mut resolver: Option<Box<dyn ProcessResolver>> =
            Some(Box::new(ConnectionAndListenerResolver {
                connection: TcpConnection::new(
                    TcpEndpoint::new(Ipv4Addr::new(10, 0, 0, 2).into(), 44_977),
                    TcpEndpoint::new(Ipv4Addr::new(10, 0, 0, 1).into(), 50_000),
                ),
                listener: TcpEndpoint::new(Ipv4Addr::new(10, 0, 0, 2).into(), 44_977),
                connection_process: demo_process(42, "server"),
                listener_process: demo_process(42, "server"),
            }));
        let mut tracker = FlowTracker::default();

        tracker.observe_lifecycle(&syn, timestamp(1, 1), &mut resolver);
        resolver = None;
        let syn_ack_observation =
            tracker.observe_lifecycle(&syn_ack, timestamp(2, 2), &mut resolver);
        let observed = tracker
            .observe(&request, timestamp(3, 3), &mut resolver)
            .payload;

        assert!(syn_ack_observation.before_lifecycle_closures.is_empty());
        assert!(syn_ack_observation.after_lifecycle.is_none());
        assert_eq!(observed.direction, Direction::Inbound);
        assert_eq!(observed.flow.local.address, "10.0.0.2");
        assert_eq!(observed.flow.remote.address, "10.0.0.1");
        assert_eq!(observed.flow.process.identity.pid, 42);
        assert_eq!(observed.flow.process.name, "server");
        assert_eq!(observed.attribution_confidence, 60);
    }

    #[test]
    fn syn_ack_with_wrong_ack_closes_stale_flow() {
        let syn = DecodedTcpSegment {
            source: ipv4(10, 0, 0, 1),
            destination: ipv4(10, 0, 0, 2),
            source_port: 50_000,
            destination_port: 44_977,
            sequence: 100,
            acknowledgment: 0,
            flags: syn_flags(),
            payload: b"",
        };
        let stale_syn_ack = DecodedTcpSegment {
            source: syn.destination,
            destination: syn.source,
            source_port: syn.destination_port,
            destination_port: syn.source_port,
            sequence: 200,
            acknowledgment: 999,
            flags: syn_ack_flags(),
            payload: b"",
        };
        let mut resolver: Option<Box<dyn ProcessResolver>> =
            Some(Box::new(ConnectionAndListenerResolver {
                connection: TcpConnection::new(
                    TcpEndpoint::new(Ipv4Addr::new(10, 0, 0, 1).into(), 50_000),
                    TcpEndpoint::new(Ipv4Addr::new(10, 0, 0, 2).into(), 44_977),
                ),
                listener: TcpEndpoint::new(Ipv4Addr::new(10, 0, 0, 2).into(), 44_977),
                connection_process: demo_process(7, "client"),
                listener_process: demo_process(42, "server"),
            }));
        let mut tracker = FlowTracker::default();

        tracker.observe_lifecycle(&syn, timestamp(1, 1), &mut resolver);
        resolver = None;
        let observation = tracker.observe_lifecycle(&stale_syn_ack, timestamp(2, 2), &mut resolver);

        assert_eq!(observation.before_lifecycle_closures.len(), 1);
        assert!(observation.after_lifecycle.is_none());
    }

    #[test]
    fn closed_flow_re_resolves_reused_four_tuple() {
        let first = DecodedTcpSegment {
            source: ipv4(10, 0, 0, 1),
            destination: ipv4(10, 0, 0, 2),
            source_port: 50_000,
            destination_port: 80,
            sequence: 100,
            acknowledgment: 0,
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
            acknowledgment: 0,
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

        let first_observed = tracker
            .observe(&first, timestamp(10, 10), &mut resolver)
            .payload;
        tracker.observe_lifecycle(&close, timestamp(11, 11), &mut resolver);
        tracker.observe_lifecycle(&peer_close, timestamp(12, 12), &mut resolver);
        let second_observed = tracker
            .observe(&second, timestamp(12, 12), &mut resolver)
            .payload;

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
            acknowledgment: 0,
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
            acknowledgment: 0,
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

        let request_observed = tracker
            .observe(&request, timestamp(10, 10), &mut resolver)
            .payload;
        tracker.observe_lifecycle(&client_fin, timestamp(11, 11), &mut resolver);
        let response_observed = tracker
            .observe(&response, timestamp(12, 12), &mut resolver)
            .payload;

        assert_eq!(request_observed.flow.id, response_observed.flow.id);
        assert_eq!(response_observed.flow.process.identity.pid, 1);
        assert_eq!(response_observed.direction, Direction::Inbound);
    }

    #[test]
    fn payload_after_same_direction_close_starts_new_observation() {
        let request = DecodedTcpSegment {
            source: ipv4(10, 0, 0, 1),
            destination: ipv4(10, 0, 0, 2),
            source_port: 50_000,
            destination_port: 80,
            sequence: 100,
            acknowledgment: 0,
            flags: default_flags(),
            payload: b"GET / HTTP/1.1\r\n\r\n",
        };
        let client_fin = DecodedTcpSegment {
            sequence: tcp_seq::advance(request.sequence, request.payload.len()),
            flags: closing_flags(),
            payload: b"",
            ..request
        };
        let late_payload = DecodedTcpSegment {
            sequence: client_fin.sequence,
            acknowledgment: 0,
            flags: default_flags(),
            payload: b"late",
            ..request
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

        let request_observed = tracker
            .observe(&request, timestamp(10, 10), &mut resolver)
            .payload;
        let client_lifecycle =
            tracker.observe_lifecycle(&client_fin, timestamp(11, 11), &mut resolver);
        let late_transitions = tracker.observe(&late_payload, timestamp(12, 12), &mut resolver);
        let late_observed = late_transitions.payload.clone();
        let closed = before_payload_close_from(&late_transitions);

        assert!(matches!(
            client_lifecycle.after_lifecycle,
            Some(FlowEnd::Finalize(_))
        ));
        assert!(client_lifecycle.before_lifecycle_closures.is_empty());
        assert_eq!(closed.flow.id, request_observed.flow.id);
        assert_ne!(late_observed.flow.id, request_observed.flow.id);
        assert_eq!(late_observed.flow.process.identity.pid, 2);
    }

    #[test]
    fn payload_fin_closes_current_flow_after_bytes() {
        let request = DecodedTcpSegment {
            source: ipv4(10, 0, 0, 1),
            destination: ipv4(10, 0, 0, 2),
            source_port: 50_000,
            destination_port: 80,
            sequence: 100,
            acknowledgment: 0,
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
            acknowledgment: 0,
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

        let request_observed = tracker
            .observe(&request, timestamp(10, 10), &mut resolver)
            .payload;
        let client_lifecycle =
            tracker.observe_lifecycle(&client_fin, timestamp(11, 11), &mut resolver);
        assert!(client_lifecycle.before_lifecycle_closures.is_empty());
        assert!(matches!(
            client_lifecycle.after_lifecycle,
            Some(FlowEnd::Finalize(_))
        ));
        let response_transitions = tracker.observe(&response_fin, timestamp(12, 12), &mut resolver);
        let response_observed = response_transitions.payload.clone();
        let closed = after_payload_close_from(&response_transitions);

        assert_eq!(request_observed.flow.id, response_observed.flow.id);
        assert_eq!(closed.flow.id, request_observed.flow.id);
    }

    #[test]
    fn idle_flow_re_resolves_reused_four_tuple() {
        let first = DecodedTcpSegment {
            source: ipv4(10, 0, 0, 1),
            destination: ipv4(10, 0, 0, 2),
            source_port: 50_000,
            destination_port: 80,
            sequence: 100,
            acknowledgment: 0,
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

        let first_observed = tracker
            .observe(&first, timestamp(10, 10), &mut resolver)
            .payload;
        let second_transitions = tracker.observe(
            &second,
            timestamp(12, FLOW_IDLE_TIMEOUT_UNIX_NS + 11),
            &mut resolver,
        );
        let second_observed = second_transitions.payload.clone();
        let closed = before_payload_close_from(&second_transitions);

        assert_eq!(first_observed.flow.process.identity.pid, 1);
        assert_eq!(closed.flow.id, first_observed.flow.id);
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
            acknowledgment: 0,
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
            acknowledgment: 0,
            flags: default_flags(),
            payload: b"GET /first HTTP/1.1\r\n\r\n",
        };
        let reused_syn = DecodedTcpSegment {
            sequence: 300,
            acknowledgment: 0,
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

        let first_observed = tracker
            .observe(&first, timestamp(10, 10), &mut resolver)
            .payload;
        let closed = tracker
            .observe_lifecycle(&reused_syn, timestamp(11, 11), &mut resolver)
            .before_lifecycle_closures
            .into_iter()
            .next()
            .expect("syn reuse should close stale flow");
        let second_observed = tracker
            .observe(&second, timestamp(12, 12), &mut resolver)
            .payload;

        assert_eq!(closed.flow.id, first_observed.flow.id);
        assert_eq!(second_observed.flow.process.identity.pid, 2);
        assert_ne!(first_observed.flow.id, second_observed.flow.id);
    }

    #[test]
    fn retransmitted_syn_payload_stays_on_existing_flow() {
        let first = DecodedTcpSegment {
            source: ipv4(10, 0, 0, 1),
            destination: ipv4(10, 0, 0, 2),
            source_port: 50_000,
            destination_port: 80,
            sequence: 100,
            acknowledgment: 0,
            flags: syn_flags(),
            payload: b"GET /first HTTP/1.1\r\n\r\n",
        };
        let retransmitted = first;
        let mut resolver: Option<Box<dyn ProcessResolver>> = Some(Box::new(SequenceResolver {
            connection: TcpConnection::new(
                TcpEndpoint::new(Ipv4Addr::new(10, 0, 0, 1).into(), 50_000),
                TcpEndpoint::new(Ipv4Addr::new(10, 0, 0, 2).into(), 80),
            ),
            responses: VecDeque::from([ResolvedProcess {
                process: demo_process(1, "first"),
                confidence: 60,
            }]),
        }));
        let mut tracker = FlowTracker::default();

        let first_observed = tracker
            .observe(&first, timestamp(10, 10), &mut resolver)
            .payload;
        let retransmitted_transitions =
            tracker.observe(&retransmitted, timestamp(11, 11), &mut resolver);
        let retransmitted_observed = retransmitted_transitions.payload.clone();

        assert!(retransmitted_transitions.before_payload_closures.is_empty());
        assert!(retransmitted_transitions.after_payload.is_none());
        assert_eq!(first_observed.flow.id, retransmitted_observed.flow.id);
    }

    #[test]
    fn full_table_does_not_evict_when_observing_existing_flow() {
        let first = DecodedTcpSegment {
            source: ipv4(10, 0, 0, 1),
            destination: ipv4(10, 0, 0, 2),
            source_port: 50_000,
            destination_port: 80,
            sequence: 100,
            acknowledgment: 0,
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

        let first_observed = tracker
            .observe(&first, timestamp(1, 1), &mut resolver)
            .payload;
        for index in 1..MAX_FLOW_TRACKER_CONNECTIONS {
            let segment = DecodedTcpSegment {
                source: ipv4(10, 1, (index / 256) as u8, (index % 256) as u8),
                destination: ipv4(10, 2, (index / 256) as u8, (index % 256) as u8),
                source_port: 10_000 + (index % 50_000) as u16,
                destination_port: 80,
                sequence: index as u32,
                acknowledgment: 0,
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
        let observed_payload = observed.payload.clone();

        assert!(observed.before_payload_closures.is_empty());
        assert!(observed.after_payload.is_none());
        assert_eq!(observed_payload.flow.id, first_observed.flow.id);
    }

    #[test]
    fn full_table_unresolved_syn_does_not_evict_existing_flow() {
        let first = DecodedTcpSegment {
            source: ipv4(10, 0, 0, 1),
            destination: ipv4(10, 0, 0, 2),
            source_port: 50_000,
            destination_port: 80,
            sequence: 100,
            acknowledgment: 0,
            flags: default_flags(),
            payload: b"GET /first HTTP/1.1\r\n\r\n",
        };
        let first_followup = DecodedTcpSegment {
            sequence: 101,
            payload: b"GET /followup HTTP/1.1\r\n\r\n",
            ..first
        };
        let unresolved_syn = DecodedTcpSegment {
            source: ipv4(192, 0, 2, 1),
            destination: ipv4(192, 0, 2, 2),
            source_port: 51_000,
            destination_port: 44_977,
            sequence: 500,
            acknowledgment: 0,
            flags: syn_flags(),
            payload: b"",
        };
        let mut resolver = None;
        let mut tracker = FlowTracker::default();

        let first_observed = tracker
            .observe(&first, timestamp(1, 1), &mut resolver)
            .payload;
        for index in 1..MAX_FLOW_TRACKER_CONNECTIONS {
            let segment = DecodedTcpSegment {
                source: ipv4(10, 1, (index / 256) as u8, (index % 256) as u8),
                destination: ipv4(10, 2, (index / 256) as u8, (index % 256) as u8),
                source_port: 10_000 + (index % 50_000) as u16,
                destination_port: 80,
                sequence: index as u32,
                acknowledgment: 0,
                flags: default_flags(),
                payload: b"GET /fill HTTP/1.1\r\n\r\n",
            };
            tracker.observe(
                &segment,
                timestamp(index as u64 + 1, index as i64 + 1),
                &mut resolver,
            );
        }

        let syn_observation =
            tracker.observe_lifecycle(&unresolved_syn, timestamp(20_000, 20_000), &mut resolver);
        let observed = tracker.observe(&first_followup, timestamp(20_001, 20_001), &mut resolver);
        let observed_payload = observed.payload.clone();

        assert!(syn_observation.before_lifecycle_closures.is_empty());
        assert!(syn_observation.after_lifecycle.is_none());
        assert!(observed.before_payload_closures.is_empty());
        assert!(observed.after_payload.is_none());
        assert_eq!(observed_payload.flow.id, first_observed.flow.id);
    }

    fn before_payload_close_from(observation: &FlowPayloadObservation) -> FlowClosure {
        observation
            .before_payload_closures
            .first()
            .cloned()
            .expect("expected before-payload close")
    }

    fn after_payload_close_from(observation: &FlowPayloadObservation) -> FlowClosure {
        match observation.after_payload.as_ref() {
            Some(FlowEnd::Close(closure)) => closure.clone(),
            Some(FlowEnd::Finalize(_)) | None => panic!("expected after-payload close"),
        }
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

    struct ConnectionAndListenerResolver {
        connection: TcpConnection,
        listener: TcpEndpoint,
        connection_process: ProcessContext,
        listener_process: ProcessContext,
    }

    impl ProcessResolver for ConnectionAndListenerResolver {
        fn resolve_tcp_process(
            &mut self,
            connection: TcpConnection,
        ) -> Result<Option<ResolvedProcess>, crate::CaptureError> {
            Ok((connection == self.connection).then(|| ResolvedProcess {
                process: self.connection_process.clone(),
                confidence: 60,
            }))
        }

        fn resolve_tcp_listener(
            &mut self,
            local_endpoint: TcpEndpoint,
        ) -> Result<Option<ResolvedProcess>, crate::CaptureError> {
            Ok((local_endpoint == self.listener).then(|| ResolvedProcess {
                process: self.listener_process.clone(),
                confidence: 60,
            }))
        }
    }

    struct EndpointOnlyListenerResolver {
        listener: TcpEndpoint,
        listener_process: ProcessContext,
    }

    impl ProcessResolver for EndpointOnlyListenerResolver {
        fn resolve_tcp_process(
            &mut self,
            _connection: TcpConnection,
        ) -> Result<Option<ResolvedProcess>, crate::CaptureError> {
            Ok(None)
        }

        fn resolve_tcp_listener(
            &mut self,
            local_endpoint: TcpEndpoint,
        ) -> Result<Option<ResolvedProcess>, crate::CaptureError> {
            Ok((local_endpoint == self.listener).then(|| ResolvedProcess {
                process: self.listener_process.clone(),
                confidence: 60,
            }))
        }
    }

    struct PortOnlyListenerResolver {
        port: u16,
        listener_process: ProcessContext,
    }

    impl ProcessResolver for PortOnlyListenerResolver {
        fn resolve_tcp_process(
            &mut self,
            _connection: TcpConnection,
        ) -> Result<Option<ResolvedProcess>, crate::CaptureError> {
            Ok(None)
        }

        fn resolve_tcp_listener(
            &mut self,
            _local_endpoint: TcpEndpoint,
        ) -> Result<Option<ResolvedProcess>, crate::CaptureError> {
            Ok(None)
        }

        fn resolve_unique_tcp_listener_owner_by_port(
            &mut self,
            local_port: u16,
        ) -> Result<Option<ResolvedProcess>, crate::CaptureError> {
            Ok((local_port == self.port).then(|| ResolvedProcess {
                process: self.listener_process.clone(),
                confidence: 55,
            }))
        }
    }

    struct ConnectionAndPortListenerResolver {
        connection: TcpConnection,
        port: u16,
        connection_process: ProcessContext,
        listener_process: ProcessContext,
    }

    impl ProcessResolver for ConnectionAndPortListenerResolver {
        fn resolve_tcp_process(
            &mut self,
            connection: TcpConnection,
        ) -> Result<Option<ResolvedProcess>, crate::CaptureError> {
            Ok((connection == self.connection).then(|| ResolvedProcess {
                process: self.connection_process.clone(),
                confidence: 65,
            }))
        }

        fn resolve_tcp_listener(
            &mut self,
            _local_endpoint: TcpEndpoint,
        ) -> Result<Option<ResolvedProcess>, crate::CaptureError> {
            Ok(None)
        }

        fn resolve_unique_tcp_listener_owner_by_port(
            &mut self,
            local_port: u16,
        ) -> Result<Option<ResolvedProcess>, crate::CaptureError> {
            Ok((local_port == self.port).then(|| ResolvedProcess {
                process: self.listener_process.clone(),
                confidence: 55,
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

    fn default_flags() -> crate::libpcap::decoder::TcpFlags {
        crate::libpcap::decoder::TcpFlags {
            syn: false,
            ack: true,
            fin: false,
            rst: false,
        }
    }

    fn closing_flags() -> crate::libpcap::decoder::TcpFlags {
        crate::libpcap::decoder::TcpFlags {
            syn: false,
            ack: true,
            fin: true,
            rst: false,
        }
    }

    fn syn_flags() -> crate::libpcap::decoder::TcpFlags {
        crate::libpcap::decoder::TcpFlags {
            syn: true,
            ack: false,
            fin: false,
            rst: false,
        }
    }

    fn syn_ack_flags() -> crate::libpcap::decoder::TcpFlags {
        crate::libpcap::decoder::TcpFlags {
            syn: true,
            ack: true,
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
