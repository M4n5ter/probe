use std::collections::{HashMap, VecDeque};

use probe_core::{Direction, FlowContext};

use super::{
    EbpfCloseTracepointObservation, EbpfConnectTracepointObservation, EbpfSocketReadObservation,
    EbpfSocketWriteObservation, payload_direction::PayloadDirections,
};

pub(super) struct TrackedEbpfFlows {
    by_descriptor: HashMap<EbpfDescriptorKey, TrackedEbpfFlow>,
    recency_order: VecDeque<EbpfDescriptorKey>,
    max_tracked_flows: usize,
}

pub(super) struct TrackedEbpfFlow {
    pub flow: FlowContext,
    pub inbound_stream_offset: u64,
    pub outbound_stream_offset: u64,
    payload_directions: PayloadDirections,
}

impl TrackedEbpfFlows {
    pub(super) fn bounded(max_tracked_flows: usize) -> Self {
        Self {
            by_descriptor: HashMap::new(),
            recency_order: VecDeque::new(),
            max_tracked_flows,
        }
    }

    pub(super) fn insert_connect(
        &mut self,
        connect: &EbpfConnectTracepointObservation,
        flow: FlowContext,
        payload_directions: PayloadDirections,
    ) {
        self.insert(
            EbpfDescriptorKey::from_connect(connect),
            flow,
            payload_directions,
        );
    }

    pub(super) fn remove_close(
        &mut self,
        close: &EbpfCloseTracepointObservation,
    ) -> Option<TrackedEbpfFlow> {
        self.remove(EbpfDescriptorKey::from_close(close))
    }

    pub(super) fn get_write_mut(
        &mut self,
        write: &EbpfSocketWriteObservation,
    ) -> Option<&mut TrackedEbpfFlow> {
        self.get_recent_mut(EbpfDescriptorKey::from_write(write), Direction::Outbound)
    }

    pub(super) fn get_read_mut(
        &mut self,
        read: &EbpfSocketReadObservation,
    ) -> Option<&mut TrackedEbpfFlow> {
        self.get_recent_mut(EbpfDescriptorKey::from_read(read), Direction::Inbound)
    }

    fn insert(
        &mut self,
        key: EbpfDescriptorKey,
        flow: FlowContext,
        payload_directions: PayloadDirections,
    ) {
        if self.max_tracked_flows == 0 {
            return;
        }
        if self.by_descriptor.contains_key(&key) {
            self.recency_order.retain(|tracked_key| *tracked_key != key);
        } else {
            self.evict_until_available();
        }
        self.recency_order.push_back(key);
        self.by_descriptor.insert(
            key,
            TrackedEbpfFlow {
                flow,
                inbound_stream_offset: 0,
                outbound_stream_offset: 0,
                payload_directions,
            },
        );
    }

    fn remove(&mut self, key: EbpfDescriptorKey) -> Option<TrackedEbpfFlow> {
        let flow = self.by_descriptor.remove(&key)?;
        self.recency_order.retain(|tracked_key| *tracked_key != key);
        Some(flow)
    }

    fn get_recent_mut(
        &mut self,
        key: EbpfDescriptorKey,
        required_direction: Direction,
    ) -> Option<&mut TrackedEbpfFlow> {
        if !self
            .by_descriptor
            .get(&key)
            .is_some_and(|tracked| tracked.allows_payload(required_direction))
        {
            return None;
        }
        self.recency_order.retain(|tracked_key| *tracked_key != key);
        self.recency_order.push_back(key);
        self.by_descriptor.get_mut(&key)
    }

    fn evict_until_available(&mut self) {
        while self.by_descriptor.len() >= self.max_tracked_flows {
            let Some(evicted) = self.recency_order.pop_front() else {
                self.by_descriptor.clear();
                break;
            };
            if self.by_descriptor.remove(&evicted).is_some() {
                break;
            }
        }
    }
}

impl TrackedEbpfFlow {
    fn allows_payload(&self, direction: Direction) -> bool {
        self.payload_directions.allows(direction)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct EbpfDescriptorKey {
    tgid: u32,
    fd: i32,
}

impl EbpfDescriptorKey {
    fn from_connect(connect: &EbpfConnectTracepointObservation) -> Self {
        Self {
            tgid: connect.process.tgid,
            fd: connect.fd,
        }
    }

    fn from_close(close: &EbpfCloseTracepointObservation) -> Self {
        Self {
            tgid: close.process.tgid,
            fd: close.fd,
        }
    }

    fn from_write(write: &EbpfSocketWriteObservation) -> Self {
        Self {
            tgid: write.process.tgid,
            fd: write.fd,
        }
    }

    fn from_read(read: &EbpfSocketReadObservation) -> Self {
        Self {
            tgid: read.process.tgid,
            fd: read.fd,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use probe_core::{
        AddressPort, FlowContext, FlowIdentity, ProcessContext, ProcessIdentity, TcpEndpoint,
        TransportProtocol,
    };

    use super::super::{
        EbpfCloseTracepointObservation, EbpfConnectEndpoint, EbpfObservedProcess,
        EbpfSocketReadObservation,
    };
    use super::*;

    #[test]
    fn tracked_flows_evict_oldest_descriptor_when_capacity_is_exceeded() {
        let mut tracked = TrackedEbpfFlows::bounded(1);
        insert_connect(&mut tracked, 7, flow("fd-7"));
        insert_connect(&mut tracked, 8, flow("fd-8"));

        assert!(tracked.remove_close(&close_observation(7)).is_none());
        assert_eq!(
            tracked
                .remove_close(&close_observation(8))
                .expect("fd 8 should remain tracked")
                .flow
                .id,
            FlowIdentity("fd-8".to_string())
        );
    }

    #[test]
    fn tracked_flows_refresh_descriptor_age_on_reuse() {
        let mut tracked = TrackedEbpfFlows::bounded(2);
        insert_connect(&mut tracked, 7, flow("fd-7-first"));
        insert_connect(&mut tracked, 8, flow("fd-8"));
        insert_connect(&mut tracked, 7, flow("fd-7-second"));
        insert_connect(&mut tracked, 9, flow("fd-9"));

        assert!(tracked.remove_close(&close_observation(8)).is_none());
        assert_eq!(
            tracked
                .remove_close(&close_observation(7))
                .expect("refreshed fd 7 should remain tracked")
                .flow
                .id,
            FlowIdentity("fd-7-second".to_string())
        );
        assert_eq!(
            tracked
                .remove_close(&close_observation(9))
                .expect("fd 9 should remain tracked")
                .flow
                .id,
            FlowIdentity("fd-9".to_string())
        );
    }

    #[test]
    fn tracked_flows_refresh_descriptor_age_on_write() {
        let mut tracked = TrackedEbpfFlows::bounded(2);
        insert_connect(&mut tracked, 7, flow("fd-7"));
        insert_connect(&mut tracked, 8, flow("fd-8"));

        tracked
            .get_write_mut(&write_observation(7))
            .expect("fd 7 should be tracked");
        insert_connect(&mut tracked, 9, flow("fd-9"));

        assert!(tracked.remove_close(&close_observation(8)).is_none());
        assert_eq!(
            tracked
                .remove_close(&close_observation(7))
                .expect("write-refreshed fd 7 should remain tracked")
                .flow
                .id,
            FlowIdentity("fd-7".to_string())
        );
        assert_eq!(
            tracked
                .remove_close(&close_observation(9))
                .expect("fd 9 should remain tracked")
                .flow
                .id,
            FlowIdentity("fd-9".to_string())
        );
    }

    #[test]
    fn tracked_flows_refresh_descriptor_age_on_read() {
        let mut tracked = TrackedEbpfFlows::bounded(2);
        insert_connect(&mut tracked, 7, flow("fd-7"));
        insert_connect(&mut tracked, 8, flow("fd-8"));

        tracked
            .get_read_mut(&read_observation(7))
            .expect("fd 7 should be tracked");
        insert_connect(&mut tracked, 9, flow("fd-9"));

        assert!(tracked.remove_close(&close_observation(8)).is_none());
        assert_eq!(
            tracked
                .remove_close(&close_observation(7))
                .expect("read-refreshed fd 7 should remain tracked")
                .flow
                .id,
            FlowIdentity("fd-7".to_string())
        );
        assert_eq!(
            tracked
                .remove_close(&close_observation(9))
                .expect("fd 9 should remain tracked")
                .flow
                .id,
            FlowIdentity("fd-9".to_string())
        );
    }

    #[test]
    fn tracked_flows_do_not_refresh_descriptor_on_unallowed_payload_direction() {
        let mut tracked = TrackedEbpfFlows::bounded(2);
        tracked.insert_connect(
            &connect_observation(7),
            flow("fd-7"),
            PayloadDirections::from_directions([Direction::Outbound]),
        );
        insert_connect(&mut tracked, 8, flow("fd-8"));

        assert!(tracked.get_read_mut(&read_observation(7)).is_none());
        insert_connect(&mut tracked, 9, flow("fd-9"));

        assert!(tracked.remove_close(&close_observation(7)).is_none());
        assert_eq!(
            tracked
                .remove_close(&close_observation(8))
                .expect("fd 8 should remain tracked")
                .flow
                .id,
            FlowIdentity("fd-8".to_string())
        );
        assert_eq!(
            tracked
                .remove_close(&close_observation(9))
                .expect("fd 9 should remain tracked")
                .flow
                .id,
            FlowIdentity("fd-9".to_string())
        );
    }

    fn connect_observation(fd: i32) -> EbpfConnectTracepointObservation {
        EbpfConnectTracepointObservation {
            process: observed_process(),
            fd,
            addrlen: 16,
            fd_table_epoch: 0,
            endpoint: EbpfConnectEndpoint::Remote(TcpEndpoint::new(
                Ipv4Addr::new(127, 0, 0, 1).into(),
                443,
            )),
        }
    }

    fn insert_connect(tracked: &mut TrackedEbpfFlows, fd: i32, flow: FlowContext) {
        tracked.insert_connect(
            &connect_observation(fd),
            flow,
            PayloadDirections::from_directions([Direction::Outbound, Direction::Inbound]),
        );
    }

    fn close_observation(fd: i32) -> EbpfCloseTracepointObservation {
        EbpfCloseTracepointObservation {
            process: observed_process(),
            fd,
        }
    }

    fn write_observation(fd: i32) -> EbpfSocketWriteObservation {
        EbpfSocketWriteObservation {
            process: observed_process(),
            fd,
            original_len: 5,
            buffer: b"hello".to_vec(),
            truncated: false,
            read_failed: false,
        }
    }

    fn read_observation(fd: i32) -> EbpfSocketReadObservation {
        EbpfSocketReadObservation {
            process: observed_process(),
            fd,
            original_len: 5,
            buffer: b"hello".to_vec(),
            truncated: false,
            read_failed: false,
        }
    }

    fn observed_process() -> EbpfObservedProcess {
        EbpfObservedProcess {
            pid: 101,
            tgid: 100,
            uid: 1000,
            gid: 1000,
            command: [0; 16],
        }
    }

    fn flow(id: &str) -> FlowContext {
        FlowContext {
            id: FlowIdentity(id.to_string()),
            process: ProcessContext {
                identity: ProcessIdentity {
                    pid: 100,
                    tgid: 100,
                    start_time_ticks: 1234,
                    boot_id: "boot".to_string(),
                    exe_path: "/usr/bin/curl".to_string(),
                    cmdline_hash: "cmd".to_string(),
                    uid: 1000,
                    gid: 1000,
                    cgroup: None,
                    systemd_service: None,
                    container_id: None,
                    runtime_hint: None,
                },
                name: "curl".to_string(),
                cmdline: vec!["curl".to_string()],
            },
            local: AddressPort {
                address: "127.0.0.1".to_string(),
                port: 50_000,
            },
            remote: AddressPort {
                address: "127.0.0.1".to_string(),
                port: 443,
            },
            protocol: TransportProtocol::Tcp,
            start_monotonic_ns: 1,
            socket_cookie: None,
            attribution_confidence: 90,
        }
    }
}
