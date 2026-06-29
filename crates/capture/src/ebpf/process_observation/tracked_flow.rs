use probe_core::{Direction, FlowContext};

use crate::bounded_recency::BoundedRecencyMap;

use super::{
    EbpfCloseRangeTracepointObservation, EbpfCloseTracepointObservation, EbpfSocketReadObservation,
    EbpfSocketWriteObservation,
    descriptor_lease::{DescriptorLease, DescriptorLeaseKey},
    payload_direction::PayloadDirections,
};

pub(super) struct TrackedEbpfFlows {
    by_lease: BoundedRecencyMap<DescriptorLeaseKey, TrackedEbpfFlow>,
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
            by_lease: BoundedRecencyMap::new(max_tracked_flows),
        }
    }

    pub(super) fn insert_flow(
        &mut self,
        lease: DescriptorLease,
        flow: FlowContext,
        payload_directions: PayloadDirections,
    ) {
        self.insert(lease.key(), flow, payload_directions);
    }

    pub(super) fn remove_close(
        &mut self,
        close: &EbpfCloseTracepointObservation,
    ) -> Option<TrackedEbpfFlow> {
        self.remove(DescriptorLeaseKey::from_close(close)?)
    }

    pub(super) fn remove_close_range(
        &mut self,
        close_range: &EbpfCloseRangeTracepointObservation,
    ) -> Vec<TrackedEbpfFlow> {
        let mut keys = self
            .by_lease
            .keys()
            .copied()
            .filter(|key| key.is_in_close_range(close_range))
            .collect::<Vec<_>>();
        keys.sort_by_key(|key| (key.fd(), key.fd_generation()));
        keys.into_iter()
            .filter_map(|key| self.remove(key))
            .collect()
    }

    pub(super) fn active_payload_loss_targets(&self) -> impl Iterator<Item = &TrackedEbpfFlow> {
        self.by_lease
            .values_by_recency()
            .filter(|tracked| !tracked.payload_directions.is_empty())
    }

    pub(super) fn get_write_mut(
        &mut self,
        write: &EbpfSocketWriteObservation,
    ) -> Option<&mut TrackedEbpfFlow> {
        self.get_recent_mut(DescriptorLeaseKey::from_write(write)?, Direction::Outbound)
    }

    pub(super) fn get_read_mut(
        &mut self,
        read: &EbpfSocketReadObservation,
    ) -> Option<&mut TrackedEbpfFlow> {
        self.get_recent_mut(DescriptorLeaseKey::from_read(read)?, Direction::Inbound)
    }

    fn insert(
        &mut self,
        key: DescriptorLeaseKey,
        flow: FlowContext,
        payload_directions: PayloadDirections,
    ) {
        self.by_lease.insert(
            key,
            TrackedEbpfFlow {
                flow,
                inbound_stream_offset: 0,
                outbound_stream_offset: 0,
                payload_directions,
            },
        );
    }

    fn remove(&mut self, key: DescriptorLeaseKey) -> Option<TrackedEbpfFlow> {
        self.by_lease.remove(&key)
    }

    fn get_recent_mut(
        &mut self,
        key: DescriptorLeaseKey,
        required_direction: Direction,
    ) -> Option<&mut TrackedEbpfFlow> {
        if !self
            .by_lease
            .get(&key)
            .is_some_and(|tracked| tracked.allows_payload(required_direction))
        {
            return None;
        }
        self.by_lease.refresh(&key);
        self.by_lease.get_mut(&key)
    }
}

impl TrackedEbpfFlow {
    fn allows_payload(&self, direction: Direction) -> bool {
        self.payload_directions.allows(direction)
    }

    pub(super) fn payload_directions(&self) -> PayloadDirections {
        self.payload_directions
    }
}

#[cfg(test)]
mod tests {
    use probe_core::{
        AddressPort, FlowContext, FlowIdentity, ProcessContext, ProcessIdentity, TransportProtocol,
    };

    use super::super::{
        EbpfCloseRangeTracepointObservation, EbpfCloseTracepointObservation, EbpfObservedProcess,
        EbpfSocketReadObservation, descriptor_lease::DescriptorLease,
    };
    use super::*;

    #[test]
    fn tracked_flows_evict_oldest_descriptor_when_capacity_is_exceeded() {
        let mut tracked = TrackedEbpfFlows::bounded(1);
        insert_flow_for_descriptor(&mut tracked, 7, flow("fd-7"));
        insert_flow_for_descriptor(&mut tracked, 8, flow("fd-8"));

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
        insert_flow_for_descriptor(&mut tracked, 7, flow("fd-7-first"));
        insert_flow_for_descriptor(&mut tracked, 8, flow("fd-8"));
        insert_flow_for_descriptor(&mut tracked, 7, flow("fd-7-second"));
        insert_flow_for_descriptor(&mut tracked, 9, flow("fd-9"));

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
        insert_flow_for_descriptor(&mut tracked, 7, flow("fd-7"));
        insert_flow_for_descriptor(&mut tracked, 8, flow("fd-8"));

        tracked
            .get_write_mut(&write_observation(7))
            .expect("fd 7 should be tracked");
        insert_flow_for_descriptor(&mut tracked, 9, flow("fd-9"));

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
        insert_flow_for_descriptor(&mut tracked, 7, flow("fd-7"));
        insert_flow_for_descriptor(&mut tracked, 8, flow("fd-8"));

        tracked
            .get_read_mut(&read_observation(7))
            .expect("fd 7 should be tracked");
        insert_flow_for_descriptor(&mut tracked, 9, flow("fd-9"));

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
        tracked.insert_flow(
            descriptor_lease(100, 7, 1),
            flow("fd-7"),
            PayloadDirections::from_directions([Direction::Outbound]),
        );
        insert_flow_for_descriptor(&mut tracked, 8, flow("fd-8"));

        assert!(tracked.get_read_mut(&read_observation(7)).is_none());
        insert_flow_for_descriptor(&mut tracked, 9, flow("fd-9"));

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

    #[test]
    fn tracked_flows_remove_close_range_for_same_process_descriptors_in_fd_order() {
        let mut tracked = TrackedEbpfFlows::bounded(4);
        insert_flow_for_descriptor(&mut tracked, 3, flow("fd-3"));
        insert_flow_for_descriptor(&mut tracked, 10, flow("fd-10"));
        insert_flow_for_descriptor(&mut tracked, 4, flow("fd-4"));
        insert_flow_for_process_descriptor(&mut tracked, 200, 4, flow("other-tgid-fd-4"));

        let removed = tracked.remove_close_range(&close_range_observation(4, 10));

        let removed_ids = removed
            .into_iter()
            .map(|tracked| tracked.flow.id)
            .collect::<Vec<_>>();
        assert_eq!(
            removed_ids,
            vec![
                FlowIdentity("fd-4".to_string()),
                FlowIdentity("fd-10".to_string())
            ]
        );
        assert_eq!(
            tracked
                .remove_close(&close_observation(3))
                .expect("fd 3 should remain tracked")
                .flow
                .id,
            FlowIdentity("fd-3".to_string())
        );
        assert_eq!(
            tracked
                .remove_close(&close_observation_for_process(200, 4))
                .expect("different TGID fd should remain tracked")
                .flow
                .id,
            FlowIdentity("other-tgid-fd-4".to_string())
        );
    }

    #[test]
    fn tracked_flows_bind_payload_and_close_to_descriptor_generation() {
        let mut tracked = TrackedEbpfFlows::bounded(4);
        insert_flow_for_descriptor_generation(&mut tracked, 7, 1, flow("fd-7-generation-1"));
        insert_flow_for_descriptor_generation(&mut tracked, 7, 2, flow("fd-7-generation-2"));

        assert_eq!(
            tracked
                .get_write_mut(&write_observation_with_generation(7, 1))
                .expect("generation 1 write should match generation 1 flow")
                .flow
                .id,
            FlowIdentity("fd-7-generation-1".to_string())
        );
        assert_eq!(
            tracked
                .remove_close(&close_observation_with_generation(7, 1))
                .expect("generation 1 close should only remove generation 1")
                .flow
                .id,
            FlowIdentity("fd-7-generation-1".to_string())
        );
        assert_eq!(
            tracked
                .remove_close(&close_observation_with_generation(7, 2))
                .expect("generation 2 flow should remain after generation 1 close")
                .flow
                .id,
            FlowIdentity("fd-7-generation-2".to_string())
        );
    }

    fn insert_flow_for_descriptor(tracked: &mut TrackedEbpfFlows, fd: i32, flow: FlowContext) {
        insert_flow_for_descriptor_generation(tracked, fd, 1, flow);
    }

    fn insert_flow_for_descriptor_generation(
        tracked: &mut TrackedEbpfFlows,
        fd: i32,
        fd_generation: u64,
        flow: FlowContext,
    ) {
        insert_flow_for_process_descriptor_generation(tracked, 100, fd, fd_generation, flow);
    }

    fn insert_flow_for_process_descriptor(
        tracked: &mut TrackedEbpfFlows,
        tgid: u32,
        fd: i32,
        flow: FlowContext,
    ) {
        insert_flow_for_process_descriptor_generation(tracked, tgid, fd, 1, flow);
    }

    fn insert_flow_for_process_descriptor_generation(
        tracked: &mut TrackedEbpfFlows,
        tgid: u32,
        fd: i32,
        fd_generation: u64,
        flow: FlowContext,
    ) {
        tracked.insert_flow(
            descriptor_lease(tgid, fd, fd_generation),
            flow,
            PayloadDirections::from_directions([Direction::Outbound, Direction::Inbound]),
        );
    }

    fn descriptor_lease(tgid: u32, fd: i32, fd_generation: u64) -> DescriptorLease {
        DescriptorLease::new(tgid, fd, 1, fd_generation)
            .expect("test descriptor lease should be valid")
    }

    fn close_observation(fd: i32) -> EbpfCloseTracepointObservation {
        close_observation_with_generation(fd, 1)
    }

    fn close_observation_for_process(tgid: u32, fd: i32) -> EbpfCloseTracepointObservation {
        close_observation_for_process_generation(tgid, fd, 1)
    }

    fn close_observation_with_generation(
        fd: i32,
        fd_generation: u64,
    ) -> EbpfCloseTracepointObservation {
        close_observation_for_process_generation(100, fd, fd_generation)
    }

    fn close_observation_for_process_generation(
        tgid: u32,
        fd: i32,
        fd_generation: u64,
    ) -> EbpfCloseTracepointObservation {
        EbpfCloseTracepointObservation {
            process: observed_process_for_tgid(tgid),
            fd,
            fd_generation,
        }
    }

    fn close_range_observation(first_fd: u32, last_fd: u32) -> EbpfCloseRangeTracepointObservation {
        EbpfCloseRangeTracepointObservation {
            process: observed_process(),
            first_fd,
            last_fd,
        }
    }

    fn write_observation(fd: i32) -> EbpfSocketWriteObservation {
        write_observation_with_generation(fd, 1)
    }

    fn write_observation_with_generation(
        fd: i32,
        fd_generation: u64,
    ) -> EbpfSocketWriteObservation {
        EbpfSocketWriteObservation {
            process: observed_process(),
            fd,
            fd_generation,
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
            fd_generation: 1,
            original_len: 5,
            buffer: b"hello".to_vec(),
            truncated: false,
            read_failed: false,
        }
    }

    fn observed_process() -> EbpfObservedProcess {
        observed_process_for_tgid(100)
    }

    fn observed_process_for_tgid(tgid: u32) -> EbpfObservedProcess {
        EbpfObservedProcess {
            pid: tgid.saturating_add(1),
            tgid,
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
