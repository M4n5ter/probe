use probe_core::{Direction, FlowContext};

use crate::bounded_recency::{BoundedInsertDisplacement, BoundedRecencyMap};

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

pub(super) enum TrackedEbpfFlowDisplacement {
    Replaced {
        key: DescriptorLeaseKey,
        tracked: TrackedEbpfFlow,
    },
    Evicted {
        key: DescriptorLeaseKey,
        tracked: TrackedEbpfFlow,
    },
    Dropped {
        key: DescriptorLeaseKey,
        tracked: TrackedEbpfFlow,
    },
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
    ) -> Option<TrackedEbpfFlowDisplacement> {
        self.insert(lease.key(), flow, payload_directions)
    }

    pub(super) fn remove_close(
        &mut self,
        close: &EbpfCloseTracepointObservation,
    ) -> Option<TrackedEbpfFlow> {
        if let Some(key) = DescriptorLeaseKey::from_close(close)
            && let Some(tracked) = self.remove(key)
        {
            return Some(tracked);
        }
        None
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

    pub(super) fn active_payload_gap_targets_for_tgid(&self, tgid: u32) -> Vec<&TrackedEbpfFlow> {
        let mut keys = self
            .by_lease
            .keys()
            .copied()
            .filter(|key| key.tgid() == tgid)
            .collect::<Vec<_>>();
        keys.sort_by_key(|key| (key.fd(), key.fd_generation()));
        keys.into_iter()
            .filter_map(|key| self.by_lease.get(&key))
            .filter(|tracked| !tracked.payload_directions.is_empty())
            .collect()
    }

    pub(super) fn active_payload_gap_targets(&self) -> impl Iterator<Item = &TrackedEbpfFlow> {
        self.by_lease
            .values_by_recency()
            .filter(|tracked| !tracked.payload_directions.is_empty())
    }

    pub(super) fn has_active_payload_gap_targets(&self) -> bool {
        self.by_lease
            .values_by_recency()
            .any(|tracked| !tracked.payload_directions.is_empty())
    }

    pub(super) fn has_payload_allowance_for_allow_map_key(&self, key: DescriptorLeaseKey) -> bool {
        self.by_lease.keys().any(|tracked_key| {
            tracked_key.has_same_allow_map_key(key)
                && self
                    .by_lease
                    .get(tracked_key)
                    .is_some_and(TrackedEbpfFlow::has_payload_allowance)
        })
    }

    pub(super) fn get_write_mut(
        &mut self,
        write: &EbpfSocketWriteObservation,
    ) -> Option<&mut TrackedEbpfFlow> {
        if let Some(key) = DescriptorLeaseKey::from_write(write)
            && self.has_exact_payload_match(key, Direction::Outbound)
        {
            return self.refresh_and_get_mut(key);
        }
        None
    }

    pub(super) fn get_read_mut(
        &mut self,
        read: &EbpfSocketReadObservation,
    ) -> Option<&mut TrackedEbpfFlow> {
        if let Some(key) = DescriptorLeaseKey::from_read(read)
            && self.has_exact_payload_match(key, Direction::Inbound)
        {
            return self.refresh_and_get_mut(key);
        }
        None
    }

    fn insert(
        &mut self,
        key: DescriptorLeaseKey,
        flow: FlowContext,
        payload_directions: PayloadDirections,
    ) -> Option<TrackedEbpfFlowDisplacement> {
        let tracked = TrackedEbpfFlow {
            flow,
            inbound_stream_offset: 0,
            outbound_stream_offset: 0,
            payload_directions,
        };
        self.by_lease
            .insert_displacing(key, tracked)
            .map(TrackedEbpfFlowDisplacement::from_bounded)
    }

    fn remove(&mut self, key: DescriptorLeaseKey) -> Option<TrackedEbpfFlow> {
        self.by_lease.remove(&key)
    }

    fn has_exact_payload_match(
        &self,
        key: DescriptorLeaseKey,
        required_direction: Direction,
    ) -> bool {
        self.by_lease
            .get(&key)
            .is_some_and(|tracked| tracked.allows_payload(required_direction))
    }

    fn refresh_and_get_mut(&mut self, key: DescriptorLeaseKey) -> Option<&mut TrackedEbpfFlow> {
        self.by_lease.refresh(&key);
        self.by_lease.get_mut(&key)
    }
}

impl TrackedEbpfFlowDisplacement {
    fn from_bounded(
        displacement: BoundedInsertDisplacement<DescriptorLeaseKey, TrackedEbpfFlow>,
    ) -> Self {
        match displacement {
            BoundedInsertDisplacement::Replaced {
                key,
                value: tracked,
            } => Self::Replaced { key, tracked },
            BoundedInsertDisplacement::Evicted {
                key,
                value: tracked,
            } => Self::Evicted { key, tracked },
            BoundedInsertDisplacement::Dropped {
                key,
                value: tracked,
            } => Self::Dropped { key, tracked },
        }
    }

    pub(super) fn key(&self) -> DescriptorLeaseKey {
        match self {
            Self::Replaced { key, .. } | Self::Evicted { key, .. } | Self::Dropped { key, .. } => {
                *key
            }
        }
    }

    pub(super) fn into_tracked_flow(self) -> TrackedEbpfFlow {
        match self {
            Self::Replaced { tracked, .. }
            | Self::Evicted { tracked, .. }
            | Self::Dropped { tracked, .. } => tracked,
        }
    }

    pub(super) fn reason(&self) -> &'static str {
        match self {
            Self::Replaced { .. } => {
                "eBPF process observation replaced an existing descriptor lease with a newer flow observation; affected bytes and next stream offset are unknown"
            }
            Self::Evicted { .. } => {
                "eBPF process observation userspace flow tracker evicted this flow because tracked-flow capacity was exceeded; affected bytes and next stream offset are unknown"
            }
            Self::Dropped { .. } => {
                "eBPF process observation could not track this flow because tracked-flow capacity is zero; affected bytes and next stream offset are unknown"
            }
        }
    }

    pub(super) fn should_revoke_allow_map_key(&self, retained_payload_allowance: bool) -> bool {
        self.tracked_flow().has_payload_allowance() && !retained_payload_allowance
    }

    fn tracked_flow(&self) -> &TrackedEbpfFlow {
        match self {
            Self::Replaced { tracked, .. }
            | Self::Evicted { tracked, .. }
            | Self::Dropped { tracked, .. } => tracked,
        }
    }
}

impl TrackedEbpfFlow {
    fn allows_payload(&self, direction: Direction) -> bool {
        self.payload_directions.allows(direction)
    }

    fn has_payload_allowance(&self) -> bool {
        !self.payload_directions.is_empty()
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
        assert!(
            tracked
                .insert_flow(
                    descriptor_lease(100, 7, 1),
                    flow("fd-7"),
                    PayloadDirections::from_directions([Direction::Outbound]),
                )
                .is_none()
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
    fn tracked_flows_find_process_payload_targets_in_fd_order_without_removing_them() {
        let mut tracked = TrackedEbpfFlows::bounded(4);
        insert_flow_for_descriptor(&mut tracked, 10, flow("fd-10"));
        insert_flow_for_descriptor(&mut tracked, 4, flow("fd-4"));
        insert_flow_for_process_descriptor(&mut tracked, 200, 4, flow("other-tgid-fd-4"));
        insert_flow_for_descriptor(&mut tracked, 3, flow("fd-3"));

        let targets = tracked.active_payload_gap_targets_for_tgid(100);

        let target_ids = targets
            .into_iter()
            .map(|tracked| tracked.flow.id.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            target_ids,
            vec![
                FlowIdentity("fd-3".to_string()),
                FlowIdentity("fd-4".to_string()),
                FlowIdentity("fd-10".to_string())
            ]
        );
        assert_eq!(
            tracked
                .remove_close(&close_observation(3))
                .expect("matching TGID fd should remain tracked")
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

    #[test]
    fn tracked_flows_do_not_match_payload_without_exact_descriptor_generation() {
        let mut tracked = TrackedEbpfFlows::bounded(4);
        insert_flow_for_descriptor_generation(&mut tracked, 7, 10, flow("fd-7"));

        let stale_other_tgid = read_observation_for_process_generation(
            observed_process_for_tgid_named(200, "curl"),
            7,
            1,
        );

        assert!(tracked.get_read_mut(&stale_other_tgid).is_none());
    }

    #[test]
    fn tracked_flows_do_not_use_process_hint_alias_for_same_tgid_generation_mismatch() {
        let mut tracked = TrackedEbpfFlows::bounded(4);
        insert_flow_for_descriptor_generation(&mut tracked, 7, 10, flow("fd-7-generation-10"));

        let stale_same_tgid = read_observation_for_process_generation(
            observed_process_for_tgid_named(100, "curl"),
            7,
            1,
        );

        assert!(tracked.get_read_mut(&stale_same_tgid).is_none());
    }

    #[test]
    fn tracked_flows_do_not_close_without_exact_descriptor_generation() {
        let mut tracked = TrackedEbpfFlows::bounded(4);
        insert_flow_for_descriptor_generation(&mut tracked, 7, 10, flow("fd-7"));

        let stale_other_tgid = close_observation_for_process_generation_named(200, 7, 1, "curl");

        assert!(tracked.remove_close(&stale_other_tgid).is_none());
        assert_eq!(
            tracked
                .remove_close(&close_observation_with_generation(7, 10))
                .expect("exact generation should remain tracked")
                .flow
                .id,
            FlowIdentity("fd-7".to_string())
        );
    }

    #[test]
    fn tracked_flows_do_not_close_with_process_hint_alias_for_same_tgid_generation_mismatch() {
        let mut tracked = TrackedEbpfFlows::bounded(4);
        insert_flow_for_descriptor_generation(&mut tracked, 7, 10, flow("fd-7-generation-10"));

        let stale_same_tgid = close_observation_for_process_generation_named(100, 7, 1, "curl");

        assert!(tracked.remove_close(&stale_same_tgid).is_none());
        assert_eq!(
            tracked
                .remove_close(&close_observation_with_generation(7, 10))
                .expect("exact generation should remain tracked")
                .flow
                .id,
            FlowIdentity("fd-7-generation-10".to_string())
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
        let _ = tracked.insert_flow(
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
            kernel_transfer: false,
        }
    }

    fn read_observation(fd: i32) -> EbpfSocketReadObservation {
        read_observation_for_process_generation(observed_process(), fd, 1)
    }

    fn read_observation_for_process_generation(
        process: EbpfObservedProcess,
        fd: i32,
        fd_generation: u64,
    ) -> EbpfSocketReadObservation {
        EbpfSocketReadObservation {
            process,
            fd,
            fd_generation,
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
        observed_process_for_tgid_named(tgid, "")
    }

    fn observed_process_for_tgid_named(tgid: u32, name: &str) -> EbpfObservedProcess {
        EbpfObservedProcess {
            pid: tgid.saturating_add(1),
            tgid,
            uid: 1000,
            gid: 1000,
            command: nul_padded_command(name),
        }
    }

    fn close_observation_for_process_generation_named(
        tgid: u32,
        fd: i32,
        fd_generation: u64,
        name: &str,
    ) -> EbpfCloseTracepointObservation {
        EbpfCloseTracepointObservation {
            process: observed_process_for_tgid_named(tgid, name),
            fd,
            fd_generation,
        }
    }

    fn nul_padded_command(name: &str) -> [u8; 16] {
        let mut command = [0; 16];
        for (slot, byte) in command.iter_mut().zip(name.bytes()) {
            *slot = byte;
        }
        command
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
