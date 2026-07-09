use probe_core::{CompiledSelector, Direction, Timestamp};

use crate::{CaptureError, CaptureEvent};

use super::super::{
    EbpfObservedProcess, EbpfSocketFlowLookup, EbpfSocketFlowResolver,
    bridge::{opened_event_from_lookup, process_hint_from_observed},
    descriptor_lease::DescriptorLeaseKey,
    payload_authorization::payload_directions_for_flow,
    payload_bridge::recovered_payload_flow_boundary_gap_event,
    tracked_flow::{TrackedEbpfFlowDisplacement, TrackedEbpfFlows},
};

pub(super) struct PayloadFlowRecovery<'a> {
    tracked_flows: &'a mut TrackedEbpfFlows,
    resolver: &'a mut dyn EbpfSocketFlowResolver,
    selector: Option<&'a CompiledSelector>,
}

pub(super) struct PayloadFlowRecoveryOutcome {
    pub(super) prefix_events: Vec<CaptureEvent>,
    pub(super) displacement: Option<TrackedEbpfFlowDisplacement>,
}

impl<'a> PayloadFlowRecovery<'a> {
    pub(super) fn new(
        tracked_flows: &'a mut TrackedEbpfFlows,
        resolver: &'a mut dyn EbpfSocketFlowResolver,
        selector: Option<&'a CompiledSelector>,
    ) -> Self {
        Self {
            tracked_flows,
            resolver,
            selector,
        }
    }

    pub(super) fn recover(
        &mut self,
        key: Option<DescriptorLeaseKey>,
        direction: Direction,
        process: &EbpfObservedProcess,
        fd: i32,
        timestamp: Timestamp,
    ) -> Result<Option<PayloadFlowRecoveryOutcome>, CaptureError> {
        let Some(key) = key else {
            return Ok(None);
        };
        let Some(selector) = self.selector else {
            return Ok(None);
        };
        let Some(opened) = opened_event_from_lookup(
            EbpfSocketFlowLookup {
                tgid: process.tgid,
                thread_pid: process.pid,
                fd,
                expected_remote_endpoint: None,
                process_hint: process_hint_from_observed(process),
            },
            timestamp,
            self.resolver,
        )?
        else {
            return Ok(None);
        };
        let CaptureEvent::ConnectionOpened { flow, .. } = &opened else {
            return Ok(None);
        };
        let payload_directions = payload_directions_for_flow(flow, selector);
        if !payload_directions.allows(direction) {
            return Ok(None);
        }

        let displacement =
            self.tracked_flows
                .insert_recovered_flow(key, flow.clone(), payload_directions);
        let boundary_gap =
            recovered_payload_flow_boundary_gap_event(timestamp, flow.clone(), direction);
        Ok(Some(PayloadFlowRecoveryOutcome {
            prefix_events: vec![opened, boundary_gap],
            displacement,
        }))
    }
}
