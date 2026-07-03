use std::time::Instant;

use probe_core::Timestamp;

use crate::{CaptureError, CaptureEvent};

use super::{
    EbpfAcceptTracepointObservation, EbpfConnectTracepointObservation, EbpfProcessLifecycleKind,
    EbpfSocketFlowResolver, accept_opened_event_from_observation,
    connect_opened_event_from_observation, descriptor_lease::DescriptorLease,
    observed_accept_opened_event_from_observation, observed_connect_opened_event_from_observation,
    unresolved_accept_gap_from_observation, unresolved_connect_gap_from_observation,
};

pub(super) struct PendingEbpfFlowResolution {
    pub(super) flow_start: PendingEbpfFlowStart,
    pub(super) timestamp: Timestamp,
    pub(super) attempts_completed: u32,
    pub(super) retry_at: Option<Instant>,
}

impl PendingEbpfFlowResolution {
    pub(super) fn new(flow_start: PendingEbpfFlowStart, timestamp: Timestamp) -> Self {
        Self {
            flow_start,
            timestamp,
            attempts_completed: 0,
            retry_at: None,
        }
    }
}

pub(super) enum PendingEbpfFlowStart {
    Connect(EbpfConnectTracepointObservation),
    Accept(EbpfAcceptTracepointObservation),
}

impl PendingEbpfFlowStart {
    pub(super) fn opened_event(
        &self,
        timestamp: Timestamp,
        resolver: &mut dyn EbpfSocketFlowResolver,
    ) -> Result<Option<CaptureEvent>, CaptureError> {
        match self {
            Self::Connect(connect) => {
                connect_opened_event_from_observation(connect, timestamp, resolver)
            }
            Self::Accept(accept) => {
                accept_opened_event_from_observation(accept, timestamp, resolver)
            }
        }
    }

    pub(super) fn observed_opened_event(
        &self,
        timestamp: Timestamp,
        resolver: &mut dyn EbpfSocketFlowResolver,
    ) -> Option<CaptureEvent> {
        let resolved_process = resolver.resolve_process(self.tgid()).ok().flatten();
        match self {
            Self::Connect(connect) => {
                observed_connect_opened_event_from_observation(connect, timestamp, resolved_process)
            }
            Self::Accept(accept) => {
                observed_accept_opened_event_from_observation(accept, timestamp, resolved_process)
            }
        }
    }

    pub(super) fn unresolved_gap(
        &self,
        timestamp: Timestamp,
        reason: String,
        resolver: &mut dyn EbpfSocketFlowResolver,
    ) -> CaptureEvent {
        let resolved_process = resolver.resolve_process(self.tgid()).ok().flatten();
        match self {
            Self::Connect(connect) => unresolved_connect_gap_from_observation(
                connect,
                timestamp,
                reason,
                resolved_process,
            ),
            Self::Accept(accept) => {
                unresolved_accept_gap_from_observation(accept, timestamp, reason, resolved_process)
            }
        }
    }

    pub(super) fn unresolved_reason(&self, attempts: u32) -> String {
        match self {
            Self::Connect(connect) => format!(
                "eBPF connect observation could not be resolved to a procfs socket after {attempts} attempt(s); tgid={}, thread_pid={}, fd={}",
                connect.process.tgid, connect.process.pid, connect.fd
            ),
            Self::Accept(accept) => format!(
                "eBPF accept observation could not be resolved to a procfs socket after {attempts} attempt(s); tgid={}, thread_pid={}, fd={}, listen_fd={}",
                accept.process.tgid, accept.process.pid, accept.fd, accept.listen_fd
            ),
        }
    }

    pub(super) fn invalid_descriptor_lease_gap(
        &self,
        timestamp: Timestamp,
        resolver: &mut dyn EbpfSocketFlowResolver,
    ) -> CaptureEvent {
        self.unresolved_gap(timestamp, self.invalid_descriptor_lease_reason(), resolver)
    }

    pub(super) fn lifecycle_boundary_gap(
        &self,
        timestamp: Timestamp,
        kind: EbpfProcessLifecycleKind,
        resolver: &mut dyn EbpfSocketFlowResolver,
    ) -> CaptureEvent {
        self.unresolved_gap(
            timestamp,
            format!(
                "eBPF flow-start observation was abandoned because {} invalidated the fd-table epoch before procfs socket resolution completed; tgid={}, thread_pid={}, fd={}",
                kind.boundary_description(),
                self.tgid(),
                self.thread_pid(),
                self.fd()
            ),
            resolver,
        )
    }

    pub(super) fn descriptor_lease(&self) -> Option<DescriptorLease> {
        DescriptorLease::new(
            self.tgid(),
            self.fd(),
            self.fd_table_epoch(),
            self.fd_generation(),
        )
    }

    fn invalid_descriptor_lease_reason(&self) -> String {
        format!(
            "eBPF flow-start observation did not carry a valid descriptor lease; tgid={}, thread_pid={}, fd={}, fd_table_epoch={}, fd_generation={}",
            self.tgid(),
            self.thread_pid(),
            self.fd(),
            self.fd_table_epoch(),
            self.fd_generation()
        )
    }

    fn thread_pid(&self) -> u32 {
        match self {
            Self::Connect(connect) => connect.process.pid,
            Self::Accept(accept) => accept.process.pid,
        }
    }

    pub(super) fn tgid(&self) -> u32 {
        match self {
            Self::Connect(connect) => connect.process.tgid,
            Self::Accept(accept) => accept.process.tgid,
        }
    }

    pub(super) fn fd(&self) -> i32 {
        match self {
            Self::Connect(connect) => connect.fd,
            Self::Accept(accept) => accept.fd,
        }
    }

    fn fd_table_epoch(&self) -> u64 {
        match self {
            Self::Connect(connect) => connect.fd_table_epoch,
            Self::Accept(accept) => accept.fd_table_epoch,
        }
    }

    fn fd_generation(&self) -> u64 {
        match self {
            Self::Connect(connect) => connect.fd_generation,
            Self::Accept(accept) => accept.fd_generation,
        }
    }
}
