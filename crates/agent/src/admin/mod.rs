mod client;
mod debug_dump;
mod event_tail;
mod prometheus;
mod protocol;
mod reload;
mod server;
mod socket;

pub(crate) use client::{
    AdminClientError, send_admin_json_request, send_admin_json_request_with_timeout,
};
#[cfg(test)]
pub(crate) use event_tail::EventTailOmissionReason;
pub(crate) use event_tail::{
    EventDetailSnapshot, EventDetailTooLargeSnapshot, EventTailAttributionMode,
    EventTailBudgetSnapshot, EventTailEvent, EventTailKind, EventTailOmission, EventTailRecord,
    EventTailSnapshot, UnknownProcessCandidateSelector, default_tail_scan_limit,
};
pub(crate) use protocol::AdminRequest;
pub(crate) use server::{AdminRuntimeState, AdminServerHandle, spawn_admin_server};
pub(crate) use socket::{AdminError, AdminServerConfig, PrometheusListenerConfig};
