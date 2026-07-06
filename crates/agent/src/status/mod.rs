mod capabilities;
mod capture;
mod enforcement;
mod export;
mod health;
mod metrics;
#[cfg(test)]
mod plan_fixture;
mod policy;
mod prometheus;
mod snapshot;
mod spool;
mod tls;

pub(crate) const TRAFFIC_STATUS_REASON_MAX_CHARS: usize = 2048;

pub(crate) use capture::{
    CaptureCandidateStatusSnapshot, CaptureOpenFailureStatusSnapshot, CaptureStatusSnapshot,
    EbpfExpectedContractStatusSnapshot,
};
pub(crate) use enforcement::{EnforcementStatusMode, EnforcementStatusSnapshot};
pub(crate) use metrics::MetricsSnapshot;
pub(crate) use prometheus::{PROMETHEUS_TEXT_CONTENT_TYPE, render_prometheus_metrics};
pub(crate) use snapshot::{
    AgentStatusSnapshot, EnforcementRuntimeStatusInput, RuntimeStatusInput,
    TrafficRuntimeStatusInput, TrafficStatusProjection, build_status_snapshot,
    build_status_snapshot_with_runtime, build_traffic_status_projection,
    build_traffic_status_projection_with_runtime,
};
pub(crate) use spool::{collect_running_spool_status, collect_spool_status};
pub(crate) use tls::TlsStatusSnapshot;

#[cfg(test)]
pub(crate) fn enforcement_status_with_transparent_proxy_for_test(
    plan: &runtime::RuntimePlan,
    l7_mitm: Option<crate::l7_mitm::L7MitmRuntimeSnapshot>,
    transparent_proxy: Option<crate::transparent_interception::TransparentProxyRuntimeSnapshot>,
) -> EnforcementStatusSnapshot {
    enforcement::enforcement_status_with_transparent_proxy(plan, l7_mitm, transparent_proxy)
}
