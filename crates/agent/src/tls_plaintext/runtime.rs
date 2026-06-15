use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use attribution::ProcfsSocketResolver;
use capture::{
    CaptureError, CaptureProvider, LibsslResolvedFlow, LibsslUprobeAttachTargetSnapshot,
    LibsslUprobeFlowLookup, LibsslUprobeFlowResolver, LibsslUprobePlaintextOpen,
    LibsslUprobePlaintextProbeConfig, LibsslUprobePlaintextProvider,
    LibsslUprobePlaintextReconcile, LibsslUprobeReconcileTargetBucket,
};
use probe_core::TcpConnection;
use runtime::RuntimePlan;
use serde::Serialize;

use crate::error::AgentError;

use super::{
    planning::LibsslUprobeAttachPlanner,
    sidecar::{LibsslUprobePlaintextReconcileObserver, LibsslUprobePlaintextSidecar},
};

const MAX_TRACKED_LIBSSL_FLOWS: usize = 8192;

#[derive(Debug, Clone)]
pub(crate) struct TlsPlaintextRuntimeState {
    inner: Arc<Mutex<TlsPlaintextRuntimeSnapshot>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsPlaintextRuntimeSnapshot {
    pub mode: TlsPlaintextRuntimeMode,
    pub reason: Option<String>,
    pub last_reconcile: Option<TlsPlaintextReconcileRuntimeSnapshot>,
}

impl TlsPlaintextRuntimeSnapshot {
    pub(crate) fn not_configured() -> Self {
        Self {
            mode: TlsPlaintextRuntimeMode::NotConfigured,
            reason: None,
            last_reconcile: None,
        }
    }

    pub(crate) fn enabled() -> Self {
        Self {
            mode: TlsPlaintextRuntimeMode::Enabled,
            reason: None,
            last_reconcile: None,
        }
    }

    pub(crate) fn disabled(reason: impl Into<String>) -> Self {
        Self {
            mode: TlsPlaintextRuntimeMode::Disabled,
            reason: Some(reason.into()),
            last_reconcile: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsPlaintextReconcileRuntimeSnapshot {
    pub sequence: u64,
    pub observed_unix_ns: u64,
    pub target_counts: TlsPlaintextReconcileTargetCountsRuntimeSnapshot,
    pub targets: TlsPlaintextReconcileTargetsRuntimeSnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TlsPlaintextReconcileTargetCountsRuntimeSnapshot {
    pub attached: u64,
    pub detached: u64,
    pub active: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsPlaintextReconcileTargetsRuntimeSnapshot {
    pub attached: TlsPlaintextReconcileTargetBucketRuntimeSnapshot,
    pub detached: TlsPlaintextReconcileTargetBucketRuntimeSnapshot,
    pub active: TlsPlaintextReconcileTargetBucketRuntimeSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsPlaintextReconcileTargetBucketRuntimeSnapshot {
    pub targets: Vec<TlsPlaintextReconcileTargetRuntimeSnapshot>,
    pub omitted: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsPlaintextReconcileTargetRuntimeSnapshot {
    pub pid: u32,
    pub start_time_ticks: u64,
    pub mapped_path: std::path::PathBuf,
    pub read_path: std::path::PathBuf,
    pub device_major: u32,
    pub device_minor: u32,
    pub inode: u64,
    pub deleted: bool,
}

impl TlsPlaintextReconcileRuntimeSnapshot {
    fn from_reconcile_success(
        result: LibsslUprobePlaintextReconcile,
        sequence: u64,
        observed_unix_ns: u64,
    ) -> Self {
        Self {
            sequence,
            observed_unix_ns,
            target_counts: TlsPlaintextReconcileTargetCountsRuntimeSnapshot {
                attached: result.attached_target_count() as u64,
                detached: result.detached_target_count() as u64,
                active: result.active_target_count() as u64,
            },
            targets: TlsPlaintextReconcileTargetsRuntimeSnapshot {
                attached: target_bucket(result.attached_targets),
                detached: target_bucket(result.detached_targets),
                active: target_bucket(result.active_targets),
            },
        }
    }
}

fn target_bucket(
    bucket: LibsslUprobeReconcileTargetBucket,
) -> TlsPlaintextReconcileTargetBucketRuntimeSnapshot {
    let omitted = bucket.omitted_count();
    let targets = bucket
        .into_targets()
        .into_iter()
        .map(TlsPlaintextReconcileTargetRuntimeSnapshot::from)
        .collect::<Vec<_>>();
    TlsPlaintextReconcileTargetBucketRuntimeSnapshot {
        omitted: omitted as u64,
        targets,
    }
}

impl From<LibsslUprobeAttachTargetSnapshot> for TlsPlaintextReconcileTargetRuntimeSnapshot {
    fn from(target: LibsslUprobeAttachTargetSnapshot) -> Self {
        Self {
            pid: target.pid,
            start_time_ticks: target.start_time_ticks,
            mapped_path: target.mapped_path,
            read_path: target.read_path,
            device_major: target.device_major,
            device_minor: target.device_minor,
            inode: target.inode,
            deleted: target.deleted,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsPlaintextRuntimeMode {
    Pending,
    NotConfigured,
    Enabled,
    Disabled,
}

impl TlsPlaintextRuntimeState {
    pub(crate) fn for_plan(plan: &RuntimePlan) -> Self {
        if plan.tls.plaintext.instrumentation.enabled {
            return Self::pending();
        }
        Self::not_configured()
    }

    fn pending() -> Self {
        Self::from_snapshot(TlsPlaintextRuntimeSnapshot {
            mode: TlsPlaintextRuntimeMode::Pending,
            reason: Some("TLS plaintext instrumentation has not been built yet".to_string()),
            last_reconcile: None,
        })
    }

    fn not_configured() -> Self {
        Self::from_snapshot(TlsPlaintextRuntimeSnapshot::not_configured())
    }

    fn from_snapshot(snapshot: TlsPlaintextRuntimeSnapshot) -> Self {
        Self {
            inner: Arc::new(Mutex::new(snapshot)),
        }
    }

    pub(crate) fn record_instrumentation_build(&self, build: &TlsPlaintextInstrumentationBuild) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *inner = build.runtime_snapshot();
    }

    pub(crate) fn record_instrumentation_disabled(&self, reason: impl Into<String>) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *inner = TlsPlaintextRuntimeSnapshot {
            mode: TlsPlaintextRuntimeMode::Disabled,
            reason: Some(reason.into()),
            last_reconcile: inner.last_reconcile.clone(),
        };
    }

    fn record_reconcile_success(&self, result: LibsslUprobePlaintextReconcile) {
        self.record_reconcile_success_at(result, current_unix_time_ns());
    }

    fn record_reconcile_success_at(
        &self,
        result: LibsslUprobePlaintextReconcile,
        observed_unix_ns: u64,
    ) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let sequence = inner
            .last_reconcile
            .as_ref()
            .map_or(1, |last| last.sequence.saturating_add(1));
        *inner = TlsPlaintextRuntimeSnapshot {
            mode: TlsPlaintextRuntimeMode::Enabled,
            reason: None,
            last_reconcile: Some(
                TlsPlaintextReconcileRuntimeSnapshot::from_reconcile_success(
                    result,
                    sequence,
                    observed_unix_ns,
                ),
            ),
        };
    }

    pub(crate) fn snapshot(&self) -> TlsPlaintextRuntimeSnapshot {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

pub(crate) fn build_tls_plaintext_instrumentation(
    plan: &RuntimePlan,
    runtime_state: Option<&TlsPlaintextRuntimeState>,
) -> Result<TlsPlaintextInstrumentationBuild, AgentError> {
    if !plan.tls.plaintext.instrumentation.enabled {
        return Ok(TlsPlaintextInstrumentationBuild::NotConfigured);
    }

    build_libssl_uprobe_plaintext_provider(plan, runtime_state)
}

fn build_libssl_uprobe_plaintext_provider(
    plan: &RuntimePlan,
    runtime_state: Option<&TlsPlaintextRuntimeState>,
) -> Result<TlsPlaintextInstrumentationBuild, AgentError> {
    plan.require_live_capture()?;
    let object_path = plan
        .tls
        .plaintext
        .instrumentation
        .libssl_uprobe_object_path
        .clone()
        .ok_or_else(|| {
            AgentError::UnsupportedRunConfig(
                "libssl uprobe TLS plaintext requires tls.plaintext.instrumentation.libssl_uprobe_object_path"
                    .to_string(),
            )
        })?;
    let selector = plan
        .config
        .tls
        .plaintext
        .instrumentation
        .selector
        .as_ref()
        .map(|selector| selector.compile())
        .transpose()
        .map_err(|source| {
            AgentError::UnsupportedRunConfig(format!(
                "invalid tls.plaintext.instrumentation.selector during runtime build: {source}"
            ))
        })?;
    let attach_planner = LibsslUprobeAttachPlanner::new(selector);
    let attach_plan = match attach_planner.plan()? {
        Ok(plan) => plan,
        Err(blocked) => {
            return Ok(TlsPlaintextInstrumentationBuild::disabled(
                blocked.into_reason(),
            ));
        }
    };

    match LibsslUprobePlaintextProvider::open_best_effort(
        LibsslUprobePlaintextProbeConfig::new(object_path, attach_plan),
        Box::<ProcfsLibsslFlowResolver>::default(),
    ) {
        LibsslUprobePlaintextOpen::Enabled(provider) => {
            Ok(TlsPlaintextInstrumentationBuild::enabled(
                provider,
                attach_planner,
                Duration::from_millis(plan.tls.plaintext.instrumentation.reconcile_interval_ms),
                runtime_state.cloned().map(|state| {
                    Box::new(state) as Box<dyn LibsslUprobePlaintextReconcileObserver>
                }),
            ))
        }
        LibsslUprobePlaintextOpen::Disabled { reason } => {
            Ok(TlsPlaintextInstrumentationBuild::disabled(reason))
        }
    }
}

pub(crate) enum TlsPlaintextInstrumentationBuild {
    NotConfigured,
    Enabled(Box<dyn CaptureProvider>),
    Disabled { reason: String },
}

impl TlsPlaintextInstrumentationBuild {
    fn enabled(
        provider: LibsslUprobePlaintextProvider,
        attach_planner: LibsslUprobeAttachPlanner,
        reconcile_interval: Duration,
        reconcile_observer: Option<Box<dyn LibsslUprobePlaintextReconcileObserver>>,
    ) -> Self {
        Self::Enabled(Box::new(LibsslUprobePlaintextSidecar::after(
            provider,
            attach_planner,
            reconcile_interval,
            reconcile_observer,
        )))
    }

    fn disabled(reason: impl Into<String>) -> Self {
        Self::Disabled {
            reason: reason.into(),
        }
    }

    fn runtime_snapshot(&self) -> TlsPlaintextRuntimeSnapshot {
        match self {
            Self::NotConfigured => TlsPlaintextRuntimeSnapshot::not_configured(),
            Self::Enabled(_) => TlsPlaintextRuntimeSnapshot::enabled(),
            Self::Disabled { reason } => TlsPlaintextRuntimeSnapshot::disabled(reason.clone()),
        }
    }
}

impl LibsslUprobePlaintextReconcileObserver for TlsPlaintextRuntimeState {
    fn record_reconcile_success(&self, result: LibsslUprobePlaintextReconcile) {
        TlsPlaintextRuntimeState::record_reconcile_success(self, result);
    }
}

fn current_unix_time_ns() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    u64::try_from(nanos).unwrap_or(u64::MAX)
}

#[derive(Default)]
struct ProcfsLibsslFlowResolver {
    resolver: ProcfsSocketResolver,
    starts: TrackedLibsslFlowStarts,
}

impl LibsslUprobeFlowResolver for ProcfsLibsslFlowResolver {
    fn resolve_libssl_uprobe_flow(
        &mut self,
        lookup: LibsslUprobeFlowLookup,
    ) -> Result<Option<LibsslResolvedFlow>, CaptureError> {
        let Some(fd) = lookup.fd else {
            return Ok(None);
        };
        self.resolver
            .resolve_tcp_fd(attribution::SocketFdLookup {
                tgid: lookup.tgid,
                thread_pid: lookup.thread_pid,
                fd,
                expected_remote_endpoint: None,
            })
            .map(|resolved| {
                resolved.map(|resolved| {
                    let key = LibsslFlowStartKey {
                        pid: resolved.process.identity.pid,
                        start_time_ticks: resolved.process.identity.start_time_ticks,
                        ssl_pointer: lookup.ssl_pointer,
                        connection: resolved.connection,
                    };
                    LibsslResolvedFlow {
                        process: resolved.process,
                        confidence: resolved.confidence,
                        connection: resolved.connection,
                        start_monotonic_ns: self.starts.start_for(key),
                    }
                })
            })
            .map_err(|error| {
                CaptureError::provider("libssl_uprobe_flow_resolver", error.to_string())
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct LibsslFlowStartKey {
    pid: u32,
    start_time_ticks: u64,
    ssl_pointer: u64,
    connection: TcpConnection,
}

struct TrackedLibsslFlowStarts {
    by_key: HashMap<LibsslFlowStartKey, u64>,
    recency: VecDeque<LibsslFlowStartKey>,
    next_start_monotonic_ns: u64,
    max_tracked_flows: usize,
}

impl Default for TrackedLibsslFlowStarts {
    fn default() -> Self {
        Self {
            by_key: HashMap::new(),
            recency: VecDeque::new(),
            next_start_monotonic_ns: 0,
            max_tracked_flows: MAX_TRACKED_LIBSSL_FLOWS,
        }
    }
}

impl TrackedLibsslFlowStarts {
    fn start_for(&mut self, key: LibsslFlowStartKey) -> u64 {
        if let Some(start) = self.by_key.get(&key).copied() {
            self.refresh(key);
            return start;
        }
        self.next_start_monotonic_ns = self.next_start_monotonic_ns.saturating_add(1);
        self.evict_until_available();
        self.recency.push_back(key);
        self.by_key.insert(key, self.next_start_monotonic_ns);
        self.next_start_monotonic_ns
    }

    fn refresh(&mut self, key: LibsslFlowStartKey) {
        self.recency.retain(|tracked| *tracked != key);
        self.recency.push_back(key);
    }

    fn evict_until_available(&mut self) {
        if self.max_tracked_flows == 0 {
            self.by_key.clear();
            self.recency.clear();
            return;
        }
        while self.by_key.len() >= self.max_tracked_flows {
            let Some(evicted) = self.recency.pop_front() else {
                self.by_key.clear();
                break;
            };
            if self.by_key.remove(&evicted).is_some() {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use capture::{
        CapturePoll, CaptureProviderKind, LibsslUprobeAttachTargetSnapshot,
        LibsslUprobeReconcileTargetBucket, MAX_LIBSSL_RECONCILE_TARGET_SNAPSHOTS_PER_BUCKET,
    };
    use probe_config::{AgentConfig, CaptureBackend, CaptureSelection};
    use probe_core::{CapabilityState, TcpEndpoint};
    use runtime::{CaptureProviderBuilder, CaptureProviderDescriptor, ProviderRegistry};

    use super::*;

    #[test]
    fn disabled_tls_instrumentation_build_records_unavailable_runtime_reason() {
        let build = TlsPlaintextInstrumentationBuild::disabled(
            "libssl uprobe attach planning produced no attachable targets",
        );

        let snapshot = build.runtime_snapshot();

        assert_eq!(snapshot.mode, TlsPlaintextRuntimeMode::Disabled);
        assert_eq!(
            snapshot.reason.as_deref(),
            Some("libssl uprobe attach planning produced no attachable targets")
        );
    }

    #[test]
    fn tls_plaintext_runtime_for_plan_is_not_configured_when_plaintext_is_disabled()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = runtime_plan_from_config(AgentConfig::default(), Vec::new())?;

        let runtime = TlsPlaintextRuntimeState::for_plan(&plan);

        let snapshot = runtime.snapshot();
        assert_eq!(snapshot.mode, TlsPlaintextRuntimeMode::NotConfigured);
        assert!(snapshot.reason.is_none());
        Ok(())
    }

    #[test]
    fn tls_plaintext_runtime_for_plan_is_pending_for_configured_libssl_sidecar()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Libpcap;
        config.tls.plaintext.instrumentation.enabled = true;
        config
            .tls
            .plaintext
            .instrumentation
            .libssl_uprobe_object_path = Some("/opt/sssa/ebpf-tls-plaintext.bpf.o".into());
        let plan = runtime_plan_from_config(
            config,
            vec![CapabilityState::degraded(
                probe_core::CapabilityKind::LibsslUprobe,
                "libssl uprobe preflight passed but runtime remains best-effort",
            )],
        )?;

        let runtime = TlsPlaintextRuntimeState::for_plan(&plan);

        let snapshot = runtime.snapshot();
        assert_eq!(snapshot.mode, TlsPlaintextRuntimeMode::Pending);
        assert!(
            snapshot
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("has not been built yet"))
        );
        Ok(())
    }

    #[test]
    fn tls_plaintext_runtime_state_records_poll_time_disable() {
        let runtime = TlsPlaintextRuntimeState::pending();
        runtime.record_instrumentation_build(&TlsPlaintextInstrumentationBuild::Enabled(Box::new(
            NoopCaptureProvider,
        )));

        assert_eq!(runtime.snapshot().mode, TlsPlaintextRuntimeMode::Enabled);
        runtime.record_reconcile_success_at(reconcile_result(2, 1, 3), 100);
        runtime.record_reconcile_success_at(reconcile_result(4, 2, 5), 200);

        runtime.record_instrumentation_disabled(
            "best-effort capture provider libssl_uprobe_plaintext disabled after error: boom",
        );

        let snapshot = runtime.snapshot();
        assert_eq!(snapshot.mode, TlsPlaintextRuntimeMode::Disabled);
        assert_eq!(
            snapshot.reason.as_deref(),
            Some("best-effort capture provider libssl_uprobe_plaintext disabled after error: boom")
        );
        let reconcile = snapshot
            .last_reconcile
            .expect("last successful reconcile should be retained after disable");
        assert_eq!(reconcile.sequence, 2);
        assert_eq!(reconcile.observed_unix_ns, 200);
        assert_eq!(
            reconcile.target_counts,
            TlsPlaintextReconcileTargetCountsRuntimeSnapshot {
                attached: 4,
                detached: 2,
                active: 5,
            }
        );
        assert_eq!(reconcile.targets.attached.targets.len(), 4);
        assert_eq!(reconcile.targets.detached.targets.len(), 2);
        assert_eq!(reconcile.targets.active.targets.len(), 5);
        assert_eq!(reconcile.targets.active.omitted, 0);
        assert_eq!(reconcile.targets.active.targets[0].pid, 3_000);
    }

    #[test]
    fn reconcile_runtime_snapshot_serializes_target_facts() -> Result<(), Box<dyn std::error::Error>>
    {
        let snapshot = TlsPlaintextReconcileRuntimeSnapshot::from_reconcile_success(
            reconcile_result(1, 0, 1),
            7,
            900,
        );

        let value = serde_json::to_value(snapshot)?;

        assert_eq!(value["sequence"], serde_json::json!(7));
        assert_eq!(value["observed_unix_ns"], serde_json::json!(900));
        assert_eq!(value["target_counts"]["attached"], serde_json::json!(1));
        assert_eq!(value["target_counts"]["detached"], serde_json::json!(0));
        assert_eq!(value["target_counts"]["active"], serde_json::json!(1));
        assert_eq!(
            value["targets"]["active"]["targets"][0]["pid"],
            serde_json::json!(3000)
        );
        assert_eq!(
            value["targets"]["active"]["targets"][0]["mapped_path"],
            serde_json::json!("/usr/lib/active-3000.so")
        );
        assert_eq!(
            value["targets"]["active"]["targets"][0]["inode"],
            serde_json::json!(3000)
        );
        assert_eq!(value["targets"]["active"]["omitted"], serde_json::json!(0));
        Ok(())
    }

    #[test]
    fn reconcile_runtime_snapshot_preserves_capture_bucket_counts_and_samples() {
        let snapshot = TlsPlaintextReconcileRuntimeSnapshot::from_reconcile_success(
            reconcile_result(MAX_LIBSSL_RECONCILE_TARGET_SNAPSHOTS_PER_BUCKET + 2, 0, 0),
            1,
            100,
        );

        assert_eq!(
            snapshot.target_counts.attached,
            (MAX_LIBSSL_RECONCILE_TARGET_SNAPSHOTS_PER_BUCKET + 2) as u64
        );
        assert_eq!(
            snapshot.targets.attached.targets.len(),
            MAX_LIBSSL_RECONCILE_TARGET_SNAPSHOTS_PER_BUCKET
        );
        assert_eq!(snapshot.targets.attached.omitted, 2);
    }

    struct NoopCaptureProvider;

    impl CaptureProvider for NoopCaptureProvider {
        fn name(&self) -> &'static str {
            "noop"
        }

        fn kind(&self) -> CaptureProviderKind {
            CaptureProviderKind::Plaintext
        }

        fn capabilities(&self) -> Vec<CapabilityState> {
            Vec::new()
        }

        fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
            Ok(CapturePoll::Finished)
        }
    }

    #[test]
    fn tracked_flow_starts_keep_identity_stable_for_same_ssl_connection() {
        let mut starts = TrackedLibsslFlowStarts::default();
        let key = flow_key(1, 0xfeed, connection(443));

        let first = starts.start_for(key);
        let second = starts.start_for(key);
        let other = starts.start_for(flow_key(1, 0xbeef, connection(443)));

        assert_eq!(first, second);
        assert_ne!(first, other);
    }

    #[test]
    fn tracked_flow_starts_include_process_generation_and_connection() {
        let mut starts = TrackedLibsslFlowStarts::default();
        let first = starts.start_for(flow_key(1, 0xfeed, connection(443)));
        let reused_pid = starts.start_for(flow_key(2, 0xfeed, connection(443)));
        let reused_ssl = starts.start_for(flow_key(1, 0xfeed, connection(8443)));

        assert_ne!(first, reused_pid);
        assert_ne!(first, reused_ssl);
    }

    fn runtime_plan_from_config(
        config: AgentConfig,
        platform_capabilities: Vec<CapabilityState>,
    ) -> Result<RuntimePlan, runtime::RuntimeError> {
        let registry = ProviderRegistry::new(
            vec![CaptureProviderDescriptor::available(
                CaptureBackend::Libpcap,
                CaptureProviderBuilder::Libpcap,
            )],
            platform_capabilities,
        );
        RuntimePlan::build(config, &registry)
    }

    fn flow_key(
        start_time_ticks: u64,
        ssl_pointer: u64,
        connection: TcpConnection,
    ) -> LibsslFlowStartKey {
        LibsslFlowStartKey {
            pid: 7,
            start_time_ticks,
            ssl_pointer,
            connection,
        }
    }

    fn connection(remote_port: u16) -> TcpConnection {
        TcpConnection::new(
            TcpEndpoint::new("127.0.0.1".parse().expect("valid local address"), 50_000),
            TcpEndpoint::new(
                "127.0.0.1".parse().expect("valid remote address"),
                remote_port,
            ),
        )
    }

    fn reconcile_result(
        attached: usize,
        detached: usize,
        active: usize,
    ) -> LibsslUprobePlaintextReconcile {
        LibsslUprobePlaintextReconcile {
            attached_targets: target_snapshots("attached", 1_000, attached),
            detached_targets: target_snapshots("detached", 2_000, detached),
            active_targets: target_snapshots("active", 3_000, active),
        }
    }

    fn target_snapshots(
        kind: &str,
        first_pid: u32,
        count: usize,
    ) -> LibsslUprobeReconcileTargetBucket {
        let targets = (0..count)
            .map(|index| {
                let pid = first_pid + index as u32;
                LibsslUprobeAttachTargetSnapshot {
                    pid,
                    start_time_ticks: u64::from(pid) * 100,
                    mapped_path: format!("/usr/lib/{kind}-{pid}.so").into(),
                    read_path: format!("/proc/{pid}/root/usr/lib/{kind}.so").into(),
                    device_major: 8,
                    device_minor: 1,
                    inode: u64::from(pid),
                    deleted: false,
                }
            })
            .collect::<Vec<_>>();
        LibsslUprobeReconcileTargetBucket::new(targets)
    }
}
