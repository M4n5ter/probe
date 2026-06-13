use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::Duration,
};

use attribution::ProcfsSocketResolver;
use capture::{
    CaptureError, CaptureProvider, LibsslResolvedFlow, LibsslUprobeFlowLookup,
    LibsslUprobeFlowResolver, LibsslUprobePlaintextOpen, LibsslUprobePlaintextProbeConfig,
    LibsslUprobePlaintextProvider, LibsslUprobePlaintextReconcile,
};
use probe_config::TlsPlaintextProvider;
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

    pub(crate) fn with_reconcile_success(mut self, result: LibsslUprobePlaintextReconcile) -> Self {
        self.last_reconcile = Some(TlsPlaintextReconcileRuntimeSnapshot::from(result));
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TlsPlaintextReconcileRuntimeSnapshot {
    pub attached_targets: u64,
    pub detached_targets: u64,
    pub active_targets: u64,
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
        if plan.tls.plaintext.enabled
            && plan.tls.plaintext.provider == TlsPlaintextProvider::LibsslUprobe
        {
            return Self::pending();
        }
        Self::not_configured()
    }

    fn pending() -> Self {
        Self::from_snapshot(TlsPlaintextRuntimeSnapshot {
            mode: TlsPlaintextRuntimeMode::Pending,
            reason: Some("TLS plaintext runtime provider has not been built yet".to_string()),
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

    pub(crate) fn record_provider_build(&self, build: &TlsPlaintextProviderBuild) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *inner = build.runtime_snapshot();
    }

    pub(crate) fn record_provider_disabled(&self, reason: impl Into<String>) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *inner = TlsPlaintextRuntimeSnapshot {
            mode: TlsPlaintextRuntimeMode::Disabled,
            reason: Some(reason.into()),
            last_reconcile: inner.last_reconcile,
        };
    }

    fn record_reconcile_success(&self, result: LibsslUprobePlaintextReconcile) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *inner = TlsPlaintextRuntimeSnapshot::enabled().with_reconcile_success(result);
    }

    pub(crate) fn snapshot(&self) -> TlsPlaintextRuntimeSnapshot {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

pub(crate) fn build_tls_plaintext_provider(
    plan: &RuntimePlan,
    runtime_state: Option<&TlsPlaintextRuntimeState>,
) -> Result<TlsPlaintextProviderBuild, AgentError> {
    if !plan.tls.plaintext.enabled {
        return Ok(TlsPlaintextProviderBuild::NotConfigured);
    }

    match plan.tls.plaintext.provider {
        TlsPlaintextProvider::LibsslUprobe => {
            build_libssl_uprobe_plaintext_provider(plan, runtime_state)
        }
        TlsPlaintextProvider::Keylog => Err(AgentError::UnsupportedRunConfig(
            "keylog TLS plaintext provider is reserved but not implemented".to_string(),
        )),
    }
}

fn build_libssl_uprobe_plaintext_provider(
    plan: &RuntimePlan,
    runtime_state: Option<&TlsPlaintextRuntimeState>,
) -> Result<TlsPlaintextProviderBuild, AgentError> {
    plan.require_live_capture()?;
    let object_path = plan
        .tls
        .plaintext
        .libssl_uprobe_object_path
        .clone()
        .ok_or_else(|| {
            AgentError::UnsupportedRunConfig(
                "libssl uprobe TLS plaintext requires tls.plaintext.libssl_uprobe_object_path"
                    .to_string(),
            )
        })?;
    let selector = plan
        .config
        .tls
        .plaintext
        .selector
        .as_ref()
        .map(|selector| selector.compile())
        .transpose()
        .map_err(|source| {
            AgentError::UnsupportedRunConfig(format!(
                "invalid tls.plaintext.selector during runtime build: {source}"
            ))
        })?;
    let attach_planner = LibsslUprobeAttachPlanner::new(selector);
    let attach_plan = match attach_planner.plan()? {
        Ok(plan) => plan,
        Err(blocked) => return Ok(TlsPlaintextProviderBuild::disabled(blocked.into_reason())),
    };

    match LibsslUprobePlaintextProvider::open_best_effort(
        LibsslUprobePlaintextProbeConfig::new(object_path, attach_plan),
        Box::<ProcfsLibsslFlowResolver>::default(),
    ) {
        LibsslUprobePlaintextOpen::Enabled(provider) => Ok(TlsPlaintextProviderBuild::enabled(
            provider,
            attach_planner,
            Duration::from_millis(plan.tls.plaintext.reconcile_interval_ms),
            runtime_state
                .cloned()
                .map(|state| Box::new(state) as Box<dyn LibsslUprobePlaintextReconcileObserver>),
        )),
        LibsslUprobePlaintextOpen::Disabled { reason } => {
            Ok(TlsPlaintextProviderBuild::disabled(reason))
        }
    }
}

pub(crate) enum TlsPlaintextProviderBuild {
    NotConfigured,
    Enabled(Box<dyn CaptureProvider>),
    Disabled { reason: String },
}

impl TlsPlaintextProviderBuild {
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

impl From<LibsslUprobePlaintextReconcile> for TlsPlaintextReconcileRuntimeSnapshot {
    fn from(value: LibsslUprobePlaintextReconcile) -> Self {
        Self {
            attached_targets: value.attached_targets as u64,
            detached_targets: value.detached_targets as u64,
            active_targets: value.active_targets as u64,
        }
    }
}

impl LibsslUprobePlaintextReconcileObserver for TlsPlaintextRuntimeState {
    fn record_reconcile_success(&self, result: LibsslUprobePlaintextReconcile) {
        TlsPlaintextRuntimeState::record_reconcile_success(self, result);
    }
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
    use capture::{CapturePoll, CaptureProviderKind};
    use probe_config::{AgentConfig, CaptureBackend, CaptureSelection};
    use probe_core::{CapabilityState, TcpEndpoint};
    use runtime::{CaptureProviderBuilder, CaptureProviderDescriptor, ProviderRegistry};

    use super::*;

    #[test]
    fn disabled_tls_plaintext_build_records_unavailable_runtime_reason() {
        let build = TlsPlaintextProviderBuild::disabled(
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
        config.tls.plaintext.enabled = true;
        config.tls.plaintext.provider = TlsPlaintextProvider::LibsslUprobe;
        config.tls.plaintext.libssl_uprobe_object_path =
            Some("/opt/sssa/ebpf-tls-plaintext.bpf.o".into());
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
        runtime.record_provider_build(&TlsPlaintextProviderBuild::Enabled(Box::new(
            NoopCaptureProvider,
        )));

        assert_eq!(runtime.snapshot().mode, TlsPlaintextRuntimeMode::Enabled);
        runtime.record_reconcile_success(LibsslUprobePlaintextReconcile {
            attached_targets: 2,
            detached_targets: 1,
            active_targets: 3,
        });

        runtime.record_provider_disabled(
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
        assert_eq!(reconcile.attached_targets, 2);
        assert_eq!(reconcile.detached_targets, 1);
        assert_eq!(reconcile.active_targets, 3);
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
}
