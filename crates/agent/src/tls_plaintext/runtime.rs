use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
};

use attribution::{AttributionError, ProcessAttributor, ProcfsAttributor, ProcfsSocketResolver};
use capture::{
    CaptureError, CaptureProvider, LibsslResolvedFlow, LibsslUprobeAttachPlan,
    LibsslUprobeFlowLookup, LibsslUprobeFlowResolver, LibsslUprobePlaintextOpen,
    LibsslUprobePlaintextProbeConfig, LibsslUprobePlaintextProvider, LibsslUprobeTargetDiscovery,
    plan_libssl_uprobes_for_processes,
};
use probe_config::TlsPlaintextProvider;
use probe_core::{CompiledSelector, TcpConnection};
use runtime::RuntimePlan;
use serde::Serialize;

use crate::error::AgentError;

const MAX_TRACKED_LIBSSL_FLOWS: usize = 8192;

#[derive(Debug, Clone)]
pub(crate) struct TlsPlaintextRuntimeState {
    inner: Arc<Mutex<TlsPlaintextRuntimeSnapshot>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsPlaintextRuntimeSnapshot {
    pub mode: TlsPlaintextRuntimeMode,
    pub reason: Option<String>,
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
        })
    }

    fn not_configured() -> Self {
        Self::from_snapshot(TlsPlaintextRuntimeSnapshot {
            mode: TlsPlaintextRuntimeMode::NotConfigured,
            reason: None,
        })
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
        };
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
) -> Result<TlsPlaintextProviderBuild, AgentError> {
    if !plan.tls.plaintext.enabled {
        return Ok(TlsPlaintextProviderBuild::NotConfigured);
    }

    match plan.tls.plaintext.provider {
        TlsPlaintextProvider::LibsslUprobe => build_libssl_uprobe_plaintext_provider(plan),
        TlsPlaintextProvider::Keylog => Err(AgentError::UnsupportedRunConfig(
            "keylog TLS plaintext provider is reserved but not implemented".to_string(),
        )),
    }
}

fn build_libssl_uprobe_plaintext_provider(
    plan: &RuntimePlan,
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
    let attach_plan = build_startup_libssl_uprobe_attach_plan(selector.as_ref())?;
    if attach_plan.processes().is_empty() {
        return Ok(TlsPlaintextProviderBuild::disabled(
            "libssl uprobe TLS plaintext sidecar disabled: startup scan found no attachable libssl processes",
        ));
    }

    match LibsslUprobePlaintextProvider::open_best_effort(
        LibsslUprobePlaintextProbeConfig::new(object_path, attach_plan),
        Box::<ProcfsLibsslFlowResolver>::default(),
    )? {
        LibsslUprobePlaintextOpen::Enabled(provider) => {
            Ok(TlsPlaintextProviderBuild::enabled(provider))
        }
        LibsslUprobePlaintextOpen::Disabled { reason } => {
            Ok(TlsPlaintextProviderBuild::disabled(reason))
        }
    }
}

fn build_startup_libssl_uprobe_attach_plan(
    selector: Option<&CompiledSelector>,
) -> Result<LibsslUprobeAttachPlan, AgentError> {
    let attributor = ProcfsAttributor::new();
    attributor.probe()?;
    let processes = attributor
        .process_ids()?
        .into_iter()
        .filter_map(|pid| identify_startup_process(&attributor, pid).transpose())
        .collect::<Result<Vec<_>, _>>()?;
    let planning_report = plan_libssl_uprobes_for_processes(
        processes,
        selector,
        &LibsslUprobeTargetDiscovery::default(),
    );
    Ok(planning_report.attach_plan)
}

fn identify_startup_process(
    attributor: &ProcfsAttributor,
    pid: u32,
) -> Result<Option<probe_core::ProcessContext>, AttributionError> {
    attributor.identify_if_present(pid)
}

pub(crate) enum TlsPlaintextProviderBuild {
    NotConfigured,
    Enabled(Box<dyn CaptureProvider>),
    Disabled { reason: String },
}

impl TlsPlaintextProviderBuild {
    fn enabled(provider: Box<LibsslUprobePlaintextProvider>) -> Self {
        Self::Enabled(provider)
    }

    fn disabled(reason: impl Into<String>) -> Self {
        Self::Disabled {
            reason: reason.into(),
        }
    }

    fn runtime_snapshot(&self) -> TlsPlaintextRuntimeSnapshot {
        match self {
            Self::NotConfigured => TlsPlaintextRuntimeSnapshot {
                mode: TlsPlaintextRuntimeMode::NotConfigured,
                reason: None,
            },
            Self::Enabled(_) => TlsPlaintextRuntimeSnapshot {
                mode: TlsPlaintextRuntimeMode::Enabled,
                reason: None,
            },
            Self::Disabled { reason } => TlsPlaintextRuntimeSnapshot {
                mode: TlsPlaintextRuntimeMode::Disabled,
                reason: Some(reason.clone()),
            },
        }
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
    use std::fs;

    use capture::{CapturePoll, CaptureProviderKind};
    use probe_config::{AgentConfig, CaptureBackend, CaptureSelection};
    use probe_core::{CapabilityState, TcpEndpoint};
    use runtime::{CaptureProviderBuilder, CaptureProviderDescriptor, ProviderRegistry};

    use super::*;

    #[test]
    fn startup_process_scan_skips_disappearing_processes() -> Result<(), Box<dyn std::error::Error>>
    {
        let proc = tempfile::tempdir()?;
        let boot = proc.path().join("boot_id");
        fs::write(&boot, "boot\n")?;
        fs::create_dir(proc.path().join("7"))?;
        let attributor = ProcfsAttributor::with_paths(proc.path(), &boot);

        let process = identify_startup_process(&attributor, 7)?;

        assert!(process.is_none());
        Ok(())
    }

    #[test]
    fn startup_process_scan_skips_invalid_process_metadata()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = tempfile::tempdir()?;
        let boot = proc.path().join("boot_id");
        fs::write(&boot, "boot\n")?;
        fs::create_dir(proc.path().join("7"))?;
        fs::write(proc.path().join("7/stat"), "invalid stat\n")?;
        let attributor = ProcfsAttributor::with_paths(proc.path(), &boot);

        let process = identify_startup_process(&attributor, 7)?;

        assert!(process.is_none());
        Ok(())
    }

    #[test]
    fn startup_process_scan_preserves_global_procfs_dependency_errors()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = tempfile::tempdir()?;
        let boot = proc.path().join("missing_boot_id");
        let pid_dir = proc.path().join("7");
        fs::create_dir(&pid_dir)?;
        fs::write(
            pid_dir.join("stat"),
            "7 (curl) S 1 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 12345 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
        )?;
        fs::write(pid_dir.join("status"), "Tgid:\t7\nUid:\t1000\nGid:\t1000\n")?;
        fs::write(pid_dir.join("cmdline"), b"curl\0")?;
        fs::write(pid_dir.join("cgroup"), "0::/user.slice\n")?;
        std::os::unix::fs::symlink("/usr/bin/curl", pid_dir.join("exe"))?;
        let attributor = ProcfsAttributor::with_paths(proc.path(), &boot);

        let error = identify_startup_process(&attributor, 7)
            .expect_err("global boot id read failure must not be treated as a per-pid race");

        assert!(matches!(
            error,
            AttributionError::Read { path, .. } if path.ends_with("missing_boot_id")
        ));
        Ok(())
    }

    #[test]
    fn disabled_tls_plaintext_build_records_unavailable_runtime_reason() {
        let build = TlsPlaintextProviderBuild::disabled("startup scan found no attachable target");

        let snapshot = build.runtime_snapshot();

        assert_eq!(snapshot.mode, TlsPlaintextRuntimeMode::Disabled);
        assert_eq!(
            snapshot.reason.as_deref(),
            Some("startup scan found no attachable target")
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

        runtime.record_provider_disabled(
            "best-effort capture provider libssl_uprobe_plaintext disabled after error: boom",
        );

        let snapshot = runtime.snapshot();
        assert_eq!(snapshot.mode, TlsPlaintextRuntimeMode::Disabled);
        assert_eq!(
            snapshot.reason.as_deref(),
            Some("best-effort capture provider libssl_uprobe_plaintext disabled after error: boom")
        );
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
