use std::{
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use capture::{
    CaptureEvent, CaptureProvider, LibsslUprobeAttachLinkOwnershipSnapshot,
    LibsslUprobeAttachProgramLinkOwnershipSnapshot, LibsslUprobeAttachTargetSnapshot,
    LibsslUprobePlaintextOpen, LibsslUprobePlaintextProbeConfig, LibsslUprobePlaintextProvider,
    LibsslUprobePlaintextReconcile, LibsslUprobeReconcileTargetBucket,
};
use probe_core::RuntimeMode;
use runtime::RuntimePlan;
use serde::Serialize;

use crate::error::AgentError;

use super::{
    flow_resolver::{AttachedLibsslProcessRegistry, ProcfsLibsslFlowResolver},
    planning::LibsslUprobeAttachPlanner,
    provider_activity::TlsPlaintextProviderActivityRuntimeSnapshot,
    sidecar::{
        LibsslUprobePlaintextReconcileFailure, LibsslUprobePlaintextSidecar,
        LibsslUprobePlaintextSidecarObserver,
    },
};

#[derive(Debug, Clone)]
pub(crate) struct TlsPlaintextRuntimeState {
    inner: Arc<Mutex<TlsPlaintextRuntimeSnapshot>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsPlaintextRuntimeSnapshot {
    pub mode: TlsPlaintextRuntimeMode,
    pub reason: Option<String>,
    pub provider_activity: TlsPlaintextProviderActivityRuntimeSnapshot,
    pub reconcile_health: TlsPlaintextReconcileHealthRuntimeSnapshot,
    pub last_reconcile: Option<TlsPlaintextReconcileRuntimeSnapshot>,
}

impl TlsPlaintextRuntimeSnapshot {
    pub(crate) fn not_configured() -> Self {
        Self {
            mode: TlsPlaintextRuntimeMode::NotConfigured,
            reason: None,
            provider_activity: TlsPlaintextProviderActivityRuntimeSnapshot::default(),
            reconcile_health: TlsPlaintextReconcileHealthRuntimeSnapshot::available(),
            last_reconcile: None,
        }
    }

    pub(crate) fn enabled() -> Self {
        Self {
            mode: TlsPlaintextRuntimeMode::Enabled,
            reason: None,
            provider_activity: TlsPlaintextProviderActivityRuntimeSnapshot::default(),
            reconcile_health: TlsPlaintextReconcileHealthRuntimeSnapshot::available(),
            last_reconcile: None,
        }
    }

    pub(crate) fn disabled(reason: impl Into<String>) -> Self {
        Self {
            mode: TlsPlaintextRuntimeMode::Disabled,
            reason: Some(reason.into()),
            provider_activity: TlsPlaintextProviderActivityRuntimeSnapshot::default(),
            reconcile_health: TlsPlaintextReconcileHealthRuntimeSnapshot::available(),
            last_reconcile: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsPlaintextReconcileHealthRuntimeSnapshot {
    mode: TlsPlaintextReconcileHealthMode,
    consecutive_failures: u64,
    last_attempt: Option<TlsPlaintextReconcileAttemptRuntimeSnapshot>,
}

impl TlsPlaintextReconcileHealthRuntimeSnapshot {
    pub(crate) fn available() -> Self {
        Self {
            mode: TlsPlaintextReconcileHealthMode::Available,
            consecutive_failures: 0,
            last_attempt: None,
        }
    }

    pub(crate) fn success(sequence: u64, observed_unix_ns: u64) -> Self {
        Self {
            mode: TlsPlaintextReconcileHealthMode::Available,
            consecutive_failures: 0,
            last_attempt: Some(TlsPlaintextReconcileAttemptRuntimeSnapshot::Succeeded {
                sequence,
                observed_unix_ns,
            }),
        }
    }

    pub(crate) fn failure(
        sequence: u64,
        observed_unix_ns: u64,
        consecutive_failures: u64,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            mode: TlsPlaintextReconcileHealthMode::Degraded,
            consecutive_failures,
            last_attempt: Some(TlsPlaintextReconcileAttemptRuntimeSnapshot::Failed {
                sequence,
                observed_unix_ns,
                reason: reason.into(),
            }),
        }
    }

    pub(crate) fn mode(&self) -> TlsPlaintextReconcileHealthMode {
        self.mode
    }

    pub(crate) fn consecutive_failures(&self) -> u64 {
        self.consecutive_failures
    }

    pub(crate) fn last_attempt(&self) -> Option<&TlsPlaintextReconcileAttemptRuntimeSnapshot> {
        self.last_attempt.as_ref()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsPlaintextReconcileHealthMode {
    Available,
    Degraded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum TlsPlaintextReconcileAttemptRuntimeSnapshot {
    Succeeded {
        sequence: u64,
        observed_unix_ns: u64,
    },
    Failed {
        sequence: u64,
        observed_unix_ns: u64,
        reason: String,
    },
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
    pub reconcile_state: TlsPlaintextTargetReconcileStateRuntimeSnapshot,
    pub link_ownership: TlsPlaintextTargetLinkOwnershipRuntimeSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsPlaintextTargetReconcileStateRuntimeSnapshot {
    pub mode: RuntimeMode,
    pub state: TlsPlaintextTargetReconcileState,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsPlaintextTargetReconcileState {
    Attached,
    Active,
    Detached,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsPlaintextTargetLinkOwnershipRuntimeSnapshot {
    pub mode: RuntimeMode,
    pub owned_link_count: u64,
    pub programs: Vec<TlsPlaintextTargetLinkProgramRuntimeSnapshot>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsPlaintextTargetLinkProgramRuntimeSnapshot {
    pub program_name: &'static str,
    pub owned_link_count: u64,
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
                attached: target_bucket(
                    result.attached_targets,
                    TlsPlaintextTargetReconcileStateRuntimeSnapshot::attached(),
                ),
                detached: target_bucket(
                    result.detached_targets,
                    TlsPlaintextTargetReconcileStateRuntimeSnapshot::detached(),
                ),
                active: target_bucket(
                    result.active_targets,
                    TlsPlaintextTargetReconcileStateRuntimeSnapshot::active(),
                ),
            },
        }
    }
}

fn target_bucket(
    bucket: LibsslUprobeReconcileTargetBucket,
    reconcile_state: TlsPlaintextTargetReconcileStateRuntimeSnapshot,
) -> TlsPlaintextReconcileTargetBucketRuntimeSnapshot {
    let omitted = bucket.omitted_count();
    let targets = bucket
        .into_targets()
        .into_iter()
        .map(|target| {
            TlsPlaintextReconcileTargetRuntimeSnapshot::from_target_reconcile_state(
                target,
                reconcile_state.clone(),
            )
        })
        .collect::<Vec<_>>();
    TlsPlaintextReconcileTargetBucketRuntimeSnapshot {
        omitted: omitted as u64,
        targets,
    }
}

impl TlsPlaintextReconcileTargetRuntimeSnapshot {
    fn from_target_reconcile_state(
        target: LibsslUprobeAttachTargetSnapshot,
        reconcile_state: TlsPlaintextTargetReconcileStateRuntimeSnapshot,
    ) -> Self {
        Self {
            pid: target.pid,
            start_time_ticks: target.start_time_ticks,
            mapped_path: target.mapped_path,
            read_path: target.read_path,
            device_major: target.device_major,
            device_minor: target.device_minor,
            inode: target.inode,
            deleted: target.deleted,
            reconcile_state,
            link_ownership: TlsPlaintextTargetLinkOwnershipRuntimeSnapshot::from_capture(
                target.link_ownership,
            ),
        }
    }
}

impl TlsPlaintextTargetReconcileStateRuntimeSnapshot {
    fn attached() -> Self {
        Self {
            mode: RuntimeMode::Available,
            state: TlsPlaintextTargetReconcileState::Attached,
            reason: Some(
                "target reached committed libssl uprobe links during the latest reconcile"
                    .to_string(),
            ),
        }
    }

    fn active() -> Self {
        Self {
            mode: RuntimeMode::Available,
            state: TlsPlaintextTargetReconcileState::Active,
            reason: Some(
                "target had committed libssl uprobe links after the latest reconcile".to_string(),
            ),
        }
    }

    fn detached() -> Self {
        Self {
            mode: RuntimeMode::Unavailable,
            state: TlsPlaintextTargetReconcileState::Detached,
            reason: Some(
                "target was detached because it was absent from the latest attach plan".to_string(),
            ),
        }
    }
}

impl TlsPlaintextTargetLinkOwnershipRuntimeSnapshot {
    fn from_capture(link_ownership: LibsslUprobeAttachLinkOwnershipSnapshot) -> Self {
        let owned_link_count = link_ownership.owned_link_count();
        if !link_ownership.is_reported() {
            return Self {
                mode: RuntimeMode::Unavailable,
                owned_link_count: 0,
                programs: Vec::new(),
                reason: Some(
                    "no committed libssl uprobe link ownership was reported for this target"
                        .to_string(),
                ),
            };
        }
        Self {
            mode: RuntimeMode::Available,
            owned_link_count: owned_link_count as u64,
            programs: link_ownership
                .into_programs()
                .into_iter()
                .map(link_program_snapshot)
                .collect(),
            reason: Some(
                "userspace attach session holds committed libssl uprobe links for this target"
                    .to_string(),
            ),
        }
    }
}

fn link_program_snapshot(
    program: LibsslUprobeAttachProgramLinkOwnershipSnapshot,
) -> TlsPlaintextTargetLinkProgramRuntimeSnapshot {
    TlsPlaintextTargetLinkProgramRuntimeSnapshot {
        program_name: program.program_name(),
        owned_link_count: program.owned_link_count() as u64,
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
            provider_activity: TlsPlaintextProviderActivityRuntimeSnapshot::default(),
            reconcile_health: TlsPlaintextReconcileHealthRuntimeSnapshot::available(),
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
            provider_activity: inner.provider_activity.clone(),
            reconcile_health: inner.reconcile_health.clone(),
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
        let attempt_sequence = next_reconcile_attempt_sequence(&inner);
        *inner = TlsPlaintextRuntimeSnapshot {
            mode: TlsPlaintextRuntimeMode::Enabled,
            reason: None,
            provider_activity: inner.provider_activity.clone(),
            reconcile_health: TlsPlaintextReconcileHealthRuntimeSnapshot::success(
                attempt_sequence,
                observed_unix_ns,
            ),
            last_reconcile: Some(
                TlsPlaintextReconcileRuntimeSnapshot::from_reconcile_success(
                    result,
                    sequence,
                    observed_unix_ns,
                ),
            ),
        };
    }

    fn record_reconcile_failure(&self, reason: impl Into<String>) {
        self.record_reconcile_failure_at(reason, current_unix_time_ns());
    }

    fn record_reconcile_failure_at(&self, reason: impl Into<String>, observed_unix_ns: u64) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let attempt_sequence = next_reconcile_attempt_sequence(&inner);
        let consecutive_failures = inner
            .reconcile_health
            .consecutive_failures
            .saturating_add(1);
        inner.reconcile_health = TlsPlaintextReconcileHealthRuntimeSnapshot::failure(
            attempt_sequence,
            observed_unix_ns,
            consecutive_failures,
            reason,
        );
    }

    fn record_reconcile_failure_and_disable(
        &self,
        failure_reason: impl Into<String>,
        disable_reason: impl Into<String>,
    ) {
        self.record_reconcile_failure_and_disable_at(
            failure_reason,
            disable_reason,
            current_unix_time_ns(),
        );
    }

    fn record_reconcile_failure_and_disable_at(
        &self,
        failure_reason: impl Into<String>,
        disable_reason: impl Into<String>,
        observed_unix_ns: u64,
    ) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let attempt_sequence = next_reconcile_attempt_sequence(&inner);
        let consecutive_failures = inner
            .reconcile_health
            .consecutive_failures
            .saturating_add(1);
        let last_reconcile = inner.last_reconcile.clone();
        let provider_activity = inner.provider_activity.clone();
        *inner = TlsPlaintextRuntimeSnapshot {
            mode: TlsPlaintextRuntimeMode::Disabled,
            reason: Some(disable_reason.into()),
            provider_activity,
            reconcile_health: TlsPlaintextReconcileHealthRuntimeSnapshot::failure(
                attempt_sequence,
                observed_unix_ns,
                consecutive_failures,
                failure_reason,
            ),
            last_reconcile,
        };
    }

    fn record_provider_progress(&self) {
        self.record_provider_progress_at(current_unix_time_ns());
    }

    fn record_provider_progress_at(&self, observed_unix_ns: u64) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.provider_activity.record_progress(observed_unix_ns);
    }

    fn record_provider_event(&self, event: &CaptureEvent) {
        self.record_provider_event_at(event, current_unix_time_ns());
    }

    fn record_provider_event_at(&self, event: &CaptureEvent, observed_unix_ns: u64) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner
            .provider_activity
            .record_event(event, observed_unix_ns);
    }

    pub(crate) fn snapshot(&self) -> TlsPlaintextRuntimeSnapshot {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

fn next_reconcile_attempt_sequence(snapshot: &TlsPlaintextRuntimeSnapshot) -> u64 {
    snapshot
        .reconcile_health
        .last_attempt
        .as_ref()
        .map_or(1, |attempt| {
            reconcile_attempt_sequence(attempt).saturating_add(1)
        })
}

fn reconcile_attempt_sequence(attempt: &TlsPlaintextReconcileAttemptRuntimeSnapshot) -> u64 {
    match attempt {
        TlsPlaintextReconcileAttemptRuntimeSnapshot::Succeeded { sequence, .. }
        | TlsPlaintextReconcileAttemptRuntimeSnapshot::Failed { sequence, .. } => *sequence,
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
    let attach_selector = compile_libssl_uprobe_selector(plan)?;
    let output_selector = compile_libssl_uprobe_selector(plan)?;
    let attach_planner = LibsslUprobeAttachPlanner::new(attach_selector);
    let attach_plan = match attach_planner.plan()? {
        Ok(plan) => plan,
        Err(blocked) => {
            return Ok(TlsPlaintextInstrumentationBuild::disabled(
                blocked.into_reason(),
            ));
        }
    };

    let attached_processes = AttachedLibsslProcessRegistry::default();

    match LibsslUprobePlaintextProvider::open_best_effort(
        LibsslUprobePlaintextProbeConfig::new(object_path, attach_plan),
        Box::new(ProcfsLibsslFlowResolver::new(attached_processes.clone())),
    ) {
        LibsslUprobePlaintextOpen::Enabled(provider) => {
            let provider = *provider;
            Ok(TlsPlaintextInstrumentationBuild::enabled(
                provider.with_output_selector(output_selector),
                attach_planner,
                Duration::from_millis(plan.tls.plaintext.instrumentation.reconcile_interval_ms),
                Some(Box::new(LibsslRuntimeObserver {
                    runtime_state: runtime_state.cloned(),
                    attached_processes,
                })),
            ))
        }
        LibsslUprobePlaintextOpen::Disabled { reason } => {
            Ok(TlsPlaintextInstrumentationBuild::disabled(reason))
        }
    }
}

fn compile_libssl_uprobe_selector(
    plan: &RuntimePlan,
) -> Result<Option<probe_core::CompiledSelector>, AgentError> {
    plan.config
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
        })
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
        observer: Option<Box<dyn LibsslUprobePlaintextSidecarObserver>>,
    ) -> Self {
        Self::Enabled(Box::new(LibsslUprobePlaintextSidecar::after(
            provider,
            attach_planner,
            reconcile_interval,
            observer,
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

fn current_unix_time_ns() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    u64::try_from(nanos).unwrap_or(u64::MAX)
}

struct LibsslRuntimeObserver {
    runtime_state: Option<TlsPlaintextRuntimeState>,
    attached_processes: AttachedLibsslProcessRegistry,
}

impl LibsslUprobePlaintextSidecarObserver for LibsslRuntimeObserver {
    fn record_reconcile_success(&self, result: &LibsslUprobePlaintextReconcile) {
        self.attached_processes.replace_from_reconcile(result);
        if let Some(runtime_state) = &self.runtime_state {
            runtime_state.record_reconcile_success(result.clone());
        }
    }

    fn record_reconcile_failure(&self, failure: LibsslUprobePlaintextReconcileFailure) {
        if let Some(runtime_state) = &self.runtime_state {
            record_runtime_reconcile_failure(runtime_state, failure);
        }
    }

    fn record_provider_progress(&self) {
        if let Some(runtime_state) = &self.runtime_state {
            runtime_state.record_provider_progress();
        }
    }

    fn record_provider_event(&self, event: &CaptureEvent) {
        if let Some(runtime_state) = &self.runtime_state {
            runtime_state.record_provider_event(event);
        }
    }
}

fn record_runtime_reconcile_failure(
    runtime_state: &TlsPlaintextRuntimeState,
    failure: LibsslUprobePlaintextReconcileFailure,
) {
    match failure {
        LibsslUprobePlaintextReconcileFailure::Recoverable { reason } => {
            runtime_state.record_reconcile_failure(reason);
        }
        LibsslUprobePlaintextReconcileFailure::Fatal { reason } => {
            let disable_reason =
                format!("TLS plaintext sidecar disabled after fatal reconcile error: {reason}");
            runtime_state.record_reconcile_failure_and_disable(reason, disable_reason);
        }
    }
}

#[cfg(test)]
mod tests {
    use capture::{
        CaptureError, CapturePoll, LibsslUprobeAttachLinkOwnershipSnapshot,
        LibsslUprobeAttachProgramLinkOwnershipSnapshot, LibsslUprobeAttachTargetSnapshot,
        LibsslUprobeReconcileTargetBucket, MAX_LIBSSL_RECONCILE_TARGET_SNAPSHOTS_PER_BUCKET,
    };
    use probe_config::{AgentConfig, CaptureBackend, CaptureSelection};
    use probe_core::CapabilityState;
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
        assert_eq!(
            snapshot.reconcile_health.mode,
            TlsPlaintextReconcileHealthMode::Available
        );
        assert_eq!(snapshot.reconcile_health.consecutive_failures, 0);
        assert!(snapshot.reconcile_health.last_attempt.is_none());
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
            .libssl_uprobe_object_path = Some("/opt/traffic-probe/ebpf-tls-plaintext.bpf.o".into());
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
        assert_eq!(
            snapshot.reconcile_health.mode,
            TlsPlaintextReconcileHealthMode::Available
        );
        assert!(snapshot.reconcile_health.last_attempt.is_none());
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
        assert_eq!(
            snapshot.reconcile_health.mode,
            TlsPlaintextReconcileHealthMode::Available
        );
        assert_eq!(snapshot.reconcile_health.consecutive_failures, 0);
        let attempt = snapshot
            .reconcile_health
            .last_attempt
            .as_ref()
            .expect("last successful reconcile attempt should be retained after disable");
        assert_succeeded_reconcile_attempt(attempt, 2, 200);
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
    fn tls_plaintext_runtime_state_records_reconcile_failure_health() {
        let runtime = TlsPlaintextRuntimeState::pending();
        runtime.record_instrumentation_build(&TlsPlaintextInstrumentationBuild::Enabled(Box::new(
            NoopCaptureProvider,
        )));
        runtime.record_reconcile_success_at(reconcile_result(1, 0, 1), 100);
        runtime.record_reconcile_failure_and_disable_at(
            "capture provider libssl_uprobe_plaintext failed: attach failed",
            "best-effort capture provider libssl_uprobe_plaintext disabled after error: attach failed",
            200,
        );

        let snapshot = runtime.snapshot();
        assert_eq!(snapshot.mode, TlsPlaintextRuntimeMode::Disabled);
        assert_eq!(
            snapshot.reason.as_deref(),
            Some(
                "best-effort capture provider libssl_uprobe_plaintext disabled after error: attach failed"
            )
        );
        assert_eq!(
            snapshot.reconcile_health.mode,
            TlsPlaintextReconcileHealthMode::Degraded
        );
        assert_eq!(snapshot.reconcile_health.consecutive_failures, 1);
        let attempt = snapshot
            .reconcile_health
            .last_attempt
            .expect("failed reconcile attempt should be recorded");
        assert_failed_reconcile_attempt(&attempt, 2, 200, "attach failed");
        assert_eq!(
            snapshot
                .last_reconcile
                .expect("last successful reconcile should remain available")
                .sequence,
            1
        );
    }

    #[test]
    fn tls_plaintext_runtime_state_clears_reconcile_failure_after_success() {
        let runtime = TlsPlaintextRuntimeState::pending();
        runtime.record_instrumentation_build(&TlsPlaintextInstrumentationBuild::Enabled(Box::new(
            NoopCaptureProvider,
        )));
        runtime.record_reconcile_failure_at("planning failed", 100);
        runtime.record_reconcile_failure_at("attach failed", 200);
        runtime.record_reconcile_success_at(reconcile_result(1, 0, 1), 300);

        let snapshot = runtime.snapshot();
        assert_eq!(snapshot.mode, TlsPlaintextRuntimeMode::Enabled);
        assert_eq!(
            snapshot.reconcile_health.mode,
            TlsPlaintextReconcileHealthMode::Available
        );
        assert_eq!(snapshot.reconcile_health.consecutive_failures, 0);
        let attempt = snapshot
            .reconcile_health
            .last_attempt
            .expect("successful reconcile attempt should be recorded");
        assert_succeeded_reconcile_attempt(&attempt, 3, 300);
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
        assert_eq!(
            value["targets"]["active"]["targets"][0]["reconcile_state"]["mode"],
            serde_json::json!("available")
        );
        assert_eq!(
            value["targets"]["active"]["targets"][0]["reconcile_state"]["state"],
            serde_json::json!("active")
        );
        assert!(
            value["targets"]["active"]["targets"][0]["reconcile_state"]["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("committed libssl uprobe links"))
        );
        assert_eq!(value["targets"]["active"]["omitted"], serde_json::json!(0));
        Ok(())
    }

    #[test]
    fn reconcile_runtime_snapshot_serializes_target_link_ownership()
    -> Result<(), Box<dyn std::error::Error>> {
        let snapshot = TlsPlaintextReconcileRuntimeSnapshot::from_reconcile_success(
            reconcile_result_with_active_link_ownership(),
            1,
            100,
        );

        let value = serde_json::to_value(snapshot)?;
        let link_ownership = &value["targets"]["active"]["targets"][0]["link_ownership"];

        assert_eq!(link_ownership["mode"], serde_json::json!("available"));
        assert_eq!(link_ownership["owned_link_count"], serde_json::json!(3));
        assert!(
            link_ownership["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("userspace attach session holds"))
        );
        assert_eq!(
            link_ownership["programs"][0]["program_name"],
            "tls_read_entry"
        );
        assert_eq!(link_ownership["programs"][0]["owned_link_count"], 1);
        assert_eq!(
            link_ownership["programs"][1]["program_name"],
            "tls_write_entry"
        );
        assert_eq!(link_ownership["programs"][1]["owned_link_count"], 2);
        Ok(())
    }

    #[test]
    fn reconcile_runtime_snapshot_marks_detached_target_reconcile_state_unavailable()
    -> Result<(), Box<dyn std::error::Error>> {
        let snapshot = TlsPlaintextReconcileRuntimeSnapshot::from_reconcile_success(
            reconcile_result(0, 1, 0),
            1,
            100,
        );

        let value = serde_json::to_value(snapshot)?;

        assert_eq!(
            value["targets"]["detached"]["targets"][0]["reconcile_state"]["mode"],
            serde_json::json!("unavailable")
        );
        assert_eq!(
            value["targets"]["detached"]["targets"][0]["reconcile_state"]["state"],
            serde_json::json!("detached")
        );
        assert!(
            value["targets"]["detached"]["targets"][0]["reconcile_state"]["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("absent from the latest attach plan"))
        );
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

        fn capabilities(&self) -> Vec<CapabilityState> {
            Vec::new()
        }

        fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
            Ok(CapturePoll::Finished)
        }
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

    fn assert_succeeded_reconcile_attempt(
        attempt: &TlsPlaintextReconcileAttemptRuntimeSnapshot,
        expected_sequence: u64,
        expected_observed_unix_ns: u64,
    ) {
        let TlsPlaintextReconcileAttemptRuntimeSnapshot::Succeeded {
            sequence,
            observed_unix_ns,
        } = attempt
        else {
            panic!("expected succeeded reconcile attempt, got {attempt:?}");
        };
        assert_eq!(*sequence, expected_sequence);
        assert_eq!(*observed_unix_ns, expected_observed_unix_ns);
    }

    fn assert_failed_reconcile_attempt(
        attempt: &TlsPlaintextReconcileAttemptRuntimeSnapshot,
        expected_sequence: u64,
        expected_observed_unix_ns: u64,
        expected_reason_fragment: &str,
    ) {
        let TlsPlaintextReconcileAttemptRuntimeSnapshot::Failed {
            sequence,
            observed_unix_ns,
            reason,
        } = attempt
        else {
            panic!("expected failed reconcile attempt, got {attempt:?}");
        };
        assert_eq!(*sequence, expected_sequence);
        assert_eq!(*observed_unix_ns, expected_observed_unix_ns);
        assert!(reason.contains(expected_reason_fragment));
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

    fn reconcile_result_with_active_link_ownership() -> LibsslUprobePlaintextReconcile {
        let mut active = target_snapshot("active", 3_000);
        active.link_ownership = LibsslUprobeAttachLinkOwnershipSnapshot::owned_by_programs([
            LibsslUprobeAttachProgramLinkOwnershipSnapshot::new("tls_read_entry", 1),
            LibsslUprobeAttachProgramLinkOwnershipSnapshot::new("tls_write_entry", 2),
        ]);
        LibsslUprobePlaintextReconcile {
            attached_targets: target_snapshots("attached", 1_000, 0),
            detached_targets: target_snapshots("detached", 2_000, 0),
            active_targets: LibsslUprobeReconcileTargetBucket::new([active]),
        }
    }

    fn target_snapshots(
        kind: &str,
        first_pid: u32,
        count: usize,
    ) -> LibsslUprobeReconcileTargetBucket {
        let targets = (0..count)
            .map(|index| target_snapshot(kind, first_pid + index as u32))
            .collect::<Vec<_>>();
        LibsslUprobeReconcileTargetBucket::new(targets)
    }

    fn target_snapshot(kind: &str, pid: u32) -> LibsslUprobeAttachTargetSnapshot {
        LibsslUprobeAttachTargetSnapshot {
            pid,
            start_time_ticks: u64::from(pid) * 100,
            mapped_path: format!("/usr/lib/{kind}-{pid}.so").into(),
            read_path: format!("/proc/{pid}/root/usr/lib/{kind}.so").into(),
            device_major: 8,
            device_minor: 1,
            inode: u64::from(pid),
            deleted: false,
            link_ownership: LibsslUprobeAttachLinkOwnershipSnapshot::unreported(),
        }
    }
}
