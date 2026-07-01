use std::{
    collections::BTreeSet,
    fs, io,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use runtime::{EnforcementPolicySourceKind, EnforcementPolicySourcePlan, RuntimePlan};
use thiserror::Error;
use tracing::{info, warn};

use crate::configured_enforcement::EnforcementRuntimeState;
use crate::enforcement_reload::{
    EnforcementReloadGate, reload_enforcement_policy, validate_enforcement_policy_reload_plan,
};
use crate::reload_watcher::{
    ReloadFuture, ReloadWatchPath, ReloadWatcherError, ReloadWatcherHandle, absolute_path,
    spawn_reload_watcher,
};

#[derive(Debug, Error)]
pub(crate) enum EnforcementReloadWatcherError {
    #[error("failed to create enforcement policy reload watcher: {0}")]
    Create(#[source] notify::Error),
    #[error("failed to watch enforcement policy reload path {path}: {source}")]
    WatchPath {
        path: PathBuf,
        #[source]
        source: notify::Error,
    },
    #[error("failed to inspect enforcement policy manifest watch path {path}: {source}")]
    InspectPath {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("enforcement policy manifest watch path {path} must be a non-symlink regular file")]
    InvalidManifestPath { path: PathBuf },
    #[error(
        "enforcement policy manifest directory watch path {path} must be a non-symlink directory"
    )]
    InvalidManifestDirectory { path: PathBuf },
    #[error(
        "enforcement policy reload watcher requires a local file or directory enforcement policy source"
    )]
    UnsupportedSource,
    #[error("enforcement policy reload watcher is not supported for this runtime plan: {0}")]
    UnsupportedPlan(#[from] crate::enforcement_reload::EnforcementReloadError),
}

pub(crate) struct EnforcementReloadWatcherHandle {
    inner: ReloadWatcherHandle,
}

impl EnforcementReloadWatcherHandle {
    pub(crate) async fn stop(self) {
        self.inner.stop().await;
    }
}

pub(crate) fn spawn_watcher(
    plan: Arc<RuntimePlan>,
    runtime_state: EnforcementRuntimeState,
    gate: EnforcementReloadGate,
) -> Result<Option<EnforcementReloadWatcherHandle>, EnforcementReloadWatcherError> {
    if !plan.config.enforcement.policy.reload.watch_local_manifest {
        return Ok(None);
    }
    let target = local_enforcement_manifest_watch_target(&plan)
        .ok_or(EnforcementReloadWatcherError::UnsupportedSource)?;
    validate_enforcement_policy_reload_plan(&plan)?;
    let watch_paths = enforcement_reload_watch_paths(&target)?;
    let manifest_path = Arc::new(target.manifest_path.clone());
    let debounce = Duration::from_millis(plan.config.enforcement.policy.reload.debounce_ms);
    let inner = spawn_reload_watcher(
        "enforcement policy reload watcher",
        watch_paths,
        debounce,
        move |event| notify_event_requests_reload(event, &manifest_path),
        WatcherReloadContext {
            plan,
            runtime_state,
            gate,
            target,
        },
        reload_after_quiet_period,
    )
    .map_err(enforcement_reload_watcher_error)?;

    Ok(Some(EnforcementReloadWatcherHandle { inner }))
}

struct WatcherReloadContext {
    plan: Arc<RuntimePlan>,
    runtime_state: EnforcementRuntimeState,
    gate: EnforcementReloadGate,
    target: LocalEnforcementManifestWatchTarget,
}

fn enforcement_reload_watcher_error(error: ReloadWatcherError) -> EnforcementReloadWatcherError {
    match error {
        ReloadWatcherError::Create(source) => EnforcementReloadWatcherError::Create(source),
        ReloadWatcherError::WatchPath { path, source } => {
            EnforcementReloadWatcherError::WatchPath { path, source }
        }
    }
}

fn reload_after_quiet_period<'a>(
    watcher: &'a mut RecommendedWatcher,
    context: &'a WatcherReloadContext,
) -> ReloadFuture<'a> {
    Box::pin(async move {
        refresh_manifest_watches(watcher, &context.target);
        reload_after_enforcement_policy_change(context).await;
    })
}

fn notify_event_requests_reload(event: notify::Result<Event>, manifest_path: &Path) -> bool {
    match event {
        Ok(event) => event_requests_reload(&event, manifest_path),
        Err(error) => {
            warn!("enforcement policy reload watcher event error: {error}");
            false
        }
    }
}

fn event_requests_reload(event: &Event, manifest_path: &Path) -> bool {
    !matches!(event.kind, EventKind::Access(_))
        && (event.paths.is_empty()
            || event
                .paths
                .iter()
                .any(|path| path_matches_manifest(path, manifest_path)))
}

fn path_matches_manifest(path: &Path, manifest_path: &Path) -> bool {
    path.starts_with(manifest_path) || manifest_path.starts_with(path)
}

fn refresh_manifest_watches(
    watcher: &mut RecommendedWatcher,
    target: &LocalEnforcementManifestWatchTarget,
) {
    refresh_manifest_dir_watch(watcher, target);
    refresh_manifest_file_watch(watcher, target);
}

fn refresh_manifest_dir_watch(
    watcher: &mut RecommendedWatcher,
    target: &LocalEnforcementManifestWatchTarget,
) {
    if target.source_kind != EnforcementPolicySourceKind::Directory {
        return;
    }
    match inspect_manifest_dir(&target.manifest_dir) {
        Ok(ManifestDirState::Missing | ManifestDirState::Invalid) => return,
        Err(error) => {
            warn!(
                path = %target.manifest_dir.display(),
                "failed to inspect enforcement policy manifest directory watch path after local change: {error}"
            );
            return;
        }
        Ok(ManifestDirState::Directory) => {}
    }
    if let Err(error) = watcher.watch(&target.manifest_dir, RecursiveMode::NonRecursive) {
        warn!(
            path = %target.manifest_dir.display(),
            "failed to refresh enforcement policy manifest directory watch after local change: {error}"
        );
    }
}

fn refresh_manifest_file_watch(
    watcher: &mut RecommendedWatcher,
    target: &LocalEnforcementManifestWatchTarget,
) {
    match inspect_manifest_path(&target.manifest_path) {
        Ok(ManifestPathState::Missing | ManifestPathState::Invalid) => return,
        Err(error) => {
            warn!(
                path = %target.manifest_path.display(),
                "failed to inspect enforcement policy manifest watch path after local change: {error}"
            );
            return;
        }
        Ok(ManifestPathState::RegularFile) => {}
    }
    if let Err(error) = watcher.watch(&target.manifest_path, RecursiveMode::NonRecursive) {
        warn!(
            path = %target.manifest_path.display(),
            "failed to refresh enforcement policy manifest watch after local change: {error}"
        );
    }
}

fn inspect_manifest_path(path: &Path) -> Result<ManifestPathState, io::Error> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Ok(ManifestPathState::Invalid),
        Ok(metadata) if metadata.is_file() => Ok(ManifestPathState::RegularFile),
        Ok(_) => Ok(ManifestPathState::Invalid),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(ManifestPathState::Missing),
        Err(error) => Err(error),
    }
}

fn inspect_manifest_dir(path: &Path) -> Result<ManifestDirState, io::Error> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Ok(ManifestDirState::Invalid),
        Ok(metadata) if metadata.is_dir() => Ok(ManifestDirState::Directory),
        Ok(_) => Ok(ManifestDirState::Invalid),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(ManifestDirState::Missing),
        Err(error) => Err(error),
    }
}

async fn reload_after_enforcement_policy_change(context: &WatcherReloadContext) {
    match reload_enforcement_policy(&context.plan, Some(&context.runtime_state), &context.gate)
        .await
    {
        Ok(summary) => {
            info!(
                manifest_selector_configured = summary.active_policy.manifest_selector_configured(),
                effective_selector_configured =
                    summary.active_policy.effective_selector_configured(),
                "reloaded enforcement policy after local manifest change"
            );
        }
        Err(error) => {
            warn!("failed to reload enforcement policy after local manifest change: {error}");
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LocalEnforcementManifestWatchTarget {
    source_kind: EnforcementPolicySourceKind,
    manifest_path: PathBuf,
    manifest_dir: PathBuf,
    watch_roots: Vec<PathBuf>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ManifestPathState {
    Missing,
    RegularFile,
    Invalid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ManifestDirState {
    Missing,
    Directory,
    Invalid,
}

fn local_enforcement_manifest_watch_target(
    plan: &RuntimePlan,
) -> Option<LocalEnforcementManifestWatchTarget> {
    match &plan.enforcement.policy_source {
        EnforcementPolicySourcePlan::LocalManifest { source_kind, path }
            if !path.as_os_str().is_empty() =>
        {
            Some(local_enforcement_manifest_watch_target_from_path(
                *source_kind,
                path,
            ))
        }
        EnforcementPolicySourcePlan::None | EnforcementPolicySourcePlan::Remote { .. } => None,
        EnforcementPolicySourcePlan::LocalManifest { .. } => None,
    }
}

fn local_enforcement_manifest_watch_target_from_path(
    source_kind: EnforcementPolicySourceKind,
    path: &Path,
) -> LocalEnforcementManifestWatchTarget {
    let manifest_path = absolute_path(path);
    let manifest_dir = manifest_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let watch_roots = local_enforcement_manifest_watch_roots(source_kind, &manifest_dir);
    LocalEnforcementManifestWatchTarget {
        source_kind,
        manifest_path,
        manifest_dir,
        watch_roots,
    }
}

fn local_enforcement_manifest_watch_roots(
    source_kind: EnforcementPolicySourceKind,
    manifest_dir: &Path,
) -> Vec<PathBuf> {
    let mut roots = BTreeSet::from([manifest_dir.to_path_buf()]);
    if source_kind == EnforcementPolicySourceKind::Directory {
        let source_parent = manifest_dir
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        roots.insert(source_parent);
    }
    roots.into_iter().collect()
}

fn enforcement_reload_watch_paths(
    target: &LocalEnforcementManifestWatchTarget,
) -> Result<Vec<ReloadWatchPath>, EnforcementReloadWatcherError> {
    let mut paths = target
        .watch_roots
        .iter()
        .cloned()
        .map(ReloadWatchPath::non_recursive)
        .collect::<Vec<_>>();
    if target.source_kind == EnforcementPolicySourceKind::Directory {
        match inspect_manifest_dir(&target.manifest_dir).map_err(|source| {
            EnforcementReloadWatcherError::InspectPath {
                path: target.manifest_dir.clone(),
                source,
            }
        })? {
            ManifestDirState::Missing => {}
            ManifestDirState::Invalid => {
                return Err(EnforcementReloadWatcherError::InvalidManifestDirectory {
                    path: target.manifest_dir.clone(),
                });
            }
            ManifestDirState::Directory => {
                paths.push(ReloadWatchPath::non_recursive(target.manifest_dir.clone()));
            }
        }
    }
    match inspect_manifest_path(&target.manifest_path).map_err(|source| {
        EnforcementReloadWatcherError::InspectPath {
            path: target.manifest_path.clone(),
            source,
        }
    })? {
        ManifestPathState::Missing => {}
        ManifestPathState::Invalid => {
            return Err(EnforcementReloadWatcherError::InvalidManifestPath {
                path: target.manifest_path.clone(),
            });
        }
        ManifestPathState::RegularFile => {
            paths.push(ReloadWatchPath::non_recursive(target.manifest_path.clone()));
        }
    }
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::symlink, time::Instant};

    use enforcement::{EnforcementPlanRequest, EnforcementPlanner, ScopedEnforcementPlanner};
    use probe_config::{
        AgentConfig, CaptureBackend, CaptureSelection, EnforcementPolicyManifest,
        EnforcementPolicyReloadConfig, EnforcementPolicySourceConfig,
        MIN_ENFORCEMENT_POLICY_RELOAD_WATCH_DEBOUNCE_MS, TransparentInterceptionStrategyConfig,
    };
    use probe_core::{
        Action, AddressPort, CapabilityKind, CapabilityState, CaptureOrigin, CaptureSource,
        Direction, EnforcementDecision, EnforcementMode, EnforcementOutcome, EventEnvelope,
        EventKind, FlowContext, FlowIdentity, HttpHeaders, ProcessContext, ProcessIdentity,
        ProcessSelector, ProtectiveActionProfile, Selector, Timestamp, TrafficSelector,
        TransportProtocol, Verdict, VerdictScope,
    };
    use runtime::{
        CaptureProviderBuilder, CaptureProviderDescriptor, EnforcementPolicySourcePlan,
        ProviderRegistry, RuntimePlan,
    };

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[tokio::test]
    async fn watcher_reloads_active_enforcement_policy_after_file_change() -> TestResult {
        let temp = tempfile::tempdir()?;
        let manifest_path = temp.path().join("enforcement.toml");
        write_enforcement_manifest(&manifest_path, "initial", 80, Action::Deny)?;
        let mut config = replay_config(temp.path().join("spool"));
        config.enforcement.mode = EnforcementMode::DryRun;
        config.enforcement.policy.source = EnforcementPolicySourceConfig::File {
            path: manifest_path.clone(),
        };
        config.enforcement.policy.reload = reload_config();
        let plan = Arc::new(runtime_plan_from_config(config)?);
        let configured = crate::configured_enforcement::build_configured_enforcement_with_backend(
            &plan,
            None,
            crate::configured_enforcement::EnforcementPolicySourceLoadContext::default(),
        )
        .await?;
        let (mut planner_view, runtime_state) =
            EnforcementRuntimeState::from_planner(configured.planner, configured.active_policy);
        assert_enforcement_decision(
            &mut planner_view,
            Action::Deny,
            80,
            EnforcementOutcome::DryRun,
            true,
        )?;

        let watcher = spawn_watcher(
            Arc::clone(&plan),
            runtime_state,
            EnforcementReloadGate::default(),
        )?
        .expect("watcher should start for a local enforcement manifest");
        write_enforcement_manifest(&manifest_path, "reloaded", 443, Action::Reset)?;

        wait_until_enforcement_decision(
            &mut planner_view,
            Action::Reset,
            443,
            EnforcementOutcome::DryRun,
            true,
        )
        .await?;
        assert_enforcement_decision(
            &mut planner_view,
            Action::Deny,
            80,
            EnforcementOutcome::SelectorMiss,
            false,
        )?;

        watcher.stop().await;
        Ok(())
    }

    #[tokio::test]
    async fn watcher_survives_local_manifest_file_replacement() -> TestResult {
        let temp = tempfile::tempdir()?;
        let manifest_path = temp.path().join("enforcement.toml");
        write_enforcement_manifest(&manifest_path, "initial", 80, Action::Deny)?;
        let mut config = replay_config(temp.path().join("spool"));
        config.enforcement.mode = EnforcementMode::DryRun;
        config.enforcement.policy.source = EnforcementPolicySourceConfig::File {
            path: manifest_path.clone(),
        };
        config.enforcement.policy.reload = reload_config();
        let plan = Arc::new(runtime_plan_from_config(config)?);
        let configured = crate::configured_enforcement::build_configured_enforcement_with_backend(
            &plan,
            None,
            crate::configured_enforcement::EnforcementPolicySourceLoadContext::default(),
        )
        .await?;
        let (mut planner_view, runtime_state) =
            EnforcementRuntimeState::from_planner(configured.planner, configured.active_policy);
        let watcher = spawn_watcher(
            Arc::clone(&plan),
            runtime_state,
            EnforcementReloadGate::default(),
        )?
        .expect("watcher should start for a local enforcement manifest");

        replace_enforcement_manifest(&manifest_path, "reloaded", 443, Action::Reset)?;
        wait_until_enforcement_decision(
            &mut planner_view,
            Action::Reset,
            443,
            EnforcementOutcome::DryRun,
            true,
        )
        .await?;

        write_enforcement_manifest(&manifest_path, "newer", 9443, Action::Deny)?;
        wait_until_enforcement_decision(
            &mut planner_view,
            Action::Deny,
            9443,
            EnforcementOutcome::DryRun,
            true,
        )
        .await?;

        watcher.stop().await;
        Ok(())
    }

    #[tokio::test]
    async fn watcher_survives_local_manifest_directory_replacement() -> TestResult {
        let temp = tempfile::tempdir()?;
        let manifest_dir = temp.path().join("enforcement.d");
        let manifest_path = manifest_dir.join("manifest.toml");
        write_enforcement_manifest(&manifest_path, "initial", 80, Action::Deny)?;
        let mut config = replay_config(temp.path().join("spool"));
        config.enforcement.mode = EnforcementMode::DryRun;
        config.enforcement.policy.source = EnforcementPolicySourceConfig::Directory {
            path: manifest_dir.clone(),
        };
        config.enforcement.policy.reload = reload_config();
        let plan = Arc::new(runtime_plan_from_config(config)?);
        let configured = crate::configured_enforcement::build_configured_enforcement_with_backend(
            &plan,
            None,
            crate::configured_enforcement::EnforcementPolicySourceLoadContext::default(),
        )
        .await?;
        let (mut planner_view, runtime_state) =
            EnforcementRuntimeState::from_planner(configured.planner, configured.active_policy);
        let watcher = spawn_watcher(
            Arc::clone(&plan),
            runtime_state,
            EnforcementReloadGate::default(),
        )?
        .expect("watcher should start for a local enforcement manifest directory");

        replace_enforcement_manifest_directory(&manifest_dir, "reloaded", 443, Action::Reset)?;
        wait_until_enforcement_decision(
            &mut planner_view,
            Action::Reset,
            443,
            EnforcementOutcome::DryRun,
            true,
        )
        .await?;

        write_enforcement_manifest(&manifest_path, "newer", 9443, Action::Deny)?;
        wait_until_enforcement_decision(
            &mut planner_view,
            Action::Deny,
            9443,
            EnforcementOutcome::DryRun,
            true,
        )
        .await?;

        watcher.stop().await;
        Ok(())
    }

    #[tokio::test]
    async fn watcher_keeps_active_policy_after_manifest_directory_becomes_symlink() -> TestResult {
        let temp = tempfile::tempdir()?;
        let manifest_dir = temp.path().join("enforcement.d");
        let manifest_path = manifest_dir.join("manifest.toml");
        write_enforcement_manifest(&manifest_path, "initial", 80, Action::Deny)?;
        let mut config = replay_config(temp.path().join("spool"));
        config.enforcement.mode = EnforcementMode::DryRun;
        config.enforcement.policy.source = EnforcementPolicySourceConfig::Directory {
            path: manifest_dir.clone(),
        };
        config.enforcement.policy.reload = reload_config();
        let plan = Arc::new(runtime_plan_from_config(config)?);
        let configured = crate::configured_enforcement::build_configured_enforcement_with_backend(
            &plan,
            None,
            crate::configured_enforcement::EnforcementPolicySourceLoadContext::default(),
        )
        .await?;
        let (mut planner_view, runtime_state) =
            EnforcementRuntimeState::from_planner(configured.planner, configured.active_policy);
        let watcher = spawn_watcher(
            Arc::clone(&plan),
            runtime_state,
            EnforcementReloadGate::default(),
        )?
        .expect("watcher should start for a local enforcement manifest directory");

        replace_enforcement_manifest_directory_with_symlink(
            &manifest_dir,
            "symlinked",
            443,
            Action::Reset,
        )?;
        assert_enforcement_decision_does_not_become(
            &mut planner_view,
            Action::Reset,
            443,
            EnforcementOutcome::DryRun,
            true,
        )
        .await?;
        assert_enforcement_decision(
            &mut planner_view,
            Action::Deny,
            80,
            EnforcementOutcome::DryRun,
            true,
        )?;

        watcher.stop().await;
        Ok(())
    }

    #[tokio::test]
    async fn watcher_rejects_symlink_manifest_path() -> TestResult {
        let temp = tempfile::tempdir()?;
        let real_manifest = temp.path().join("real.toml");
        let manifest_path = temp.path().join("enforcement.toml");
        write_enforcement_manifest(&real_manifest, "initial", 80, Action::Deny)?;
        symlink(&real_manifest, &manifest_path)?;
        let mut config = replay_config(temp.path().join("spool"));
        config.enforcement.policy.source = EnforcementPolicySourceConfig::File {
            path: manifest_path.clone(),
        };
        config.enforcement.policy.reload = reload_config();
        let plan = Arc::new(runtime_plan_from_config(config)?);
        let runtime_state = empty_runtime_state().await?;

        let Err(error) = spawn_watcher(plan, runtime_state, EnforcementReloadGate::default())
        else {
            panic!("symlink enforcement manifest must not be watched");
        };

        assert!(matches!(
            error,
            EnforcementReloadWatcherError::InvalidManifestPath { path } if path == manifest_path
        ));
        Ok(())
    }

    #[tokio::test]
    async fn watcher_rejects_setup_time_interception_plan() -> TestResult {
        let temp = tempfile::tempdir()?;
        let manifest_path = temp.path().join("enforcement.toml");
        write_enforcement_manifest(&manifest_path, "initial", 80, Action::Deny)?;
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Libpcap;
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::InboundTproxy;
        config.enforcement.interception.proxy.listen_port = Some(15001);
        config.enforcement.interception.selector = Some(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                local_ports: vec![8443],
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        ));
        config.enforcement.policy.source = EnforcementPolicySourceConfig::File {
            path: manifest_path,
        };
        config.enforcement.policy.reload = reload_config();
        let plan = Arc::new(RuntimePlan::build(
            config,
            &transparent_interception_registry(),
        )?);
        let runtime_state = empty_runtime_state().await?;

        let Err(error) = spawn_watcher(plan, runtime_state, EnforcementReloadGate::default())
        else {
            panic!("setup-time interception plan must reject watcher reload");
        };

        assert!(matches!(
            error,
            EnforcementReloadWatcherError::UnsupportedPlan(
                crate::enforcement_reload::EnforcementReloadError::SetupTimeInterception
            )
        ));
        Ok(())
    }

    async fn wait_until_enforcement_decision(
        planner: &mut impl EnforcementPlanner,
        action: Action,
        remote_port: u16,
        expected_outcome: EnforcementOutcome,
        expected_selector_match: bool,
    ) -> TestResult {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let decision = enforcement_decision(planner, action, remote_port)?;
            if decision.outcome == expected_outcome
                && decision.selector_matched == expected_selector_match
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "timed out waiting for enforcement reload, last outcome {:?}",
                    decision.outcome
                )
                .into());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn assert_enforcement_decision_does_not_become(
        planner: &mut impl EnforcementPlanner,
        action: Action,
        remote_port: u16,
        rejected_outcome: EnforcementOutcome,
        rejected_selector_match: bool,
    ) -> TestResult {
        let deadline = Instant::now() + Duration::from_millis(500);
        loop {
            let decision = enforcement_decision(planner, action, remote_port)?;
            if decision.outcome == rejected_outcome
                && decision.selector_matched == rejected_selector_match
            {
                return Err("enforcement policy unexpectedly changed".into());
            }
            if Instant::now() >= deadline {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn assert_enforcement_decision(
        planner: &mut impl EnforcementPlanner,
        action: Action,
        remote_port: u16,
        expected_outcome: EnforcementOutcome,
        expected_selector_match: bool,
    ) -> TestResult {
        let decision = enforcement_decision(planner, action, remote_port)?;
        assert_eq!(decision.outcome, expected_outcome);
        assert_eq!(decision.selector_matched, expected_selector_match);
        Ok(())
    }

    fn enforcement_decision(
        planner: &mut impl EnforcementPlanner,
        action: Action,
        remote_port: u16,
    ) -> Result<EnforcementDecision, Box<dyn std::error::Error>> {
        let trigger = request_event(remote_port);
        let verdict = Verdict {
            action,
            scope: VerdictScope::Flow,
            reason: "managed policy".to_string(),
            confidence: 100,
            ttl_ms: None,
        };
        Ok(planner
            .evaluate(EnforcementPlanRequest {
                verdict: &verdict,
                trigger: &trigger,
            })
            .expect("protective verdict should produce enforcement audit"))
    }

    async fn empty_runtime_state() -> Result<EnforcementRuntimeState, Box<dyn std::error::Error>> {
        let planner = ScopedEnforcementPlanner::new(EnforcementMode::AuditOnly, None)?;
        let selector_registry = probe_core::SelectorRegistry::default();
        let active_policy =
            crate::configured_enforcement::load_configured_enforcement_policy_runtime(
                None,
                &selector_registry,
                &EnforcementPolicySourcePlan::None,
                crate::configured_enforcement::EnforcementPolicySourceLoadContext::default(),
            )
            .await?;
        let (_, runtime_state) = EnforcementRuntimeState::from_planner(planner, active_policy);
        Ok(runtime_state)
    }

    fn runtime_plan_from_config(config: AgentConfig) -> Result<RuntimePlan, runtime::RuntimeError> {
        RuntimePlan::build(config, &replay_registry())
    }

    fn replay_registry() -> ProviderRegistry {
        ProviderRegistry::new(
            vec![CaptureProviderDescriptor::available(
                CaptureBackend::Replay,
                CaptureProviderBuilder::Replay,
            )],
            platform_capabilities(),
        )
    }

    fn transparent_interception_registry() -> ProviderRegistry {
        ProviderRegistry::new(
            vec![CaptureProviderDescriptor::available(
                CaptureBackend::Libpcap,
                CaptureProviderBuilder::Libpcap,
            )],
            platform_capabilities()
                .into_iter()
                .map(|state| {
                    if state.kind == CapabilityKind::TransparentInterception {
                        CapabilityState::available(CapabilityKind::TransparentInterception)
                    } else {
                        state
                    }
                })
                .collect(),
        )
    }

    fn platform_capabilities() -> Vec<CapabilityState> {
        vec![
            CapabilityState::available(CapabilityKind::Http1),
            CapabilityState::available(CapabilityKind::Sse),
            CapabilityState::available(CapabilityKind::WebSocketHandoff),
            CapabilityState::available(CapabilityKind::WebSocketFrame),
            CapabilityState::unavailable(CapabilityKind::LibsslUprobe, "not built"),
            CapabilityState::available(CapabilityKind::L7Mitm),
            CapabilityState::available(CapabilityKind::DryRunEnforcement),
            CapabilityState::unavailable(CapabilityKind::ConnectionEnforcement, "not built"),
            CapabilityState::unavailable(CapabilityKind::TransparentInterception, "not built"),
        ]
    }

    fn replay_config(storage_path: PathBuf) -> AgentConfig {
        AgentConfig {
            capture: probe_config::CaptureConfig {
                selection: CaptureSelection::Replay,
                ..Default::default()
            },
            storage: probe_config::StorageConfig {
                path: storage_path,
                ..Default::default()
            },
            ..AgentConfig::default()
        }
    }

    fn reload_config() -> EnforcementPolicyReloadConfig {
        EnforcementPolicyReloadConfig {
            watch_local_manifest: true,
            debounce_ms: MIN_ENFORCEMENT_POLICY_RELOAD_WATCH_DEBOUNCE_MS,
            ..EnforcementPolicyReloadConfig::default()
        }
    }

    fn write_enforcement_manifest(
        path: &Path,
        version: &str,
        remote_port: u16,
        action: Action,
    ) -> TestResult {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let manifest = EnforcementPolicyManifest {
            id: "managed-apps".to_string(),
            version: version.to_string(),
            selectors: Default::default(),
            selector: Some(Selector::term(
                ProcessSelector::default(),
                TrafficSelector {
                    remote_ports: vec![remote_port],
                    directions: vec![Direction::Outbound],
                    ..TrafficSelector::default()
                },
            )),
            protective_actions: ProtectiveActionProfile::new([action])?,
        };
        fs::write(path, toml::to_string(&manifest)?)?;
        Ok(())
    }

    fn replace_enforcement_manifest(
        path: &Path,
        version: &str,
        remote_port: u16,
        action: Action,
    ) -> TestResult {
        let replacement = path.with_extension("toml.next");
        if replacement.exists() {
            fs::remove_file(&replacement)?;
        }
        write_enforcement_manifest(&replacement, version, remote_port, action)?;
        fs::remove_file(path)?;
        fs::rename(replacement, path)?;
        Ok(())
    }

    fn replace_enforcement_manifest_directory(
        path: &Path,
        version: &str,
        remote_port: u16,
        action: Action,
    ) -> TestResult {
        let replacement = path.with_extension("d.next");
        if replacement.exists() {
            fs::remove_dir_all(&replacement)?;
        }
        write_enforcement_manifest(
            &replacement.join("manifest.toml"),
            version,
            remote_port,
            action,
        )?;
        fs::remove_dir_all(path)?;
        fs::rename(replacement, path)?;
        Ok(())
    }

    fn replace_enforcement_manifest_directory_with_symlink(
        path: &Path,
        version: &str,
        remote_port: u16,
        action: Action,
    ) -> TestResult {
        let replacement = path.with_extension("d.symlink-target");
        if replacement.exists() {
            fs::remove_dir_all(&replacement)?;
        }
        write_enforcement_manifest(
            &replacement.join("manifest.toml"),
            version,
            remote_port,
            action,
        )?;
        fs::remove_dir_all(path)?;
        symlink(replacement, path)?;
        Ok(())
    }

    fn request_event(remote_port: u16) -> EventEnvelope {
        EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            demo_flow(remote_port),
            CaptureOrigin::from_source(CaptureSource::Replay),
            "test",
            EventKind::HttpRequestHeaders(HttpHeaders {
                direction: Direction::Outbound,
                stream_sequence: 1,
                method: Some("GET".to_string()),
                target: Some("/".to_string()),
                status: None,
                reason: None,
                version: "HTTP/1.1".to_string(),
                headers: Vec::new(),
            }),
        )
    }

    fn demo_flow(remote_port: u16) -> FlowContext {
        let process = ProcessIdentity {
            pid: 100,
            tgid: 100,
            start_time_ticks: 1,
            boot_id: "boot".to_string(),
            exe_path: "/usr/bin/demo".to_string(),
            cmdline_hash: "hash".to_string(),
            uid: 1000,
            gid: 1000,
            cgroup: None,
            systemd_service: None,
            container_id: None,
            runtime_hint: None,
        };
        let local = AddressPort {
            address: "127.0.0.1".to_string(),
            port: 50_000,
        };
        let remote = AddressPort {
            address: "127.0.0.1".to_string(),
            port: remote_port,
        };
        FlowContext {
            id: FlowIdentity::stable(&process, &local, &remote, TransportProtocol::Tcp, 1, None),
            process: ProcessContext {
                identity: process,
                name: "demo".to_string(),
                cmdline: vec!["demo".to_string()],
            },
            local,
            remote,
            protocol: TransportProtocol::Tcp,
            start_monotonic_ns: 1,
            socket_cookie: None,
            attribution_confidence: 100,
        }
    }
}
