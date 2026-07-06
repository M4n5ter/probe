use std::{
    fs, io,
    path::{Path, PathBuf},
    time::Duration,
};

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use pipeline::PipelinePolicySet;
use thiserror::Error;
use tracing::{info, warn};

use crate::{
    configured_enforcement::EnforcementRuntimeState,
    enforcement_reload::EnforcementReloadGate,
    policy_reload::PolicyReloadGate,
    reload_watcher::{
        ReloadFuture, ReloadWatchPath, ReloadWatcherError, ReloadWatcherHandle, absolute_path,
        spawn_reload_watcher_with_dynamic_debounce,
    },
    runtime_generation::RuntimeGenerationState,
    runtime_plan::RuntimePlanHandle,
    runtime_reload::{
        RuntimeReloadGate,
        config_reload::{
            ConfigReloadApplyAction, ConfigReloadApplyActionOutcome, ConfigReloadApplyRestriction,
            ConfigReloadApplyRuntime, ConfigReloadApplySnapshot, ConfigReloadDecision,
            ConfigReloadRuntimeGenerationActionOutcome, RuntimeConfigReloadOwner,
            apply_config_reload_to_runtime,
        },
    },
};

#[derive(Debug, Error)]
pub(crate) enum RuntimeConfigWatcherError {
    #[error("failed to create runtime config reload watcher: {0}")]
    Create(#[source] notify::Error),
    #[error("failed to watch runtime config reload path {path}: {source}")]
    WatchPath {
        path: PathBuf,
        #[source]
        source: notify::Error,
    },
    #[error("failed to inspect runtime config watch path {path}: {source}")]
    InspectPath {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("runtime config watch path {path} must be a non-symlink regular file")]
    InvalidConfigPath { path: PathBuf },
    #[error("runtime config parent watch path {path} must be a non-symlink directory")]
    InvalidConfigDirectory { path: PathBuf },
}

pub(crate) struct RuntimeConfigWatcherHandle {
    inner: ReloadWatcherHandle,
}

impl RuntimeConfigWatcherHandle {
    pub(crate) async fn stop(self) {
        self.inner.stop().await;
    }
}

pub(crate) struct RuntimeConfigWatcherContext {
    pub(crate) plan: RuntimePlanHandle,
    pub(crate) policy_set: PipelinePolicySet,
    pub(crate) policy_reload_gate: PolicyReloadGate,
    pub(crate) config_apply_gate: RuntimeReloadGate,
    pub(crate) enforcement_runtime: Option<EnforcementRuntimeState>,
    pub(crate) enforcement_reload_gate: EnforcementReloadGate,
    pub(crate) runtime_generation: RuntimeGenerationState,
}

pub(crate) fn spawn_watcher(
    config_path: Option<PathBuf>,
    context: RuntimeConfigWatcherContext,
) -> Result<Option<RuntimeConfigWatcherHandle>, RuntimeConfigWatcherError> {
    let initial_plan = context.plan.snapshot();
    let Some(config_path) = config_path else {
        if initial_plan.config.runtime_reload.watch_config {
            warn!("runtime config reload watcher is enabled, but no config path was provided");
        }
        return Ok(None);
    };
    let target = runtime_config_watch_target(&config_path)?;
    drop(initial_plan);
    let event_path = target.config_path.clone();
    let inner = spawn_reload_watcher_with_dynamic_debounce(
        "runtime config reload watcher",
        runtime_config_watch_paths(&target),
        runtime_config_reload_debounce,
        move |event| notify_event_requests_reload(event, &event_path),
        WatcherReloadContext { context, target },
        reload_after_quiet_period,
    )
    .map_err(runtime_config_watcher_error)?;

    Ok(Some(RuntimeConfigWatcherHandle { inner }))
}

struct WatcherReloadContext {
    context: RuntimeConfigWatcherContext,
    target: RuntimeConfigWatchTarget,
}

fn runtime_config_reload_debounce(context: &WatcherReloadContext) -> Duration {
    runtime_config_reload_debounce_for_context(&context.context)
}

fn runtime_config_reload_debounce_for_context(context: &RuntimeConfigWatcherContext) -> Duration {
    Duration::from_millis(context.plan.snapshot().config.runtime_reload.debounce_ms)
}

fn runtime_config_watcher_error(error: ReloadWatcherError) -> RuntimeConfigWatcherError {
    match error {
        ReloadWatcherError::Create(source) => RuntimeConfigWatcherError::Create(source),
        ReloadWatcherError::WatchPath { path, source } => {
            RuntimeConfigWatcherError::WatchPath { path, source }
        }
    }
}

fn reload_after_quiet_period<'a>(
    watcher: &'a mut RecommendedWatcher,
    context: &'a WatcherReloadContext,
) -> ReloadFuture<'a> {
    Box::pin(async move {
        refresh_config_watches(watcher, &context.target);
        reload_after_config_change(&context.context, &context.target.config_path).await;
    })
}

fn notify_event_requests_reload(event: notify::Result<Event>, config_path: &Path) -> bool {
    match event {
        Ok(event) => event_requests_reload(&event, config_path),
        Err(error) => {
            warn!("runtime config reload watcher event error: {error}");
            false
        }
    }
}

fn event_requests_reload(event: &Event, config_path: &Path) -> bool {
    !matches!(event.kind, EventKind::Access(_))
        && (event.paths.is_empty()
            || event
                .paths
                .iter()
                .any(|path| path_matches_config(path, config_path)))
}

fn path_matches_config(path: &Path, config_path: &Path) -> bool {
    path.starts_with(config_path) || config_path.starts_with(path)
}

fn refresh_config_watches(watcher: &mut RecommendedWatcher, target: &RuntimeConfigWatchTarget) {
    refresh_config_parent_watch(watcher, target);
    refresh_config_file_watch(watcher, target);
}

fn refresh_config_parent_watch(
    watcher: &mut RecommendedWatcher,
    target: &RuntimeConfigWatchTarget,
) {
    match inspect_config_parent(&target.config_dir) {
        Ok(ConfigParentState::Missing | ConfigParentState::Invalid) => return,
        Err(error) => {
            warn!(
                path = %target.config_dir.display(),
                "failed to inspect runtime config parent watch path after local change: {error}"
            );
            return;
        }
        Ok(ConfigParentState::Directory) => {}
    }
    if let Err(error) = watcher.watch(&target.config_dir, RecursiveMode::NonRecursive) {
        warn!(
            path = %target.config_dir.display(),
            "failed to refresh runtime config parent watch after local change: {error}"
        );
    }
}

fn refresh_config_file_watch(watcher: &mut RecommendedWatcher, target: &RuntimeConfigWatchTarget) {
    match inspect_config_path(&target.config_path) {
        Ok(ConfigPathState::Missing | ConfigPathState::Invalid) => return,
        Err(error) => {
            warn!(
                path = %target.config_path.display(),
                "failed to inspect runtime config watch path after local change: {error}"
            );
            return;
        }
        Ok(ConfigPathState::RegularFile) => {}
    }
    if let Err(error) = watcher.watch(&target.config_path, RecursiveMode::NonRecursive) {
        warn!(
            path = %target.config_path.display(),
            "failed to refresh runtime config file watch after local change: {error}"
        );
    }
}

async fn reload_after_config_change(
    context: &RuntimeConfigWatcherContext,
    config_path: &Path,
) -> ConfigReloadApplySnapshot {
    let snapshot = apply_config_reload_once(context, config_path).await;
    if reload_outcome_was_ignored_by_disabled_runtime_reload(&snapshot) {
        info!("runtime config reload watcher ignored config change while disabled");
    } else {
        log_config_reload_apply_outcome(config_path, &snapshot);
    }
    snapshot
}

async fn apply_config_reload_once(
    context: &RuntimeConfigWatcherContext,
    config_path: &Path,
) -> ConfigReloadApplySnapshot {
    apply_config_reload_once_with_restriction(
        context,
        config_path,
        ConfigReloadApplyRestriction::RespectActiveRuntimeReload,
    )
    .await
}

async fn apply_config_reload_once_with_restriction(
    context: &RuntimeConfigWatcherContext,
    config_path: &Path,
    apply_restriction: ConfigReloadApplyRestriction,
) -> ConfigReloadApplySnapshot {
    apply_config_reload_to_runtime(
        ConfigReloadApplyRuntime {
            plan_handle: &context.plan,
            config_apply_gate: &context.config_apply_gate,
            policy_set: &context.policy_set,
            policy_reload_gate: &context.policy_reload_gate,
            enforcement_runtime_state: context.enforcement_runtime.as_ref(),
            enforcement_reload_gate: &context.enforcement_reload_gate,
            runtime_generation: Some(&context.runtime_generation),
            runtime_config_reload_owner: RuntimeConfigReloadOwner::Attached,
            apply_restriction,
        },
        config_path,
    )
    .await
}

fn log_config_reload_apply_outcome(config_path: &Path, snapshot: &ConfigReloadApplySnapshot) {
    if reload_outcome_needs_operator_attention(snapshot) {
        warn!(
            path = %config_path.display(),
            decision = ?snapshot.plan.decision,
            actions = ?snapshot.actions,
            "runtime config reload watcher needs operator attention"
        );
        return;
    }
    info!(
        path = %config_path.display(),
        decision = ?snapshot.plan.decision,
        active_plan_updated = snapshot.active_plan_updated,
        actions = ?snapshot.actions,
        "runtime config reload watcher processed config change"
    );
}

fn reload_outcome_needs_operator_attention(snapshot: &ConfigReloadApplySnapshot) -> bool {
    matches!(
        snapshot.plan.decision,
        ConfigReloadDecision::RestartRequired { .. }
            | ConfigReloadDecision::InvalidCandidate { .. }
    ) || snapshot
        .actions
        .iter()
        .any(config_reload_apply_action_failed)
}

fn reload_outcome_was_ignored_by_disabled_runtime_reload(
    snapshot: &ConfigReloadApplySnapshot,
) -> bool {
    matches!(
        snapshot.plan.decision,
        ConfigReloadDecision::ApplyOnline { .. }
    ) && !snapshot.plan.only_updates_runtime_reload_online()
        && !snapshot.active_plan_updated
        && snapshot.actions.is_empty()
}

fn config_reload_apply_action_failed(action: &ConfigReloadApplyAction) -> bool {
    matches!(
        action,
        ConfigReloadApplyAction::ReloadPolicies(ConfigReloadApplyActionOutcome::Failed { .. })
            | ConfigReloadApplyAction::ReloadEnforcementPolicy(
                ConfigReloadApplyActionOutcome::Failed { .. },
            )
            | ConfigReloadApplyAction::RequestRuntimeGeneration(
                ConfigReloadRuntimeGenerationActionOutcome::Failed { .. },
            )
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RuntimeConfigWatchTarget {
    config_path: PathBuf,
    config_dir: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConfigPathState {
    Missing,
    RegularFile,
    Invalid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConfigParentState {
    Missing,
    Directory,
    Invalid,
}

fn runtime_config_watch_target(
    config_path: &Path,
) -> Result<RuntimeConfigWatchTarget, RuntimeConfigWatcherError> {
    let config_path = absolute_path(config_path);
    match inspect_config_path(&config_path) {
        Ok(ConfigPathState::RegularFile) => {}
        Ok(ConfigPathState::Missing | ConfigPathState::Invalid) => {
            return Err(RuntimeConfigWatcherError::InvalidConfigPath { path: config_path });
        }
        Err(source) => {
            return Err(RuntimeConfigWatcherError::InspectPath {
                path: config_path,
                source,
            });
        }
    }
    let config_dir = config_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    match inspect_config_parent(&config_dir) {
        Ok(ConfigParentState::Directory) => {}
        Ok(ConfigParentState::Missing | ConfigParentState::Invalid) => {
            return Err(RuntimeConfigWatcherError::InvalidConfigDirectory { path: config_dir });
        }
        Err(source) => {
            return Err(RuntimeConfigWatcherError::InspectPath {
                path: config_dir,
                source,
            });
        }
    }
    Ok(RuntimeConfigWatchTarget {
        config_path,
        config_dir,
    })
}

fn runtime_config_watch_paths(target: &RuntimeConfigWatchTarget) -> Vec<ReloadWatchPath> {
    vec![
        ReloadWatchPath::non_recursive(target.config_dir.clone()),
        ReloadWatchPath::non_recursive(target.config_path.clone()),
    ]
}

fn inspect_config_path(path: &Path) -> Result<ConfigPathState, io::Error> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Ok(ConfigPathState::Invalid),
        Ok(metadata) if metadata.is_file() => Ok(ConfigPathState::RegularFile),
        Ok(_) => Ok(ConfigPathState::Invalid),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(ConfigPathState::Missing),
        Err(error) => Err(error),
    }
}

fn inspect_config_parent(path: &Path) -> Result<ConfigParentState, io::Error> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Ok(ConfigParentState::Invalid),
        Ok(metadata) if metadata.is_dir() => Ok(ConfigParentState::Directory),
        Ok(_) => Ok(ConfigParentState::Invalid),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(ConfigParentState::Missing),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, sync::Arc};

    use notify::{
        Config, Event, EventKind, RecommendedWatcher,
        event::{AccessKind, DataChange, ModifyKind, RenameMode},
    };
    use probe_config::{
        AgentConfig, CaptureSelection, IngressJournalRetentionConfig, LiveCaptureBackend,
        StorageConfig, StorageRetentionConfig,
    };
    use probe_core::{CapabilityKind, CapabilityState};
    use runtime::{
        CaptureProviderBuilder, CaptureProviderDescriptor, ProviderRegistry, RuntimePlan,
    };

    use crate::runtime_generation::RuntimeGenerationReloadRequestInput;

    use super::*;

    #[test]
    fn config_event_matches_atomic_replace_parent_event() {
        let config_path = PathBuf::from("/tmp/probe/agent.toml");
        let event = Event {
            kind: EventKind::Modify(ModifyKind::Name(RenameMode::Any)),
            paths: vec![PathBuf::from("/tmp/probe")],
            attrs: Default::default(),
        };

        assert!(event_requests_reload(&event, &config_path));
    }

    #[test]
    fn config_event_ignores_unrelated_paths() {
        let config_path = PathBuf::from("/tmp/probe/agent.toml");
        let event = Event {
            kind: EventKind::Modify(ModifyKind::Data(DataChange::Any)),
            paths: vec![PathBuf::from("/tmp/probe/other.toml")],
            attrs: Default::default(),
        };

        assert!(!event_requests_reload(&event, &config_path));
    }

    #[test]
    fn config_event_ignores_access_events() {
        let config_path = PathBuf::from("/tmp/probe/agent.toml");
        let event = Event {
            kind: EventKind::Access(AccessKind::Any),
            paths: vec![config_path.clone()],
            attrs: Default::default(),
        };

        assert!(!event_requests_reload(&event, &config_path));
    }

    #[test]
    fn runtime_config_reload_debounce_follows_active_plan() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut config = base_config(PathBuf::from("/tmp/probe-spool"));
        config.runtime_reload.debounce_ms = 500;
        let context = watcher_context(runtime_plan(config)?);
        let mut updated_config = context.plan.snapshot().config.clone();
        updated_config.runtime_reload.debounce_ms = 1_000;

        assert_eq!(
            runtime_config_reload_debounce_for_context(&context),
            Duration::from_millis(500)
        );
        context.plan.replace(runtime_plan(updated_config)?);
        assert_eq!(
            runtime_config_reload_debounce_for_context(&context),
            Duration::from_millis(1_000)
        );
        Ok(())
    }

    #[tokio::test]
    async fn spawn_watcher_creates_dormant_watcher_when_runtime_reload_is_disabled()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let mut config = base_config(temp.path().join("spool"));
        config.runtime_reload.watch_config = false;
        let config_path = temp.path().join("agent.toml");
        fs::write(&config_path, toml::to_string(&config)?)?;
        let context = watcher_context(runtime_plan(config)?);

        let watcher = spawn_watcher(Some(config_path), context)?;

        let watcher = watcher.expect("config path should create a dormant runtime config watcher");
        watcher.stop().await;
        Ok(())
    }

    #[tokio::test]
    async fn disabled_runtime_config_reload_watcher_ignores_mixed_candidate_file()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let mut current_config = base_config(temp.path().join("spool"));
        current_config.runtime_reload.watch_config = false;
        let current = runtime_plan(current_config)?;
        let mut candidate = current.config.clone();
        candidate.runtime_reload.watch_config = true;
        candidate.storage.retention = StorageRetentionConfig {
            ingress: IngressJournalRetentionConfig {
                max_age_ms: None,
                max_records: Some(100_000),
                sweep_interval_ms: 5_000,
                prune_batch_limit: 128,
            },
            ..StorageRetentionConfig::default()
        };
        let config_path = temp.path().join("agent.toml");
        fs::write(&config_path, toml::to_string(&candidate)?)?;
        let context = watcher_context(current);
        let target = runtime_config_watch_target(&config_path)?;
        let watch_context = WatcherReloadContext { context, target };
        let mut watcher = RecommendedWatcher::new(|_| {}, Config::default())?;

        reload_after_quiet_period(&mut watcher, &watch_context).await;

        assert_eq!(
            watch_context
                .context
                .plan
                .snapshot()
                .config
                .storage
                .retention
                .ingress
                .max_records,
            None
        );
        Ok(())
    }

    #[tokio::test]
    async fn disabled_runtime_config_reload_watcher_applies_runtime_reload_config()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let mut current_config = base_config(temp.path().join("spool"));
        current_config.runtime_reload.watch_config = false;
        current_config.runtime_reload.debounce_ms = 500;
        let current = runtime_plan(current_config)?;
        let mut candidate = current.config.clone();
        candidate.runtime_reload.watch_config = true;
        candidate.runtime_reload.debounce_ms = 1_000;
        let config_path = temp.path().join("agent.toml");
        fs::write(&config_path, toml::to_string(&candidate)?)?;
        let context = watcher_context(current);
        let target = runtime_config_watch_target(&config_path)?;
        let watch_context = WatcherReloadContext { context, target };
        let mut watcher = RecommendedWatcher::new(|_| {}, Config::default())?;

        reload_after_quiet_period(&mut watcher, &watch_context).await;

        let active_config = &watch_context.context.plan.snapshot().config;
        assert!(active_config.runtime_reload.watch_config);
        assert_eq!(active_config.runtime_reload.debounce_ms, 1_000);
        Ok(())
    }

    #[tokio::test]
    async fn runtime_config_reload_watcher_rechecks_disabled_plan_after_apply_gate_wait()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let mut current_config = base_config(temp.path().join("spool"));
        current_config.runtime_reload.watch_config = true;
        let current = runtime_plan(current_config)?;
        let mut candidate = current.config.clone();
        candidate.storage.retention = StorageRetentionConfig {
            ingress: IngressJournalRetentionConfig {
                max_age_ms: None,
                max_records: Some(100_000),
                sweep_interval_ms: 5_000,
                prune_batch_limit: 128,
            },
            ..StorageRetentionConfig::default()
        };
        let config_path = temp.path().join("agent.toml");
        fs::write(&config_path, toml::to_string(&candidate)?)?;
        let context = watcher_context(current);
        let target = runtime_config_watch_target(&config_path)?;
        let watch_context = WatcherReloadContext { context, target };
        let mut watcher = RecommendedWatcher::new(|_| {}, Config::default())?;
        let apply_guard = watch_context.context.config_apply_gate.lock().await;
        let mut reload = reload_after_quiet_period(&mut watcher, &watch_context);

        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut reload)
                .await
                .is_err()
        );
        let mut disabled_config = watch_context.context.plan.snapshot().config.clone();
        disabled_config.runtime_reload.watch_config = false;
        watch_context
            .context
            .plan
            .replace(runtime_plan(disabled_config)?);
        drop(apply_guard);
        reload.await;

        let active_config = &watch_context.context.plan.snapshot().config;
        assert!(!active_config.runtime_reload.watch_config);
        assert_eq!(active_config.storage.retention.ingress.max_records, None);
        Ok(())
    }

    #[tokio::test]
    async fn runtime_config_reload_watcher_rechecks_enabled_plan_after_apply_gate_wait()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let mut current_config = base_config(temp.path().join("spool"));
        current_config.runtime_reload.watch_config = false;
        let current = runtime_plan(current_config)?;
        let mut candidate = current.config.clone();
        candidate.runtime_reload.watch_config = true;
        candidate.storage.retention = StorageRetentionConfig {
            ingress: IngressJournalRetentionConfig {
                max_age_ms: None,
                max_records: Some(100_000),
                sweep_interval_ms: 5_000,
                prune_batch_limit: 128,
            },
            ..StorageRetentionConfig::default()
        };
        let config_path = temp.path().join("agent.toml");
        fs::write(&config_path, toml::to_string(&candidate)?)?;
        let context = watcher_context(current);
        let target = runtime_config_watch_target(&config_path)?;
        let watch_context = WatcherReloadContext { context, target };
        let mut watcher = RecommendedWatcher::new(|_| {}, Config::default())?;
        let apply_guard = watch_context.context.config_apply_gate.lock().await;
        let mut reload = reload_after_quiet_period(&mut watcher, &watch_context);

        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut reload)
                .await
                .is_err()
        );
        let mut enabled_config = watch_context.context.plan.snapshot().config.clone();
        enabled_config.runtime_reload.watch_config = true;
        watch_context
            .context
            .plan
            .replace(runtime_plan(enabled_config)?);
        drop(apply_guard);
        reload.await;

        let active_config = &watch_context.context.plan.snapshot().config;
        assert!(active_config.runtime_reload.watch_config);
        assert_eq!(
            active_config.storage.retention.ingress.max_records,
            Some(100_000)
        );
        Ok(())
    }

    #[tokio::test]
    async fn config_change_replaces_pending_generation_with_latest_file()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let current = runtime_plan(base_config(temp.path().join("spool")))?;
        let mut first_candidate = current.config.clone();
        first_candidate.config_version = "first".to_string();
        first_candidate.capture.fallback_backends = vec![LiveCaptureBackend::Libpcap];
        let mut latest_candidate = first_candidate.clone();
        latest_candidate.config_version = "latest".to_string();
        let config_path = temp.path().join("agent.toml");
        fs::write(&config_path, toml::to_string(&latest_candidate)?)?;
        let runtime_generation =
            RuntimeGenerationState::for_config_version(current.config.config_version.clone());
        runtime_generation.request_reload(RuntimeGenerationReloadRequestInput {
            candidate_path: config_path.clone(),
            base_config: current.config.clone(),
            candidate_config: first_candidate,
            current_config_version: current.config.config_version.clone(),
            candidate_config_version: Some("first".to_string()),
            changed_sections: vec!["agent_identity".to_string(), "capture".to_string()],
        });
        let context = RuntimeConfigWatcherContext {
            plan: RuntimePlanHandle::new(Arc::new(current)),
            policy_set: PipelinePolicySet::default(),
            policy_reload_gate: PolicyReloadGate::default(),
            config_apply_gate: RuntimeReloadGate::default(),
            enforcement_runtime: None,
            enforcement_reload_gate: EnforcementReloadGate::default(),
            runtime_generation: runtime_generation.clone(),
        };

        let snapshot = reload_after_config_change(&context, &config_path).await;

        assert!(matches!(
            snapshot.actions.as_slice(),
            [ConfigReloadApplyAction::RequestRuntimeGeneration(
                ConfigReloadRuntimeGenerationActionOutcome::Queued { request_id: 2, .. },
            )]
        ));
        assert_eq!(
            runtime_generation
                .snapshot()
                .pending
                .and_then(|request| request.candidate_config_version),
            Some("latest".to_string())
        );
        Ok(())
    }

    #[tokio::test]
    async fn config_change_while_applying_replaces_intervening_pending_generation()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let current = runtime_plan(base_config(temp.path().join("spool")))?;
        let mut applying_candidate = current.config.clone();
        applying_candidate.config_version = "applying".to_string();
        applying_candidate.capture.fallback_backends = vec![LiveCaptureBackend::Libpcap];
        let mut stale_candidate = applying_candidate.clone();
        stale_candidate.config_version = "stale".to_string();
        let mut latest_candidate = applying_candidate.clone();
        latest_candidate.config_version = "latest".to_string();
        let config_path = temp.path().join("agent.toml");
        fs::write(&config_path, toml::to_string(&latest_candidate)?)?;
        let runtime_generation =
            RuntimeGenerationState::for_config_version(current.config.config_version.clone());
        let applying = runtime_generation.request_reload(RuntimeGenerationReloadRequestInput {
            candidate_path: config_path.clone(),
            base_config: current.config.clone(),
            candidate_config: applying_candidate,
            current_config_version: current.config.config_version.clone(),
            candidate_config_version: Some("applying".to_string()),
            changed_sections: vec!["agent_identity".to_string(), "capture".to_string()],
        });
        runtime_generation.begin_pending_reload();
        let stale_request =
            runtime_generation.request_reload(RuntimeGenerationReloadRequestInput {
                candidate_path: config_path.clone(),
                base_config: current.config.clone(),
                candidate_config: stale_candidate,
                current_config_version: current.config.config_version.clone(),
                candidate_config_version: Some("stale".to_string()),
                changed_sections: vec!["agent_identity".to_string(), "capture".to_string()],
            });
        let context = RuntimeConfigWatcherContext {
            plan: RuntimePlanHandle::new(Arc::new(current.clone())),
            policy_set: PipelinePolicySet::default(),
            policy_reload_gate: PolicyReloadGate::default(),
            config_apply_gate: RuntimeReloadGate::default(),
            enforcement_runtime: None,
            enforcement_reload_gate: EnforcementReloadGate::default(),
            runtime_generation: runtime_generation.clone(),
        };

        let snapshot = reload_after_config_change(&context, &config_path).await;

        assert!(matches!(
            snapshot.actions.as_slice(),
            [ConfigReloadApplyAction::RequestRuntimeGeneration(
                ConfigReloadRuntimeGenerationActionOutcome::Queued { request_id: 3, .. },
            )]
        ));
        let pending = runtime_generation
            .snapshot()
            .pending
            .expect("latest candidate should replace stale pending generation");
        assert_eq!(applying.request_id, 1);
        assert_eq!(stale_request.request_id, 2);
        assert_eq!(pending.request_id, 3);
        assert_eq!(pending.candidate_config_version.as_deref(), Some("latest"));
        Ok(())
    }

    fn watcher_context(plan: RuntimePlan) -> RuntimeConfigWatcherContext {
        RuntimeConfigWatcherContext {
            runtime_generation: RuntimeGenerationState::for_config_version(
                plan.config.config_version.clone(),
            ),
            plan: RuntimePlanHandle::new(Arc::new(plan)),
            policy_set: PipelinePolicySet::default(),
            policy_reload_gate: PolicyReloadGate::default(),
            config_apply_gate: RuntimeReloadGate::default(),
            enforcement_runtime: None,
            enforcement_reload_gate: EnforcementReloadGate::default(),
        }
    }

    fn runtime_plan(config: AgentConfig) -> Result<RuntimePlan, runtime::RuntimeError> {
        RuntimePlan::build(config, &registry())
    }

    fn registry() -> ProviderRegistry {
        ProviderRegistry::new(
            vec![
                CaptureProviderDescriptor::available(
                    probe_config::CaptureBackend::Replay,
                    CaptureProviderBuilder::Replay,
                ),
                CaptureProviderDescriptor::available(
                    probe_config::CaptureBackend::PlaintextFeed,
                    CaptureProviderBuilder::PlaintextFeed,
                ),
                CaptureProviderDescriptor::available(
                    probe_config::CaptureBackend::Libpcap,
                    CaptureProviderBuilder::Libpcap,
                ),
            ],
            vec![
                CapabilityState::available(CapabilityKind::Http1),
                CapabilityState::available(CapabilityKind::Sse),
                CapabilityState::available(CapabilityKind::WebSocketHandoff),
                CapabilityState::available(CapabilityKind::WebSocketFrame),
                CapabilityState::available(CapabilityKind::DryRunEnforcement),
                CapabilityState::unavailable(CapabilityKind::LibsslUprobe, "not built"),
                CapabilityState::unavailable(CapabilityKind::ConnectionEnforcement, "not built"),
            ],
        )
    }

    fn base_config(storage_path: PathBuf) -> AgentConfig {
        AgentConfig {
            capture: probe_config::CaptureConfig {
                selection: CaptureSelection::Replay,
                ..probe_config::CaptureConfig::default()
            },
            storage: StorageConfig {
                path: storage_path,
                ..StorageConfig::default()
            },
            ..AgentConfig::default()
        }
    }
}
