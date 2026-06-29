use std::{
    collections::BTreeSet,
    fs, io,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use pipeline::PipelinePolicySet;
use probe_config::{AgentConfig, PolicySourceConfig};
use runtime::RuntimePlan;
use thiserror::Error;
use tokio::{
    sync::{Notify, mpsc},
    task::JoinHandle,
};
use tracing::{info, warn};

use crate::policy_reload::{PolicyReloadGate, reload_policies};

const WATCHER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Error)]
pub(crate) enum PolicyReloadWatcherError {
    #[error("failed to create policy reload watcher: {0}")]
    Create(#[source] notify::Error),
    #[error("failed to watch policy reload root {path}: {source}")]
    WatchPath {
        path: PathBuf,
        #[source]
        source: notify::Error,
    },
    #[error("failed to inspect policy bundle watch path {path}: {source}")]
    InspectPath {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("policy bundle watch path {path} must be a non-symlink directory")]
    InvalidBundleRoot { path: PathBuf },
}

pub(crate) struct PolicyReloadWatcherHandle {
    shutdown: WatcherShutdown,
    task: JoinHandle<()>,
}

impl PolicyReloadWatcherHandle {
    pub(crate) async fn stop(mut self) {
        self.shutdown.request();
        match tokio::time::timeout(WATCHER_SHUTDOWN_TIMEOUT, &mut self.task).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) if !error.is_cancelled() => {
                warn!("policy reload watcher stopped with error: {error}");
            }
            Ok(Err(_)) => {}
            Err(_) => {
                self.task.abort();
                if let Err(error) = self.task.await
                    && !error.is_cancelled()
                {
                    warn!("policy reload watcher stopped with error: {error}");
                }
            }
        }
    }
}

pub(crate) fn spawn_watcher(
    plan: Arc<RuntimePlan>,
    policy_set: PipelinePolicySet,
    gate: PolicyReloadGate,
) -> Result<Option<PolicyReloadWatcherHandle>, PolicyReloadWatcherError> {
    if !plan.config.policy_reload.watch_local_bundles {
        return Ok(None);
    }
    let targets = local_policy_bundle_watch_targets(&plan.config);
    if targets.is_empty() {
        return Ok(None);
    }
    let watch_roots = local_policy_bundle_watch_roots(&targets);
    let bundle_paths = Arc::new(
        targets
            .iter()
            .map(|target| target.bundle_path.clone())
            .collect::<Vec<_>>(),
    );

    let (event_sender, event_receiver) = mpsc::channel(1);
    let mut watcher = RecommendedWatcher::new(
        {
            let bundle_paths = Arc::clone(&bundle_paths);
            move |event| {
                if notify_event_requests_reload(event, &bundle_paths) {
                    let _ = event_sender.try_send(());
                }
            }
        },
        Config::default().with_follow_symlinks(false),
    )
    .map_err(PolicyReloadWatcherError::Create)?;

    for path in &watch_roots {
        watcher
            .watch(path, RecursiveMode::NonRecursive)
            .map_err(|source| PolicyReloadWatcherError::WatchPath {
                path: path.clone(),
                source,
            })?;
    }
    watch_initial_bundle_dirs(&mut watcher, &targets)?;

    let shutdown = WatcherShutdown::default();
    let task_shutdown = shutdown.clone();
    let debounce = Duration::from_millis(plan.config.policy_reload.debounce_ms);
    let task = tokio::spawn(async move {
        run_watcher(
            watcher,
            event_receiver,
            WatcherReloadContext {
                plan,
                policy_set,
                gate,
                debounce,
                targets,
                shutdown: task_shutdown,
            },
        )
        .await;
    });

    Ok(Some(PolicyReloadWatcherHandle { shutdown, task }))
}

struct WatcherReloadContext {
    plan: Arc<RuntimePlan>,
    policy_set: PipelinePolicySet,
    gate: PolicyReloadGate,
    debounce: Duration,
    targets: Vec<LocalPolicyBundleWatchTarget>,
    shutdown: WatcherShutdown,
}

async fn run_watcher(
    mut watcher: RecommendedWatcher,
    mut events: mpsc::Receiver<()>,
    context: WatcherReloadContext,
) {
    while !context.shutdown.is_requested() {
        tokio::select! {
            event = events.recv() => {
                if event.is_none() {
                    break;
                }
                if !wait_for_quiet_period(&mut events, context.debounce, &context.shutdown).await {
                    break;
                }
                refresh_bundle_dir_watches(&mut watcher, &context.targets);
                reload_after_policy_change(&context).await;
            }
            () = context.shutdown.notified() => break,
        }
    }
}

fn notify_event_requests_reload(event: notify::Result<Event>, bundle_paths: &[PathBuf]) -> bool {
    match event {
        Ok(event) => event_requests_reload(&event, bundle_paths),
        Err(error) => {
            warn!("policy reload watcher event error: {error}");
            false
        }
    }
}

fn event_requests_reload(event: &Event, bundle_paths: &[PathBuf]) -> bool {
    !matches!(event.kind, EventKind::Access(_))
        && (event.paths.is_empty()
            || event
                .paths
                .iter()
                .any(|path| path_matches_any_bundle(path, bundle_paths)))
}

fn path_matches_any_bundle(path: &Path, bundle_paths: &[PathBuf]) -> bool {
    bundle_paths
        .iter()
        .any(|bundle| path.starts_with(bundle) || bundle.starts_with(path))
}

fn watch_initial_bundle_dirs(
    watcher: &mut RecommendedWatcher,
    targets: &[LocalPolicyBundleWatchTarget],
) -> Result<(), PolicyReloadWatcherError> {
    for target in targets {
        let is_directory = is_non_symlink_directory(&target.bundle_path).map_err(|source| {
            PolicyReloadWatcherError::InspectPath {
                path: target.bundle_path.clone(),
                source,
            }
        })?;
        if !is_directory {
            return Err(PolicyReloadWatcherError::InvalidBundleRoot {
                path: target.bundle_path.clone(),
            });
        }
        watcher
            .watch(&target.bundle_path, RecursiveMode::Recursive)
            .map_err(|source| PolicyReloadWatcherError::WatchPath {
                path: target.bundle_path.clone(),
                source,
            })?;
    }
    Ok(())
}

fn refresh_bundle_dir_watches(
    watcher: &mut RecommendedWatcher,
    targets: &[LocalPolicyBundleWatchTarget],
) {
    for target in targets {
        match is_non_symlink_directory(&target.bundle_path) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(error) => {
                warn!(
                    path = %target.bundle_path.display(),
                    "failed to inspect policy bundle watch path after local change: {error}"
                );
                continue;
            }
        }
        if let Err(error) = watcher.watch(&target.bundle_path, RecursiveMode::Recursive) {
            warn!(
                path = %target.bundle_path.display(),
                "failed to refresh policy bundle watch after local change: {error}"
            );
        }
    }
}

fn is_non_symlink_directory(path: &Path) -> Result<bool, io::Error> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Ok(false);
    }
    Ok(metadata.is_dir())
}

async fn wait_for_quiet_period(
    events: &mut mpsc::Receiver<()>,
    debounce: Duration,
    shutdown: &WatcherShutdown,
) -> bool {
    loop {
        tokio::select! {
            () = tokio::time::sleep(debounce) => return true,
            event = events.recv() => {
                if event.is_none() {
                    return false;
                }
            }
            () = shutdown.notified() => return false,
        }
    }
}

async fn reload_after_policy_change(context: &WatcherReloadContext) {
    match reload_policies(&context.plan, &context.policy_set, &context.gate).await {
        Ok(summary) => {
            info!(
                loaded_count = summary.loaded_count,
                "reloaded policy bundles after local bundle change"
            );
        }
        Err(error) => {
            warn!("failed to reload policy bundles after local bundle change: {error}");
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct LocalPolicyBundleWatchTarget {
    bundle_path: PathBuf,
    watch_root: PathBuf,
}

#[derive(Clone, Default)]
struct WatcherShutdown {
    requested: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl WatcherShutdown {
    fn request(&self) {
        self.requested.store(true, Ordering::Relaxed);
        self.notify.notify_one();
    }

    fn is_requested(&self) -> bool {
        self.requested.load(Ordering::Relaxed)
    }

    async fn notified(&self) {
        if self.is_requested() {
            return;
        }
        self.notify.notified().await;
    }
}

fn local_policy_bundle_watch_targets(config: &AgentConfig) -> Vec<LocalPolicyBundleWatchTarget> {
    config
        .policies
        .iter()
        .filter(|policy| policy.enabled)
        .filter_map(|policy| match &policy.source {
            PolicySourceConfig::LocalDirectory { path } => {
                local_policy_bundle_watch_target(path.as_path())
            }
            PolicySourceConfig::RemoteBundle { .. } => None,
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn local_policy_bundle_watch_target(path: &Path) -> Option<LocalPolicyBundleWatchTarget> {
    if path.as_os_str().is_empty() {
        return None;
    }
    let bundle_path = absolute_path(path);
    let watch_root = bundle_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    Some(LocalPolicyBundleWatchTarget {
        bundle_path,
        watch_root,
    })
}

fn local_policy_bundle_watch_roots(targets: &[LocalPolicyBundleWatchTarget]) -> Vec<PathBuf> {
    targets
        .iter()
        .map(|target| target.watch_root.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn absolute_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::symlink, time::Instant};

    use capture::ReplayProvider;
    use parsers::Http1ParserFactory;
    use pipeline::CapturePipeline;
    use probe_config::{
        CaptureBackend, CaptureSelection, ExporterConfig, MIN_POLICY_RELOAD_WATCH_DEBOUNCE_MS,
        PolicyConfig, PolicyReloadConfig,
    };
    use probe_core::{
        AddressPort, Direction, EventEnvelope, EventKind, FlowContext, FlowIdentity,
        ProcessContext, ProcessIdentity, SpoolPayloadSchema, Timestamp, TransportProtocol,
    };
    use runtime::{CaptureProviderBuilder, CaptureProviderDescriptor, ProviderRegistry};
    use storage::FjallSpool;

    use super::*;
    use crate::configured_policy::{
        PolicySourceLoadContext, load_configured_pipeline_policies_with_context,
    };

    #[test]
    fn watch_paths_include_enabled_local_bundles_only() {
        let config = AgentConfig {
            policy_reload: PolicyReloadConfig {
                watch_local_bundles: true,
                debounce_ms: 250,
            },
            policies: vec![
                PolicyConfig {
                    id: "local-a".to_string(),
                    source: PolicySourceConfig::LocalDirectory {
                        path: "/tmp/policies/a.bundle".into(),
                    },
                    enabled: true,
                    selector: None,
                },
                PolicyConfig {
                    id: "local-disabled".to_string(),
                    source: PolicySourceConfig::LocalDirectory {
                        path: "/tmp/policies/disabled.bundle".into(),
                    },
                    enabled: false,
                    selector: None,
                },
                PolicyConfig {
                    id: "remote".to_string(),
                    source: PolicySourceConfig::RemoteBundle {
                        endpoint: "https://policy.example.test/bundle".to_string(),
                        max_body_bytes: None,
                    },
                    enabled: true,
                    selector: None,
                },
                PolicyConfig {
                    id: "local-a-copy".to_string(),
                    source: PolicySourceConfig::LocalDirectory {
                        path: "/tmp/policies/a.bundle".into(),
                    },
                    enabled: true,
                    selector: None,
                },
            ],
            ..AgentConfig::default()
        };

        let targets = local_policy_bundle_watch_targets(&config);

        assert_eq!(
            targets,
            vec![LocalPolicyBundleWatchTarget {
                bundle_path: PathBuf::from("/tmp/policies/a.bundle"),
                watch_root: PathBuf::from("/tmp/policies"),
            }]
        );
        assert_eq!(
            local_policy_bundle_watch_roots(&targets),
            vec![PathBuf::from("/tmp/policies")]
        );
    }

    #[test]
    fn watch_paths_ignore_empty_default_policy_source() {
        let config = AgentConfig {
            policy_reload: PolicyReloadConfig {
                watch_local_bundles: true,
                ..PolicyReloadConfig::default()
            },
            policies: vec![PolicyConfig::default()],
            ..AgentConfig::default()
        };

        assert!(local_policy_bundle_watch_targets(&config).is_empty());
    }

    #[tokio::test]
    async fn watcher_reloads_active_policy_set_after_local_bundle_change()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let policy_path = temp.path().join("guard.bundle");
        let spool_path = temp.path().join("spool");
        write_policy_bundle(&policy_path, "old", "old")?;
        let mut config = replay_config(spool_path.clone());
        config.policy_reload = PolicyReloadConfig {
            watch_local_bundles: true,
            debounce_ms: MIN_POLICY_RELOAD_WATCH_DEBOUNCE_MS,
        };
        config.policies.push(PolicyConfig {
            id: "guard".to_string(),
            source: PolicySourceConfig::LocalDirectory {
                path: policy_path.clone(),
            },
            enabled: true,
            selector: None,
        });
        let plan = Arc::new(runtime_plan_from_config(config.clone())?);
        let policy_set = load_configured_pipeline_policies_with_context(
            &config,
            PolicySourceLoadContext::default(),
        )
        .await?
        .into_policy_set();
        let spool = FjallSpool::open(&spool_path)?;
        run_policy_request(&spool, policy_set.clone(), "/before", 1)?;
        assert!(
            policy_alert_messages(&spool)?
                .iter()
                .any(|message| message == "old /before")
        );

        let watcher = spawn_watcher(
            Arc::clone(&plan),
            policy_set.clone(),
            PolicyReloadGate::default(),
        )?
        .expect("watcher should start for enabled local bundle");
        write_policy_bundle(&policy_path, "new", "new")?;

        wait_until_policy_message(&spool, policy_set, "new ").await?;

        watcher.stop().await;
        Ok(())
    }

    #[tokio::test]
    async fn watcher_survives_local_bundle_directory_replacement()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let policy_path = temp.path().join("guard.bundle");
        let spool_path = temp.path().join("spool");
        write_policy_bundle(&policy_path, "old", "old")?;
        let mut config = replay_config(spool_path.clone());
        config.policy_reload = PolicyReloadConfig {
            watch_local_bundles: true,
            debounce_ms: MIN_POLICY_RELOAD_WATCH_DEBOUNCE_MS,
        };
        config.policies.push(PolicyConfig {
            id: "guard".to_string(),
            source: PolicySourceConfig::LocalDirectory {
                path: policy_path.clone(),
            },
            enabled: true,
            selector: None,
        });
        let plan = Arc::new(runtime_plan_from_config(config.clone())?);
        let policy_set = load_configured_pipeline_policies_with_context(
            &config,
            PolicySourceLoadContext::default(),
        )
        .await?
        .into_policy_set();
        let spool = FjallSpool::open(&spool_path)?;
        let watcher = spawn_watcher(
            Arc::clone(&plan),
            policy_set.clone(),
            PolicyReloadGate::default(),
        )?
        .expect("watcher should start for enabled local bundle");

        replace_policy_bundle(&policy_path, "new", "new")?;
        wait_until_policy_message(&spool, policy_set.clone(), "new ").await?;
        write_policy_bundle(&policy_path, "newer", "newer")?;
        wait_until_policy_message(&spool, policy_set, "newer ").await?;

        watcher.stop().await;
        Ok(())
    }

    #[tokio::test]
    async fn watcher_rejects_symlink_bundle_root() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let real_bundle = temp.path().join("real.bundle");
        let policy_path = temp.path().join("guard.bundle");
        let spool_path = temp.path().join("spool");
        write_policy_bundle(&real_bundle, "old", "old")?;
        symlink(&real_bundle, &policy_path)?;
        let mut config = replay_config(spool_path);
        config.policy_reload = PolicyReloadConfig {
            watch_local_bundles: true,
            debounce_ms: MIN_POLICY_RELOAD_WATCH_DEBOUNCE_MS,
        };
        config.policies.push(PolicyConfig {
            id: "guard".to_string(),
            source: PolicySourceConfig::LocalDirectory {
                path: policy_path.clone(),
            },
            enabled: true,
            selector: None,
        });
        let plan = Arc::new(runtime_plan_from_config(config)?);

        let Err(error) = spawn_watcher(
            plan,
            PipelinePolicySet::default(),
            PolicyReloadGate::default(),
        ) else {
            panic!("symlink bundle root must not be watched");
        };

        assert!(matches!(
            error,
            PolicyReloadWatcherError::InvalidBundleRoot { path } if path == policy_path
        ));
        Ok(())
    }

    async fn wait_until_policy_message(
        spool: &FjallSpool,
        policy_set: PipelinePolicySet,
        prefix: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut attempt = 0;
        loop {
            attempt += 1;
            run_policy_request(
                spool,
                policy_set.clone(),
                &format!("/after-{attempt}"),
                attempt + 10,
            )?;
            if policy_alert_messages(spool)?
                .iter()
                .any(|message| message.starts_with(prefix))
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("timed out waiting for policy reload watcher".into());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn runtime_plan_from_config(config: AgentConfig) -> Result<RuntimePlan, runtime::RuntimeError> {
        let registry = ProviderRegistry::new(
            vec![CaptureProviderDescriptor::available(
                CaptureBackend::Replay,
                CaptureProviderBuilder::Replay,
            )],
            Vec::new(),
        );
        RuntimePlan::build(config, &registry)
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
            exporters: vec![ExporterConfig {
                id: "primary".to_string(),
                transport: probe_config::ExporterTransportConfig::Webhook {
                    endpoint: "https://collector.example/batches".to_string(),
                    headers: Default::default(),
                    tls: Default::default(),
                },
                codec: probe_config::CompressionCodecName::None,
                worker: Default::default(),
            }],
            ..AgentConfig::default()
        }
    }

    fn write_policy_bundle(
        path: &Path,
        version: &str,
        alert_prefix: &str,
    ) -> Result<(), std::io::Error> {
        std::fs::create_dir_all(path)?;
        std::fs::write(
            path.join("manifest.toml"),
            format!(
                r#"id = "guard"
version = "{version}"
hooks = ["on_http_request_headers"]
"#
            ),
        )?;
        std::fs::write(
            path.join("main.lua"),
            format!(
                r#"
function on_http_request_headers(event)
  return probe.emit_alert("{alert_prefix} " .. event.kind.target)
end
"#
            ),
        )
    }

    fn replace_policy_bundle(
        path: &Path,
        version: &str,
        alert_prefix: &str,
    ) -> Result<(), std::io::Error> {
        let replacement = path.with_extension("bundle.next");
        if replacement.exists() {
            fs::remove_dir_all(&replacement)?;
        }
        write_policy_bundle(&replacement, version, alert_prefix)?;
        fs::remove_dir_all(path)?;
        fs::rename(replacement, path)
    }

    fn run_policy_request(
        spool: &FjallSpool,
        policy_set: PipelinePolicySet,
        target: &str,
        timestamp: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut parser_factory = Http1ParserFactory::default();
        let mut provider = ReplayProvider::new(
            demo_flow(),
            Direction::Outbound,
            format!("GET {target} HTTP/1.1\r\nHost: test\r\n\r\n").into_bytes(),
            Timestamp {
                monotonic_ns: timestamp,
                wall_time_unix_ns: timestamp as i64,
            },
        );
        let mut pipeline = CapturePipeline::new(spool, &mut parser_factory, policy_set, "test");
        pipeline.run_provider(&mut provider)?;
        Ok(())
    }

    fn policy_alert_messages(
        spool: &FjallSpool,
    ) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let mut messages = Vec::new();
        for stored in spool.read_export_batch("sink", 256)? {
            if stored.payload.schema() != &SpoolPayloadSchema::EventEnvelopeSubjectOriginJson {
                continue;
            }
            let envelope: EventEnvelope = serde_json::from_slice(stored.payload.bytes())?;
            if let EventKind::PolicyAlert(alert) = envelope.kind() {
                messages.push(alert.message.clone());
            }
        }
        Ok(messages)
    }

    fn demo_flow() -> FlowContext {
        let process = ProcessIdentity {
            pid: 1,
            tgid: 1,
            start_time_ticks: 1,
            boot_id: "boot".to_string(),
            exe_path: "replay".to_string(),
            cmdline_hash: "hash".to_string(),
            uid: 0,
            gid: 0,
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
            port: 80,
        };
        FlowContext {
            id: FlowIdentity::stable(&process, &local, &remote, TransportProtocol::Tcp, 1, None),
            process: ProcessContext {
                identity: process,
                name: "replay".to_string(),
                cmdline: vec!["replay".to_string()],
            },
            local,
            remote,
            protocol: TransportProtocol::Tcp,
            start_monotonic_ns: 1,
            socket_cookie: None,
            attribution_confidence: 0,
        }
    }
}
