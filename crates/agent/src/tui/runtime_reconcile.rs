use std::path::{Path, PathBuf};

use probe_config::AgentConfig;

use super::{
    agent::TuiAgentSupervisor,
    app::{StatusKind, StatusMessage, TuiApp},
    config_reload::{ConfigReloadApplyDisposition, request_config_reload_apply},
    runtime_actions::request_runtime_actions_reload,
    runtime_attachment::RuntimeAttachment,
};

pub(super) struct QueuedRuntimeReconcile {
    pub(super) config: AgentConfig,
    pub(super) config_path: PathBuf,
    pub(super) saved_status: StatusMessage,
}

pub(super) struct PendingRuntimeReconcile {
    task: tokio::task::JoinHandle<RuntimeReconcileResult>,
    failure_context: RuntimeReconcileFailureContext,
}

enum RuntimeReconcileFailureContext {
    Startup,
    Saved(StatusMessage),
}

pub(super) struct RuntimeReconcileResult {
    supervisor: Option<TuiAgentSupervisor>,
    completion: RuntimeReconcileCompletion,
}

#[derive(Debug)]
enum RuntimeReconcileCompletion {
    StartupAttached {
        attachment: RuntimeAttachment,
    },
    StartupUnavailable {
        message: String,
    },
    SavedAttached {
        attachment: RuntimeAttachment,
        saved_status: StatusMessage,
        plan_note: Option<RuntimeApplyPlanNote>,
    },
    SavedRuntimeKept {
        saved_status: StatusMessage,
        plan_note: RuntimeApplyPlanNote,
    },
    SavedRestarted {
        attachment: RuntimeAttachment,
        saved_status: StatusMessage,
        plan_note: Option<RuntimeApplyPlanNote>,
    },
    SavedExternalNeedsRestart {
        saved_status: StatusMessage,
        plan_note: Option<RuntimeApplyPlanNote>,
    },
    SavedUnavailable {
        saved_status: StatusMessage,
        message: String,
    },
    SavedManagedRestartFailed {
        saved_status: StatusMessage,
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeApplyPlanNote {
    text: String,
    follow_up: RuntimeApplyFollowUp,
    status_kind: StatusKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeApplyFollowUp {
    KeepRunning,
    RestartToApply,
}

pub(super) fn spawn_startup_runtime_reconcile(config: AgentConfig) -> PendingRuntimeReconcile {
    PendingRuntimeReconcile {
        task: tokio::spawn(async move { startup_runtime_reconcile(config).await }),
        failure_context: RuntimeReconcileFailureContext::Startup,
    }
}

async fn startup_runtime_reconcile(config: AgentConfig) -> RuntimeReconcileResult {
    match TuiAgentSupervisor::attach_or_spawn(&config).await {
        Ok(supervisor) => {
            let attachment = supervisor.attachment(&config);
            RuntimeReconcileResult {
                supervisor: Some(supervisor),
                completion: RuntimeReconcileCompletion::StartupAttached { attachment },
            }
        }
        Err(error) => RuntimeReconcileResult {
            supervisor: None,
            completion: RuntimeReconcileCompletion::StartupUnavailable {
                message: error.to_string(),
            },
        },
    }
}

pub(super) fn spawn_saved_runtime_reconcile(
    supervisor: &mut Option<TuiAgentSupervisor>,
    queued: QueuedRuntimeReconcile,
    active_socket_path: Option<PathBuf>,
) -> PendingRuntimeReconcile {
    let failure_context = RuntimeReconcileFailureContext::Saved(queued.saved_status.clone());
    let running = supervisor.take();
    PendingRuntimeReconcile {
        task: tokio::spawn(async move {
            saved_runtime_reconcile(running, queued, active_socket_path).await
        }),
        failure_context,
    }
}

async fn saved_runtime_reconcile(
    supervisor: Option<TuiAgentSupervisor>,
    queued: QueuedRuntimeReconcile,
    active_socket_path: Option<PathBuf>,
) -> RuntimeReconcileResult {
    let QueuedRuntimeReconcile {
        config,
        config_path,
        saved_status,
    } = queued;
    let plan_note = runtime_apply_plan_note(active_socket_path.as_deref(), &config_path).await;
    if let (Some(_running), Some(note)) = (&supervisor, &plan_note)
        && note.follow_up == RuntimeApplyFollowUp::KeepRunning
    {
        let running = supervisor.expect("supervisor was checked");
        return RuntimeReconcileResult {
            supervisor: Some(running),
            completion: RuntimeReconcileCompletion::SavedRuntimeKept {
                saved_status,
                plan_note: note.clone(),
            },
        };
    }
    match supervisor {
        Some(running) if running.is_managed() => match running.restart(&config).await {
            Ok(next) => {
                let attachment = next.attachment(&config);
                RuntimeReconcileResult {
                    supervisor: Some(next),
                    completion: RuntimeReconcileCompletion::SavedRestarted {
                        attachment,
                        saved_status,
                        plan_note,
                    },
                }
            }
            Err(error) => RuntimeReconcileResult {
                supervisor: None,
                completion: RuntimeReconcileCompletion::SavedManagedRestartFailed {
                    saved_status,
                    message: error.to_string(),
                },
            },
        },
        Some(running) => RuntimeReconcileResult {
            supervisor: Some(running),
            completion: RuntimeReconcileCompletion::SavedExternalNeedsRestart {
                saved_status,
                plan_note,
            },
        },
        None => match TuiAgentSupervisor::attach_or_spawn(&config).await {
            Ok(next) => {
                let attachment = next.attachment(&config);
                RuntimeReconcileResult {
                    supervisor: Some(next),
                    completion: RuntimeReconcileCompletion::SavedAttached {
                        attachment,
                        saved_status,
                        plan_note,
                    },
                }
            }
            Err(error) => RuntimeReconcileResult {
                supervisor: None,
                completion: RuntimeReconcileCompletion::SavedUnavailable {
                    saved_status,
                    message: error.to_string(),
                },
            },
        },
    }
}

async fn runtime_apply_plan_note(
    active_socket_path: Option<&Path>,
    config_path: &Path,
) -> Option<RuntimeApplyPlanNote> {
    let socket_path = active_socket_path?;
    Some(
        match request_config_reload_apply(socket_path, config_path).await {
            Ok(summary) => {
                let disposition = summary.disposition();
                RuntimeApplyPlanNote {
                    follow_up: runtime_apply_follow_up(&disposition),
                    status_kind: runtime_apply_status_kind(&disposition),
                    text: summary.status_text(),
                }
            }
            Err(error) => RuntimeApplyPlanNote {
                follow_up: RuntimeApplyFollowUp::RestartToApply,
                status_kind: StatusKind::Warning,
                text: format!("runtime config apply unavailable: {error}"),
            },
        },
    )
}

pub(super) async fn take_finished_runtime_reconcile(
    pending: &mut Option<PendingRuntimeReconcile>,
) -> Option<RuntimeReconcileResult> {
    if !pending
        .as_ref()
        .is_some_and(|pending| pending.task.is_finished())
    {
        return None;
    }
    let pending = pending.take().expect("pending runtime task was checked");
    Some(match pending.task.await {
        Ok(result) => result,
        Err(error) => RuntimeReconcileResult {
            supervisor: None,
            completion: pending.failure_context.task_failed(error),
        },
    })
}

pub(super) async fn cancel_pending_runtime_reconcile(pending: Option<PendingRuntimeReconcile>) {
    let Some(pending) = pending else {
        return;
    };
    pending.task.abort();
    let _ = pending.task.await;
}

impl RuntimeReconcileFailureContext {
    fn task_failed(self, error: tokio::task::JoinError) -> RuntimeReconcileCompletion {
        let message = format!("TUI runtime task failed: {error}");
        match self {
            Self::Startup => RuntimeReconcileCompletion::StartupUnavailable { message },
            Self::Saved(saved_status) => RuntimeReconcileCompletion::SavedUnavailable {
                saved_status,
                message,
            },
        }
    }
}

pub(super) fn apply_runtime_reconcile_result(
    supervisor: &mut Option<TuiAgentSupervisor>,
    app: &mut TuiApp,
    result: RuntimeReconcileResult,
) {
    *supervisor = result.supervisor;
    match result.completion {
        RuntimeReconcileCompletion::StartupAttached { attachment } => {
            app.attach_agent(attachment);
        }
        RuntimeReconcileCompletion::StartupUnavailable { message } => {
            app.mark_error(format!("TUI agent unavailable: {message}"));
        }
        RuntimeReconcileCompletion::SavedAttached {
            attachment,
            saved_status,
            plan_note,
        } => {
            app.attach_agent(attachment);
            mark_saved_runtime_success(
                app,
                &saved_status,
                saved_runtime_apply_suffix(
                    plan_note.as_ref(),
                    format!("attached TUI agent; {}", app.runtime_agent_status()),
                ),
            );
        }
        RuntimeReconcileCompletion::SavedRuntimeKept {
            saved_status,
            plan_note,
        } => {
            mark_saved_runtime_with_kind(app, &saved_status, plan_note.text, plan_note.status_kind);
        }
        RuntimeReconcileCompletion::SavedRestarted {
            attachment,
            saved_status,
            plan_note,
        } => {
            app.attach_agent(attachment);
            mark_saved_runtime_success(
                app,
                &saved_status,
                saved_runtime_apply_suffix(
                    plan_note.as_ref(),
                    format!(
                        "restarted TUI managed agent; {}",
                        app.runtime_agent_status()
                    ),
                ),
            );
        }
        RuntimeReconcileCompletion::SavedExternalNeedsRestart {
            saved_status,
            plan_note,
        } => {
            mark_saved_runtime_warning(
                app,
                &saved_status,
                saved_runtime_apply_suffix(
                    plan_note.as_ref(),
                    "restart the attached agent to apply capture and MITM runtime resources",
                ),
            );
        }
        RuntimeReconcileCompletion::SavedUnavailable {
            saved_status,
            message,
        } => {
            mark_saved_runtime_error(
                app,
                &saved_status,
                format!("TUI agent is still unavailable: {message}"),
            );
        }
        RuntimeReconcileCompletion::SavedManagedRestartFailed {
            saved_status,
            message,
        } => {
            detach_saved_runtime_error(
                app,
                &saved_status,
                format!("failed to restart TUI managed agent: {message}"),
            );
        }
    }
}

fn runtime_apply_status_kind(disposition: &ConfigReloadApplyDisposition) -> StatusKind {
    match disposition {
        ConfigReloadApplyDisposition::Rejected
        | ConfigReloadApplyDisposition::OnlineApplyFailed
        | ConfigReloadApplyDisposition::RuntimeGenerationQueueFailed
        | ConfigReloadApplyDisposition::Failed => StatusKind::Error,
        ConfigReloadApplyDisposition::NeedsRestart => StatusKind::Warning,
        ConfigReloadApplyDisposition::NoChange
        | ConfigReloadApplyDisposition::AppliedOnline
        | ConfigReloadApplyDisposition::QueuedGeneration { .. } => StatusKind::Info,
    }
}

fn runtime_apply_follow_up(disposition: &ConfigReloadApplyDisposition) -> RuntimeApplyFollowUp {
    match disposition {
        ConfigReloadApplyDisposition::NeedsRestart
        | ConfigReloadApplyDisposition::RuntimeGenerationQueueFailed
        | ConfigReloadApplyDisposition::Failed => RuntimeApplyFollowUp::RestartToApply,
        ConfigReloadApplyDisposition::NoChange
        | ConfigReloadApplyDisposition::AppliedOnline
        | ConfigReloadApplyDisposition::QueuedGeneration { .. }
        | ConfigReloadApplyDisposition::Rejected
        | ConfigReloadApplyDisposition::OnlineApplyFailed => RuntimeApplyFollowUp::KeepRunning,
    }
}

fn mark_saved_runtime_with_kind(
    app: &mut TuiApp,
    saved_status: &StatusMessage,
    suffix: impl AsRef<str>,
    status_kind: StatusKind,
) {
    let text = saved_runtime_status_text(saved_status, suffix);
    match strongest_status_kind(saved_status.kind, status_kind) {
        StatusKind::Error => app.mark_error(text),
        StatusKind::Warning => app.mark_warning(text),
        StatusKind::Info | StatusKind::Saved => app.mark_info(text),
    }
}

fn strongest_status_kind(left: StatusKind, right: StatusKind) -> StatusKind {
    if left == StatusKind::Error || right == StatusKind::Error {
        StatusKind::Error
    } else if left == StatusKind::Warning || right == StatusKind::Warning {
        StatusKind::Warning
    } else {
        StatusKind::Info
    }
}

pub(super) fn mark_saved_runtime_success(
    app: &mut TuiApp,
    saved_status: &StatusMessage,
    suffix: impl AsRef<str>,
) {
    let text = saved_runtime_status_text(saved_status, suffix);
    match saved_status.kind {
        StatusKind::Warning => app.mark_warning(text),
        StatusKind::Error => app.mark_error(text),
        _ => app.mark_info(text),
    }
}

fn mark_saved_runtime_warning(
    app: &mut TuiApp,
    saved_status: &StatusMessage,
    suffix: impl AsRef<str>,
) {
    app.mark_warning(saved_runtime_status_text(saved_status, suffix));
}

fn mark_saved_runtime_error(
    app: &mut TuiApp,
    saved_status: &StatusMessage,
    suffix: impl AsRef<str>,
) {
    app.mark_error(saved_runtime_status_text(saved_status, suffix));
}

fn detach_saved_runtime_error(
    app: &mut TuiApp,
    saved_status: &StatusMessage,
    suffix: impl AsRef<str>,
) {
    app.detach_agent(saved_runtime_status_text(saved_status, suffix));
}

fn saved_runtime_status_text(saved_status: &StatusMessage, suffix: impl AsRef<str>) -> String {
    format!("{}; {}", saved_status.text, suffix.as_ref())
}

fn saved_runtime_apply_suffix(
    plan_note: Option<&RuntimeApplyPlanNote>,
    action: impl AsRef<str>,
) -> String {
    match plan_note {
        Some(note) => format!("{}; {}", note.text, action.as_ref()),
        None => action.as_ref().to_string(),
    }
}

pub(super) async fn reload_runtime_actions(app: &mut TuiApp) {
    let Some(socket_path) = app.active_admin_socket_path().map(PathBuf::from) else {
        app.mark_warning("No active agent admin socket is attached to this TUI session");
        return;
    };
    match request_runtime_actions_reload(&socket_path).await {
        Ok(summary) if summary.has_failures() => app.mark_warning(summary.status_text()),
        Ok(summary) => app.mark_info(summary.status_text()),
        Err(error) => app.mark_error(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use probe_config::AgentConfig;

    use super::{
        super::{
            app::{StatusKind, StatusMessage, TuiApp},
            processes::ProcessCatalog,
            runtime_attachment::RuntimeAttachment,
        },
        *,
    };

    #[test]
    fn saved_runtime_success_preserves_warning_severity() {
        let mut app = TuiApp::new(
            PathBuf::from("/tmp/agent.toml"),
            AgentConfig::default(),
            ProcessCatalog::default(),
        );
        let status = StatusMessage::warning(
            "Outbound reliable MITM proxy data path configured, but MITM proxy executable is missing",
        );

        mark_saved_runtime_success(&mut app, &status, "restarted TUI managed agent");

        assert_eq!(app.status().kind, StatusKind::Warning);
        assert!(
            app.status()
                .text
                .contains("MITM proxy executable is missing")
        );
        assert!(app.status().text.contains("restarted TUI managed agent"));
    }

    #[test]
    fn saved_runtime_error_preserves_operation_context() {
        let mut app = TuiApp::new(
            PathBuf::from("/tmp/agent.toml"),
            AgentConfig::default(),
            ProcessCatalog::default(),
        );
        let status = StatusMessage::saved(
            "Saved bidirectional MITM observation for curl; runtime bidirectional MITM expansion is pending",
        );

        mark_saved_runtime_error(
            &mut app,
            &status,
            "TUI agent is still unavailable: startup failed",
        );

        assert_eq!(app.status().kind, StatusKind::Error);
        assert!(app.status().text.contains("bidirectional MITM observation"));
        assert!(app.status().text.contains("MITM expansion is pending"));
        assert!(app.status().text.contains("startup failed"));
    }

    #[test]
    fn saved_runtime_detach_error_preserves_operation_context() {
        let mut app = TuiApp::new(
            PathBuf::from("/tmp/agent.toml"),
            AgentConfig::default(),
            ProcessCatalog::default(),
        );
        let status = StatusMessage::saved(
            "Saved bidirectional MITM observation for curl; runtime bidirectional MITM expansion is pending",
        );

        detach_saved_runtime_error(
            &mut app,
            &status,
            "failed to restart TUI managed agent: restart failed",
        );

        assert_eq!(app.status().kind, StatusKind::Error);
        assert!(app.status().text.contains("bidirectional MITM observation"));
        assert!(app.status().text.contains("MITM expansion is pending"));
        assert!(
            app.runtime_agent_status()
                .contains("bidirectional MITM observation")
        );
        assert!(
            app.runtime_agent_status()
                .contains("MITM expansion is pending")
        );
        assert!(app.status().text.contains("restart failed"));
    }

    #[test]
    fn saved_runtime_reconcile_result_attaches_restarted_agent_without_losing_warning() {
        let mut app = TuiApp::new(
            PathBuf::from("/tmp/agent.toml"),
            AgentConfig::default(),
            ProcessCatalog::default(),
        );
        let saved_status =
            StatusMessage::warning("Saved capture config; MITM proxy executable is still missing");
        let result = RuntimeReconcileResult {
            supervisor: None,
            completion: RuntimeReconcileCompletion::SavedRestarted {
                attachment: RuntimeAttachment::managed(
                    PathBuf::from("/tmp/admin.sock"),
                    Some(42),
                    PathBuf::from("/tmp/agent.log"),
                ),
                saved_status,
                plan_note: Some(RuntimeApplyPlanNote {
                    text: "runtime rebuild required for observations".to_string(),
                    follow_up: RuntimeApplyFollowUp::RestartToApply,
                    status_kind: StatusKind::Warning,
                }),
            },
        };
        let mut supervisor = None;

        apply_runtime_reconcile_result(&mut supervisor, &mut app, result);

        assert_eq!(app.status().kind, StatusKind::Warning);
        assert_eq!(
            app.active_admin_socket_path(),
            Some(std::path::Path::new("/tmp/admin.sock"))
        );
        assert!(app.status().text.contains("MITM proxy executable"));
        assert!(app.status().text.contains("runtime rebuild required"));
        assert!(app.status().text.contains("restarted TUI managed agent"));
    }

    #[test]
    fn saved_runtime_reconcile_keeps_running_agent_without_restart() {
        let mut app = TuiApp::new(
            PathBuf::from("/tmp/agent.toml"),
            AgentConfig::default(),
            ProcessCatalog::default(),
        );
        let result = RuntimeReconcileResult {
            supervisor: None,
            completion: RuntimeReconcileCompletion::SavedRuntimeKept {
                saved_status: StatusMessage::saved("Saved config"),
                plan_note: RuntimeApplyPlanNote {
                    text: "running agent already matches saved config".to_string(),
                    follow_up: RuntimeApplyFollowUp::KeepRunning,
                    status_kind: StatusKind::Info,
                },
            },
        };
        let mut supervisor = None;

        apply_runtime_reconcile_result(&mut supervisor, &mut app, result);

        assert_eq!(app.status().kind, StatusKind::Info);
        assert!(app.status().text.contains("Saved config"));
        assert!(
            app.status()
                .text
                .contains("running agent already matches saved config")
        );
        assert!(!app.status().text.contains("restart"));
    }

    #[test]
    fn queued_runtime_generation_maps_to_non_restart_info_disposition() {
        let disposition = ConfigReloadApplyDisposition::QueuedGeneration { request_id: 7 };

        assert_eq!(
            runtime_apply_follow_up(&disposition),
            RuntimeApplyFollowUp::KeepRunning
        );
        assert_eq!(runtime_apply_status_kind(&disposition), StatusKind::Info);
    }

    #[tokio::test]
    async fn finished_runtime_reconcile_task_preserves_saved_context_on_join_failure() {
        let saved_status = StatusMessage::saved("Saved selected process observation");
        let task = tokio::spawn(async { std::future::pending::<RuntimeReconcileResult>().await });
        task.abort();
        let mut pending = Some(PendingRuntimeReconcile {
            task,
            failure_context: RuntimeReconcileFailureContext::Saved(saved_status),
        });
        for _ in 0..10 {
            if pending
                .as_ref()
                .is_some_and(|pending| pending.task.is_finished())
            {
                break;
            }
            tokio::task::yield_now().await;
        }

        let result = take_finished_runtime_reconcile(&mut pending)
            .await
            .expect("finished runtime task should be reaped");

        match result.completion {
            RuntimeReconcileCompletion::SavedUnavailable {
                saved_status,
                message,
            } => {
                assert_eq!(saved_status.text, "Saved selected process observation");
                assert!(message.contains("TUI runtime task failed"));
            }
            other => panic!("unexpected runtime reconcile completion: {other:?}"),
        }
        assert!(pending.is_none());
    }
}
