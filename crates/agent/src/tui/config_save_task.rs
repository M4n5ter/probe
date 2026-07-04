use std::path::PathBuf;

use probe_config::AgentConfig;

use super::{
    app::{StatusMessage, TuiApp},
    config_edit::{TuiError, save_config},
};

struct PendingConfigSave {
    config_path: PathBuf,
    config: AgentConfig,
    saved_status: StatusMessage,
    should_reconcile_runtime: bool,
    task: tokio::task::JoinHandle<Result<String, TuiError>>,
}

struct QueuedConfigSave {
    config_path: PathBuf,
    config: AgentConfig,
    saved_status: StatusMessage,
    should_reconcile_runtime: bool,
}

struct SuccessfulConfigSave {
    config_path: PathBuf,
    config: AgentConfig,
    saved_status: StatusMessage,
    should_reconcile_runtime: bool,
    source: String,
}

#[derive(Default)]
pub(super) struct ConfigSaveState {
    pending: Option<PendingConfigSave>,
    queued: Option<QueuedConfigSave>,
    deferred_runtime_reconcile: Option<SavedConfigRuntimeReconcile>,
}

pub(super) struct ConfigSaveCompletion {
    config_path: PathBuf,
    config: AgentConfig,
    saved_status: StatusMessage,
    should_reconcile_runtime: bool,
    result: Result<String, TuiError>,
}

pub(super) struct SavedConfigRuntimeReconcile {
    pub(super) config: AgentConfig,
    pub(super) config_path: PathBuf,
    pub(super) status: StatusMessage,
}

enum ConfigSaveApplyOutcome {
    Saved {
        runtime_reconcile: Option<Box<SavedConfigRuntimeReconcile>>,
    },
    FailedLatest {
        message: String,
    },
    FailedStale {
        message: String,
    },
}

impl ConfigSaveState {
    pub(super) fn start_or_queue(
        &mut self,
        original_source: &str,
        app: &mut TuiApp,
        saved_status: StatusMessage,
        should_reconcile_runtime: bool,
    ) {
        let queued = config_save_request(app, saved_status, should_reconcile_runtime);
        if self.pending.is_some() {
            self.queued = Some(queued);
            app.mark_info("Config save is running; queued latest config save");
            return;
        }
        self.start_save(original_source, app, queued);
    }

    pub(super) async fn take_finished(&mut self) -> Option<ConfigSaveCompletion> {
        if !self
            .pending
            .as_ref()
            .is_some_and(|pending| pending.task.is_finished())
        {
            return None;
        }
        self.wait_for_pending().await
    }

    pub(super) async fn wait_for_pending(&mut self) -> Option<ConfigSaveCompletion> {
        let pending = self.pending.take()?;
        Some(config_save_completion(pending).await)
    }

    pub(super) fn apply_completion(
        &mut self,
        loaded_source: &mut String,
        app: &mut TuiApp,
        completion: ConfigSaveCompletion,
    ) -> Option<SavedConfigRuntimeReconcile> {
        let queued_save_waiting = self.queued.is_some();
        let outcome =
            apply_config_save_completion(loaded_source, app, completion, queued_save_waiting);
        let runtime_reconcile = match outcome {
            ConfigSaveApplyOutcome::Saved {
                runtime_reconcile: Some(reconcile),
            } if queued_save_waiting => {
                self.deferred_runtime_reconcile = Some(*reconcile);
                None
            }
            ConfigSaveApplyOutcome::Saved {
                runtime_reconcile: Some(reconcile),
            } => {
                self.deferred_runtime_reconcile = None;
                Some(*reconcile)
            }
            ConfigSaveApplyOutcome::Saved {
                runtime_reconcile: None,
            } => {
                self.deferred_runtime_reconcile = None;
                None
            }
            ConfigSaveApplyOutcome::FailedLatest { message }
            | ConfigSaveApplyOutcome::FailedStale { message }
                if !queued_save_waiting =>
            {
                self.deferred_runtime_reconcile_after_failed_save(message)
            }
            ConfigSaveApplyOutcome::FailedLatest { .. }
            | ConfigSaveApplyOutcome::FailedStale { .. } => None,
        };
        self.start_next_queued(loaded_source, app);
        runtime_reconcile
    }

    pub(super) fn reject_reload(&self, app: &mut TuiApp) -> bool {
        if self.pending.is_none() {
            return false;
        }
        app.mark_warning("Config save is running; reload after it finishes");
        true
    }

    pub(super) fn has_work(&self) -> bool {
        self.pending.is_some() || self.queued.is_some()
    }

    fn start_next_queued(&mut self, loaded_source: &str, app: &mut TuiApp) {
        if self.pending.is_some() {
            return;
        }
        let Some(queued) = self.queued.take() else {
            return;
        };
        self.start_save(loaded_source, app, queued);
    }

    fn start_save(&mut self, original_source: &str, app: &mut TuiApp, queued: QueuedConfigSave) {
        let original_source = original_source.to_string();
        let display_path = queued.config_path.display().to_string();
        let task_path = queued.config_path.clone();
        let task_config = queued.config.clone();
        self.pending = Some(PendingConfigSave {
            config_path: queued.config_path,
            config: queued.config,
            saved_status: queued.saved_status,
            should_reconcile_runtime: queued.should_reconcile_runtime,
            task: tokio::task::spawn_blocking(move || {
                save_config(&task_path, &original_source, &task_config)
            }),
        });
        app.mark_info(format!("Saving config to {display_path} in background"));
    }

    fn deferred_runtime_reconcile_after_failed_save(
        &mut self,
        failure_message: String,
    ) -> Option<SavedConfigRuntimeReconcile> {
        let mut reconcile = self.deferred_runtime_reconcile.take()?;
        reconcile.status = StatusMessage::error(format!(
            "Config save failed; applying last saved config snapshot: {failure_message}"
        ));
        Some(reconcile)
    }
}

fn config_save_request(
    app: &TuiApp,
    saved_status: StatusMessage,
    should_reconcile_runtime: bool,
) -> QueuedConfigSave {
    QueuedConfigSave {
        config_path: app.config_path().clone(),
        config: app.config().clone(),
        saved_status,
        should_reconcile_runtime,
    }
}

async fn config_save_completion(pending: PendingConfigSave) -> ConfigSaveCompletion {
    let result = match pending.task.await {
        Ok(result) => result,
        Err(error) => Err(TuiError::TaskFailed {
            task: "config save",
            message: error.to_string(),
        }),
    };
    ConfigSaveCompletion {
        config_path: pending.config_path,
        config: pending.config,
        saved_status: pending.saved_status,
        should_reconcile_runtime: pending.should_reconcile_runtime,
        result,
    }
}

fn apply_config_save_completion(
    loaded_source: &mut String,
    app: &mut TuiApp,
    completion: ConfigSaveCompletion,
    superseded_by_queued_save: bool,
) -> ConfigSaveApplyOutcome {
    let ConfigSaveCompletion {
        config_path,
        config,
        saved_status,
        should_reconcile_runtime,
        result,
    } = completion;
    match result {
        Ok(source) => ConfigSaveApplyOutcome::Saved {
            runtime_reconcile: apply_successful_save(
                loaded_source,
                app,
                SuccessfulConfigSave {
                    config_path,
                    config,
                    saved_status,
                    should_reconcile_runtime,
                    source,
                },
                superseded_by_queued_save,
            )
            .map(Box::new),
        },
        Err(error) if app.config() == &config => {
            let message = error.to_string();
            app.mark_save_failed(message.clone());
            ConfigSaveApplyOutcome::FailedLatest { message }
        }
        Err(error) => {
            let message = format!(
                "Save failed for a previous config snapshot: {error}; newer edits are still unsaved"
            );
            app.mark_warning(message.clone());
            ConfigSaveApplyOutcome::FailedStale { message }
        }
    }
}

fn apply_successful_save(
    loaded_source: &mut String,
    app: &mut TuiApp,
    save: SuccessfulConfigSave,
    superseded_by_queued_save: bool,
) -> Option<SavedConfigRuntimeReconcile> {
    let SuccessfulConfigSave {
        config_path,
        config,
        saved_status,
        should_reconcile_runtime,
        source,
    } = save;
    *loaded_source = source;
    let saved_config_is_current = app.config() == &config;
    let runtime_status = if superseded_by_queued_save {
        StatusMessage::warning("Saved a superseded config snapshot; queued save is still pending")
    } else if saved_config_is_current {
        saved_status
    } else {
        StatusMessage::warning("Saved a previous config snapshot; newer edits are still unsaved")
    };
    if superseded_by_queued_save {
        app.mark_info("Saved a superseded config snapshot; queued save is still pending");
    } else if saved_config_is_current {
        app.mark_saved(runtime_status.clone());
    } else {
        app.mark_warning(runtime_status.text.clone());
    }
    should_reconcile_runtime.then_some(SavedConfigRuntimeReconcile {
        config,
        config_path,
        status: runtime_status,
    })
}

#[cfg(test)]
mod tests {
    use super::{super::processes::ProcessCatalog, *};
    use crate::tui::app::StatusKind;

    #[tokio::test]
    async fn waiting_for_config_save_before_quit_drains_pending_save() {
        let config = AgentConfig::default();
        let mut state = ConfigSaveState {
            pending: Some(pending_config_save(
                config.clone(),
                Ok("saved source".to_string()),
            )),
            ..Default::default()
        };

        let completion = state
            .wait_for_pending()
            .await
            .expect("pending save should complete");

        assert!(!state.has_work());
        assert_eq!(completion.config, config);
        assert!(matches!(completion.result, Ok(source) if source == "saved source"));
    }

    #[tokio::test]
    async fn reload_is_rejected_while_config_save_is_pending() {
        let config = AgentConfig::default();
        let mut app = TuiApp::new(
            PathBuf::from("/tmp/agent.toml"),
            config.clone(),
            ProcessCatalog::default(),
        );
        let mut state = ConfigSaveState {
            pending: Some(pending_config_save(config, Ok("saved source".to_string()))),
            ..Default::default()
        };

        assert!(state.reject_reload(&mut app));
        assert_eq!(app.status().kind, StatusKind::Warning);
        assert!(app.status().text.contains("reload after it finishes"));

        let _ = state.wait_for_pending().await;
    }

    #[tokio::test]
    async fn save_while_pending_keeps_latest_queued_snapshot() {
        let first = config_with_version("first");
        let second = config_with_version("second");
        let mut app = TuiApp::new(
            PathBuf::from("/tmp/agent.toml"),
            first.clone(),
            ProcessCatalog::default(),
        );
        let mut state = ConfigSaveState {
            pending: Some(pending_config_save(
                AgentConfig::default(),
                Ok("saved source".to_string()),
            )),
            ..Default::default()
        };

        state.start_or_queue(
            "old source",
            &mut app,
            StatusMessage::saved("Saved first"),
            true,
        );
        app.replace_config(second.clone(), ProcessCatalog::default());
        state.start_or_queue(
            "old source",
            &mut app,
            StatusMessage::saved("Saved second"),
            true,
        );

        let queued = state.queued.as_ref().expect("latest save should be queued");
        assert_eq!(queued.config, second);
        assert_eq!(queued.saved_status.text, "Saved second");
        assert!(queued.should_reconcile_runtime);
        assert!(app.status().text.contains("queued latest config save"));

        let _ = state.wait_for_pending().await;
    }

    #[tokio::test]
    async fn queued_save_success_reconciles_latest_snapshot()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let config_path = temp.path().join("agent.toml");
        let first = config_with_version("first");
        let second = config_with_version("second");
        let first_source = toml::to_string(&first)?;
        std::fs::write(&config_path, &first_source)?;
        let mut loaded_source = first_source.clone();
        let mut app = TuiApp::new(config_path, first.clone(), ProcessCatalog::default());
        let mut state = ConfigSaveState {
            pending: Some(pending_config_save(first.clone(), Ok(first_source))),
            ..Default::default()
        };

        app.replace_config(second.clone(), ProcessCatalog::default());
        state.start_or_queue(
            &loaded_source,
            &mut app,
            StatusMessage::saved("Saved second"),
            true,
        );

        let first_completion = state
            .wait_for_pending()
            .await
            .expect("first save should complete");
        let first_runtime = state.apply_completion(&mut loaded_source, &mut app, first_completion);
        assert!(first_runtime.is_none());
        assert!(state.pending.is_some());

        let second_completion = state
            .wait_for_pending()
            .await
            .expect("queued save should start and complete");
        let second_runtime = state
            .apply_completion(&mut loaded_source, &mut app, second_completion)
            .expect("latest saved snapshot should reconcile runtime");

        assert_eq!(second_runtime.config, second);
        assert_eq!(second_runtime.status.kind, StatusKind::Saved);
        assert_eq!(AgentConfig::from_toml_str(&loaded_source)?, second);
        assert!(!state.has_work());
        Ok(())
    }

    #[tokio::test]
    async fn queued_save_keeps_dirty_when_older_snapshot_matches_current_config()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let config_path = temp.path().join("agent.toml");
        let first = config_with_version("first");
        let second = config_with_version("second");
        let first_source = toml::to_string(&first)?;
        std::fs::write(&config_path, &first_source)?;
        let mut loaded_source = first_source.clone();
        let mut app = TuiApp::new(
            config_path.clone(),
            first.clone(),
            ProcessCatalog::default(),
        );
        let mut state = ConfigSaveState {
            pending: Some(PendingConfigSave {
                config_path,
                config: first.clone(),
                saved_status: StatusMessage::saved("Saved first"),
                should_reconcile_runtime: true,
                task: tokio::spawn(async move { Ok(first_source) }),
            }),
            ..Default::default()
        };

        app.replace_config(second.clone(), ProcessCatalog::default());
        state.start_or_queue(
            &loaded_source,
            &mut app,
            StatusMessage::saved("Saved second"),
            true,
        );
        app.replace_config(first.clone(), ProcessCatalog::default());
        app.mark_dirty("Changed back before queued save finished");

        let first_completion = state
            .wait_for_pending()
            .await
            .expect("first save should complete");
        assert!(
            state
                .apply_completion(&mut loaded_source, &mut app, first_completion)
                .is_none()
        );
        assert!(app.dirty());

        let second_completion = state
            .wait_for_pending()
            .await
            .expect("queued save should start and complete");
        let second_runtime = state
            .apply_completion(&mut loaded_source, &mut app, second_completion)
            .expect("queued save should reconcile runtime");

        assert_eq!(second_runtime.config, second);
        assert!(app.dirty());
        assert_eq!(app.status().kind, StatusKind::Warning);
        Ok(())
    }

    #[tokio::test]
    async fn queued_save_failure_reconciles_last_successful_snapshot_with_error_status()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let target_path = temp.path().join("agent.target.toml");
        let config_path = temp.path().join("agent.toml");
        let saved = config_with_version("saved");
        let failed = config_with_version("failed");
        let saved_source = toml::to_string(&saved)?;
        std::fs::write(&target_path, &saved_source)?;
        std::os::unix::fs::symlink(&target_path, &config_path)?;
        let mut loaded_source = saved_source.clone();
        let mut app = TuiApp::new(
            config_path.clone(),
            saved.clone(),
            ProcessCatalog::default(),
        );
        let mut state = ConfigSaveState {
            pending: Some(PendingConfigSave {
                config_path: config_path.clone(),
                config: saved.clone(),
                saved_status: StatusMessage::saved("Saved config"),
                should_reconcile_runtime: true,
                task: tokio::spawn(async move { Ok(saved_source) }),
            }),
            ..Default::default()
        };

        app.replace_config(failed.clone(), ProcessCatalog::default());
        state.start_or_queue(
            &loaded_source,
            &mut app,
            StatusMessage::saved("Saved failed snapshot"),
            true,
        );

        let saved_completion = state
            .wait_for_pending()
            .await
            .expect("first save should complete");
        assert!(
            state
                .apply_completion(&mut loaded_source, &mut app, saved_completion)
                .is_none()
        );

        let failed_completion = state
            .wait_for_pending()
            .await
            .expect("queued save should start and fail");
        let reconcile = state
            .apply_completion(&mut loaded_source, &mut app, failed_completion)
            .expect("last successful snapshot should still reconcile runtime");

        assert_eq!(reconcile.config, saved);
        assert_eq!(reconcile.status.kind, StatusKind::Error);
        assert!(reconcile.status.text.contains("Config save failed"));
        assert!(state.deferred_runtime_reconcile.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn queued_stale_save_failure_marks_fallback_runtime_reconcile_as_error()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let target_path = temp.path().join("agent.target.toml");
        let config_path = temp.path().join("agent.toml");
        let saved = config_with_version("saved");
        let failed = config_with_version("failed");
        let saved_source = toml::to_string(&saved)?;
        std::fs::write(&target_path, &saved_source)?;
        std::os::unix::fs::symlink(&target_path, &config_path)?;
        let mut loaded_source = saved_source.clone();
        let mut app = TuiApp::new(
            config_path.clone(),
            saved.clone(),
            ProcessCatalog::default(),
        );
        let mut state = ConfigSaveState {
            pending: Some(PendingConfigSave {
                config_path: config_path.clone(),
                config: saved.clone(),
                saved_status: StatusMessage::saved("Saved config"),
                should_reconcile_runtime: true,
                task: tokio::spawn(async move { Ok(saved_source) }),
            }),
            ..Default::default()
        };

        app.replace_config(failed.clone(), ProcessCatalog::default());
        state.start_or_queue(
            &loaded_source,
            &mut app,
            StatusMessage::saved("Saved failed snapshot"),
            true,
        );
        app.replace_config(saved.clone(), ProcessCatalog::default());
        app.mark_dirty("Changed back before queued save failed");

        let saved_completion = state
            .wait_for_pending()
            .await
            .expect("first save should complete");
        assert!(
            state
                .apply_completion(&mut loaded_source, &mut app, saved_completion)
                .is_none()
        );
        assert!(app.dirty());

        let failed_completion = state
            .wait_for_pending()
            .await
            .expect("queued save should start and fail");
        let reconcile = state
            .apply_completion(&mut loaded_source, &mut app, failed_completion)
            .expect("last successful snapshot should still reconcile runtime");

        assert_eq!(reconcile.config, saved);
        assert_eq!(reconcile.status.kind, StatusKind::Error);
        assert!(reconcile.status.text.contains("Config save failed"));
        assert!(app.dirty());
        Ok(())
    }

    #[test]
    fn completed_current_config_save_clears_dirty() {
        let config = AgentConfig::default();
        let mut loaded_source = "old".to_string();
        let mut app = TuiApp::new(
            PathBuf::from("/tmp/agent.toml"),
            config.clone(),
            ProcessCatalog::default(),
        );
        app.mark_dirty("changed");

        let outcome = apply_config_save_completion(
            &mut loaded_source,
            &mut app,
            ConfigSaveCompletion {
                config_path: PathBuf::from("/tmp/agent.toml"),
                config,
                saved_status: StatusMessage::saved("Saved config"),
                should_reconcile_runtime: false,
                result: Ok("new".to_string()),
            },
            false,
        );

        assert_eq!(loaded_source, "new");
        assert!(!app.dirty());
        assert_eq!(app.status().kind, StatusKind::Saved);
        assert!(matches!(
            outcome,
            ConfigSaveApplyOutcome::Saved {
                runtime_reconcile: None
            }
        ));
    }

    #[test]
    fn completed_stale_config_save_keeps_newer_edits_dirty_and_reconciles_saved_snapshot() {
        let saved_config = AgentConfig::default();
        let mut current_config = saved_config.clone();
        current_config.config_version = "newer".to_string();
        let mut loaded_source = "old".to_string();
        let mut app = TuiApp::new(
            PathBuf::from("/tmp/agent.toml"),
            current_config,
            ProcessCatalog::default(),
        );
        app.mark_dirty("changed again");

        let outcome = apply_config_save_completion(
            &mut loaded_source,
            &mut app,
            ConfigSaveCompletion {
                config_path: PathBuf::from("/tmp/agent.toml"),
                config: saved_config.clone(),
                saved_status: StatusMessage::saved("Saved config"),
                should_reconcile_runtime: true,
                result: Ok("saved snapshot".to_string()),
            },
            false,
        );
        let ConfigSaveApplyOutcome::Saved {
            runtime_reconcile: Some(reconcile),
        } = outcome
        else {
            panic!("saved snapshot should still be reconciled");
        };

        assert_eq!(loaded_source, "saved snapshot");
        assert!(app.dirty());
        assert_eq!(app.status().kind, StatusKind::Warning);
        assert!(app.status().text.contains("newer edits are still unsaved"));
        assert_eq!(reconcile.config, saved_config);
        assert_eq!(reconcile.status.kind, StatusKind::Warning);
    }

    fn config_with_version(version: &str) -> AgentConfig {
        AgentConfig {
            config_version: version.to_string(),
            ..AgentConfig::default()
        }
    }

    fn pending_config_save(
        config: AgentConfig,
        result: Result<String, TuiError>,
    ) -> PendingConfigSave {
        pending_config_save_at(PathBuf::from("/tmp/agent.toml"), config, result)
    }

    fn pending_config_save_at(
        config_path: PathBuf,
        config: AgentConfig,
        result: Result<String, TuiError>,
    ) -> PendingConfigSave {
        PendingConfigSave {
            config_path,
            config,
            saved_status: StatusMessage::saved("Saved config"),
            should_reconcile_runtime: false,
            task: tokio::spawn(async move { result }),
        }
    }
}
