use std::path::PathBuf;

use probe_config::AgentConfig;

use super::{
    app::{StatusMessage, TuiApp},
    config_edit::{TuiError, save_config},
};

pub(super) struct PendingConfigSave {
    config_path: PathBuf,
    config: AgentConfig,
    saved_status: StatusMessage,
    should_reconcile_runtime: bool,
    task: tokio::task::JoinHandle<Result<String, TuiError>>,
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

pub(super) fn start_config_save(
    pending_config_save: &mut Option<PendingConfigSave>,
    original_source: &str,
    app: &mut TuiApp,
    saved_status: StatusMessage,
    should_reconcile_runtime: bool,
) {
    if pending_config_save.is_some() {
        app.mark_warning("Config save is already running in the background");
        return;
    }
    let config_path = app.config_path().clone();
    let config = app.config().clone();
    let original_source = original_source.to_string();
    let display_path = config_path.display().to_string();
    let task_path = config_path.clone();
    let task_config = config.clone();
    *pending_config_save = Some(PendingConfigSave {
        config_path,
        config,
        saved_status,
        should_reconcile_runtime,
        task: tokio::task::spawn_blocking(move || {
            save_config(&task_path, &original_source, &task_config)
        }),
    });
    app.mark_info(format!("Saving config to {display_path} in background"));
}

pub(super) async fn take_finished_config_save(
    pending: &mut Option<PendingConfigSave>,
) -> Option<ConfigSaveCompletion> {
    if !pending
        .as_ref()
        .is_some_and(|pending| pending.task.is_finished())
    {
        return None;
    }
    let pending = pending.take().expect("pending save task was checked");
    Some(config_save_completion(pending).await)
}

pub(super) async fn wait_for_config_save(
    pending: &mut Option<PendingConfigSave>,
) -> Option<ConfigSaveCompletion> {
    let pending = pending.take()?;
    Some(config_save_completion(pending).await)
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

pub(super) fn reject_reload_during_config_save(
    pending_config_save: &Option<PendingConfigSave>,
    app: &mut TuiApp,
) -> bool {
    if pending_config_save.is_none() {
        return false;
    }
    app.mark_warning("Config save is running; reload after it finishes");
    true
}

pub(super) fn apply_config_save_completion(
    loaded_source: &mut String,
    app: &mut TuiApp,
    completion: ConfigSaveCompletion,
) -> Option<SavedConfigRuntimeReconcile> {
    let ConfigSaveCompletion {
        config_path,
        config,
        saved_status,
        should_reconcile_runtime,
        result,
    } = completion;
    match result {
        Ok(source) => apply_successful_save(
            loaded_source,
            app,
            config_path,
            config,
            saved_status,
            should_reconcile_runtime,
            source,
        ),
        Err(error) if app.config() == &config => {
            app.mark_save_failed(error.to_string());
            None
        }
        Err(error) => {
            app.mark_warning(format!(
                "Save failed for a previous config snapshot: {error}; newer edits are still unsaved"
            ));
            None
        }
    }
}

fn apply_successful_save(
    loaded_source: &mut String,
    app: &mut TuiApp,
    config_path: PathBuf,
    config: AgentConfig,
    saved_status: StatusMessage,
    should_reconcile_runtime: bool,
    source: String,
) -> Option<SavedConfigRuntimeReconcile> {
    *loaded_source = source;
    let saved_config_is_current = app.config() == &config;
    let runtime_status = if saved_config_is_current {
        saved_status
    } else {
        StatusMessage::warning("Saved a previous config snapshot; newer edits are still unsaved")
    };
    if saved_config_is_current {
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
        let mut pending = Some(pending_config_save(
            config.clone(),
            Ok("saved source".to_string()),
        ));

        let completion = wait_for_config_save(&mut pending)
            .await
            .expect("pending save should complete");

        assert!(pending.is_none());
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
        let mut pending = Some(pending_config_save(config, Ok("saved source".to_string())));

        assert!(reject_reload_during_config_save(&pending, &mut app));
        assert_eq!(app.status().kind, StatusKind::Warning);
        assert!(app.status().text.contains("reload after it finishes"));

        let _ = wait_for_config_save(&mut pending).await;
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

        let reconcile = apply_config_save_completion(
            &mut loaded_source,
            &mut app,
            ConfigSaveCompletion {
                config_path: PathBuf::from("/tmp/agent.toml"),
                config,
                saved_status: StatusMessage::saved("Saved config"),
                should_reconcile_runtime: false,
                result: Ok("new".to_string()),
            },
        );

        assert_eq!(loaded_source, "new");
        assert!(!app.dirty());
        assert_eq!(app.status().kind, StatusKind::Saved);
        assert!(reconcile.is_none());
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

        let reconcile = apply_config_save_completion(
            &mut loaded_source,
            &mut app,
            ConfigSaveCompletion {
                config_path: PathBuf::from("/tmp/agent.toml"),
                config: saved_config.clone(),
                saved_status: StatusMessage::saved("Saved config"),
                should_reconcile_runtime: true,
                result: Ok("saved snapshot".to_string()),
            },
        )
        .expect("saved snapshot should still be reconciled");

        assert_eq!(loaded_source, "saved snapshot");
        assert!(app.dirty());
        assert_eq!(app.status().kind, StatusKind::Warning);
        assert!(app.status().text.contains("newer edits are still unsaved"));
        assert_eq!(reconcile.config, saved_config);
        assert_eq!(reconcile.status.kind, StatusKind::Warning);
    }

    fn pending_config_save(
        config: AgentConfig,
        result: Result<String, TuiError>,
    ) -> PendingConfigSave {
        PendingConfigSave {
            config_path: PathBuf::from("/tmp/agent.toml"),
            config,
            saved_status: StatusMessage::saved("Saved config"),
            should_reconcile_runtime: false,
            task: tokio::spawn(async move { result }),
        }
    }
}
