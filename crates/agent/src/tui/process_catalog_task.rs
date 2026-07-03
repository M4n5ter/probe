use super::{
    app::{StatusKind, StatusMessage, TuiApp},
    processes::ProcessCatalog,
};

pub(super) const STARTUP_BACKGROUND_STATUS: &str =
    "Loading process list and starting or attaching TUI agent in background";

const RELOAD_PROCESS_CATALOG_STATUS_PREFIX: &str = "Reloaded config; refreshing process list";

pub(super) struct PendingProcessCatalog {
    task: tokio::task::JoinHandle<ProcessCatalog>,
}

pub(super) fn spawn_process_catalog_load() -> PendingProcessCatalog {
    PendingProcessCatalog {
        task: tokio::task::spawn_blocking(ProcessCatalog::from_proc),
    }
}

pub(super) async fn take_finished_process_catalog(
    pending: &mut Option<PendingProcessCatalog>,
) -> Option<Result<ProcessCatalog, String>> {
    if !pending
        .as_ref()
        .is_some_and(|pending| pending.task.is_finished())
    {
        return None;
    }
    let pending = pending.take().expect("pending process task was checked");
    Some(match pending.task.await {
        Ok(processes) => Ok(processes),
        Err(error) => Err(format!("process list task failed: {error}")),
    })
}

pub(super) async fn cancel_pending_process_catalog(pending: Option<PendingProcessCatalog>) {
    let Some(pending) = pending else {
        return;
    };
    pending.task.abort();
    let _ = pending.task.await;
}

pub(super) fn apply_process_catalog_load_result(
    app: &mut TuiApp,
    result: Result<ProcessCatalog, String>,
) {
    match result {
        Ok(processes) => {
            let status = process_catalog_loaded_status(&processes);
            app.replace_process_catalog(processes);
            apply_process_catalog_status(app, status);
        }
        Err(message) if app.status().kind != StatusKind::Error => {
            app.mark_warning(message);
        }
        Err(_) => {}
    }
}

fn process_catalog_loaded_status(processes: &ProcessCatalog) -> StatusMessage {
    match (processes.is_empty(), processes.diagnostic_summary()) {
        (true, Some(diagnostic)) => StatusMessage::warning(diagnostic),
        (true, None) => StatusMessage::warning("No process entries were readable under /proc"),
        (false, Some(diagnostic)) => StatusMessage::warning(format!(
            "Loaded {} process entries with warnings: {diagnostic}",
            processes.entries().len()
        )),
        (false, None) => StatusMessage::info(format!(
            "Loaded {} process entries",
            processes.entries().len()
        )),
    }
}

fn apply_process_catalog_status(app: &mut TuiApp, status: StatusMessage) {
    match (app.status().kind, status.kind) {
        (StatusKind::Error, _) => {}
        (_, StatusKind::Warning) => app.mark_warning(status.text),
        (StatusKind::Info, StatusKind::Info)
            if app.status().text == STARTUP_BACKGROUND_STATUS
                || app
                    .status()
                    .text
                    .starts_with(RELOAD_PROCESS_CATALOG_STATUS_PREFIX) =>
        {
            app.mark_info(status.text);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use probe_config::AgentConfig;

    use super::{
        super::processes::{ProcessCatalog, ProcessEntry},
        *,
    };

    #[test]
    fn process_catalog_load_does_not_hide_agent_errors() {
        let mut app = TuiApp::new(
            PathBuf::from("/tmp/agent.toml"),
            AgentConfig::default(),
            ProcessCatalog::default(),
        );
        app.mark_error("TUI agent unavailable: startup failed");

        apply_process_catalog_load_result(
            &mut app,
            Ok(ProcessCatalog::from_entries([process(
                42,
                "curl",
                "/usr/bin/curl",
            )])),
        );

        assert_eq!(app.processes().entries().len(), 1);
        assert_eq!(app.status().kind, StatusKind::Error);
        assert_eq!(app.status().text, "TUI agent unavailable: startup failed");
    }

    #[test]
    fn process_catalog_warning_is_visible_after_background_load() {
        let mut app = TuiApp::new(
            PathBuf::from("/tmp/agent.toml"),
            AgentConfig::default(),
            ProcessCatalog::default(),
        );
        app.mark_info(STARTUP_BACKGROUND_STATUS);

        apply_process_catalog_load_result(
            &mut app,
            Err("process list task failed: join error".to_string()),
        );

        assert_eq!(app.status().kind, StatusKind::Warning);
        assert!(app.status().text.contains("process list task failed"));
    }

    fn process(pid: u32, name: &str, exe_path: &str) -> ProcessEntry {
        ProcessEntry {
            pid,
            name: name.to_string(),
            exe_path: Some(PathBuf::from(exe_path)),
            argv: vec![name.to_string()],
            uid: 1000,
            gid: 1000,
            cgroup_path: Some(format!("system.slice/{name}.service")),
        }
    }
}
