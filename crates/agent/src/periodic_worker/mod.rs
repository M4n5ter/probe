use std::{
    fmt::Display,
    sync::Arc,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use tokio::sync::Notify;

const WORKER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct PeriodicWorkerHandle {
    label: &'static str,
    stop_requested: Arc<AtomicBool>,
    stop_notify: Arc<Notify>,
    task: tokio::task::JoinHandle<()>,
}

impl PeriodicWorkerHandle {
    pub(crate) async fn stop(mut self) {
        self.stop_requested.store(true, Ordering::Relaxed);
        self.stop_notify.notify_one();
        match tokio::time::timeout(WORKER_SHUTDOWN_TIMEOUT, &mut self.task).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) if !error.is_cancelled() => {
                eprintln!("{} worker stopped with error: {error}", self.label);
            }
            Ok(Err(_)) => {}
            Err(_) => {
                self.task.abort();
                if let Err(error) = self.task.await
                    && !error.is_cancelled()
                {
                    eprintln!("{} worker stopped with error: {error}", self.label);
                }
            }
        }
    }
}

pub(crate) fn spawn_periodic_worker<F, E>(
    label: &'static str,
    interval: Duration,
    mut run_once: F,
) -> PeriodicWorkerHandle
where
    F: FnMut() -> Result<(), E> + Send + 'static,
    E: Display,
{
    let stop_requested = Arc::new(AtomicBool::new(false));
    let stop_notify = Arc::new(Notify::new());
    let task_stop_requested = Arc::clone(&stop_requested);
    let task_stop_notify = Arc::clone(&stop_notify);
    let task = tokio::spawn(async move {
        while !task_stop_requested.load(Ordering::Relaxed) {
            if let Err(error) = run_once() {
                eprintln!("{label} worker cleanup failed: {error}");
            }
            if task_stop_requested.load(Ordering::Relaxed) {
                break;
            }
            tokio::select! {
                () = tokio::time::sleep(interval) => {}
                () = task_stop_notify.notified() => {}
            }
        }
    });
    PeriodicWorkerHandle {
        label,
        stop_requested,
        stop_notify,
        task,
    }
}
