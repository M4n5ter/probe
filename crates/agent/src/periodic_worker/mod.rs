use std::{
    fmt::Display,
    future::{Future, ready},
    sync::Arc,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use tokio::sync::Notify;

const WORKER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy)]
enum InitialTick {
    Immediate,
    Delayed,
}

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
    E: Display + Send + 'static,
{
    spawn_async_periodic_worker(label, interval, InitialTick::Immediate, move || {
        ready(run_once())
    })
}

pub(crate) fn spawn_delayed_async_periodic_worker<F, Fut, E>(
    label: &'static str,
    interval: Duration,
    run_once: F,
) -> PeriodicWorkerHandle
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: Future<Output = Result<(), E>> + Send + 'static,
    E: Display,
{
    spawn_async_periodic_worker(label, interval, InitialTick::Delayed, run_once)
}

fn spawn_async_periodic_worker<F, Fut, E>(
    label: &'static str,
    interval: Duration,
    initial_tick: InitialTick,
    mut run_once: F,
) -> PeriodicWorkerHandle
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: Future<Output = Result<(), E>> + Send + 'static,
    E: Display,
{
    let stop_requested = Arc::new(AtomicBool::new(false));
    let stop_notify = Arc::new(Notify::new());
    let task_stop_requested = Arc::clone(&stop_requested);
    let task_stop_notify = Arc::clone(&stop_notify);
    let task = tokio::spawn(async move {
        if matches!(initial_tick, InitialTick::Delayed)
            && !sleep_or_stop(interval, &task_stop_requested, &task_stop_notify).await
        {
            return;
        }
        while !task_stop_requested.load(Ordering::Relaxed) {
            if let Err(error) = run_once().await {
                eprintln!("{label} worker iteration failed: {error}");
            }
            if !sleep_or_stop(interval, &task_stop_requested, &task_stop_notify).await {
                break;
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

async fn sleep_or_stop(
    duration: Duration,
    stop_requested: &AtomicBool,
    stop_notify: &Notify,
) -> bool {
    if stop_requested.load(Ordering::Relaxed) {
        return false;
    }
    tokio::select! {
        () = tokio::time::sleep(duration) => !stop_requested.load(Ordering::Relaxed),
        () = stop_notify.notified() => false,
    }
}
