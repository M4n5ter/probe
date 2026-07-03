use std::{
    fmt::Display,
    future::Future,
    sync::Arc,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use tokio::sync::Notify;

const WORKER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct WorkerHandle {
    label: &'static str,
    context: WorkerContext,
    task: tokio::task::JoinHandle<()>,
}

pub(crate) type PeriodicWorkerHandle = WorkerHandle;

#[derive(Clone)]
pub(crate) struct WorkerContext {
    stop_requested: Arc<AtomicBool>,
    stop_notify: Arc<Notify>,
}

impl WorkerHandle {
    pub(crate) async fn stop(mut self) {
        self.context.request_stop();
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

impl WorkerContext {
    fn new() -> Self {
        Self {
            stop_requested: Arc::new(AtomicBool::new(false)),
            stop_notify: Arc::new(Notify::new()),
        }
    }

    pub(crate) fn stop_requested(&self) -> bool {
        self.stop_requested.load(Ordering::Relaxed)
    }

    pub(crate) async fn sleep_or_stop(&self, duration: Duration) -> bool {
        if self.stop_requested() {
            return false;
        }
        tokio::select! {
            () = tokio::time::sleep(duration) => !self.stop_requested(),
            () = self.stop_notify.notified() => false,
        }
    }

    pub(crate) async fn wait_or_stop(&self, event: impl Future<Output = ()>) -> bool {
        if self.stop_requested() {
            return false;
        }
        tokio::select! {
            () = event => !self.stop_requested(),
            () = self.stop_notify.notified() => false,
        }
    }

    pub(crate) async fn sleep_or_wait_or_stop(
        &self,
        duration: Duration,
        event: impl Future<Output = ()>,
    ) -> bool {
        if self.stop_requested() {
            return false;
        }
        tokio::select! {
            () = tokio::time::sleep(duration) => !self.stop_requested(),
            () = event => !self.stop_requested(),
            () = self.stop_notify.notified() => false,
        }
    }

    fn request_stop(&self) {
        self.stop_requested.store(true, Ordering::Relaxed);
        self.stop_notify.notify_one();
    }
}

pub(crate) fn spawn_worker<F, Fut>(label: &'static str, run: F) -> WorkerHandle
where
    F: FnOnce(WorkerContext) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let context = WorkerContext::new();
    let task = tokio::spawn(run(context.clone()));
    WorkerHandle {
        label,
        context,
        task,
    }
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
    spawn_async_periodic_worker(label, interval, run_once)
}

fn spawn_async_periodic_worker<F, Fut, E>(
    label: &'static str,
    interval: Duration,
    mut run_once: F,
) -> PeriodicWorkerHandle
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: Future<Output = Result<(), E>> + Send + 'static,
    E: Display,
{
    spawn_worker(label, move |context| async move {
        if !context.sleep_or_stop(interval).await {
            return;
        }
        while !context.stop_requested() {
            if let Err(error) = run_once().await {
                eprintln!("{label} worker iteration failed: {error}");
            }
            if !context.sleep_or_stop(interval).await {
                return;
            }
        }
    })
}
