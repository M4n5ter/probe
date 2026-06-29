use std::{
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use thiserror::Error;
use tokio::{
    sync::{Notify, mpsc},
    task::JoinHandle,
};
use tracing::warn;

const WATCHER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) type ReloadFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

#[derive(Debug, Error)]
pub(crate) enum ReloadWatcherError {
    #[error("failed to create reload watcher: {0}")]
    Create(#[source] notify::Error),
    #[error("failed to watch reload path {path}: {source}")]
    WatchPath {
        path: PathBuf,
        #[source]
        source: notify::Error,
    },
}

#[derive(Clone)]
pub(crate) struct ReloadWatchPath {
    path: PathBuf,
    mode: RecursiveMode,
}

impl ReloadWatchPath {
    pub(crate) fn non_recursive(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            mode: RecursiveMode::NonRecursive,
        }
    }

    pub(crate) fn recursive(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            mode: RecursiveMode::Recursive,
        }
    }
}

pub(crate) struct ReloadWatcherHandle {
    label: &'static str,
    shutdown: WatcherShutdown,
    task: JoinHandle<()>,
}

impl ReloadWatcherHandle {
    pub(crate) async fn stop(self) {
        stop_watcher_task(self.label, self.shutdown, self.task).await;
    }
}

pub(crate) fn spawn_reload_watcher<C, E, R>(
    label: &'static str,
    watch_paths: impl IntoIterator<Item = ReloadWatchPath>,
    debounce: Duration,
    event_requests_reload: E,
    context: C,
    reload: R,
) -> Result<ReloadWatcherHandle, ReloadWatcherError>
where
    C: Send + 'static,
    E: Fn(notify::Result<Event>) -> bool + Send + 'static,
    R: for<'a> Fn(&'a mut RecommendedWatcher, &'a C) -> ReloadFuture<'a> + Send + 'static,
{
    let (event_sender, event_receiver) = mpsc::channel(1);
    let mut watcher = RecommendedWatcher::new(
        move |event| {
            if event_requests_reload(event) {
                let _ = event_sender.try_send(());
            }
        },
        Config::default().with_follow_symlinks(false),
    )
    .map_err(ReloadWatcherError::Create)?;

    for watch_path in watch_paths {
        watcher
            .watch(&watch_path.path, watch_path.mode)
            .map_err(|source| ReloadWatcherError::WatchPath {
                path: watch_path.path,
                source,
            })?;
    }

    let shutdown = WatcherShutdown::default();
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move {
        run_reload_watcher(
            watcher,
            event_receiver,
            debounce,
            context,
            task_shutdown,
            reload,
        )
        .await;
    });

    Ok(ReloadWatcherHandle {
        label,
        shutdown,
        task,
    })
}

async fn run_reload_watcher<C, R>(
    mut watcher: RecommendedWatcher,
    mut events: mpsc::Receiver<()>,
    debounce: Duration,
    context: C,
    shutdown: WatcherShutdown,
    reload: R,
) where
    R: for<'a> Fn(&'a mut RecommendedWatcher, &'a C) -> ReloadFuture<'a>,
{
    while !shutdown.is_requested() {
        tokio::select! {
            event = events.recv() => {
                if event.is_none() {
                    break;
                }
                if !wait_for_quiet_period(&mut events, debounce, &shutdown).await {
                    break;
                }
                reload(&mut watcher, &context).await;
            }
            () = shutdown.notified() => break,
        }
    }
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

async fn stop_watcher_task(
    label: &'static str,
    shutdown: WatcherShutdown,
    mut task: JoinHandle<()>,
) {
    shutdown.request();
    match tokio::time::timeout(WATCHER_SHUTDOWN_TIMEOUT, &mut task).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) if !error.is_cancelled() => {
            warn!("{label} stopped with error: {error}");
        }
        Ok(Err(_)) => {}
        Err(_) => {
            task.abort();
            if let Err(error) = task.await
                && !error.is_cancelled()
            {
                warn!("{label} stopped with error: {error}");
            }
        }
    }
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

pub(crate) fn absolute_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    }
}
