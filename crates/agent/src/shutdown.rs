use probe_core::CancellationToken;

pub(crate) type ShutdownFlag = CancellationToken;

pub(crate) fn new_flag() -> ShutdownFlag {
    CancellationToken::new()
}

pub(crate) fn requested(flag: &ShutdownFlag) -> bool {
    flag.is_cancelled()
}

pub(crate) fn spawn_signal_task(flag: ShutdownFlag) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        flag.cancel();
    })
}

#[cfg(unix)]
async fn wait_for_shutdown_signal() {
    let mut sigterm =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = wait_optional_unix_signal(&mut sigterm) => {}
    }
}

#[cfg(unix)]
async fn wait_optional_unix_signal(signal: &mut Option<tokio::signal::unix::Signal>) {
    if let Some(signal) = signal.as_mut() {
        signal.recv().await;
    } else {
        std::future::pending::<()>().await;
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
