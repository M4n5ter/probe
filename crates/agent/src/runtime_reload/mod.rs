pub(crate) mod config_reload;
mod online_actions;

use std::sync::Arc;

use tokio::sync::Mutex;

#[derive(Clone)]
pub(crate) struct RuntimeReloadGate {
    inner: Arc<Mutex<()>>,
}

impl RuntimeReloadGate {
    pub(crate) async fn lock(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.inner.lock().await
    }

    pub(crate) fn blocking_lock(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.inner.blocking_lock()
    }
}

impl Default for RuntimeReloadGate {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(())),
        }
    }
}
