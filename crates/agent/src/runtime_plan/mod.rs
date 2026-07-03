use std::sync::{
    Arc, RwLock,
    atomic::{AtomicU64, Ordering},
};

use runtime::RuntimePlan;
use tokio::sync::watch;

#[derive(Clone)]
pub(crate) struct RuntimePlanHandle {
    inner: Arc<RwLock<Arc<RuntimePlan>>>,
    version: Arc<AtomicU64>,
    changes: watch::Sender<u64>,
}

pub(crate) struct RuntimePlanChangeReceiver {
    changes: watch::Receiver<u64>,
}

impl RuntimePlanHandle {
    pub(crate) fn new(plan: Arc<RuntimePlan>) -> Self {
        let (changes, _) = watch::channel(0);
        Self {
            inner: Arc::new(RwLock::new(plan)),
            version: Arc::new(AtomicU64::new(0)),
            changes,
        }
    }

    pub(crate) fn snapshot(&self) -> Arc<RuntimePlan> {
        Arc::clone(
            &self
                .inner
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        )
    }

    pub(crate) fn replace(&self, plan: RuntimePlan) {
        let mut current = self
            .inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *current = Arc::new(plan);
        drop(current);
        let version = self
            .version
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        self.changes.send_replace(version);
    }

    pub(crate) fn subscribe_changes(&self) -> RuntimePlanChangeReceiver {
        RuntimePlanChangeReceiver {
            changes: self.changes.subscribe(),
        }
    }
}

impl RuntimePlanChangeReceiver {
    pub(crate) async fn changed(&mut self) {
        let _ = self.changes.changed().await;
    }
}
