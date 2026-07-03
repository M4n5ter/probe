use std::sync::{Arc, RwLock};

use runtime::RuntimePlan;

#[derive(Clone)]
pub(crate) struct RuntimePlanHandle {
    inner: Arc<RwLock<Arc<RuntimePlan>>>,
}

impl RuntimePlanHandle {
    pub(crate) fn new(plan: Arc<RuntimePlan>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(plan)),
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
    }
}
