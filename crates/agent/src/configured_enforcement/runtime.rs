use std::sync::{Arc, RwLock};

use enforcement::{
    EnforcementPlanRequest, EnforcementPlanner, PlannerPolicy, ScopedEnforcementPlanner,
};

use super::builder::ActiveEnforcementPolicy;

#[derive(Clone)]
pub(crate) struct EnforcementRuntimeState {
    control: Arc<RwLock<EnforcementRuntimeControl>>,
}

pub(crate) struct RuntimeEnforcementPlanner {
    planner: ScopedEnforcementPlanner,
    control: Arc<RwLock<EnforcementRuntimeControl>>,
    generation: u64,
}

struct EnforcementRuntimeControl {
    policy: ActiveEnforcementPolicy,
    generation: u64,
}

impl EnforcementRuntimeState {
    pub(crate) fn from_planner(
        mut planner: ScopedEnforcementPlanner,
        policy: ActiveEnforcementPolicy,
    ) -> (RuntimeEnforcementPlanner, Self) {
        planner.replace_policy(policy.planner_policy().clone());
        let control = Arc::new(RwLock::new(EnforcementRuntimeControl {
            policy,
            generation: 0,
        }));
        let runtime_planner = RuntimeEnforcementPlanner {
            planner,
            control: Arc::clone(&control),
            generation: 0,
        };
        (runtime_planner, Self { control })
    }

    pub(crate) fn active_policy(&self) -> ActiveEnforcementPolicy {
        let control = self
            .control
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        control.policy.clone()
    }

    pub(crate) fn replace(&self, policy: ActiveEnforcementPolicy) {
        let mut control = self
            .control
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        control.policy = policy;
        control.generation = control.generation.wrapping_add(1);
    }
}

impl EnforcementPlanner for RuntimeEnforcementPlanner {
    fn evaluate(
        &mut self,
        request: EnforcementPlanRequest<'_>,
    ) -> Option<probe_core::EnforcementDecision> {
        self.refresh();
        self.planner.evaluate(request)
    }
}

impl RuntimeEnforcementPlanner {
    fn refresh(&mut self) {
        let Some(snapshot) = self.pending_update() else {
            return;
        };
        self.planner.replace_policy(snapshot.policy);
        self.generation = snapshot.generation;
    }

    fn pending_update(&self) -> Option<EnforcementRuntimeSnapshot> {
        let control = self
            .control
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (control.generation != self.generation).then(|| EnforcementRuntimeSnapshot {
            policy: control.policy.planner_policy().clone(),
            generation: control.generation,
        })
    }
}

struct EnforcementRuntimeSnapshot {
    policy: PlannerPolicy,
    generation: u64,
}
