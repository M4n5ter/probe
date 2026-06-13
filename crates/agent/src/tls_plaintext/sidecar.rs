use std::time::{Duration, Instant};

use capture::{
    CaptureError, CapturePoll, CaptureProvider, CaptureProviderKind, LibsslUprobeAttachPlan,
    LibsslUprobePlaintextProvider, LibsslUprobePlaintextReconcile,
};
use probe_core::CapabilityState;

use super::planning::LibsslUprobeAttachPlanner;

pub(super) trait LibsslUprobePlaintextSidecarProvider: CaptureProvider {
    fn reconcile_libssl_uprobes(
        &mut self,
        next_plan: LibsslUprobeAttachPlan,
    ) -> Result<LibsslUprobePlaintextReconcile, CaptureError>;
}

impl LibsslUprobePlaintextSidecarProvider for LibsslUprobePlaintextProvider {
    fn reconcile_libssl_uprobes(
        &mut self,
        next_plan: LibsslUprobeAttachPlan,
    ) -> Result<LibsslUprobePlaintextReconcile, CaptureError> {
        LibsslUprobePlaintextProvider::reconcile_libssl_uprobes(self, next_plan)
    }
}

pub(super) trait LibsslUprobePlaintextReconcileObserver {
    fn record_reconcile_success(&self, result: LibsslUprobePlaintextReconcile);
}

pub(super) struct LibsslUprobePlaintextSidecar<P = LibsslUprobePlaintextProvider>
where
    P: LibsslUprobePlaintextSidecarProvider,
{
    provider: P,
    planner: LibsslUprobeAttachPlanner,
    schedule: FixedIntervalSchedule,
    reconcile_observer: Option<Box<dyn LibsslUprobePlaintextReconcileObserver>>,
}

impl LibsslUprobePlaintextSidecar<LibsslUprobePlaintextProvider> {
    pub(super) fn after(
        provider: LibsslUprobePlaintextProvider,
        planner: LibsslUprobeAttachPlanner,
        interval: Duration,
        reconcile_observer: Option<Box<dyn LibsslUprobePlaintextReconcileObserver>>,
    ) -> Self {
        Self {
            provider,
            planner,
            schedule: FixedIntervalSchedule::after(interval),
            reconcile_observer,
        }
    }
}

impl<P> LibsslUprobePlaintextSidecar<P>
where
    P: LibsslUprobePlaintextSidecarProvider,
{
    #[cfg(test)]
    fn with_schedule(
        provider: P,
        planner: LibsslUprobeAttachPlanner,
        schedule: FixedIntervalSchedule,
        reconcile_observer: Option<Box<dyn LibsslUprobePlaintextReconcileObserver>>,
    ) -> Self {
        Self {
            provider,
            planner,
            schedule,
            reconcile_observer,
        }
    }

    fn reconcile_if_due(&mut self) -> Result<(), CaptureError> {
        if !self.schedule.take_due(Instant::now()) {
            return Ok(());
        }
        let next_plan = self
            .planner
            .plan()
            .map_err(|error| {
                CaptureError::provider(
                    "libssl_uprobe_plaintext",
                    format!("dynamic libssl uprobe attach planning failed: {error}"),
                )
            })?
            .map_err(|blocked| {
                CaptureError::provider("libssl_uprobe_plaintext", blocked.into_reason())
            })?;
        let result = self.provider.reconcile_libssl_uprobes(next_plan)?;
        if let Some(observer) = &self.reconcile_observer {
            observer.record_reconcile_success(result);
        }
        Ok(())
    }
}

impl<P> CaptureProvider for LibsslUprobePlaintextSidecar<P>
where
    P: LibsslUprobePlaintextSidecarProvider,
{
    fn name(&self) -> &'static str {
        self.provider.name()
    }

    fn kind(&self) -> CaptureProviderKind {
        self.provider.kind()
    }

    fn capabilities(&self) -> Vec<CapabilityState> {
        self.provider.capabilities()
    }

    fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
        self.reconcile_if_due()?;
        self.provider.poll_next()
    }
}

struct FixedIntervalSchedule {
    interval: Duration,
    next_due: Instant,
}

impl FixedIntervalSchedule {
    fn after(interval: Duration) -> Self {
        let now = Instant::now();
        Self {
            interval,
            next_due: next_due_after(now, interval),
        }
    }

    #[cfg(test)]
    fn due_at(interval: Duration, next_due: Instant) -> Self {
        Self { interval, next_due }
    }

    fn take_due(&mut self, now: Instant) -> bool {
        if now < self.next_due {
            return false;
        }
        self.next_due = next_due_after(now, self.interval);
        true
    }
}

fn next_due_after(now: Instant, interval: Duration) -> Instant {
    now.checked_add(interval)
        .expect("validated TLS plaintext reconcile interval must fit Instant")
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        rc::Rc,
        time::{Duration, Instant},
    };

    use probe_core::CapabilityState;

    use super::super::planning::{LibsslUprobeAttachPlanBlocked, empty_attach_plan};
    use super::*;

    #[test]
    fn fixed_interval_schedule_runs_only_after_due_time() {
        let now = Instant::now();
        let interval = Duration::from_millis(10);
        let mut schedule = FixedIntervalSchedule::due_at(interval, now + interval);

        assert!(!schedule.take_due(now));
        assert!(schedule.take_due(now + interval));
        assert!(!schedule.take_due(now + interval + Duration::from_millis(5)));
        assert!(schedule.take_due(now + interval + interval));
    }

    #[test]
    fn sidecar_reconciles_due_plan_before_polling_provider()
    -> Result<(), Box<dyn std::error::Error>> {
        let reconciled = Rc::new(Cell::new(false));
        let polled_after_reconcile = Rc::new(Cell::new(false));
        let mut sidecar = LibsslUprobePlaintextSidecar::with_schedule(
            FakeSidecarProvider {
                reconciled: Rc::clone(&reconciled),
                polled: Rc::clone(&polled_after_reconcile),
                reconcile_result: empty_reconcile_result(),
            },
            LibsslUprobeAttachPlanner::from_results([Ok(empty_attach_plan())]),
            FixedIntervalSchedule::due_at(Duration::from_millis(10), Instant::now()),
            None,
        );

        let poll = sidecar.poll_next()?;

        assert_eq!(poll, CapturePoll::Idle);
        assert!(reconciled.get());
        assert!(polled_after_reconcile.get());
        Ok(())
    }

    #[test]
    fn sidecar_stops_polling_when_due_planning_is_blocked() {
        let reconciled = Rc::new(Cell::new(false));
        let polled = Rc::new(Cell::new(false));
        let mut sidecar = LibsslUprobePlaintextSidecar::with_schedule(
            FakeSidecarProvider {
                reconciled,
                polled: Rc::clone(&polled),
                reconcile_result: empty_reconcile_result(),
            },
            LibsslUprobeAttachPlanner::from_results([Err(LibsslUprobeAttachPlanBlocked::new(
                "blocked",
            ))]),
            FixedIntervalSchedule::due_at(Duration::from_millis(10), Instant::now()),
            None,
        );

        let error = sidecar
            .poll_next()
            .expect_err("blocked planning should disable the best-effort sidecar");

        assert!(error.to_string().contains("blocked"));
        assert!(!polled.get());
    }

    #[test]
    fn sidecar_reports_successful_reconcile_to_observer() -> Result<(), Box<dyn std::error::Error>>
    {
        let observed = Rc::new(Cell::new(None));
        let mut sidecar = LibsslUprobePlaintextSidecar::with_schedule(
            FakeSidecarProvider {
                reconciled: Rc::new(Cell::new(false)),
                polled: Rc::new(Cell::new(false)),
                reconcile_result: LibsslUprobePlaintextReconcile {
                    attached_targets: 2,
                    detached_targets: 1,
                    active_targets: 3,
                },
            },
            LibsslUprobeAttachPlanner::from_results([Ok(empty_attach_plan())]),
            FixedIntervalSchedule::due_at(Duration::from_millis(10), Instant::now()),
            Some(Box::new(FakeReconcileObserver {
                observed: Rc::clone(&observed),
            })),
        );

        let poll = sidecar.poll_next()?;

        assert_eq!(poll, CapturePoll::Idle);
        let reconcile = observed
            .get()
            .expect("successful reconcile counters should be reported");
        assert_eq!(reconcile.attached_targets, 2);
        assert_eq!(reconcile.detached_targets, 1);
        assert_eq!(reconcile.active_targets, 3);
        Ok(())
    }

    struct FakeSidecarProvider {
        reconciled: Rc<Cell<bool>>,
        polled: Rc<Cell<bool>>,
        reconcile_result: LibsslUprobePlaintextReconcile,
    }

    struct FakeReconcileObserver {
        observed: Rc<Cell<Option<LibsslUprobePlaintextReconcile>>>,
    }

    impl LibsslUprobePlaintextReconcileObserver for FakeReconcileObserver {
        fn record_reconcile_success(&self, result: LibsslUprobePlaintextReconcile) {
            self.observed.set(Some(result));
        }
    }

    impl LibsslUprobePlaintextSidecarProvider for FakeSidecarProvider {
        fn reconcile_libssl_uprobes(
            &mut self,
            _next_plan: LibsslUprobeAttachPlan,
        ) -> Result<LibsslUprobePlaintextReconcile, CaptureError> {
            self.reconciled.set(true);
            Ok(self.reconcile_result)
        }
    }

    impl CaptureProvider for FakeSidecarProvider {
        fn name(&self) -> &'static str {
            "fake_tls_sidecar"
        }

        fn kind(&self) -> CaptureProviderKind {
            CaptureProviderKind::Plaintext
        }

        fn capabilities(&self) -> Vec<CapabilityState> {
            Vec::new()
        }

        fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
            self.polled.set(self.reconciled.get());
            Ok(CapturePoll::Idle)
        }
    }

    fn empty_reconcile_result() -> LibsslUprobePlaintextReconcile {
        LibsslUprobePlaintextReconcile {
            attached_targets: 0,
            detached_targets: 0,
            active_targets: 0,
        }
    }
}
