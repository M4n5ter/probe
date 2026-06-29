use std::time::{Duration, Instant};

use capture::{
    CaptureError, CapturePoll, CaptureProvider, LibsslUprobeAttachPlan,
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
    fn record_reconcile_success(&self, result: &LibsslUprobePlaintextReconcile);
    fn record_reconcile_failure(&self, failure: LibsslUprobePlaintextReconcileFailure);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum LibsslUprobePlaintextReconcileFailure {
    Recoverable { reason: String },
    Fatal { reason: String },
}

impl LibsslUprobePlaintextReconcileFailure {
    fn recoverable(error: &CaptureError) -> Self {
        Self::Recoverable {
            reason: error.to_string(),
        }
    }

    fn fatal(error: &CaptureError) -> Self {
        Self::Fatal {
            reason: error.to_string(),
        }
    }

    #[cfg(test)]
    fn reason(&self) -> &str {
        match self {
            Self::Recoverable { reason } | Self::Fatal { reason } => reason,
        }
    }

    #[cfg(test)]
    fn is_fatal(&self) -> bool {
        matches!(self, Self::Fatal { .. })
    }
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
        let next_plan = match self.plan_due_reconcile() {
            DueReconcilePlan::Ready(next_plan) => next_plan,
            DueReconcilePlan::Blocked(error) => {
                self.record_reconcile_failure(LibsslUprobePlaintextReconcileFailure::recoverable(
                    &error,
                ));
                return Ok(());
            }
            DueReconcilePlan::Failed(error) => {
                self.record_reconcile_failure(LibsslUprobePlaintextReconcileFailure::fatal(&error));
                return Err(error);
            }
        };
        match self.provider.reconcile_libssl_uprobes(next_plan) {
            Ok(reconcile) => {
                if let Some(observer) = &self.reconcile_observer {
                    observer.record_reconcile_success(&reconcile);
                }
                Ok(())
            }
            Err(error) => {
                self.record_reconcile_failure(LibsslUprobePlaintextReconcileFailure::fatal(&error));
                Err(error)
            }
        }
    }

    fn plan_due_reconcile(&mut self) -> DueReconcilePlan {
        match self.planner.plan() {
            Ok(Ok(next_plan)) => DueReconcilePlan::Ready(next_plan),
            Ok(Err(blocked)) => DueReconcilePlan::Blocked(CaptureError::provider(
                "libssl_uprobe_plaintext",
                blocked.into_reason(),
            )),
            Err(error) => DueReconcilePlan::Failed(CaptureError::provider(
                "libssl_uprobe_plaintext",
                format!("dynamic libssl uprobe attach planning failed: {error}"),
            )),
        }
    }

    fn record_reconcile_failure(&self, failure: LibsslUprobePlaintextReconcileFailure) {
        if let Some(observer) = &self.reconcile_observer {
            observer.record_reconcile_failure(failure);
        }
    }
}

enum DueReconcilePlan {
    Ready(LibsslUprobeAttachPlan),
    Blocked(CaptureError),
    Failed(CaptureError),
}

impl<P> CaptureProvider for LibsslUprobePlaintextSidecar<P>
where
    P: LibsslUprobePlaintextSidecarProvider,
{
    fn name(&self) -> &'static str {
        self.provider.name()
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
        cell::{Cell, RefCell},
        rc::Rc,
        time::{Duration, Instant},
    };

    use capture::{LibsslUprobeAttachTargetSnapshot, LibsslUprobeReconcileTargetBucket};
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
        let polled = Rc::new(Cell::new(false));
        let mut sidecar = LibsslUprobePlaintextSidecar::with_schedule(
            FakeSidecarProvider {
                reconciled: Rc::clone(&reconciled),
                polled: Rc::clone(&polled),
                reconcile_result: Ok(empty_reconcile_result()),
            },
            LibsslUprobeAttachPlanner::from_results([Ok(empty_attach_plan())]),
            FixedIntervalSchedule::due_at(Duration::from_millis(10), Instant::now()),
            None,
        );

        let poll = sidecar.poll_next()?;

        assert_eq!(poll, CapturePoll::Idle);
        assert!(reconciled.get());
        assert!(polled.get());
        Ok(())
    }

    #[test]
    fn sidecar_records_blocked_planning_and_keeps_polling_provider() {
        let reconciled = Rc::new(Cell::new(false));
        let polled = Rc::new(Cell::new(false));
        let observed_success = Rc::new(RefCell::new(None));
        let observed_failure = Rc::new(RefCell::new(None));
        let mut sidecar = LibsslUprobePlaintextSidecar::with_schedule(
            FakeSidecarProvider {
                reconciled: Rc::clone(&reconciled),
                polled: Rc::clone(&polled),
                reconcile_result: Ok(empty_reconcile_result()),
            },
            LibsslUprobeAttachPlanner::from_results([Err(LibsslUprobeAttachPlanBlocked::new(
                "blocked",
            ))]),
            FixedIntervalSchedule::due_at(Duration::from_millis(10), Instant::now()),
            Some(Box::new(FakeReconcileObserver {
                observed_success: Rc::clone(&observed_success),
                observed_failure: Rc::clone(&observed_failure),
            })),
        );

        let poll = sidecar
            .poll_next()
            .expect("blocked planning should not disable the best-effort sidecar");

        assert_eq!(poll, CapturePoll::Idle);
        assert!(!reconciled.get());
        assert!(polled.get());
        assert!(observed_success.borrow().is_none());
        assert!(
            observed_failure
                .borrow()
                .as_ref()
                .is_some_and(|failure| !failure.is_fatal() && failure.reason().contains("blocked"))
        );
    }

    #[test]
    fn sidecar_treats_planner_error_as_fatal() {
        let observed_success = Rc::new(RefCell::new(None));
        let observed_failure = Rc::new(RefCell::new(None));
        let polled = Rc::new(Cell::new(false));
        let mut sidecar = LibsslUprobePlaintextSidecar::with_schedule(
            FakeSidecarProvider {
                reconciled: Rc::new(Cell::new(false)),
                polled: Rc::clone(&polled),
                reconcile_result: Ok(empty_reconcile_result()),
            },
            LibsslUprobeAttachPlanner::from_planner_results([Err(
                crate::error::AgentError::UnsupportedRunConfig("planner failed".to_string()),
            )]),
            FixedIntervalSchedule::due_at(Duration::from_millis(10), Instant::now()),
            Some(Box::new(FakeReconcileObserver {
                observed_success: Rc::clone(&observed_success),
                observed_failure: Rc::clone(&observed_failure),
            })),
        );

        let error = sidecar
            .poll_next()
            .expect_err("planner errors should disable the best-effort sidecar");

        assert!(error.to_string().contains("planner failed"));
        assert!(observed_success.borrow().is_none());
        assert!(observed_failure.borrow().as_ref().is_some_and(
            |failure| failure.is_fatal() && failure.reason().contains("planner failed")
        ));
        assert!(!polled.get());
    }

    #[test]
    fn sidecar_recovers_after_transient_blocked_planning() -> Result<(), Box<dyn std::error::Error>>
    {
        let reconciled = Rc::new(Cell::new(false));
        let polled = Rc::new(Cell::new(false));
        let observed_success = Rc::new(RefCell::new(None));
        let observed_failure = Rc::new(RefCell::new(None));
        let mut sidecar = LibsslUprobePlaintextSidecar::with_schedule(
            FakeSidecarProvider {
                reconciled: Rc::clone(&reconciled),
                polled: Rc::clone(&polled),
                reconcile_result: Ok(reconcile_result(1, 0, 1)),
            },
            LibsslUprobeAttachPlanner::from_results([
                Err(LibsslUprobeAttachPlanBlocked::new("transient blocked")),
                Ok(empty_attach_plan()),
            ]),
            FixedIntervalSchedule::due_at(Duration::ZERO, Instant::now()),
            Some(Box::new(FakeReconcileObserver {
                observed_success: Rc::clone(&observed_success),
                observed_failure: Rc::clone(&observed_failure),
            })),
        );

        assert_eq!(sidecar.poll_next()?, CapturePoll::Idle);
        assert!(!reconciled.get());
        assert!(polled.get());
        assert!(observed_failure.borrow().as_ref().is_some_and(
            |failure| !failure.is_fatal() && failure.reason().contains("transient blocked")
        ));

        polled.set(false);
        assert_eq!(sidecar.poll_next()?, CapturePoll::Idle);

        assert!(reconciled.get());
        assert!(polled.get());
        let reconcile = observed_success
            .borrow()
            .clone()
            .expect("successful reconcile should be reported after transient planning failure");
        assert_eq!(reconcile.attached_target_count(), 1);
        Ok(())
    }

    #[test]
    fn sidecar_reports_successful_reconcile_to_observer() -> Result<(), Box<dyn std::error::Error>>
    {
        let observed = Rc::new(RefCell::new(None));
        let observed_failure = Rc::new(RefCell::new(None));
        let mut sidecar = LibsslUprobePlaintextSidecar::with_schedule(
            FakeSidecarProvider {
                reconciled: Rc::new(Cell::new(false)),
                polled: Rc::new(Cell::new(false)),
                reconcile_result: Ok(reconcile_result(2, 1, 3)),
            },
            LibsslUprobeAttachPlanner::from_results([Ok(empty_attach_plan())]),
            FixedIntervalSchedule::due_at(Duration::from_millis(10), Instant::now()),
            Some(Box::new(FakeReconcileObserver {
                observed_success: Rc::clone(&observed),
                observed_failure: Rc::clone(&observed_failure),
            })),
        );

        let poll = sidecar.poll_next()?;

        assert_eq!(poll, CapturePoll::Idle);
        let reconcile = observed
            .borrow()
            .clone()
            .expect("successful reconcile counters should be reported");
        assert_eq!(reconcile.attached_target_count(), 2);
        assert_eq!(reconcile.detached_target_count(), 1);
        assert_eq!(reconcile.active_target_count(), 3);
        assert!(observed_failure.borrow().is_none());
        Ok(())
    }

    #[test]
    fn sidecar_reports_failed_reconcile_to_observer() {
        let observed_success = Rc::new(RefCell::new(None));
        let observed_failure = Rc::new(RefCell::new(None));
        let polled = Rc::new(Cell::new(false));
        let mut sidecar = LibsslUprobePlaintextSidecar::with_schedule(
            FakeSidecarProvider {
                reconciled: Rc::new(Cell::new(false)),
                polled: Rc::clone(&polled),
                reconcile_result: Err("attach failed"),
            },
            LibsslUprobeAttachPlanner::from_results([Ok(empty_attach_plan())]),
            FixedIntervalSchedule::due_at(Duration::from_millis(10), Instant::now()),
            Some(Box::new(FakeReconcileObserver {
                observed_success: Rc::clone(&observed_success),
                observed_failure: Rc::clone(&observed_failure),
            })),
        );

        let error = sidecar
            .poll_next()
            .expect_err("failed reconcile should disable the best-effort sidecar");

        assert!(error.to_string().contains("attach failed"));
        assert!(observed_success.borrow().is_none());
        assert!(observed_failure.borrow().as_ref().is_some_and(
            |failure| failure.is_fatal() && failure.reason().contains("attach failed")
        ));
        assert!(!polled.get());
    }

    struct FakeSidecarProvider {
        reconciled: Rc<Cell<bool>>,
        polled: Rc<Cell<bool>>,
        reconcile_result: Result<LibsslUprobePlaintextReconcile, &'static str>,
    }

    struct FakeReconcileObserver {
        observed_success: Rc<RefCell<Option<LibsslUprobePlaintextReconcile>>>,
        observed_failure: Rc<RefCell<Option<LibsslUprobePlaintextReconcileFailure>>>,
    }

    impl LibsslUprobePlaintextReconcileObserver for FakeReconcileObserver {
        fn record_reconcile_success(&self, result: &LibsslUprobePlaintextReconcile) {
            *self.observed_success.borrow_mut() = Some(result.clone());
        }

        fn record_reconcile_failure(&self, failure: LibsslUprobePlaintextReconcileFailure) {
            *self.observed_failure.borrow_mut() = Some(failure);
        }
    }

    impl LibsslUprobePlaintextSidecarProvider for FakeSidecarProvider {
        fn reconcile_libssl_uprobes(
            &mut self,
            _next_plan: LibsslUprobeAttachPlan,
        ) -> Result<LibsslUprobePlaintextReconcile, CaptureError> {
            self.reconciled.set(true);
            self.reconcile_result
                .clone()
                .map_err(|reason| CaptureError::provider("fake_tls_sidecar", reason.to_string()))
        }
    }

    impl CaptureProvider for FakeSidecarProvider {
        fn name(&self) -> &'static str {
            "fake_tls_sidecar"
        }

        fn capabilities(&self) -> Vec<CapabilityState> {
            Vec::new()
        }

        fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
            self.polled.set(true);
            Ok(CapturePoll::Idle)
        }
    }

    fn empty_reconcile_result() -> LibsslUprobePlaintextReconcile {
        reconcile_result(0, 0, 0)
    }

    fn reconcile_result(
        attached: usize,
        detached: usize,
        active: usize,
    ) -> LibsslUprobePlaintextReconcile {
        LibsslUprobePlaintextReconcile {
            attached_targets: target_snapshots("attached", attached),
            detached_targets: target_snapshots("detached", detached),
            active_targets: target_snapshots("active", active),
        }
    }

    fn target_snapshots(kind: &str, count: usize) -> LibsslUprobeReconcileTargetBucket {
        let targets = (0..count)
            .map(|index| LibsslUprobeAttachTargetSnapshot {
                pid: 1_000 + index as u32,
                start_time_ticks: 10_000 + index as u64,
                mapped_path: format!("/usr/lib/{kind}-{index}.so").into(),
                read_path: format!("/proc/1/root/usr/lib/{kind}-{index}.so").into(),
                device_major: 8,
                device_minor: 1,
                inode: index as u64 + 1,
                deleted: false,
            })
            .collect::<Vec<_>>();
        LibsslUprobeReconcileTargetBucket::new(targets)
    }
}
