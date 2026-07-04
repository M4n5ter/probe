use pipeline::PipelineHandoffDrainOutcome;

use crate::runtime_generation::RuntimeGenerationHandoffOutcomeSnapshot;

pub(super) const RUNTIME_GENERATION_HANDOFF_DRAIN_POLLS: u64 = 64;
const MAX_BUDGET_EXHAUSTED_BATCHES: u32 = 2;
const PROGRESS_RETRY_BATCHES: u32 = 20;

#[derive(Debug, Default)]
pub(super) struct RuntimeGenerationHandoffDrain {
    budget_exhausted_batches: u32,
    progress_batches: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RuntimeGenerationHandoffDecision {
    WaitForDrain,
    Proceed(RuntimeGenerationHandoffOutcomeSnapshot),
}

impl RuntimeGenerationHandoffDrain {
    pub(super) fn observe(
        &mut self,
        outcome: PipelineHandoffDrainOutcome,
    ) -> RuntimeGenerationHandoffDecision {
        match outcome {
            PipelineHandoffDrainOutcome::Drained => {
                self.reset();
                RuntimeGenerationHandoffDecision::Proceed(
                    RuntimeGenerationHandoffOutcomeSnapshot::Drained,
                )
            }
            PipelineHandoffDrainOutcome::Progress => {
                self.progress_batches = self.progress_batches.saturating_add(1);
                if self.progress_batches <= PROGRESS_RETRY_BATCHES {
                    RuntimeGenerationHandoffDecision::WaitForDrain
                } else {
                    self.force()
                }
            }
            PipelineHandoffDrainOutcome::BudgetExhausted => {
                self.budget_exhausted_batches = self.budget_exhausted_batches.saturating_add(1);
                if self.budget_exhausted_batches < MAX_BUDGET_EXHAUSTED_BATCHES {
                    RuntimeGenerationHandoffDecision::WaitForDrain
                } else {
                    self.force()
                }
            }
        }
    }

    fn force(&mut self) -> RuntimeGenerationHandoffDecision {
        let after_batches = self
            .budget_exhausted_batches
            .saturating_add(self.progress_batches);
        self.reset();
        RuntimeGenerationHandoffDecision::Proceed(RuntimeGenerationHandoffOutcomeSnapshot::Forced {
            after_batches,
        })
    }

    fn reset(&mut self) {
        self.budget_exhausted_batches = 0;
        self.progress_batches = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_generation_handoff_uses_interactive_forced_swap_budget() {
        assert_eq!(RUNTIME_GENERATION_HANDOFF_DRAIN_POLLS, 64);
        assert_eq!(MAX_BUDGET_EXHAUSTED_BATCHES, 2);
        assert_eq!(PROGRESS_RETRY_BATCHES, 20);
    }

    #[test]
    fn runtime_generation_handoff_decision_waits_until_drain_budget_is_exhausted() {
        let mut handoff = RuntimeGenerationHandoffDrain::default();

        for _ in 1..MAX_BUDGET_EXHAUSTED_BATCHES {
            assert_eq!(
                handoff.observe(PipelineHandoffDrainOutcome::BudgetExhausted),
                RuntimeGenerationHandoffDecision::WaitForDrain
            );
        }

        assert_eq!(
            handoff.observe(PipelineHandoffDrainOutcome::BudgetExhausted),
            RuntimeGenerationHandoffDecision::Proceed(
                RuntimeGenerationHandoffOutcomeSnapshot::Forced {
                    after_batches: MAX_BUDGET_EXHAUSTED_BATCHES
                }
            )
        );
    }

    #[test]
    fn runtime_generation_handoff_decision_preserves_provider_progress_retry_window() {
        let mut handoff = RuntimeGenerationHandoffDrain::default();

        for _ in 0..PROGRESS_RETRY_BATCHES {
            assert_eq!(
                handoff.observe(PipelineHandoffDrainOutcome::Progress),
                RuntimeGenerationHandoffDecision::WaitForDrain
            );
        }

        assert_eq!(
            handoff.observe(PipelineHandoffDrainOutcome::Progress),
            RuntimeGenerationHandoffDecision::Proceed(
                RuntimeGenerationHandoffOutcomeSnapshot::Forced {
                    after_batches: PROGRESS_RETRY_BATCHES + 1
                }
            )
        );
    }

    #[test]
    fn runtime_generation_handoff_decision_resets_after_successful_drain() {
        let mut handoff = RuntimeGenerationHandoffDrain::default();
        assert_eq!(
            handoff.observe(PipelineHandoffDrainOutcome::BudgetExhausted),
            RuntimeGenerationHandoffDecision::WaitForDrain
        );

        assert_eq!(
            handoff.observe(PipelineHandoffDrainOutcome::Drained),
            RuntimeGenerationHandoffDecision::Proceed(
                RuntimeGenerationHandoffOutcomeSnapshot::Drained
            )
        );
        assert_eq!(
            handoff.observe(PipelineHandoffDrainOutcome::BudgetExhausted),
            RuntimeGenerationHandoffDecision::WaitForDrain
        );
    }
}
