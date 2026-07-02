use ebpf_abi::{
    EBPF_PROCESS_TRACEPOINT_SPECS, EbpfProcessTracepointRole, EbpfProcessTracepointSpec,
};
use rustix::{
    fd::OwnedFd,
    io::{self, IoSlice, IoSliceMut},
    pipe,
};

use super::{
    EbpfProcessObservationActiveTracepointLiveness,
    EbpfProcessObservationActiveTracepointLivenessProgram,
    EbpfProcessObservationActiveTracepointLivenessState, EbpfProcessObservationTracepointFiring,
};

const ACTIVE_LIVENESS_ADVANCED_REASON: &str =
    "safe active syscall probe advanced this tracepoint firing counter";
const ACTIVE_LIVENESS_NOT_ADVANCED_REASON: &str =
    "safe active syscall probe ran but this tracepoint firing counter did not advance";
const ACTIVE_LIVENESS_UNSUPPORTED_REASON: &str =
    "this tracepoint is outside the current safe active syscall probe set";

const SAFE_ACTIVE_LIVENESS_PROBE_ROLES: [EbpfProcessTracepointRole; 8] = [
    EbpfProcessTracepointRole::WriteEnter,
    EbpfProcessTracepointRole::WriteExit,
    EbpfProcessTracepointRole::WritevEnter,
    EbpfProcessTracepointRole::WritevExit,
    EbpfProcessTracepointRole::ReadEnter,
    EbpfProcessTracepointRole::ReadExit,
    EbpfProcessTracepointRole::ReadvEnter,
    EbpfProcessTracepointRole::ReadvExit,
];

pub(super) fn active_tracepoint_liveness_from_firings(
    before: &[EbpfProcessObservationTracepointFiring],
    after: &[EbpfProcessObservationTracepointFiring],
) -> EbpfProcessObservationActiveTracepointLiveness {
    EbpfProcessObservationActiveTracepointLiveness {
        programs: EBPF_PROCESS_TRACEPOINT_SPECS
            .into_iter()
            .map(|spec| active_liveness_program(spec, before, after))
            .collect(),
    }
}

pub(super) fn trigger_safe_active_tracepoint_liveness_probe()
-> io::Result<ActiveTracepointLivenessProbeGuard> {
    let pipe = ProbePipe::new()?;

    trigger_scalar_read_write(&pipe)?;
    trigger_vector_read_write(&pipe)?;

    Ok(ActiveTracepointLivenessProbeGuard { _pipe: pipe })
}

fn active_liveness_program(
    spec: EbpfProcessTracepointSpec,
    before: &[EbpfProcessObservationTracepointFiring],
    after: &[EbpfProcessObservationTracepointFiring],
) -> EbpfProcessObservationActiveTracepointLivenessProgram {
    let before_firing_count = firing_count(before, spec).unwrap_or(0);
    let after_firing_count = firing_count(after, spec).unwrap_or(0);
    let (state, reason) = if !SAFE_ACTIVE_LIVENESS_PROBE_ROLES.contains(&spec.role) {
        (
            EbpfProcessObservationActiveTracepointLivenessState::Unsupported,
            ACTIVE_LIVENESS_UNSUPPORTED_REASON,
        )
    } else if after_firing_count > before_firing_count {
        (
            EbpfProcessObservationActiveTracepointLivenessState::Advanced,
            ACTIVE_LIVENESS_ADVANCED_REASON,
        )
    } else {
        (
            EbpfProcessObservationActiveTracepointLivenessState::NotAdvanced,
            ACTIVE_LIVENESS_NOT_ADVANCED_REASON,
        )
    };
    EbpfProcessObservationActiveTracepointLivenessProgram {
        program_name: spec.program_name,
        category: spec.category,
        tracepoint_name: spec.tracepoint_name,
        state,
        before_firing_count,
        after_firing_count,
        reason,
    }
}

fn firing_count(
    firings: &[EbpfProcessObservationTracepointFiring],
    spec: EbpfProcessTracepointSpec,
) -> Option<u64> {
    firings
        .iter()
        .find(|firing| {
            firing.program_name == spec.program_name
                && firing.category == spec.category
                && firing.tracepoint_name == spec.tracepoint_name
        })
        .map(|firing| firing.firing_count)
}

fn trigger_scalar_read_write(pipe: &ProbePipe) -> io::Result<()> {
    io::write(&pipe.writer, b"x")?;
    let mut buffer = [0_u8; 1];
    io::read(&pipe.reader, &mut buffer)?;
    Ok(())
}

fn trigger_vector_read_write(pipe: &ProbePipe) -> io::Result<()> {
    let buffers = [IoSlice::new(b"y")];
    io::writev(&pipe.writer, &buffers)?;
    let mut byte = [0_u8; 1];
    let mut buffers = [IoSliceMut::new(&mut byte)];
    io::readv(&pipe.reader, &mut buffers)?;
    Ok(())
}

struct ProbePipe {
    reader: OwnedFd,
    writer: OwnedFd,
}

impl ProbePipe {
    fn new() -> io::Result<Self> {
        let (reader, writer) = pipe::pipe()?;
        Ok(Self { reader, writer })
    }
}

pub(super) struct ActiveTracepointLivenessProbeGuard {
    _pipe: ProbePipe,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_liveness_marks_supported_tracepoint_when_counter_advances() {
        let before = vec![firing(EbpfProcessTracepointRole::WriteEnter, 10)];
        let after = vec![firing(EbpfProcessTracepointRole::WriteEnter, 11)];

        let liveness = active_tracepoint_liveness_from_firings(&before, &after);

        let write_enter = liveness_program(&liveness, EbpfProcessTracepointRole::WriteEnter);
        assert_eq!(
            write_enter.state,
            EbpfProcessObservationActiveTracepointLivenessState::Advanced
        );
        assert_eq!(write_enter.before_firing_count, 10);
        assert_eq!(write_enter.after_firing_count, 11);
    }

    #[test]
    fn active_liveness_marks_readv_tracepoint_when_counter_advances() {
        let before = vec![firing(EbpfProcessTracepointRole::ReadvEnter, 7)];
        let after = vec![firing(EbpfProcessTracepointRole::ReadvEnter, 8)];

        let liveness = active_tracepoint_liveness_from_firings(&before, &after);

        assert_eq!(
            liveness_program(&liveness, EbpfProcessTracepointRole::ReadvEnter).state,
            EbpfProcessObservationActiveTracepointLivenessState::Advanced
        );
    }

    #[test]
    fn active_liveness_marks_supported_tracepoint_when_counter_does_not_advance() {
        let before = vec![firing(EbpfProcessTracepointRole::ReadExit, 4)];
        let after = vec![firing(EbpfProcessTracepointRole::ReadExit, 4)];

        let liveness = active_tracepoint_liveness_from_firings(&before, &after);

        assert_eq!(
            liveness_program(&liveness, EbpfProcessTracepointRole::ReadExit).state,
            EbpfProcessObservationActiveTracepointLivenessState::NotAdvanced
        );
    }

    #[test]
    fn active_liveness_marks_unsupported_tracepoint_without_failure() {
        let liveness = active_tracepoint_liveness_from_firings(&[], &[]);

        let connect_enter = liveness_program(&liveness, EbpfProcessTracepointRole::ConnectEnter);
        assert_eq!(
            connect_enter.state,
            EbpfProcessObservationActiveTracepointLivenessState::Unsupported
        );
        assert_eq!(connect_enter.before_firing_count, 0);
        assert_eq!(connect_enter.after_firing_count, 0);
    }

    fn liveness_program(
        liveness: &EbpfProcessObservationActiveTracepointLiveness,
        role: EbpfProcessTracepointRole,
    ) -> &EbpfProcessObservationActiveTracepointLivenessProgram {
        let spec = role.spec();
        liveness
            .programs
            .iter()
            .find(|program| {
                program.program_name == spec.program_name
                    && program.category == spec.category
                    && program.tracepoint_name == spec.tracepoint_name
            })
            .expect("role should have an active liveness program")
    }

    fn firing(
        role: EbpfProcessTracepointRole,
        firing_count: u64,
    ) -> EbpfProcessObservationTracepointFiring {
        let spec = role.spec();
        EbpfProcessObservationTracepointFiring {
            program_name: spec.program_name,
            category: spec.category,
            tracepoint_name: spec.tracepoint_name,
            firing_count,
        }
    }
}
