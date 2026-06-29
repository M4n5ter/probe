use std::process::ExitCode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum E2eOutcome {
    Passed,
    Skipped(String),
    Failed,
}

impl E2eOutcome {
    pub(crate) fn from_exit_code(status: ExitCode) -> Self {
        if status == ExitCode::SUCCESS {
            Self::Passed
        } else {
            Self::Failed
        }
    }
}
