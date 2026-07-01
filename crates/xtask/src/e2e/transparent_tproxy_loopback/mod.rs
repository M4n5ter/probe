use std::process::ExitCode;

mod case;
mod flow_classified;
mod support;

pub(crate) fn run() -> ExitCode {
    case::run()
}

pub(crate) fn run_process_scoped() -> ExitCode {
    case::run_process_scoped()
}

pub(crate) fn run_process_derived() -> ExitCode {
    case::run_process_derived()
}

pub(crate) fn run_flow_classified() -> ExitCode {
    flow_classified::run()
}
