use std::{
    env,
    ffi::OsStr,
    process::{Command, ExitCode},
};

use crate::{e2e, ebpf};

pub(crate) fn run() -> ExitCode {
    let mut args = env::args().skip(1);
    let Some(name) = args.next() else {
        print_usage();
        return ExitCode::FAILURE;
    };
    let command_args = args.collect::<Vec<_>>();
    if let Some(command) = COMMANDS.iter().find(|command| command.name == name) {
        return command.run(&command_args);
    }
    if let Some(status) = e2e::run_case_by_name(&name, &command_args) {
        return status;
    }

    print_usage();
    ExitCode::FAILURE
}

struct XtaskCommand {
    name: &'static str,
    runner: XtaskRunner,
}

impl XtaskCommand {
    const fn new(name: &'static str, run: fn() -> ExitCode) -> Self {
        Self {
            name,
            runner: XtaskRunner::NoArgs(run),
        }
    }

    const fn with_args(name: &'static str, run: fn(&[String]) -> ExitCode) -> Self {
        Self {
            name,
            runner: XtaskRunner::WithArgs(run),
        }
    }

    fn run(&self, args: &[String]) -> ExitCode {
        self.runner.run(self.name, args)
    }
}

enum XtaskRunner {
    NoArgs(fn() -> ExitCode),
    WithArgs(fn(&[String]) -> ExitCode),
}

impl XtaskRunner {
    fn run(&self, name: &str, args: &[String]) -> ExitCode {
        match self {
            Self::NoArgs(run) => {
                if !args.is_empty() {
                    eprintln!("xtask command `{name}` does not accept arguments");
                    return ExitCode::FAILURE;
                }
                run()
            }
            Self::WithArgs(run) => run(args),
        }
    }
}

const COMMANDS: &[XtaskCommand] = &[
    XtaskCommand::new("check", run_check),
    XtaskCommand::new("check-host", run_host_check),
    XtaskCommand::new("check-all", run_check_all),
    XtaskCommand::new("check-ebpf", ebpf::run_check),
    XtaskCommand::new("ebpf-build", ebpf::run_build),
    XtaskCommand::new("validate-local", e2e::run_local_validation),
    XtaskCommand::with_args("e2e-suite", e2e::run_suite),
];

fn print_usage() {
    let commands = COMMANDS
        .iter()
        .map(|command| command.name)
        .chain(e2e::case_names())
        .collect::<Vec<_>>()
        .join("|");
    eprintln!("usage: cargo run -p xtask -- <{commands}>");
    eprintln!("       cargo run -p xtask -- e2e-suite --help");
}

fn run_check() -> ExitCode {
    run_host_check()
}

fn run_check_all() -> ExitCode {
    if run_host_check() != ExitCode::SUCCESS {
        return ExitCode::FAILURE;
    }
    ebpf::run_check()
}

fn run_host_check() -> ExitCode {
    for command in [
        CargoCommand::new(&["fmt", "--check"]),
        CargoCommand::new(&["check", "--workspace", "--locked"]),
        CargoCommand::new(&["test", "--workspace", "--locked"]),
        CargoCommand::new(&[
            "clippy",
            "--workspace",
            "--all-targets",
            "--locked",
            "--",
            "-D",
            "warnings",
        ]),
    ] {
        if !command.run() {
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}

struct CargoCommand {
    args: &'static [&'static str],
}

impl CargoCommand {
    const fn new(args: &'static [&'static str]) -> Self {
        Self { args }
    }

    fn run(&self) -> bool {
        let mut command = Command::new("cargo");
        command.args(self.args.iter().map(OsStr::new));
        match command.status() {
            Ok(status) => status.success(),
            Err(error) => {
                eprintln!("failed to run cargo {}: {error}", self.args.join(" "));
                false
            }
        }
    }
}
