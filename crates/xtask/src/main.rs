use std::{
    env,
    ffi::OsStr,
    process::{Command, ExitCode},
};

mod ebpf;

fn main() -> ExitCode {
    match env::args().nth(1).as_deref() {
        Some("check") => run_check(),
        Some("check-host") => run_host_check(),
        Some("check-all") => run_check_all(),
        Some("check-ebpf") => ebpf::run_check(),
        Some("check-privileged-ebpf") => ebpf::run_privileged_smoke(),
        Some("ebpf-build") => ebpf::run_build(),
        _ => {
            eprintln!(
                "usage: cargo run -p xtask -- <check|check-host|check-ebpf|check-privileged-ebpf|check-all|ebpf-build>"
            );
            ExitCode::FAILURE
        }
    }
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
