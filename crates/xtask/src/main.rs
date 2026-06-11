use std::{
    env,
    ffi::OsStr,
    process::{Command, ExitCode},
};

fn main() -> ExitCode {
    match env::args().nth(1).as_deref() {
        Some("check") => run_check(),
        _ => {
            eprintln!("usage: cargo run -p xtask -- check");
            ExitCode::FAILURE
        }
    }
}

fn run_check() -> ExitCode {
    for command in [
        CargoCommand::new(&["fmt", "--check"]),
        CargoCommand::new(&["check"]),
        CargoCommand::new(&["test"]),
        CargoCommand::new(&["clippy", "--all-targets", "--all-features"]),
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
