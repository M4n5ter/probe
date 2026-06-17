use std::process::ExitCode;

mod command;
mod e2e;
mod ebpf;

fn main() -> ExitCode {
    command::run()
}
