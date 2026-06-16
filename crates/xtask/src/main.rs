use std::{
    env,
    ffi::OsStr,
    process::{Command, ExitCode},
};

mod e2e;
mod ebpf;

fn main() -> ExitCode {
    match env::args().nth(1).as_deref() {
        Some("check") => run_check(),
        Some("check-host") => run_host_check(),
        Some("check-all") => run_check_all(),
        Some("check-ebpf") => ebpf::run_check(),
        Some("ebpf-build") => ebpf::run_build(),
        Some("e2e-ebpf-process-loopback") => e2e::run_ebpf_process_loopback(),
        Some("e2e-libpcap-loopback") => e2e::run_libpcap_loopback(),
        Some("e2e-plaintext-feed") => e2e::run_plaintext_feed(),
        Some("e2e-tls-plaintext-loopback") => e2e::run_tls_plaintext_loopback(),
        Some("e2e-tls-plaintext-provider-loopback") => e2e::run_tls_plaintext_provider_loopback(),
        _ => {
            eprintln!(
                "usage: cargo run -p xtask -- <check|check-host|check-ebpf|check-all|ebpf-build|e2e-plaintext-feed|e2e-libpcap-loopback|e2e-ebpf-process-loopback|e2e-tls-plaintext-provider-loopback|e2e-tls-plaintext-loopback>"
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
