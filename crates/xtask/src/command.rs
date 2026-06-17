use std::{
    env,
    ffi::OsStr,
    process::{Command, ExitCode},
};

use crate::{e2e, ebpf};

pub(crate) fn run() -> ExitCode {
    let Some(name) = env::args().nth(1) else {
        print_usage();
        return ExitCode::FAILURE;
    };
    if let Some(command) = COMMANDS.iter().find(|command| command.name == name) {
        return (command.run)();
    }

    print_usage();
    ExitCode::FAILURE
}

struct XtaskCommand {
    name: &'static str,
    run: fn() -> ExitCode,
}

const COMMANDS: &[XtaskCommand] = &[
    XtaskCommand {
        name: "check",
        run: run_check,
    },
    XtaskCommand {
        name: "check-host",
        run: run_host_check,
    },
    XtaskCommand {
        name: "check-all",
        run: run_check_all,
    },
    XtaskCommand {
        name: "check-ebpf",
        run: ebpf::run_check,
    },
    XtaskCommand {
        name: "ebpf-build",
        run: ebpf::run_build,
    },
    XtaskCommand {
        name: "e2e-admin-policy-reload",
        run: e2e::run_admin_policy_reload,
    },
    XtaskCommand {
        name: "e2e-ebpf-process-loopback",
        run: e2e::run_ebpf_process_loopback,
    },
    XtaskCommand {
        name: "e2e-file-exporter",
        run: e2e::run_file_exporter,
    },
    XtaskCommand {
        name: "e2e-libpcap-loopback",
        run: e2e::run_libpcap_loopback,
    },
    XtaskCommand {
        name: "e2e-plaintext-feed",
        run: e2e::run_plaintext_feed,
    },
    XtaskCommand {
        name: "e2e-remote-enforcement-policy",
        run: e2e::run_remote_enforcement_policy,
    },
    XtaskCommand {
        name: "e2e-tls-plaintext-dynamic-loopback",
        run: e2e::run_tls_plaintext_dynamic_loopback,
    },
    XtaskCommand {
        name: "e2e-tls-plaintext-loopback",
        run: e2e::run_tls_plaintext_loopback,
    },
    XtaskCommand {
        name: "e2e-tls-plaintext-provider-loopback",
        run: e2e::run_tls_plaintext_provider_loopback,
    },
    XtaskCommand {
        name: "e2e-transparent-tproxy-loopback",
        run: e2e::run_transparent_tproxy_loopback,
    },
    XtaskCommand {
        name: "e2e-webhook-exporter",
        run: e2e::run_webhook_exporter,
    },
    XtaskCommand {
        name: "e2e-websocket-plaintext-feed",
        run: e2e::run_websocket_plaintext_feed,
    },
];

fn print_usage() {
    let commands = COMMANDS
        .iter()
        .map(|command| command.name)
        .collect::<Vec<_>>()
        .join("|");
    eprintln!("usage: cargo run -p xtask -- <{commands}>");
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
