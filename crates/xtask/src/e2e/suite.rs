use std::{
    collections::BTreeSet,
    process::ExitCode,
    time::{Duration, Instant},
};

use super::{
    admin_enforcement_reload::run as run_admin_enforcement_reload,
    admin_policy_reload::run as run_admin_policy_reload,
    ebpf_process_loopback::run as run_ebpf_process_loopback,
    file_exporter::run as run_file_exporter,
    libpcap_loopback::run as run_libpcap_loopback,
    plaintext_feed::run as run_plaintext_feed,
    remote_enforcement_policy::run as run_remote_enforcement_policy,
    tls_plaintext_dynamic_library::run as run_tls_plaintext_dynamic_library_loopback,
    tls_plaintext_loopback::{
        run as run_tls_plaintext_loopback, run_dynamic as run_tls_plaintext_dynamic_loopback,
        run_target_lifecycle as run_tls_plaintext_target_lifecycle_loopback,
    },
    tls_plaintext_provider_loopback::run as run_tls_plaintext_provider_loopback,
    tls_session_secret_auto_binding_loopback::run as run_tls_session_secret_auto_binding_loopback,
    transparent_tproxy_loopback::run as run_transparent_tproxy_loopback,
    webhook_exporter::run as run_webhook_exporter,
    websocket_plaintext_feed::run as run_websocket_plaintext_feed,
};

pub(crate) fn run(args: &[String]) -> ExitCode {
    let options = match SuiteOptions::parse(args) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("{error}");
            print_usage();
            return ExitCode::FAILURE;
        }
    };

    if options.help {
        print_usage();
        return ExitCode::SUCCESS;
    }

    if options.list {
        print_cases();
        return ExitCode::SUCCESS;
    }

    let selected = match select_cases(&options) {
        Ok(selected) => selected,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };

    run_cases(selected)
}

pub(crate) fn case_names() -> impl Iterator<Item = &'static str> {
    E2E_CASES.iter().map(|case| case.name)
}

pub(crate) fn run_case_by_name(name: &str, args: &[String]) -> Option<ExitCode> {
    let case = E2E_CASES.iter().find(|case| case.name == name)?;
    if !args.is_empty() {
        eprintln!("e2e case `{name}` does not accept arguments");
        return Some(ExitCode::FAILURE);
    }
    Some(run_cases(vec![case]))
}

#[derive(Debug, Clone, Default)]
struct SuiteOptions {
    help: bool,
    list: bool,
    include_privileged: bool,
    only_privileged: bool,
    selected_cases: BTreeSet<String>,
}

impl SuiteOptions {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut options = Self::default();
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "--list" => options.list = true,
                "--include-privileged" => options.include_privileged = true,
                "--only-privileged" => options.only_privileged = true,
                "--case" => {
                    index += 1;
                    let Some(name) = args.get(index) else {
                        return Err("--case requires an e2e case name".to_string());
                    };
                    options.selected_cases.insert(name.clone());
                }
                "-h" | "--help" => options.help = true,
                argument => return Err(format!("unknown e2e-suite argument `{argument}`")),
            }
            index += 1;
        }

        if options.include_privileged && options.only_privileged {
            return Err(
                "--include-privileged and --only-privileged cannot be used together".to_string(),
            );
        }
        if !options.selected_cases.is_empty()
            && (options.include_privileged || options.only_privileged)
        {
            return Err(
                "--case cannot be combined with --include-privileged or --only-privileged"
                    .to_string(),
            );
        }

        Ok(options)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum E2eRequirement {
    User,
    RootCapNetRaw,
    RootBpffs,
    RootNetAdmin,
}

impl E2eRequirement {
    fn is_privileged(self) -> bool {
        !matches!(self, Self::User)
    }

    fn label(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::RootCapNetRaw => "root/CAP_NET_RAW",
            Self::RootBpffs => "root/bpffs",
            Self::RootNetAdmin => "root/net-admin",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct E2eCase {
    name: &'static str,
    requirement: E2eRequirement,
    run: fn() -> ExitCode,
}

const E2E_CASES: &[E2eCase] = &[
    E2eCase {
        name: "e2e-plaintext-feed",
        requirement: E2eRequirement::User,
        run: run_plaintext_feed,
    },
    E2eCase {
        name: "e2e-websocket-plaintext-feed",
        requirement: E2eRequirement::User,
        run: run_websocket_plaintext_feed,
    },
    E2eCase {
        name: "e2e-webhook-exporter",
        requirement: E2eRequirement::User,
        run: run_webhook_exporter,
    },
    E2eCase {
        name: "e2e-file-exporter",
        requirement: E2eRequirement::User,
        run: run_file_exporter,
    },
    E2eCase {
        name: "e2e-remote-enforcement-policy",
        requirement: E2eRequirement::User,
        run: run_remote_enforcement_policy,
    },
    E2eCase {
        name: "e2e-libpcap-loopback",
        requirement: E2eRequirement::RootCapNetRaw,
        run: run_libpcap_loopback,
    },
    E2eCase {
        name: "e2e-admin-policy-reload",
        requirement: E2eRequirement::RootCapNetRaw,
        run: run_admin_policy_reload,
    },
    E2eCase {
        name: "e2e-admin-enforcement-reload",
        requirement: E2eRequirement::RootCapNetRaw,
        run: run_admin_enforcement_reload,
    },
    E2eCase {
        name: "e2e-ebpf-process-loopback",
        requirement: E2eRequirement::RootBpffs,
        run: run_ebpf_process_loopback,
    },
    E2eCase {
        name: "e2e-tls-plaintext-provider-loopback",
        requirement: E2eRequirement::RootBpffs,
        run: run_tls_plaintext_provider_loopback,
    },
    E2eCase {
        name: "e2e-tls-plaintext-loopback",
        requirement: E2eRequirement::RootBpffs,
        run: run_tls_plaintext_loopback,
    },
    E2eCase {
        name: "e2e-tls-plaintext-dynamic-loopback",
        requirement: E2eRequirement::RootBpffs,
        run: run_tls_plaintext_dynamic_loopback,
    },
    E2eCase {
        name: "e2e-tls-plaintext-target-lifecycle-loopback",
        requirement: E2eRequirement::RootBpffs,
        run: run_tls_plaintext_target_lifecycle_loopback,
    },
    E2eCase {
        name: "e2e-tls-plaintext-dynamic-library-loopback",
        requirement: E2eRequirement::RootBpffs,
        run: run_tls_plaintext_dynamic_library_loopback,
    },
    E2eCase {
        name: "e2e-tls-session-secret-auto-binding-loopback",
        requirement: E2eRequirement::RootCapNetRaw,
        run: run_tls_session_secret_auto_binding_loopback,
    },
    E2eCase {
        name: "e2e-transparent-tproxy-loopback",
        requirement: E2eRequirement::RootNetAdmin,
        run: run_transparent_tproxy_loopback,
    },
];

fn select_cases(options: &SuiteOptions) -> Result<Vec<&'static E2eCase>, String> {
    if !options.selected_cases.is_empty() {
        return select_named_cases(&options.selected_cases);
    }

    let selected = E2E_CASES
        .iter()
        .filter(|case| {
            if options.only_privileged {
                case.requirement.is_privileged()
            } else if options.include_privileged {
                true
            } else {
                !case.requirement.is_privileged()
            }
        })
        .collect::<Vec<_>>();
    Ok(selected)
}

fn select_named_cases(names: &BTreeSet<String>) -> Result<Vec<&'static E2eCase>, String> {
    for name in names {
        if !E2E_CASES.iter().any(|case| case.name == name) {
            return Err(format!("unknown e2e case `{name}`"));
        }
    }
    Ok(E2E_CASES
        .iter()
        .filter(|case| names.contains(case.name))
        .collect())
}

fn run_cases(cases: Vec<&'static E2eCase>) -> ExitCode {
    if cases.is_empty() {
        eprintln!("e2e suite selected no cases");
        return ExitCode::FAILURE;
    }

    println!("running {} e2e case(s)", cases.len());
    let started_at = Instant::now();
    for (index, case) in cases.iter().enumerate() {
        println!(
            "[{}/{}] {} ({})",
            index + 1,
            cases.len(),
            case.name,
            case.requirement.label()
        );
        let case_started_at = Instant::now();
        let status = (case.run)();
        if status != ExitCode::SUCCESS {
            eprintln!(
                "e2e suite failed at {} after {}",
                case.name,
                format_duration(case_started_at.elapsed())
            );
            return ExitCode::FAILURE;
        }
        println!(
            "[{}/{}] {} passed in {}",
            index + 1,
            cases.len(),
            case.name,
            format_duration(case_started_at.elapsed())
        );
    }

    println!(
        "e2e suite passed in {}",
        format_duration(started_at.elapsed())
    );
    ExitCode::SUCCESS
}

fn print_cases() {
    for case in E2E_CASES {
        println!("{}\t{}", case.name, case.requirement.label());
    }
}

fn print_usage() {
    eprintln!(
        "usage: cargo run -p xtask -- e2e-suite [--list] [--include-privileged | --only-privileged] [--case <name> ...]"
    );
}

fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    let millis = duration.subsec_millis();
    format!("{seconds}.{millis:03}s")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_selection_contains_only_user_cases() {
        let options = SuiteOptions::parse(&[]).expect("default suite options");

        let selected = select_cases(&options).expect("default suite selection");

        assert!(!selected.is_empty());
        assert!(
            selected
                .iter()
                .all(|case| case.requirement == E2eRequirement::User)
        );
    }

    #[test]
    fn include_privileged_selection_contains_all_cases() {
        let options = SuiteOptions::parse(&["--include-privileged".to_string()])
            .expect("include-privileged suite options");

        let selected = select_cases(&options).expect("include-privileged suite selection");

        assert_eq!(selected.len(), E2E_CASES.len());
    }

    #[test]
    fn only_privileged_selection_excludes_user_cases() {
        let options = SuiteOptions::parse(&["--only-privileged".to_string()])
            .expect("only-privileged suite options");

        let selected = select_cases(&options).expect("only-privileged suite selection");

        assert!(!selected.is_empty());
        assert!(selected.iter().all(|case| case.requirement.is_privileged()));
    }

    #[test]
    fn named_selection_uses_canonical_case_order() {
        let options = SuiteOptions::parse(&[
            "--case".to_string(),
            "e2e-file-exporter".to_string(),
            "--case".to_string(),
            "e2e-plaintext-feed".to_string(),
        ])
        .expect("named suite options");

        let selected = select_cases(&options).expect("named suite selection");
        let names = selected.iter().map(|case| case.name).collect::<Vec<_>>();

        assert_eq!(names, vec!["e2e-plaintext-feed", "e2e-file-exporter"]);
    }

    #[test]
    fn named_selection_rejects_unknown_cases() {
        let options = SuiteOptions::parse(&["--case".to_string(), "missing".to_string()])
            .expect("unknown case option parsing should succeed");

        let error = select_cases(&options).expect_err("unknown case must fail selection");

        assert!(error.contains("unknown e2e case `missing`"));
    }

    #[test]
    fn rejects_conflicting_privileged_flags() {
        let error = SuiteOptions::parse(&[
            "--include-privileged".to_string(),
            "--only-privileged".to_string(),
        ])
        .expect_err("conflicting privilege flags must fail");

        assert!(error.contains("cannot be used together"));
    }

    #[test]
    fn rejects_named_selection_with_privilege_filter() {
        let error = SuiteOptions::parse(&[
            "--only-privileged".to_string(),
            "--case".to_string(),
            "e2e-plaintext-feed".to_string(),
        ])
        .expect_err("case and privilege filter must fail");

        assert!(error.contains("--case cannot be combined"));
    }
}
