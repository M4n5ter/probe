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
    tls_material_auto_binding_loopback::{
        run as run_tls_session_secret_auto_binding_loopback,
        run_key_log as run_tls_key_log_auto_binding_loopback,
        run_key_log_refresh as run_tls_key_log_material_refresh_auto_binding_loopback,
        run_refresh as run_tls_session_secret_material_refresh_auto_binding_loopback,
    },
    tls_plaintext_dynamic_library::run as run_tls_plaintext_dynamic_library_loopback,
    tls_plaintext_loopback::{
        run as run_tls_plaintext_loopback, run_dynamic as run_tls_plaintext_dynamic_loopback,
        run_target_lifecycle as run_tls_plaintext_target_lifecycle_loopback,
    },
    tls_plaintext_provider_loopback::run as run_tls_plaintext_provider_loopback,
    transparent_tproxy_loopback::run as run_transparent_tproxy_loopback,
    webhook_exporter::run as run_webhook_exporter,
    websocket_plaintext_feed::run as run_websocket_plaintext_feed,
};

pub(crate) fn run(args: &[String]) -> ExitCode {
    let action = match SuiteAction::parse(args) {
        Ok(action) => action,
        Err(error) => {
            eprintln!("{error}");
            print_usage();
            return ExitCode::FAILURE;
        }
    };

    match action {
        SuiteAction::Help => {
            print_usage();
            ExitCode::SUCCESS
        }
        SuiteAction::ListCases => {
            print_cases();
            ExitCode::SUCCESS
        }
        SuiteAction::ListProfiles => {
            print_profiles();
            ExitCode::SUCCESS
        }
        SuiteAction::Run(selection) => {
            let selected = match select_cases(&selection) {
                Ok(selected) => selected,
                Err(error) => {
                    eprintln!("{error}");
                    return ExitCode::FAILURE;
                }
            };

            run_cases(selected)
        }
    }
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum SuiteAction {
    Help,
    ListCases,
    ListProfiles,
    Run(SuiteSelection),
}

impl SuiteAction {
    fn parse(args: &[String]) -> Result<Self, String> {
        match args.first().map(String::as_str) {
            None => Ok(Self::Run(SuiteSelection::Default)),
            Some("-h" | "--help") => standalone_action(args, "-h/--help", Self::Help),
            Some("--list") => standalone_action(args, "--list", Self::ListCases),
            Some("--list-profiles") => {
                standalone_action(args, "--list-profiles", Self::ListProfiles)
            }
            Some(_) => SuiteSelection::parse(args).map(Self::Run),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SuiteSelection {
    Default,
    IncludePrivileged,
    OnlyPrivileged,
    Cases(BTreeSet<String>),
    Profile(E2eProfileId),
}

impl SuiteSelection {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut selection = Self::Default;
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "--include-privileged" => {
                    selection = match selection {
                        Self::Default => Self::IncludePrivileged,
                        _ => {
                            return Err(
                                "--include-privileged cannot be combined with --profile, --case, or --only-privileged"
                                    .to_string(),
                            );
                        }
                    };
                }
                "--only-privileged" => {
                    selection = match selection {
                        Self::Default => Self::OnlyPrivileged,
                        _ => {
                            return Err(
                                "--only-privileged cannot be combined with --profile, --case, or --include-privileged"
                                    .to_string(),
                            );
                        }
                    };
                }
                "--profile" => {
                    let name = option_value(args, index, "--profile", "an e2e profile name")?;
                    selection = match selection {
                        Self::Default => Self::Profile(profile_id_by_name(name)?),
                        _ => {
                            return Err(
                                "--profile cannot be combined with --case, --include-privileged, or --only-privileged"
                                    .to_string(),
                            );
                        }
                    };
                    index += 1;
                }
                "--case" => {
                    let name = option_value(args, index, "--case", "an e2e case name")?;
                    match &mut selection {
                        Self::Default => {
                            let mut names = BTreeSet::new();
                            names.insert(name.to_string());
                            selection = Self::Cases(names);
                        }
                        Self::Cases(names) => {
                            names.insert(name.to_string());
                        }
                        _ => {
                            return Err(
                                "--case cannot be combined with --profile, --include-privileged, or --only-privileged"
                                    .to_string(),
                            );
                        }
                    }
                    index += 1;
                }
                "-h" | "--help" => {
                    return Err(
                        "-h/--help cannot be combined with other e2e-suite arguments".to_string(),
                    );
                }
                "--list" => {
                    return Err(
                        "--list cannot be combined with other e2e-suite arguments".to_string()
                    );
                }
                "--list-profiles" => {
                    return Err(
                        "--list-profiles cannot be combined with other e2e-suite arguments"
                            .to_string(),
                    );
                }
                argument => return Err(format!("unknown e2e-suite argument `{argument}`")),
            }
            index += 1;
        }

        Ok(selection)
    }
}

fn option_value<'a>(
    args: &'a [String],
    flag_index: usize,
    flag: &str,
    value_kind: &str,
) -> Result<&'a str, String> {
    let Some(value) = args.get(flag_index + 1) else {
        return Err(format!("{flag} requires {value_kind}"));
    };
    if value.starts_with('-') {
        return Err(format!("{flag} requires {value_kind}"));
    }
    Ok(value)
}

fn standalone_action(
    args: &[String],
    name: &str,
    action: SuiteAction,
) -> Result<SuiteAction, String> {
    if args.len() == 1 {
        Ok(action)
    } else {
        Err(format!(
            "{name} cannot be combined with other e2e-suite arguments"
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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

#[derive(Debug, Clone, Copy)]
struct E2eProfile {
    id: E2eProfileId,
    name: &'static str,
    description: &'static str,
    cases: &'static [&'static str],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum E2eProfileId {
    Baseline,
    LiveCore,
    ProcessEbpf,
    TlsPlaintext,
    HostRules,
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
        name: "e2e-tls-session-secret-material-refresh-auto-binding-loopback",
        requirement: E2eRequirement::RootCapNetRaw,
        run: run_tls_session_secret_material_refresh_auto_binding_loopback,
    },
    E2eCase {
        name: "e2e-tls-keylog-auto-binding-loopback",
        requirement: E2eRequirement::RootCapNetRaw,
        run: run_tls_key_log_auto_binding_loopback,
    },
    E2eCase {
        name: "e2e-tls-keylog-material-refresh-auto-binding-loopback",
        requirement: E2eRequirement::RootCapNetRaw,
        run: run_tls_key_log_material_refresh_auto_binding_loopback,
    },
    E2eCase {
        name: "e2e-transparent-tproxy-loopback",
        requirement: E2eRequirement::RootNetAdmin,
        run: run_transparent_tproxy_loopback,
    },
];

const E2E_PROFILES: &[E2eProfile] = &[
    E2eProfile {
        id: E2eProfileId::Baseline,
        name: "baseline",
        description: "non-privileged replay/plaintext/export/policy regression suite",
        cases: &[
            "e2e-plaintext-feed",
            "e2e-websocket-plaintext-feed",
            "e2e-webhook-exporter",
            "e2e-file-exporter",
            "e2e-remote-enforcement-policy",
        ],
    },
    E2eProfile {
        id: E2eProfileId::LiveCore,
        name: "live-core",
        description: "root/CAP_NET_RAW live libpcap, admin reload, and TLS material suite",
        cases: &[
            "e2e-libpcap-loopback",
            "e2e-admin-policy-reload",
            "e2e-admin-enforcement-reload",
            "e2e-tls-session-secret-auto-binding-loopback",
            "e2e-tls-session-secret-material-refresh-auto-binding-loopback",
            "e2e-tls-keylog-auto-binding-loopback",
            "e2e-tls-keylog-material-refresh-auto-binding-loopback",
        ],
    },
    E2eProfile {
        id: E2eProfileId::ProcessEbpf,
        name: "process-ebpf",
        description: "root/bpffs eBPF process observation suite",
        cases: &["e2e-ebpf-process-loopback"],
    },
    E2eProfile {
        id: E2eProfileId::TlsPlaintext,
        name: "tls-plaintext",
        description: "root/bpffs libssl plaintext instrumentation lifecycle suite",
        cases: &[
            "e2e-tls-plaintext-provider-loopback",
            "e2e-tls-plaintext-loopback",
            "e2e-tls-plaintext-dynamic-loopback",
            "e2e-tls-plaintext-target-lifecycle-loopback",
            "e2e-tls-plaintext-dynamic-library-loopback",
        ],
    },
    E2eProfile {
        id: E2eProfileId::HostRules,
        name: "host-rules",
        description: "root/net-admin transparent interception host rule suite",
        cases: &["e2e-transparent-tproxy-loopback"],
    },
];

fn select_cases(selection: &SuiteSelection) -> Result<Vec<&'static E2eCase>, String> {
    match selection {
        SuiteSelection::Default => select_profile_cases(E2eProfileId::Baseline),
        SuiteSelection::IncludePrivileged => Ok(E2E_CASES.iter().collect()),
        SuiteSelection::OnlyPrivileged => Ok(E2E_CASES
            .iter()
            .filter(|case| case.requirement.is_privileged())
            .collect()),
        SuiteSelection::Cases(names) => {
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
        SuiteSelection::Profile(profile_id) => select_profile_cases(*profile_id),
    }
}

fn case_by_name(name: &str) -> Option<&'static E2eCase> {
    E2E_CASES.iter().find(|case| case.name == name)
}

fn profile_id_by_name(name: &str) -> Result<E2eProfileId, String> {
    E2E_PROFILES
        .iter()
        .find(|profile| profile.name == name)
        .map(|profile| profile.id)
        .ok_or_else(|| format!("unknown e2e profile `{name}`"))
}

fn select_profile_cases(profile_id: E2eProfileId) -> Result<Vec<&'static E2eCase>, String> {
    let Some(profile) = E2E_PROFILES.iter().find(|profile| profile.id == profile_id) else {
        return Err(format!("unregistered e2e profile `{profile_id:?}`"));
    };
    let selected = profile
        .cases
        .iter()
        .map(|name| {
            case_by_name(name).ok_or_else(|| {
                format!(
                    "e2e profile `{}` references unknown case `{name}`",
                    profile.name
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if selected.is_empty() {
        return Err(format!("e2e profile `{}` selected no cases", profile.name));
    }
    Ok(selected)
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

fn print_profiles() {
    for listing in profile_listings().expect("profile registry is valid") {
        println!(
            "{}\t{}\t{}\t{}",
            listing.name,
            listing.requirements,
            listing.description,
            listing.case_names.join(",")
        );
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct E2eProfileListing {
    name: &'static str,
    requirements: String,
    description: &'static str,
    case_names: Vec<&'static str>,
}

fn profile_listings() -> Result<Vec<E2eProfileListing>, String> {
    E2E_PROFILES
        .iter()
        .map(|profile| {
            let cases = select_profile_cases(profile.id)?;
            Ok(E2eProfileListing {
                name: profile.name,
                requirements: requirement_summary(&cases),
                description: profile.description,
                case_names: cases.iter().map(|case| case.name).collect(),
            })
        })
        .collect()
}

fn requirement_summary(cases: &[&E2eCase]) -> String {
    let requirements = cases
        .iter()
        .map(|case| case.requirement)
        .collect::<BTreeSet<_>>();
    requirements
        .iter()
        .map(|requirement| requirement.label())
        .collect::<Vec<_>>()
        .join(",")
}

fn print_usage() {
    eprintln!(
        "usage: cargo run -p xtask -- e2e-suite [--list | --list-profiles | --profile <name> | --include-privileged | --only-privileged | --case <name> ...]"
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

    fn parse_selection(args: &[&str]) -> SuiteSelection {
        let args = args
            .iter()
            .map(|arg| (*arg).to_string())
            .collect::<Vec<_>>();
        match SuiteAction::parse(&args).expect("suite action should parse") {
            SuiteAction::Run(selection) => selection,
            action => panic!("expected run action, got {action:?}"),
        }
    }

    fn parse_error(args: &[&str]) -> String {
        let args = args
            .iter()
            .map(|arg| (*arg).to_string())
            .collect::<Vec<_>>();
        SuiteAction::parse(&args).expect_err("suite action should fail")
    }

    fn selected_names(selection: &SuiteSelection) -> Vec<&'static str> {
        select_cases(selection)
            .expect("suite selection should resolve")
            .iter()
            .map(|case| case.name)
            .collect()
    }

    struct ExpectedProfile {
        name: &'static str,
        requirements: &'static str,
        description: &'static str,
        cases: &'static [&'static str],
    }

    const EXPECTED_PROFILES: &[ExpectedProfile] = &[
        ExpectedProfile {
            name: "baseline",
            requirements: "user",
            description: "non-privileged replay/plaintext/export/policy regression suite",
            cases: &[
                "e2e-plaintext-feed",
                "e2e-websocket-plaintext-feed",
                "e2e-webhook-exporter",
                "e2e-file-exporter",
                "e2e-remote-enforcement-policy",
            ],
        },
        ExpectedProfile {
            name: "live-core",
            requirements: "root/CAP_NET_RAW",
            description: "root/CAP_NET_RAW live libpcap, admin reload, and TLS material suite",
            cases: &[
                "e2e-libpcap-loopback",
                "e2e-admin-policy-reload",
                "e2e-admin-enforcement-reload",
                "e2e-tls-session-secret-auto-binding-loopback",
                "e2e-tls-session-secret-material-refresh-auto-binding-loopback",
                "e2e-tls-keylog-auto-binding-loopback",
                "e2e-tls-keylog-material-refresh-auto-binding-loopback",
            ],
        },
        ExpectedProfile {
            name: "process-ebpf",
            requirements: "root/bpffs",
            description: "root/bpffs eBPF process observation suite",
            cases: &["e2e-ebpf-process-loopback"],
        },
        ExpectedProfile {
            name: "tls-plaintext",
            requirements: "root/bpffs",
            description: "root/bpffs libssl plaintext instrumentation lifecycle suite",
            cases: &[
                "e2e-tls-plaintext-provider-loopback",
                "e2e-tls-plaintext-loopback",
                "e2e-tls-plaintext-dynamic-loopback",
                "e2e-tls-plaintext-target-lifecycle-loopback",
                "e2e-tls-plaintext-dynamic-library-loopback",
            ],
        },
        ExpectedProfile {
            name: "host-rules",
            requirements: "root/net-admin",
            description: "root/net-admin transparent interception host rule suite",
            cases: &["e2e-transparent-tproxy-loopback"],
        },
    ];

    #[test]
    fn default_selection_contains_only_user_cases() {
        let selection = parse_selection(&[]);

        let selected = select_cases(&selection).expect("default suite selection");

        assert!(!selected.is_empty());
        assert!(
            selected
                .iter()
                .all(|case| case.requirement == E2eRequirement::User)
        );
    }

    #[test]
    fn include_privileged_selection_contains_all_cases() {
        let selection = parse_selection(&["--include-privileged"]);

        let selected = select_cases(&selection).expect("include-privileged suite selection");

        assert_eq!(selected.len(), E2E_CASES.len());
    }

    #[test]
    fn only_privileged_selection_excludes_user_cases() {
        let selection = parse_selection(&["--only-privileged"]);

        let selected = select_cases(&selection).expect("only-privileged suite selection");

        assert!(!selected.is_empty());
        assert!(selected.iter().all(|case| case.requirement.is_privileged()));
    }

    #[test]
    fn named_selection_uses_canonical_case_order() {
        let selection = parse_selection(&[
            "--case",
            "e2e-file-exporter",
            "--case",
            "e2e-plaintext-feed",
        ]);

        let selected = select_cases(&selection).expect("named suite selection");
        let names = selected.iter().map(|case| case.name).collect::<Vec<_>>();

        assert_eq!(names, vec!["e2e-plaintext-feed", "e2e-file-exporter"]);
    }

    #[test]
    fn named_selection_rejects_unknown_cases() {
        let selection = parse_selection(&["--case", "missing"]);

        let error = select_cases(&selection).expect_err("unknown case must fail selection");

        assert!(error.contains("unknown e2e case `missing`"));
    }

    #[test]
    fn stable_profiles_select_expected_cases() {
        for profile in EXPECTED_PROFILES {
            let profile_id = profile_id_by_name(profile.name).expect("known profile");

            assert_eq!(
                selected_names(&SuiteSelection::Profile(profile_id)),
                profile.cases.to_vec(),
                "{}",
                profile.name
            );
        }
    }

    #[test]
    fn profile_selection_rejects_unknown_profiles() {
        let error = parse_error(&["--profile", "missing"]);

        assert!(error.contains("unknown e2e profile `missing`"));
    }

    #[test]
    fn baseline_profile_matches_default_selection() {
        let baseline = parse_selection(&["--profile", "baseline"]);

        assert_eq!(
            selected_names(&baseline),
            selected_names(&SuiteSelection::Default)
        );
    }

    #[test]
    fn registry_invariants_hold() {
        let mut case_names = BTreeSet::new();
        for case in E2E_CASES {
            assert!(case_names.insert(case.name), "duplicate case {}", case.name);
        }

        let mut profile_names = BTreeSet::new();
        let mut profile_ids = BTreeSet::new();
        for profile in E2E_PROFILES {
            assert!(
                profile_names.insert(profile.name),
                "duplicate profile name {}",
                profile.name
            );
            assert!(
                profile_ids.insert(profile.id),
                "duplicate profile id {:?}",
                profile.id
            );
            assert!(!profile.cases.is_empty(), "empty profile {}", profile.name);

            let mut profile_case_names = BTreeSet::new();
            for case_name in profile.cases {
                assert!(
                    profile_case_names.insert(case_name),
                    "duplicate case {case_name} in profile {}",
                    profile.name
                );
                assert!(
                    case_names.contains(case_name),
                    "profile {} references unknown case {case_name}",
                    profile.name
                );
            }
        }

        let covered_case_names = E2E_PROFILES
            .iter()
            .flat_map(|profile| profile.cases.iter().copied())
            .collect::<BTreeSet<_>>();
        for case in E2E_CASES {
            assert!(
                covered_case_names.contains(case.name),
                "registered case {} is not covered by any stable profile",
                case.name
            );
        }
    }

    #[test]
    fn profile_listings_expose_public_contract() {
        let listings = profile_listings().expect("profile listing rows");
        let expected = EXPECTED_PROFILES
            .iter()
            .map(|profile| E2eProfileListing {
                name: profile.name,
                requirements: profile.requirements.to_string(),
                description: profile.description,
                case_names: profile.cases.to_vec(),
            })
            .collect::<Vec<_>>();

        assert_eq!(listings, expected);
    }

    #[test]
    fn rejects_conflicting_privileged_flags() {
        let error = parse_error(&["--include-privileged", "--only-privileged"]);

        assert!(error.contains("--only-privileged cannot be combined"));
    }

    #[test]
    fn rejects_named_selection_with_privilege_filter() {
        let error = parse_error(&["--only-privileged", "--case", "e2e-plaintext-feed"]);

        assert!(error.contains("--case cannot be combined"));
    }

    #[test]
    fn rejects_profile_with_named_selection() {
        let error = parse_error(&["--profile", "baseline", "--case", "e2e-plaintext-feed"]);

        assert!(error.contains("--case cannot be combined"));
    }

    #[test]
    fn rejects_named_selection_with_unknown_profile_as_conflict() {
        let error = parse_error(&["--case", "e2e-plaintext-feed", "--profile", "missing"]);

        assert!(error.contains("--profile cannot be combined"));
    }

    #[test]
    fn rejects_profile_with_privilege_filter() {
        let error = parse_error(&["--profile", "baseline", "--include-privileged"]);

        assert!(error.contains("--include-privileged cannot be combined"));
    }

    #[test]
    fn rejects_duplicate_profile() {
        let error = parse_error(&["--profile", "baseline", "--profile", "live-core"]);

        assert!(error.contains("--profile cannot be combined"));
    }

    #[test]
    fn rejects_missing_case_value_before_next_flag() {
        let error = parse_error(&["--case", "--profile"]);

        assert!(error.contains("--case requires an e2e case name"));
    }

    #[test]
    fn rejects_missing_profile_value_before_next_flag() {
        let error = parse_error(&["--profile", "--case"]);

        assert!(error.contains("--profile requires an e2e profile name"));
    }

    #[test]
    fn rejects_missing_case_value_before_standalone_flag() {
        let error = parse_error(&["--case", "--list"]);

        assert!(error.contains("--case requires an e2e case name"));
    }

    #[test]
    fn rejects_missing_profile_value_before_standalone_flag() {
        let error = parse_error(&["--profile", "--list-profiles"]);

        assert!(error.contains("--profile requires an e2e profile name"));
    }

    #[test]
    fn rejects_list_action_with_run_selection() {
        let error = parse_error(&["--list", "--profile", "missing"]);

        assert!(error.contains("--list cannot be combined"));
    }

    #[test]
    fn parses_list_profiles_as_action() {
        let args = ["--list-profiles".to_string()];

        assert_eq!(
            SuiteAction::parse(&args).expect("list profile action"),
            SuiteAction::ListProfiles
        );
    }
}
