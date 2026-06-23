use std::{
    collections::BTreeSet,
    process::ExitCode,
    time::{Duration, Instant},
};

mod registry;

use registry::{E2eCase, SuiteSelection};

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
            let selected = match registry::select_cases(&selection) {
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
    registry::case_names()
}

pub(crate) fn run_case_by_name(name: &str, args: &[String]) -> Option<ExitCode> {
    let case = registry::case_by_name(name)?;
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
                        Self::Default => Self::Profile(registry::profile_id_by_name(name)?),
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
    for case in registry::cases() {
        println!("{}\t{}", case.name, case.requirement.label());
    }
}

fn print_profiles() {
    for listing in registry::profile_listings().expect("profile registry is valid") {
        println!(
            "{}\t{}\t{}\t{}",
            listing.name,
            listing.requirements,
            listing.description,
            listing.case_names.join(",")
        );
    }
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
        registry::select_cases(selection)
            .expect("suite selection should resolve")
            .iter()
            .map(|case| case.name)
            .collect()
    }

    #[test]
    fn default_selection_contains_only_user_cases() {
        let selection = parse_selection(&[]);

        let selected = registry::select_cases(&selection).expect("default suite selection");

        assert!(!selected.is_empty());
        assert!(
            selected
                .iter()
                .all(|case| case.requirement == registry::E2eRequirement::User)
        );
    }

    #[test]
    fn include_privileged_selection_matches_product_profile() {
        let include_privileged = parse_selection(&["--include-privileged"]);
        let product = parse_selection(&["--profile", "product"]);

        assert_eq!(
            selected_names(&include_privileged),
            selected_names(&product)
        );
    }

    #[test]
    fn only_privileged_selection_excludes_user_cases() {
        let selection = parse_selection(&["--only-privileged"]);

        let selected = registry::select_cases(&selection).expect("only-privileged suite selection");

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

        let selected = registry::select_cases(&selection).expect("named suite selection");
        let names = selected.iter().map(|case| case.name).collect::<Vec<_>>();

        assert_eq!(names, vec!["e2e-plaintext-feed", "e2e-file-exporter"]);
    }

    #[test]
    fn named_selection_rejects_unknown_cases() {
        let selection = parse_selection(&["--case", "missing"]);

        let error =
            registry::select_cases(&selection).expect_err("unknown case must fail selection");

        assert!(error.contains("unknown e2e case `missing`"));
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
