use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::ExitCode,
    time::{Duration, Instant},
};

mod registry;
mod report;

use super::E2eOutcome;
use registry::{E2eCase, SuiteSelection};
use report::{E2eCaseRunReport, E2eSuiteRunReport, write_report};

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
        SuiteAction::InventoryJson => print_inventory_json(),
        SuiteAction::Run(request) => {
            let selected = match registry::select_cases(&request.selection) {
                Ok(selected) => selected,
                Err(error) => {
                    eprintln!("{error}");
                    return ExitCode::FAILURE;
                }
            };

            run_cases(selected, &request)
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
    Some(run_cases(vec![case], &SuiteRunRequest::default()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SuiteAction {
    Help,
    ListCases,
    ListProfiles,
    InventoryJson,
    Run(SuiteRunRequest),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SuiteRunRequest {
    selection: SuiteSelection,
    report_json: Option<PathBuf>,
}

impl SuiteRunRequest {
    fn default() -> Self {
        Self {
            selection: SuiteSelection::Default,
            report_json: None,
        }
    }
}

impl SuiteAction {
    fn parse(args: &[String]) -> Result<Self, String> {
        match args.first().map(String::as_str) {
            None => Ok(Self::Run(SuiteRunRequest::default())),
            Some("-h" | "--help") => standalone_action(args, "-h/--help", Self::Help),
            Some("--list") => standalone_action(args, "--list", Self::ListCases),
            Some("--list-profiles") => {
                standalone_action(args, "--list-profiles", Self::ListProfiles)
            }
            Some("--inventory-json") => {
                standalone_action(args, "--inventory-json", Self::InventoryJson)
            }
            Some(_) => SuiteRunRequest::parse(args).map(Self::Run),
        }
    }
}

impl SuiteRunRequest {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut request = Self::default();
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "--include-privileged" => {
                    request.selection = match request.selection {
                        SuiteSelection::Default => SuiteSelection::IncludePrivileged,
                        _ => {
                            return Err(
                                "--include-privileged cannot be combined with --profile, --case, or --only-privileged"
                                    .to_string(),
                            );
                        }
                    };
                }
                "--only-privileged" => {
                    request.selection = match request.selection {
                        SuiteSelection::Default => SuiteSelection::OnlyPrivileged,
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
                    request.selection = match request.selection {
                        SuiteSelection::Default => {
                            SuiteSelection::Profile(registry::profile_id_by_name(name)?)
                        }
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
                    match &mut request.selection {
                        SuiteSelection::Default => {
                            let mut names = BTreeSet::new();
                            names.insert(name.to_string());
                            request.selection = SuiteSelection::Cases(names);
                        }
                        SuiteSelection::Cases(names) => {
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
                "--report-json" => {
                    let path = option_value(args, index, "--report-json", "a report path")?;
                    if request.report_json.is_some() {
                        return Err("--report-json cannot be specified more than once".to_string());
                    }
                    request.report_json = Some(PathBuf::from(path));
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
                "--inventory-json" => {
                    return Err(
                        "--inventory-json cannot be combined with other e2e-suite arguments"
                            .to_string(),
                    );
                }
                argument => return Err(format!("unknown e2e-suite argument `{argument}`")),
            }
            index += 1;
        }

        Ok(request)
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

fn run_cases(cases: Vec<&'static E2eCase>, request: &SuiteRunRequest) -> ExitCode {
    if cases.is_empty() {
        eprintln!("e2e suite selected no cases");
        return ExitCode::FAILURE;
    }

    println!("running {} e2e case(s)", cases.len());
    let started_at = Instant::now();
    let mut passed = 0_usize;
    let mut skipped = 0_usize;
    let mut case_reports = Vec::new();
    for (index, case) in cases.iter().enumerate() {
        println!(
            "[{}/{}] {} ({})",
            index + 1,
            cases.len(),
            case.name,
            case.requirement.label()
        );
        let case_started_at = Instant::now();
        match case.run.run() {
            E2eOutcome::Passed => {
                let elapsed = case_started_at.elapsed();
                passed += 1;
                println!(
                    "[{}/{}] {} passed in {}",
                    index + 1,
                    cases.len(),
                    case.name,
                    format_duration(elapsed)
                );
                case_reports.push(E2eCaseRunReport::passed(case, elapsed));
            }
            E2eOutcome::Skipped(reason) => {
                let elapsed = case_started_at.elapsed();
                skipped += 1;
                println!(
                    "[{}/{}] {} skipped in {}: {}",
                    index + 1,
                    cases.len(),
                    case.name,
                    format_duration(elapsed),
                    reason
                );
                case_reports.push(E2eCaseRunReport::skipped(case, elapsed, reason));
            }
            E2eOutcome::Failed => {
                let elapsed = case_started_at.elapsed();
                eprintln!(
                    "e2e suite failed at {} after {}",
                    case.name,
                    format_duration(elapsed)
                );
                case_reports.push(E2eCaseRunReport::failed(case, elapsed));
                for not_run in cases.iter().skip(index + 1) {
                    case_reports.push(E2eCaseRunReport::not_run(not_run));
                }
                let report =
                    E2eSuiteRunReport::new(&request.selection, case_reports, started_at.elapsed());
                return finish_run(request.report_json.as_deref(), report, ExitCode::FAILURE);
            }
        }
    }

    let elapsed = started_at.elapsed();
    if skipped == 0 {
        println!(
            "e2e suite passed: {passed} passed in {}",
            format_duration(elapsed)
        );
    } else {
        println!(
            "e2e suite completed with skips: {passed} passed, {skipped} skipped in {}",
            format_duration(elapsed)
        );
    }
    let report = E2eSuiteRunReport::new(&request.selection, case_reports, elapsed);
    finish_run(request.report_json.as_deref(), report, ExitCode::SUCCESS)
}

fn finish_run(
    report_path: Option<&Path>,
    report: E2eSuiteRunReport,
    exit_code: ExitCode,
) -> ExitCode {
    let Some(path) = report_path else {
        return exit_code;
    };
    match write_report(path, &report) {
        Ok(()) => {
            println!("wrote e2e suite report {}", path.display());
            exit_code
        }
        Err(error) => {
            eprintln!(
                "failed to write e2e suite report {}: {error}",
                path.display()
            );
            ExitCode::FAILURE
        }
    }
}

fn print_cases() {
    for case in registry::cases() {
        println!(
            "{}\t{}\t{}",
            case.name,
            case.requirement.label(),
            case.capability_summary()
        );
    }
}

fn print_profiles() {
    for listing in registry::profile_listings().expect("profile registry is valid") {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            listing.name,
            listing.requirements,
            listing.capabilities,
            listing.description,
            listing.case_names.join(",")
        );
    }
}

fn print_inventory_json() -> ExitCode {
    let inventory = match registry::inventory() {
        Ok(inventory) => inventory,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&inventory).expect("e2e inventory JSON should serialize")
    );
    ExitCode::SUCCESS
}

fn print_usage() {
    eprintln!(
        "usage: cargo run -p xtask -- e2e-suite [--list | --list-profiles | --inventory-json | [--profile <name> | --include-privileged | --only-privileged | --case <name> ...] [--report-json <path>]]"
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

    fn parse_run(args: &[&str]) -> SuiteRunRequest {
        let args = args
            .iter()
            .map(|arg| (*arg).to_string())
            .collect::<Vec<_>>();
        match SuiteAction::parse(&args).expect("suite action should parse") {
            SuiteAction::Run(request) => request,
            action => panic!("expected run action, got {action:?}"),
        }
    }

    fn parse_selection(args: &[&str]) -> SuiteSelection {
        parse_run(args).selection
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
    fn parses_report_json_with_profile_selection() {
        let request = parse_run(&[
            "--profile",
            "baseline",
            "--report-json",
            "target/e2e/baseline.json",
        ]);

        assert_eq!(
            request.selection,
            SuiteSelection::Profile(
                registry::profile_id_by_name("baseline").expect("baseline profile should exist")
            )
        );
        assert_eq!(
            request.report_json,
            Some(PathBuf::from("target/e2e/baseline.json"))
        );
    }

    #[test]
    fn parses_report_json_before_case_selection() {
        let request = parse_run(&[
            "--report-json",
            "target/e2e/cases.json",
            "--case",
            "e2e-plaintext-feed",
        ]);

        assert_eq!(
            request.report_json,
            Some(PathBuf::from("target/e2e/cases.json"))
        );
        assert_eq!(
            selected_names(&request.selection),
            vec!["e2e-plaintext-feed"]
        );
    }

    #[test]
    fn rejects_duplicate_report_json() {
        let error = parse_error(&["--report-json", "a.json", "--report-json", "b.json"]);

        assert!(error.contains("--report-json cannot be specified more than once"));
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

    #[test]
    fn parses_inventory_json_as_action() {
        let args = ["--inventory-json".to_string()];

        assert_eq!(
            SuiteAction::parse(&args).expect("inventory JSON action"),
            SuiteAction::InventoryJson
        );
    }

    #[test]
    fn rejects_inventory_json_with_run_selection() {
        let error = parse_error(&["--inventory-json", "--profile", "baseline"]);

        assert!(error.contains("--inventory-json cannot be combined"));
    }
}
