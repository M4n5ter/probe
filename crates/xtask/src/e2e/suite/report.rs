use std::{fs, path::Path, time::Duration};

use serde::Serialize;

use super::registry::{self, E2eCase, E2eCaseMetadata, SuiteSelection, SuiteSelectionDescriptor};

const E2E_RUN_REPORT_SCHEMA_VERSION: u16 = 1;

pub(super) fn write_report(path: &Path, report: &E2eSuiteRunReport) -> Result<(), std::io::Error> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(report).expect("e2e run report should serialize");
    fs::write(path, bytes)?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct E2eSuiteRunReport {
    schema_version: u16,
    selection: SuiteSelectionDescriptor,
    summary: E2eSuiteRunSummary,
    cases: Vec<E2eCaseRunReport>,
}

impl E2eSuiteRunReport {
    pub(super) fn new(
        selection: &SuiteSelection,
        cases: Vec<E2eCaseRunReport>,
        elapsed: Duration,
    ) -> Self {
        Self {
            schema_version: E2E_RUN_REPORT_SCHEMA_VERSION,
            selection: registry::describe_selection(selection),
            summary: E2eSuiteRunSummary::from_cases(&cases, elapsed),
            cases,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct E2eSuiteRunSummary {
    status: E2eSuiteRunStatus,
    total: usize,
    passed: usize,
    skipped: usize,
    failed: usize,
    not_run: usize,
    duration_ms: u64,
}

impl E2eSuiteRunSummary {
    fn from_cases(cases: &[E2eCaseRunReport], elapsed: Duration) -> Self {
        let passed = cases
            .iter()
            .filter(|case| case.status == E2eCaseRunStatus::Passed)
            .count();
        let skipped = cases
            .iter()
            .filter(|case| case.status == E2eCaseRunStatus::Skipped)
            .count();
        let failed = cases
            .iter()
            .filter(|case| case.status == E2eCaseRunStatus::Failed)
            .count();
        let not_run = cases
            .iter()
            .filter(|case| case.status == E2eCaseRunStatus::NotRun)
            .count();
        Self {
            status: E2eSuiteRunStatus::from_counts(failed, skipped, not_run),
            total: cases.len(),
            passed,
            skipped,
            failed,
            not_run,
            duration_ms: duration_ms(elapsed),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum E2eSuiteRunStatus {
    Passed,
    CompletedWithSkips,
    Failed,
}

impl E2eSuiteRunStatus {
    fn from_counts(failed: usize, skipped: usize, not_run: usize) -> Self {
        if failed > 0 || not_run > 0 {
            Self::Failed
        } else if skipped > 0 {
            Self::CompletedWithSkips
        } else {
            Self::Passed
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct E2eCaseRunReport {
    #[serde(flatten)]
    metadata: E2eCaseMetadata,
    status: E2eCaseRunStatus,
    duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    skip_reason: Option<String>,
}

impl E2eCaseRunReport {
    pub(super) fn passed(case: &E2eCase, elapsed: Duration) -> Self {
        Self::new(case, E2eCaseRunStatus::Passed, elapsed, None)
    }

    pub(super) fn skipped(case: &E2eCase, elapsed: Duration, reason: String) -> Self {
        Self::new(case, E2eCaseRunStatus::Skipped, elapsed, Some(reason))
    }

    pub(super) fn failed(case: &E2eCase, elapsed: Duration) -> Self {
        Self::new(case, E2eCaseRunStatus::Failed, elapsed, None)
    }

    pub(super) fn not_run(case: &E2eCase) -> Self {
        Self::new(case, E2eCaseRunStatus::NotRun, Duration::ZERO, None)
    }

    fn new(
        case: &E2eCase,
        status: E2eCaseRunStatus,
        elapsed: Duration,
        skip_reason: Option<String>,
    ) -> Self {
        Self {
            metadata: E2eCaseMetadata::from_case(case),
            status,
            duration_ms: duration_ms(elapsed),
            skip_reason,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum E2eCaseRunStatus {
    Passed,
    Skipped,
    Failed,
    NotRun,
}

fn duration_ms(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_report_serializes_case_statuses_and_summary() {
        let cases = registry::select_cases(&SuiteSelection::Default).expect("baseline cases");
        let report = E2eSuiteRunReport::new(
            &SuiteSelection::Default,
            vec![
                E2eCaseRunReport::passed(cases[0], Duration::from_millis(7)),
                E2eCaseRunReport::skipped(
                    cases[1],
                    Duration::from_millis(3),
                    "missing capability".to_string(),
                ),
            ],
            Duration::from_millis(10),
        );

        let value = serde_json::to_value(report).expect("report should serialize");

        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["selection"]["kind"], "default_profile");
        assert_eq!(value["selection"]["profile"], "baseline");
        assert_eq!(value["summary"]["status"], "completed_with_skips");
        assert_eq!(value["summary"]["total"], 2);
        assert_eq!(value["summary"]["passed"], 1);
        assert_eq!(value["summary"]["skipped"], 1);
        assert_eq!(value["summary"]["duration_ms"], 10);
        assert_eq!(value["cases"][0]["name"], "e2e-replay");
        assert_eq!(value["cases"][0]["status"], "passed");
        assert_eq!(value["cases"][0]["requirement"]["id"], "user");
        assert_eq!(value["cases"][1]["status"], "skipped");
        assert_eq!(value["cases"][1]["skip_reason"], "missing capability");
    }

    #[test]
    fn run_report_serializes_failure_and_not_run_cases() {
        let cases = registry::select_cases(&SuiteSelection::Default).expect("baseline cases");
        let report = E2eSuiteRunReport::new(
            &SuiteSelection::Default,
            vec![
                E2eCaseRunReport::failed(cases[0], Duration::from_millis(11)),
                E2eCaseRunReport::not_run(cases[1]),
            ],
            Duration::from_millis(11),
        );

        let value = serde_json::to_value(report).expect("report should serialize");

        assert_eq!(value["summary"]["status"], "failed");
        assert_eq!(value["summary"]["failed"], 1);
        assert_eq!(value["summary"]["not_run"], 1);
        assert_eq!(value["cases"][0]["status"], "failed");
        assert_eq!(value["cases"][0]["duration_ms"], 11);
        assert_eq!(value["cases"][1]["status"], "not_run");
        assert_eq!(value["cases"][1]["duration_ms"], 0);
        assert!(
            !value["cases"][1]
                .as_object()
                .expect("case should serialize as object")
                .contains_key("skip_reason")
        );
    }
}
