use std::{
    collections::BTreeSet,
    fmt,
    path::{Path, PathBuf},
};

use attribution::{ProcessAttributor, ProcfsAttributor};
use probe_core::ProcessContext;
use probe_core::{ProcessSelector, Selector, TrafficSelector};

use super::process_traffic_scope::{ProcessTrafficScope, ProcessTrafficSelector};

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ProcessEntry {
    pub(crate) pid: u32,
    pub(crate) name: String,
    pub(crate) exe_path: Option<PathBuf>,
    pub(crate) argv: Vec<String>,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) cgroup_path: Option<String>,
}

impl fmt::Debug for ProcessEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProcessEntry")
            .field("pid", &self.pid)
            .field("name", &self.name)
            .field("exe_path", &self.exe_path)
            .field("uid", &self.uid)
            .field("gid", &self.gid)
            .field("cgroup_path", &self.cgroup_path)
            .field("argv_len", &self.argv.len())
            .finish()
    }
}

impl ProcessEntry {
    pub(crate) fn selector_key(&self) -> Option<String> {
        self.exe_path
            .as_ref()
            .and_then(|path| path.to_str())
            .map(str::to_string)
    }

    pub(crate) fn selector(&self) -> Option<Selector> {
        self.selector_key().map(selector_for_exe_path)
    }

    pub(crate) fn observation_scope_label(&self) -> &'static str {
        if self.selector().is_some() {
            "exe"
        } else {
            "-"
        }
    }

    pub(crate) fn argv_summary(&self, max_chars: usize) -> String {
        if self.argv.is_empty() {
            return "-".to_string();
        }
        truncate_chars(&escaped_argv(&self.argv), max_chars)
    }

    pub(crate) fn argv_detail_lines(&self) -> Vec<String> {
        if self.argv.is_empty() {
            return vec!["argv: -".to_string()];
        }
        self.argv
            .iter()
            .enumerate()
            .map(|(index, value)| format!("argv[{index}]: {}", escape_text(value)))
            .collect()
    }

    pub(crate) fn matches_query(&self, query: &str) -> bool {
        if query.is_empty() {
            return true;
        }
        let query = query.to_ascii_lowercase();
        self.pid.to_string().contains(&query)
            || self.name.to_ascii_lowercase().contains(&query)
            || self
                .exe_path
                .as_ref()
                .map(|path| {
                    path.display()
                        .to_string()
                        .to_ascii_lowercase()
                        .contains(&query)
                })
                .unwrap_or(false)
            || self
                .argv
                .iter()
                .any(|arg| arg.to_ascii_lowercase().contains(&query))
    }

    fn from_process(process: ProcessContext) -> Self {
        Self {
            pid: process.identity.pid,
            name: process.name,
            exe_path: (!process.identity.exe_path.is_empty())
                .then(|| PathBuf::from(process.identity.exe_path)),
            argv: process.cmdline,
            uid: process.identity.uid,
            gid: process.identity.gid,
            cgroup_path: process.identity.cgroup,
        }
    }
}

fn escaped_argv(argv: &[String]) -> String {
    argv.iter()
        .map(|arg| escape_text(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn escape_text(value: &str) -> String {
    let mut output = String::new();
    for character in value.chars() {
        for escaped in character.escape_default() {
            output.push(escaped);
        }
    }
    output
}

fn truncate_chars(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    let prefix = value
        .chars()
        .take(max_chars.saturating_sub(3))
        .collect::<String>();
    format!("{prefix}...")
}

pub(crate) fn selector_for_exe_path(exe_path: String) -> Selector {
    Selector::term(
        ProcessSelector {
            exe_path_globs: vec![exe_path],
            ..ProcessSelector::default()
        },
        TrafficSelector::default(),
    )
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ProcessCatalog {
    entries: Vec<ProcessEntry>,
    diagnostics: Vec<String>,
    traffic_scope: ProcessTrafficScope,
}

impl ProcessCatalog {
    pub(crate) fn from_proc() -> Self {
        let mut catalog = Self::from_attributor(&ProcfsAttributor::new());
        catalog.load_traffic_scope();
        catalog
    }

    fn from_attributor(attributor: &ProcfsAttributor) -> Self {
        let pids = match attributor.process_ids() {
            Ok(pids) => pids,
            Err(error) => {
                return Self {
                    entries: Vec::new(),
                    diagnostics: vec![format!("procfs process scan failed: {error}")],
                    traffic_scope: ProcessTrafficScope::default(),
                };
            }
        };
        let mut entries = Vec::new();
        let mut diagnostics = Vec::new();
        let mut failed_processes = 0usize;
        for pid in pids {
            match attributor.identify_if_present(pid) {
                Ok(Some(process)) => entries.push(ProcessEntry::from_process(process)),
                Ok(None) => {}
                Err(error) => {
                    failed_processes += 1;
                    if diagnostics.len() < 3 {
                        diagnostics.push(format!("procfs process {pid} failed: {error}"));
                    }
                }
            }
        }
        if failed_processes > diagnostics.len() {
            diagnostics.push(format!(
                "skipped {} additional process entries due to procfs read errors",
                failed_processes - diagnostics.len()
            ));
        }
        entries.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.pid.cmp(&right.pid))
        });
        Self {
            entries,
            diagnostics,
            traffic_scope: ProcessTrafficScope::default(),
        }
    }

    pub(crate) fn entries(&self) -> &[ProcessEntry] {
        &self.entries
    }

    pub(crate) fn traffic_selector_for_exe_paths(
        &self,
        exe_paths: impl IntoIterator<Item = String>,
    ) -> Option<ProcessTrafficSelector> {
        let exe_paths = exe_paths.into_iter().collect::<Vec<_>>();
        let mut selector = self
            .traffic_scope
            .selector_for_exe_paths(exe_paths.iter().cloned())?;
        selector.unknown_process_candidate_scope = candidate_scope_label_for_exe_paths(
            &self.entries,
            &selector.unknown_process_candidate_exe_paths,
        );
        Some(selector)
    }

    #[cfg(test)]
    pub(crate) fn from_entries(entries: impl IntoIterator<Item = ProcessEntry>) -> Self {
        Self {
            entries: entries.into_iter().collect(),
            diagnostics: Vec::new(),
            traffic_scope: ProcessTrafficScope::default(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_listener_ports(
        mut self,
        exe_path: impl Into<String>,
        ports: impl IntoIterator<Item = u16>,
    ) -> Self {
        self.traffic_scope = self.traffic_scope.with_listener_ports(exe_path, ports);
        self
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn diagnostic_summary(&self) -> Option<String> {
        let diagnostics = self
            .diagnostics
            .iter()
            .chain(self.traffic_scope.diagnostics())
            .cloned()
            .collect::<Vec<_>>();
        if diagnostics.is_empty() {
            None
        } else {
            Some(diagnostics.join("; "))
        }
    }

    fn load_traffic_scope(&mut self) {
        match ProcessTrafficScope::from_procfs() {
            Ok(scope) => self.traffic_scope = scope,
            Err(error) => {
                self.diagnostics
                    .push(format!("procfs listener scan failed: {error}"));
            }
        }
    }
}

fn candidate_scope_label_for_exe_paths(
    entries: &[ProcessEntry],
    exe_paths: &[String],
) -> Option<String> {
    if exe_paths.is_empty() {
        return None;
    }
    let requested = exe_paths.iter().cloned().collect::<BTreeSet<_>>();
    let mut matched = BTreeSet::new();
    let mut labels = BTreeSet::new();
    for process in entries {
        let Some(exe_path) = process.selector_key() else {
            continue;
        };
        if requested.contains(&exe_path) {
            matched.insert(exe_path);
            labels.insert(process.name.clone());
        }
    }
    for exe_path in exe_paths {
        if !matched.contains(exe_path) {
            labels.insert(candidate_label_from_exe_path(exe_path));
        }
    }
    (!labels.is_empty()).then(|| labels.into_iter().collect::<Vec<_>>().join(", "))
}

fn candidate_label_from_exe_path(exe_path: &str) -> String {
    Path::new(exe_path)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| exe_path.to_string())
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::symlink};

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn process_catalog_reuses_procfs_attributor_without_external_commands()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let proc_root = temp.path().join("proc");
        let boot_id_path = proc_root.join("boot_id");
        let process = proc_root.join("42");
        fs::create_dir_all(&process)?;
        fs::write(&boot_id_path, "boot-test\n")?;
        fs::write(
            process.join("stat"),
            "42 (curl) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 99 21\n",
        )?;
        fs::write(
            process.join("status"),
            "Name:\tcurl\nTgid:\t42\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n",
        )?;
        fs::write(process.join("cmdline"), b"curl\0https://example.com\0")?;
        fs::write(process.join("cgroup"), "0::/system.slice/curl.service\n")?;
        symlink("/usr/bin/curl", process.join("exe"))?;

        let attributor = ProcfsAttributor::with_paths(&proc_root, &boot_id_path);
        let catalog = ProcessCatalog::from_attributor(&attributor);

        assert_eq!(catalog.entries().len(), 1);
        assert_eq!(catalog.entries()[0].pid, 42);
        assert_eq!(catalog.entries()[0].name, "curl");
        assert_eq!(catalog.entries()[0].argv.len(), 2);
        assert_eq!(
            catalog.entries()[0].argv,
            ["curl".to_string(), "https://example.com".to_string()]
        );
        assert_eq!(
            catalog.entries()[0].exe_path,
            Some(PathBuf::from("/usr/bin/curl"))
        );
        assert_eq!(catalog.entries()[0].uid, 1000);
        assert_eq!(catalog.entries()[0].gid, 1000);
        assert_eq!(
            catalog.entries()[0].cgroup_path.as_deref(),
            Some("/system.slice/curl.service")
        );
        Ok(())
    }

    #[test]
    fn process_entry_selector_prefers_executable_path_when_available() {
        let entry = ProcessEntry {
            pid: 7,
            name: "curl".to_string(),
            exe_path: Some(PathBuf::from("/usr/bin/curl")),
            argv: Vec::new(),
            uid: 1000,
            gid: 1000,
            cgroup_path: None,
        };

        let Some(selector) = entry.selector() else {
            panic!("executable path should produce a safe selector");
        };

        let Selector::Match { term } = selector else {
            panic!("process entry should create a match selector");
        };
        assert_eq!(term.process.exe_path_globs, ["/usr/bin/curl".to_string()]);
        assert!(term.process.names.is_empty());
    }

    #[test]
    fn process_entry_without_executable_path_does_not_broaden_capture_to_process_name() {
        let entry = ProcessEntry {
            pid: 7,
            name: "python".to_string(),
            exe_path: None,
            argv: vec!["python".to_string()],
            uid: 1000,
            gid: 1000,
            cgroup_path: None,
        };

        assert_eq!(entry.selector(), None);
        assert_eq!(entry.observation_scope_label(), "-");
        assert_eq!(entry.argv_summary(96), "python");
    }

    #[test]
    fn process_entry_search_and_detail_include_argv() {
        let entry = ProcessEntry {
            pid: 7,
            name: "python".to_string(),
            exe_path: Some(PathBuf::from("/usr/bin/python")),
            argv: vec![
                "python".to_string(),
                "-m".to_string(),
                "http.server".to_string(),
            ],
            uid: 1000,
            gid: 1000,
            cgroup_path: None,
        };

        assert!(entry.matches_query("http.server"));
        assert_eq!(
            entry.argv_detail_lines(),
            [
                "argv[0]: python".to_string(),
                "argv[1]: -m".to_string(),
                "argv[2]: http.server".to_string()
            ]
        );
        assert!(!format!("{entry:?}").contains("http.server"));
    }

    #[test]
    fn process_catalog_reports_global_procfs_scan_failure() {
        let temp = TempDir::new().expect("tempdir");
        let proc_root = temp.path().join("missing-proc");
        let boot_id_path = temp.path().join("boot_id");
        let attributor = ProcfsAttributor::with_paths(&proc_root, &boot_id_path);

        let catalog = ProcessCatalog::from_attributor(&attributor);

        assert!(catalog.entries().is_empty());
        assert!(
            catalog
                .diagnostic_summary()
                .is_some_and(|summary| summary.contains("procfs process scan failed"))
        );
    }
}
