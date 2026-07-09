use std::{collections::BTreeSet, fmt, path::PathBuf};

use attribution::{ProcessAttributor, ProcfsAttributor};
use probe_core::ProcessContext;
use probe_core::{ProcessSelector, Selector, TrafficSelector};

use super::traffic_scope::{ProcessTrafficScope, ProcessTrafficSelector};

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ProcessEntry {
    pub(crate) pid: u32,
    pub(crate) process_key: String,
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
            .field("process_key", &self.process_key)
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
    pub(crate) fn observation_key(&self) -> String {
        process_observation_key_for_process_key(&self.process_key)
    }

    pub(crate) fn selector(&self) -> Selector {
        selector_for_process_key(self.process_key.clone())
    }

    pub(crate) fn observation_scope_label(&self) -> &'static str {
        "process"
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
            process_key: process.identity.stable_key(),
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

pub(crate) fn process_observation_key_for_pid(pid: u32) -> String {
    format!("pid:{pid}")
}

pub(crate) fn process_observation_key_for_process_key(process_key: &str) -> String {
    format!("process:{process_key}")
}

#[cfg(test)]
pub(crate) fn selector_for_pid(pid: u32) -> Selector {
    Selector::term(
        ProcessSelector {
            pids: vec![pid],
            ..ProcessSelector::default()
        },
        TrafficSelector::default(),
    )
}

pub(crate) fn selector_for_process_key(process_key: String) -> Selector {
    Selector::term(
        ProcessSelector {
            process_keys: vec![process_key],
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

    pub(crate) fn from_proc_processes_only() -> Self {
        Self::from_attributor(&ProcfsAttributor::new())
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

    pub(crate) fn diagnostics(&self) -> &[String] {
        &self.diagnostics
    }

    pub(crate) fn traffic_selector_for_observations(
        &self,
        observations: impl IntoIterator<Item = (String, Selector)>,
    ) -> Option<ProcessTrafficSelector> {
        let observations = observations.into_iter().collect::<Vec<_>>();
        if observations.is_empty() {
            return None;
        }
        let selector = merge_selectors(observations.iter().map(|(_, selector)| selector.clone()));
        let keys = observations
            .iter()
            .map(|(key, _)| key.as_str())
            .collect::<Vec<_>>();
        let exe_paths = exe_paths_for_keys(&self.entries, &keys);
        let exe_path_selector = self
            .traffic_scope
            .selector_for_exe_paths(exe_paths.iter().cloned());
        let unknown_process_candidate_selector = exe_path_selector
            .as_ref()
            .and_then(|selector| selector.unknown_process_candidate_selector.clone());
        let unknown_process_candidate_exe_paths = if unknown_process_candidate_selector.is_some() {
            exe_path_selector
                .map(|selector| selector.unknown_process_candidate_exe_paths)
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let unknown_process_candidate_scope = candidate_scope_label_for_exe_paths(
            &self.entries,
            &unknown_process_candidate_exe_paths,
        );
        Some(ProcessTrafficSelector {
            selector: Some(selector),
            unknown_process_candidate_selector,
            unknown_process_candidate_scope,
            unknown_process_candidate_exe_paths,
        })
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
    pub(crate) fn with_diagnostics(
        mut self,
        diagnostics: impl IntoIterator<Item = String>,
    ) -> Self {
        self.diagnostics = diagnostics.into_iter().collect();
        self
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
    let labels = entries
        .iter()
        .filter(|process| {
            process_exe_path(process)
                .as_ref()
                .is_some_and(|exe_path| requested.contains(exe_path))
        })
        .map(|process| process.name.clone())
        .collect::<BTreeSet<_>>();
    (!labels.is_empty()).then(|| labels.into_iter().collect::<Vec<_>>().join(", "))
}

fn exe_paths_for_keys(entries: &[ProcessEntry], keys: &[&str]) -> Vec<String> {
    let requested = keys.iter().copied().collect::<BTreeSet<_>>();
    entries
        .iter()
        .filter(|process| {
            let pid_key = process_observation_key_for_pid(process.pid);
            requested.contains(process.observation_key().as_str())
                || requested.contains(pid_key.as_str())
        })
        .filter_map(process_exe_path)
        .collect()
}

fn process_exe_path(process: &ProcessEntry) -> Option<String> {
    process
        .exe_path
        .as_ref()
        .and_then(|path| path.to_str())
        .map(str::to_string)
}

fn merge_selectors(selectors: impl IntoIterator<Item = Selector>) -> Selector {
    let selectors = selectors.into_iter().collect::<Vec<_>>();
    match selectors.as_slice() {
        [] => Selector::default(),
        [selector] => selector.clone(),
        _ => Selector::Any { selectors },
    }
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
    fn process_entry_selector_targets_process_key() {
        let entry = ProcessEntry {
            pid: 7,
            process_key: "process-key-7".to_string(),
            name: "curl".to_string(),
            exe_path: Some(PathBuf::from("/usr/bin/curl")),
            argv: Vec::new(),
            uid: 1000,
            gid: 1000,
            cgroup_path: None,
        };

        let selector = entry.selector();
        let Selector::Match { term } = selector else {
            panic!("process entry should create a match selector");
        };
        assert!(term.process.pids.is_empty());
        assert_eq!(term.process.process_keys, ["process-key-7"]);
        assert!(term.process.exe_path_globs.is_empty());
        assert!(term.process.names.is_empty());
    }

    #[test]
    fn process_entry_without_executable_path_still_targets_process_key() {
        let entry = ProcessEntry {
            pid: 7,
            process_key: "process-key-7".to_string(),
            name: "python".to_string(),
            exe_path: None,
            argv: vec!["python".to_string()],
            uid: 1000,
            gid: 1000,
            cgroup_path: None,
        };

        let Selector::Match { term } = entry.selector() else {
            panic!("process entry should create a process-key selector");
        };
        assert!(term.process.pids.is_empty());
        assert_eq!(term.process.process_keys, ["process-key-7"]);
        assert_eq!(entry.observation_scope_label(), "process");
        assert_eq!(entry.argv_summary(96), "python");
    }

    #[test]
    fn process_entry_search_and_detail_include_argv() {
        let entry = ProcessEntry {
            pid: 7,
            process_key: "process-key-7".to_string(),
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
