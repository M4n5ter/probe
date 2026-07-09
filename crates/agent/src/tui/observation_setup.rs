use probe_config::{AgentConfig, ObservationDataPathMode, ProcessObservationConfig};
use probe_core::{Direction, ProcessSelector, Selector, SelectorTerm, TrafficSelector};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProcessObservationMode {
    Auto,
    Ebpf,
    Libpcap,
}

impl ProcessObservationMode {
    pub(crate) fn data_path(self) -> ObservationDataPathMode {
        match self {
            Self::Auto => ObservationDataPathMode::Auto,
            Self::Ebpf => ObservationDataPathMode::Ebpf,
            Self::Libpcap => ObservationDataPathMode::Libpcap,
        }
    }

    pub(crate) fn label(self) -> &'static str {
        self.data_path().label()
    }
}

pub(crate) fn upsert_process_observation(
    config: &mut AgentConfig,
    key: &str,
    selector: Selector,
    mode: ProcessObservationMode,
) {
    let id = retained_process_observation_id(config, key);
    retain_without_process_observation(config, key);
    config
        .observations
        .push(process_observation(id, selector, mode));
}

pub(crate) fn replace_process_observations_with(
    config: &mut AgentConfig,
    key: &str,
    selector: Selector,
    mode: ProcessObservationMode,
) {
    let id = retained_process_observation_id(config, key);
    config
        .observations
        .retain(|observation| simple_process_observation_key(observation).is_none());
    config
        .observations
        .push(process_observation(id, selector, mode));
}

pub(crate) fn remove_process_observation(config: &mut AgentConfig, key: &str) -> bool {
    let before = config.observations.len();
    config
        .observations
        .retain(|observation| simple_process_observation_key(observation).as_deref() != Some(key));
    config.observations.len() != before
}

pub(crate) fn process_observation_pids(config: &AgentConfig) -> Vec<u32> {
    config
        .observations
        .iter()
        .filter_map(simple_process_observation_pid)
        .collect()
}

pub(crate) fn process_observation_id(key: &str) -> String {
    key.to_string()
}

fn simple_process_observation_key(observation: &ProcessObservationConfig) -> Option<String> {
    simple_process_observation_pid(observation).map(|pid| format!("pid:{pid}"))
}

fn simple_process_observation_pid(observation: &ProcessObservationConfig) -> Option<u32> {
    let Selector::Match { term } = &observation.selector else {
        return None;
    };
    simple_process_selector_pid(term)
}

fn retained_process_observation_id(config: &AgentConfig, key: &str) -> String {
    config
        .observations
        .iter()
        .find(|observation| simple_process_observation_key(observation).as_deref() == Some(key))
        .map(|observation| observation.id.clone())
        .filter(|id| !retained_observation_id_exists(config, key, id))
        .unwrap_or_else(|| unique_process_observation_id(config, key))
}

fn retained_observation_id_exists(config: &AgentConfig, key: &str, id: &str) -> bool {
    config.observations.iter().any(|observation| {
        simple_process_observation_key(observation).as_deref() != Some(key) && observation.id == id
    })
}

fn unique_process_observation_id(config: &AgentConfig, key: &str) -> String {
    let base = process_observation_id(key);
    if !config
        .observations
        .iter()
        .any(|observation| observation.id == base)
    {
        return base;
    }
    (1..)
        .map(|index| format!("{base}:{index}"))
        .find(|id| {
            !config
                .observations
                .iter()
                .any(|observation| observation.id == *id)
        })
        .expect("unbounded observation id suffix search should find a free id")
}

fn retain_without_process_observation(config: &mut AgentConfig, key: &str) {
    config
        .observations
        .retain(|observation| simple_process_observation_key(observation).as_deref() != Some(key));
}

fn process_observation(
    id: String,
    selector: Selector,
    mode: ProcessObservationMode,
) -> ProcessObservationConfig {
    ProcessObservationConfig {
        id,
        selector,
        data_path: mode.data_path(),
        directions: vec![Direction::Inbound, Direction::Outbound],
    }
}

fn simple_process_selector_pid(term: &SelectorTerm) -> Option<u32> {
    simple_process_selector(&term.process).and_then(|process| {
        let pid = process.pids.first().copied()?;
        simple_traffic_selector(&term.traffic).then_some(pid)
    })
}

fn simple_process_selector(process: &ProcessSelector) -> Option<&ProcessSelector> {
    (process.pids.len() == 1
        && process.uids.is_empty()
        && process.gids.is_empty()
        && process.names.is_empty()
        && process.exe_path_globs.is_empty()
        && process.cmdline_regexes.is_empty()
        && process.systemd_services.is_empty()
        && process.container_ids.is_empty()
        && process.cgroup_paths.is_empty())
    .then_some(process)
}

fn simple_traffic_selector(traffic: &TrafficSelector) -> bool {
    traffic.local_ports.is_empty()
        && traffic.remote_ports.is_empty()
        && traffic.directions.is_empty()
        && traffic.remote_addresses.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_observation_pids_ignore_non_pid_observations() {
        let mut config = AgentConfig::default();
        config
            .observations
            .push(observation_with_exe_glob("wildcard", "/app/*"));
        config.observations.push(observation_with_pid("exact", 42));

        assert_eq!(process_observation_pids(&config), [42]);
    }

    #[test]
    fn replace_process_observations_preserves_non_pid_observations() {
        let mut config = AgentConfig::default();
        config
            .observations
            .push(observation_with_exe_glob("wildcard", "/app/*"));

        replace_process_observations_with(
            &mut config,
            "pid:42",
            selector_with_pid(42),
            ProcessObservationMode::Auto,
        );

        assert_eq!(config.observations.len(), 2);
        assert!(
            config
                .observations
                .iter()
                .any(|observation| observation.id == "wildcard")
        );
        assert_eq!(process_observation_pids(&config), [42]);
    }

    #[test]
    fn remove_process_observation_preserves_non_pid_observations() {
        let mut config = AgentConfig::default();
        config
            .observations
            .push(observation_with_exe_glob("wildcard", "/app/*"));
        config.observations.push(observation_with_pid("exact", 42));

        assert!(remove_process_observation(&mut config, "pid:42"));

        assert_eq!(config.observations.len(), 1);
        assert_eq!(config.observations[0].id, "wildcard");
    }

    #[test]
    fn upsert_process_observation_deduplicates_exact_managed_observations() {
        let mut config = AgentConfig::default();
        config.observations.push(observation_with_pid("first", 42));
        config.observations.push(observation_with_pid("second", 42));

        upsert_process_observation(
            &mut config,
            "pid:42",
            selector_with_pid(42),
            ProcessObservationMode::Auto,
        );

        assert_eq!(config.observations.len(), 1);
        assert_eq!(config.observations[0].id, "first");
    }

    #[test]
    fn upsert_process_observation_does_not_delete_wildcard_id_collision() {
        let mut config = AgentConfig::default();
        config
            .observations
            .push(observation_with_exe_glob("pid:42", "/app/*"));

        upsert_process_observation(
            &mut config,
            "pid:42",
            selector_with_pid(42),
            ProcessObservationMode::Auto,
        );

        assert_eq!(config.observations.len(), 2);
        assert_eq!(config.observations[0].id, "pid:42");
        assert_eq!(config.observations[1].id, "pid:42:1");
    }

    #[test]
    fn replace_process_observations_avoids_retained_id_collision() {
        let mut config = AgentConfig::default();
        config
            .observations
            .push(observation_with_exe_glob("shared", "/app/*"));
        config.observations.push(observation_with_pid("shared", 42));

        replace_process_observations_with(
            &mut config,
            "pid:42",
            selector_with_pid(42),
            ProcessObservationMode::Auto,
        );

        assert_eq!(config.observations.len(), 2);
        assert_eq!(config.observations[0].id, "shared");
        assert_eq!(config.observations[1].id, "pid:42");
    }

    fn observation_with_exe_glob(id: &str, exe_glob: &str) -> ProcessObservationConfig {
        ProcessObservationConfig {
            id: id.to_string(),
            selector: selector_with_exe_glob(exe_glob),
            data_path: ObservationDataPathMode::Auto,
            directions: vec![Direction::Inbound, Direction::Outbound],
        }
    }

    fn observation_with_pid(id: &str, pid: u32) -> ProcessObservationConfig {
        ProcessObservationConfig {
            id: id.to_string(),
            selector: selector_with_pid(pid),
            data_path: ObservationDataPathMode::Auto,
            directions: vec![Direction::Inbound, Direction::Outbound],
        }
    }

    fn selector_with_exe_glob(exe_glob: &str) -> Selector {
        Selector::Match {
            term: Box::new(SelectorTerm {
                process: ProcessSelector {
                    exe_path_globs: vec![exe_glob.to_string()],
                    ..ProcessSelector::default()
                },
                traffic: TrafficSelector::default(),
            }),
        }
    }

    fn selector_with_pid(pid: u32) -> Selector {
        Selector::Match {
            term: Box::new(SelectorTerm {
                process: ProcessSelector {
                    pids: vec![pid],
                    ..ProcessSelector::default()
                },
                traffic: TrafficSelector::default(),
            }),
        }
    }
}
