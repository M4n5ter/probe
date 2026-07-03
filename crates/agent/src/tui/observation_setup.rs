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
    exe_path: &str,
    selector: Selector,
    mode: ProcessObservationMode,
) {
    let id = retained_process_observation_id(config, exe_path);
    retain_without_process_observation(config, exe_path);
    config
        .observations
        .push(process_observation(id, selector, mode));
}

pub(crate) fn replace_process_observations_with(
    config: &mut AgentConfig,
    exe_path: &str,
    selector: Selector,
    mode: ProcessObservationMode,
) {
    let id = retained_process_observation_id(config, exe_path);
    config
        .observations
        .retain(|observation| simple_process_observation_exe_path(observation).is_none());
    config
        .observations
        .push(process_observation(id, selector, mode));
}

pub(crate) fn remove_process_observation(config: &mut AgentConfig, exe_path: &str) -> bool {
    let before = config.observations.len();
    config
        .observations
        .retain(|observation| simple_process_observation_exe_path(observation) != Some(exe_path));
    config.observations.len() != before
}

pub(crate) fn process_observation_exe_paths(config: &AgentConfig) -> Vec<String> {
    config
        .observations
        .iter()
        .filter_map(simple_process_observation_exe_path)
        .map(str::to_string)
        .collect()
}

pub(crate) fn process_observation_id(exe_path: &str) -> String {
    format!("exe:{exe_path}")
}

fn simple_process_observation_exe_path(observation: &ProcessObservationConfig) -> Option<&str> {
    let Selector::Match { term } = &observation.selector else {
        return None;
    };
    simple_process_selector_exe_path(term)
}

fn retained_process_observation_id(config: &AgentConfig, exe_path: &str) -> String {
    config
        .observations
        .iter()
        .find(|observation| simple_process_observation_exe_path(observation) == Some(exe_path))
        .map(|observation| observation.id.clone())
        .filter(|id| !retained_observation_id_exists(config, exe_path, id))
        .unwrap_or_else(|| unique_process_observation_id(config, exe_path))
}

fn retained_observation_id_exists(config: &AgentConfig, exe_path: &str, id: &str) -> bool {
    config.observations.iter().any(|observation| {
        simple_process_observation_exe_path(observation) != Some(exe_path) && observation.id == id
    })
}

fn unique_process_observation_id(config: &AgentConfig, exe_path: &str) -> String {
    let base = process_observation_id(exe_path);
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

fn retain_without_process_observation(config: &mut AgentConfig, exe_path: &str) {
    config
        .observations
        .retain(|observation| simple_process_observation_exe_path(observation) != Some(exe_path));
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

fn simple_process_selector_exe_path(term: &SelectorTerm) -> Option<&str> {
    simple_process_selector(&term.process).and_then(|process| {
        let exe_path = process.exe_path_globs.first()?;
        (simple_traffic_selector(&term.traffic) && exact_exe_path_glob(exe_path))
            .then_some(exe_path.as_str())
    })
}

fn exact_exe_path_glob(value: &str) -> bool {
    !value
        .chars()
        .any(|ch| matches!(ch, '*' | '?' | '[' | ']' | '{' | '}' | '\\'))
}

fn simple_process_selector(process: &ProcessSelector) -> Option<&ProcessSelector> {
    (process.pids.is_empty()
        && process.uids.is_empty()
        && process.gids.is_empty()
        && process.names.is_empty()
        && process.exe_path_globs.len() == 1
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
    fn process_observation_exe_paths_ignore_wildcard_observations() {
        let mut config = AgentConfig::default();
        config
            .observations
            .push(observation_with_exe_glob("wildcard", "/app/*"));
        config
            .observations
            .push(observation_with_exe_glob("exact", "/app/backend"));

        assert_eq!(process_observation_exe_paths(&config), ["/app/backend"]);
    }

    #[test]
    fn replace_process_observations_preserves_wildcard_observations() {
        let mut config = AgentConfig::default();
        config
            .observations
            .push(observation_with_exe_glob("wildcard", "/app/*"));

        replace_process_observations_with(
            &mut config,
            "/app/backend",
            selector_with_exe_glob("/app/backend"),
            ProcessObservationMode::Auto,
        );

        assert_eq!(config.observations.len(), 2);
        assert!(
            config
                .observations
                .iter()
                .any(|observation| observation.id == "wildcard")
        );
        assert_eq!(
            process_observation_exe_paths(&config),
            ["/app/backend".to_string()]
        );
    }

    #[test]
    fn remove_process_observation_preserves_wildcard_observations() {
        let mut config = AgentConfig::default();
        config
            .observations
            .push(observation_with_exe_glob("wildcard", "/app/*"));
        config
            .observations
            .push(observation_with_exe_glob("exact", "/app/backend"));

        assert!(remove_process_observation(&mut config, "/app/backend"));

        assert_eq!(config.observations.len(), 1);
        assert_eq!(config.observations[0].id, "wildcard");
    }

    #[test]
    fn upsert_process_observation_deduplicates_exact_managed_observations() {
        let mut config = AgentConfig::default();
        config
            .observations
            .push(observation_with_exe_glob("first", "/app/backend"));
        config
            .observations
            .push(observation_with_exe_glob("second", "/app/backend"));

        upsert_process_observation(
            &mut config,
            "/app/backend",
            selector_with_exe_glob("/app/backend"),
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
            .push(observation_with_exe_glob("exe:/app/backend", "/app/*"));

        upsert_process_observation(
            &mut config,
            "/app/backend",
            selector_with_exe_glob("/app/backend"),
            ProcessObservationMode::Auto,
        );

        assert_eq!(config.observations.len(), 2);
        assert_eq!(config.observations[0].id, "exe:/app/backend");
        assert_eq!(config.observations[1].id, "exe:/app/backend:1");
    }

    #[test]
    fn replace_process_observations_avoids_retained_id_collision() {
        let mut config = AgentConfig::default();
        config
            .observations
            .push(observation_with_exe_glob("shared", "/app/*"));
        config
            .observations
            .push(observation_with_exe_glob("shared", "/app/backend"));

        replace_process_observations_with(
            &mut config,
            "/app/backend",
            selector_with_exe_glob("/app/backend"),
            ProcessObservationMode::Auto,
        );

        assert_eq!(config.observations.len(), 2);
        assert_eq!(config.observations[0].id, "shared");
        assert_eq!(config.observations[1].id, "exe:/app/backend");
    }

    fn observation_with_exe_glob(id: &str, exe_glob: &str) -> ProcessObservationConfig {
        ProcessObservationConfig {
            id: id.to_string(),
            selector: selector_with_exe_glob(exe_glob),
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
}
