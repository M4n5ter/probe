use probe_config::{
    AgentConfig, CaptureBackend, CaptureConfig, CaptureSelection, ObservationDataPathMode,
    ProcessObservationConfig,
};
use probe_core::{Direction, ProcessSelector, Selector, TrafficSelector};

pub(super) fn apply_process_observation_projection(mut config: AgentConfig) -> AgentConfig {
    if config.observations.is_empty() {
        return config;
    }

    let raw_selection = config.capture.selection;
    let raw_may_use_libpcap = config.capture.may_use_backend(CaptureBackend::Libpcap);
    config.capture.selection = projected_capture_selection_for(&config.observations, raw_selection);
    normalize_projected_capture_defaults(&mut config.capture, raw_selection, raw_may_use_libpcap);
    config.capture.deep_observe_selector = Some(selector_for(&config.observations));
    config
}

fn normalize_projected_capture_defaults(
    capture: &mut CaptureConfig,
    raw_selection: CaptureSelection,
    raw_may_use_libpcap: bool,
) {
    let defaults = CaptureConfig::default();

    match capture.selection {
        CaptureSelection::Auto => {
            if raw_selection != CaptureSelection::Auto || capture.fallback_backends.is_empty() {
                capture.fallback_backends = defaults.fallback_backends;
            }
        }
        CaptureSelection::Ebpf | CaptureSelection::Libpcap => {
            capture.fallback_backends = defaults.fallback_backends;
        }
        CaptureSelection::PlaintextFeed
        | CaptureSelection::CaptureEventFeed
        | CaptureSelection::Replay => {}
    }

    let projected_may_use_libpcap = capture.may_use_backend(CaptureBackend::Libpcap);
    if !projected_may_use_libpcap || !raw_may_use_libpcap {
        capture.libpcap = defaults.libpcap;
    }
    capture.plaintext_feed = defaults.plaintext_feed;
    capture.capture_event_feed = defaults.capture_event_feed;
}

fn projected_capture_selection_for(
    observations: &[ProcessObservationConfig],
    raw_selection: CaptureSelection,
) -> CaptureSelection {
    let mut explicit = observations
        .iter()
        .filter_map(|observation| match observation.data_path {
            ObservationDataPathMode::Auto => None,
            ObservationDataPathMode::Ebpf => Some(CaptureSelection::Ebpf),
            ObservationDataPathMode::Libpcap => Some(CaptureSelection::Libpcap),
        })
        .collect::<Vec<_>>();
    explicit.sort_by_key(|selection| match selection {
        CaptureSelection::Ebpf => 0,
        CaptureSelection::Libpcap => 1,
        _ => 2,
    });
    explicit.dedup();

    match explicit.as_slice() {
        [] => live_capture_selection_or_auto(raw_selection),
        [selection] => *selection,
        _ => CaptureSelection::Auto,
    }
}

fn live_capture_selection_or_auto(selection: CaptureSelection) -> CaptureSelection {
    match selection {
        CaptureSelection::Auto | CaptureSelection::Ebpf | CaptureSelection::Libpcap => selection,
        CaptureSelection::PlaintextFeed
        | CaptureSelection::CaptureEventFeed
        | CaptureSelection::Replay => CaptureSelection::Auto,
    }
}

fn selector_for(observations: &[ProcessObservationConfig]) -> Selector {
    let mut selectors = observations
        .iter()
        .map(selector_for_observation)
        .collect::<Vec<_>>();
    if selectors.len() == 1 {
        selectors.remove(0)
    } else {
        Selector::Any { selectors }
    }
}

fn selector_for_observation(observation: &ProcessObservationConfig) -> Selector {
    if covers_both_directions(&observation.directions) {
        return observation.selector.clone();
    }

    Selector::All {
        selectors: vec![
            observation.selector.clone(),
            Selector::term(
                ProcessSelector::default(),
                TrafficSelector {
                    directions: observation.directions.clone(),
                    ..TrafficSelector::default()
                },
            ),
        ],
    }
}

fn covers_both_directions(directions: &[Direction]) -> bool {
    directions.contains(&Direction::Inbound) && directions.contains(&Direction::Outbound)
}

#[cfg(test)]
mod tests {
    use probe_config::{ObservationDataPathMode, ProcessObservationConfig};
    use probe_core::{
        Direction, ProcessContext, ProcessIdentity, ProcessSelector, Selector, TrafficSelector,
    };

    use super::*;

    #[test]
    fn explicit_single_backend_observation_drives_capture_selection() {
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Auto;
        config.observations.push(observation(
            "nginx",
            "/usr/sbin/nginx",
            ObservationDataPathMode::Libpcap,
            vec![Direction::Inbound, Direction::Outbound],
        ));

        let projected = apply_process_observation_projection(config);

        assert_eq!(projected.capture.selection, CaptureSelection::Libpcap);
        assert!(
            projected
                .capture
                .deep_observe_selector
                .expect("selector should be projected")
                .compile()
                .expect("selector should compile")
                .matches_unattributed_flow(&process("/usr/sbin/nginx"), Direction::Inbound)
        );
    }

    #[test]
    fn auto_observations_follow_the_only_explicit_capture_selection() {
        let mut config = AgentConfig::default();
        config.observations.extend([
            observation(
                "frontend",
                "/usr/bin/frontend",
                ObservationDataPathMode::Auto,
                vec![Direction::Inbound, Direction::Outbound],
            ),
            observation(
                "worker",
                "/usr/bin/worker",
                ObservationDataPathMode::Libpcap,
                vec![Direction::Inbound, Direction::Outbound],
            ),
        ]);

        let projected = apply_process_observation_projection(config);

        assert_eq!(projected.capture.selection, CaptureSelection::Libpcap);
        let Selector::Any { selectors } = projected
            .capture
            .deep_observe_selector
            .expect("selector should be projected")
        else {
            panic!("multiple observations should project to any selector");
        };
        assert_eq!(selectors.len(), 2);
    }

    #[test]
    fn auto_only_observations_preserve_explicit_capture_selection() {
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Libpcap;
        config.observations.push(observation(
            "frontend",
            "/usr/bin/frontend",
            ObservationDataPathMode::Auto,
            vec![Direction::Inbound, Direction::Outbound],
        ));

        let projected = apply_process_observation_projection(config);

        assert_eq!(projected.capture.selection, CaptureSelection::Libpcap);
        assert!(
            projected
                .capture
                .deep_observe_selector
                .expect("selector should be projected")
                .compile()
                .expect("selector should compile")
                .matches_unattributed_flow(&process("/usr/bin/frontend"), Direction::Inbound)
        );
    }

    #[test]
    fn auto_only_observations_project_non_live_capture_selection_to_live_auto() {
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Replay;
        config.capture.fallback_backends.clear();
        config.capture.plaintext_feed.path = Some("/tmp/plaintext.jsonl".into());
        config.capture.capture_event_feed.path = Some("/tmp/capture-events.jsonl".into());
        config.capture.capture_event_feed.follow = Some(true);
        config.observations.push(observation(
            "frontend",
            "/usr/bin/frontend",
            ObservationDataPathMode::Auto,
            vec![Direction::Inbound, Direction::Outbound],
        ));

        let projected = apply_process_observation_projection(config);

        assert_eq!(projected.capture.selection, CaptureSelection::Auto);
        assert_eq!(
            projected.capture.fallback_backends,
            CaptureConfig::default().fallback_backends
        );
        assert_eq!(
            projected.capture.plaintext_feed,
            CaptureConfig::default().plaintext_feed
        );
        assert_eq!(
            projected.capture.capture_event_feed,
            CaptureConfig::default().capture_event_feed
        );
    }

    #[test]
    fn mixed_explicit_observation_backends_project_to_auto() {
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Ebpf;
        config.capture.fallback_backends.clear();
        config.capture.libpcap.bpf_filter.clear();
        config.capture.plaintext_feed.path = Some("/tmp/plaintext.jsonl".into());
        config.capture.capture_event_feed.path = Some("/tmp/capture-events.jsonl".into());
        config.capture.capture_event_feed.follow = Some(true);
        config.observations.extend([
            observation(
                "frontend",
                "/usr/bin/frontend",
                ObservationDataPathMode::Ebpf,
                vec![Direction::Inbound, Direction::Outbound],
            ),
            observation(
                "worker",
                "/usr/bin/worker",
                ObservationDataPathMode::Libpcap,
                vec![Direction::Inbound, Direction::Outbound],
            ),
        ]);

        let projected = apply_process_observation_projection(config);

        assert_eq!(projected.capture.selection, CaptureSelection::Auto);
        assert_eq!(
            projected.capture.fallback_backends,
            CaptureConfig::default().fallback_backends
        );
        assert_eq!(projected.capture.libpcap, CaptureConfig::default().libpcap);
        assert_eq!(
            projected.capture.plaintext_feed,
            CaptureConfig::default().plaintext_feed
        );
        assert_eq!(
            projected.capture.capture_event_feed,
            CaptureConfig::default().capture_event_feed
        );
    }

    #[test]
    fn explicit_projection_resets_stale_target_backend_config() {
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Ebpf;
        config.capture.fallback_backends.clear();
        config.capture.libpcap.bpf_filter.clear();
        config.capture.plaintext_feed.path = Some("/tmp/plaintext.jsonl".into());
        config.capture.capture_event_feed.path = Some("/tmp/capture-events.jsonl".into());
        config.capture.capture_event_feed.follow = Some(true);
        config.observations.push(observation(
            "worker",
            "/usr/bin/worker",
            ObservationDataPathMode::Libpcap,
            vec![Direction::Inbound, Direction::Outbound],
        ));

        let projected = apply_process_observation_projection(config);

        assert_eq!(projected.capture.selection, CaptureSelection::Libpcap);
        assert_eq!(projected.capture.libpcap, CaptureConfig::default().libpcap);
        assert_eq!(
            projected.capture.plaintext_feed,
            CaptureConfig::default().plaintext_feed
        );
        assert_eq!(
            projected.capture.capture_event_feed,
            CaptureConfig::default().capture_event_feed
        );
    }

    #[test]
    fn observation_directions_are_projected_into_runtime_selector() {
        let mut config = AgentConfig::default();
        config.observations.push(observation(
            "nginx",
            "/usr/sbin/nginx",
            ObservationDataPathMode::Auto,
            vec![Direction::Inbound],
        ));

        let projected = apply_process_observation_projection(config);
        let selector = projected
            .capture
            .deep_observe_selector
            .expect("selector should be projected")
            .compile()
            .expect("selector should compile");

        assert!(
            selector.matches_unattributed_flow(&process("/usr/sbin/nginx"), Direction::Inbound)
        );
        assert!(
            !selector.matches_unattributed_flow(&process("/usr/sbin/nginx"), Direction::Outbound)
        );
    }

    fn observation(
        id: &str,
        exe_path: &str,
        data_path: ObservationDataPathMode,
        directions: Vec<Direction>,
    ) -> ProcessObservationConfig {
        ProcessObservationConfig {
            id: id.to_string(),
            selector: Selector::term(
                ProcessSelector {
                    exe_path_globs: vec![exe_path.to_string()],
                    ..ProcessSelector::default()
                },
                TrafficSelector::default(),
            ),
            data_path,
            directions,
        }
    }

    fn process(exe_path: &str) -> ProcessContext {
        ProcessContext {
            identity: ProcessIdentity {
                pid: 42,
                tgid: 42,
                start_time_ticks: 1,
                boot_id: "boot".to_string(),
                exe_path: exe_path.to_string(),
                cmdline_hash: "hash".to_string(),
                uid: 1000,
                gid: 1000,
                cgroup: None,
                systemd_service: None,
                container_id: None,
                runtime_hint: None,
            },
            name: exe_path.rsplit('/').next().unwrap_or(exe_path).to_string(),
            cmdline: vec![exe_path.to_string()],
        }
    }
}
