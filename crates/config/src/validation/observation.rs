use std::collections::HashSet;

use probe_core::{ProcessSelector, Selector, SelectorRegistry, TrafficSelector};

use crate::{ConfigViolation, ProcessObservationConfig};

pub(super) fn validate(
    observations: &[ProcessObservationConfig],
    selectors: &SelectorRegistry,
    violations: &mut Vec<ConfigViolation>,
) {
    let mut ids = HashSet::new();
    for (index, observation) in observations.iter().enumerate() {
        let field = format!("observations[{index}]");
        if observation.id.trim().is_empty() {
            violations.push(ConfigViolation {
                field: format!("{field}.id"),
                reason: "observation id cannot be empty".to_string(),
            });
        } else if !ids.insert(observation.id.as_str()) {
            violations.push(ConfigViolation {
                field: format!("{field}.id"),
                reason: format!("observation id {:?} is duplicated", observation.id),
            });
        }
        if observation.directions.is_empty() {
            violations.push(ConfigViolation {
                field: format!("{field}.directions"),
                reason: "observation directions cannot be empty".to_string(),
            });
        }
        match observation.selector.resolve_refs_with_registry(selectors) {
            Ok(resolved) => {
                validate_selector_scope(field.as_str(), resolved.as_selector(), violations)
            }
            Err(error) => {
                violations.push(ConfigViolation {
                    field: format!("{field}.selector"),
                    reason: error.to_string(),
                });
            }
        }
    }
}

fn validate_selector_scope(
    field: &str,
    selector: &Selector,
    violations: &mut Vec<ConfigViolation>,
) {
    if selector_contains_negative_match(selector) {
        violations.push(ConfigViolation {
            field: format!("{field}.selector"),
            reason:
                "observation selector cannot use not; process observation must be positively scoped"
                    .to_string(),
        });
    }
    if !selector_has_process_constraint(selector) {
        violations.push(ConfigViolation {
            field: format!("{field}.selector.term.process"),
            reason: "observation selector must include at least one process constraint".to_string(),
        });
    }
    if selector_has_traffic_constraint(selector) {
        violations.push(ConfigViolation {
            field: format!("{field}.selector.term.traffic"),
            reason:
                "observation selector cannot include traffic constraints; use observations[].directions for direction scope"
                    .to_string(),
        });
    }
}

fn selector_has_process_constraint(selector: &Selector) -> bool {
    match selector {
        Selector::Match { term } => process_selector_has_constraint(&term.process),
        Selector::All { selectors } | Selector::Any { selectors } => {
            selectors.iter().any(selector_has_process_constraint)
        }
        Selector::Not { .. } | Selector::Ref { .. } => false,
    }
}

fn selector_has_traffic_constraint(selector: &Selector) -> bool {
    match selector {
        Selector::Match { term } => traffic_selector_has_constraint(&term.traffic),
        Selector::All { selectors } | Selector::Any { selectors } => {
            selectors.iter().any(selector_has_traffic_constraint)
        }
        Selector::Not { selector } => selector_has_traffic_constraint(selector),
        Selector::Ref { .. } => false,
    }
}

fn selector_contains_negative_match(selector: &Selector) -> bool {
    match selector {
        Selector::Match { .. } | Selector::Ref { .. } => false,
        Selector::All { selectors } | Selector::Any { selectors } => {
            selectors.iter().any(selector_contains_negative_match)
        }
        Selector::Not { .. } => true,
    }
}

fn process_selector_has_constraint(process: &ProcessSelector) -> bool {
    !process.pids.is_empty()
        || !process.process_keys.is_empty()
        || !process.uids.is_empty()
        || !process.gids.is_empty()
        || !process.names.is_empty()
        || !process.exe_path_globs.is_empty()
        || !process.cmdline_regexes.is_empty()
        || !process.systemd_services.is_empty()
        || !process.container_ids.is_empty()
        || !process.cgroup_paths.is_empty()
}

fn traffic_selector_has_constraint(traffic: &TrafficSelector) -> bool {
    !traffic.local_ports.is_empty()
        || !traffic.remote_ports.is_empty()
        || !traffic.directions.is_empty()
        || !traffic.remote_addresses.is_empty()
}

#[cfg(test)]
mod tests {
    use probe_core::{Direction, ProcessSelector, SelectorTerm, TrafficSelector};

    use super::*;
    use crate::ObservationDataPathMode;

    #[test]
    fn observation_requires_positive_process_scope() {
        let observation = ProcessObservationConfig {
            id: "default".to_string(),
            selector: Selector::default(),
            data_path: ObservationDataPathMode::Auto,
            directions: vec![Direction::Inbound, Direction::Outbound],
        };
        let mut violations = Vec::new();

        validate(
            &[observation],
            &SelectorRegistry::default(),
            &mut violations,
        );

        assert!(violations.iter().any(|violation| {
            violation.field == "observations[0].selector.term.process"
                && violation.reason.contains("at least one process constraint")
        }));
    }

    #[test]
    fn observation_rejects_traffic_constraints_inside_selector() {
        let observation = ProcessObservationConfig {
            id: "curl".to_string(),
            selector: Selector::Match {
                term: Box::new(SelectorTerm {
                    process: ProcessSelector {
                        exe_path_globs: vec!["/usr/bin/curl".to_string()],
                        ..ProcessSelector::default()
                    },
                    traffic: TrafficSelector {
                        directions: vec![Direction::Inbound],
                        ..TrafficSelector::default()
                    },
                }),
            },
            data_path: ObservationDataPathMode::Auto,
            directions: vec![Direction::Inbound, Direction::Outbound],
        };
        let mut violations = Vec::new();

        validate(
            &[observation],
            &SelectorRegistry::default(),
            &mut violations,
        );

        assert!(violations.iter().any(|violation| {
            violation.field == "observations[0].selector.term.traffic"
                && violation.reason.contains("use observations[].directions")
        }));
    }

    #[test]
    fn observation_accepts_process_selector_with_outer_directions() {
        let observation = ProcessObservationConfig {
            id: "curl".to_string(),
            selector: Selector::Match {
                term: Box::new(SelectorTerm {
                    process: ProcessSelector {
                        exe_path_globs: vec!["/usr/bin/curl".to_string()],
                        ..ProcessSelector::default()
                    },
                    traffic: TrafficSelector::default(),
                }),
            },
            data_path: ObservationDataPathMode::Auto,
            directions: vec![Direction::Inbound, Direction::Outbound],
        };
        let mut violations = Vec::new();

        validate(
            &[observation],
            &SelectorRegistry::default(),
            &mut violations,
        );

        assert!(violations.is_empty());
    }

    #[test]
    fn observation_accepts_process_key_scope() {
        let observation = ProcessObservationConfig {
            id: "selected-process".to_string(),
            selector: Selector::Match {
                term: Box::new(SelectorTerm {
                    process: ProcessSelector {
                        process_keys: vec!["stable-process-key".to_string()],
                        ..ProcessSelector::default()
                    },
                    traffic: TrafficSelector::default(),
                }),
            },
            data_path: ObservationDataPathMode::Auto,
            directions: vec![Direction::Inbound, Direction::Outbound],
        };
        let mut violations = Vec::new();

        validate(
            &[observation],
            &SelectorRegistry::default(),
            &mut violations,
        );

        assert!(violations.is_empty());
    }
}
