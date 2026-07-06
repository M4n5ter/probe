use std::collections::{BTreeMap, BTreeSet};

use attribution::{ProcfsSocketResolver, TcpListenerOwnerSource, TcpListenerProcessLookup};
use probe_core::Selector;

use crate::admin::UnknownProcessCandidateSelector;

use super::processes::selector_for_exe_path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessTrafficSelector {
    pub(crate) selector: Option<Selector>,
    pub(crate) unknown_process_candidate_selector: Option<UnknownProcessCandidateSelector>,
    pub(crate) unknown_process_candidate_scope: Option<String>,
    pub(crate) unknown_process_candidate_exe_paths: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ProcessTrafficScope {
    listener_ports_by_exe_path: BTreeMap<String, Vec<u16>>,
    diagnostics: Vec<String>,
}

impl ProcessTrafficScope {
    pub(crate) fn from_procfs() -> Result<Self, attribution::AttributionError> {
        let mut resolver = ProcfsSocketResolver::new();
        resolver.resolve_tcp_listeners().map(Self::from_lookup)
    }

    pub(crate) fn diagnostics(&self) -> &[String] {
        &self.diagnostics
    }

    pub(crate) fn selector_for_exe_path(&self, exe_path: String) -> ProcessTrafficSelector {
        let unknown_process_candidate_selector = self.unknown_process_candidate_selector(&exe_path);
        let unknown_process_candidate_exe_paths = unknown_process_candidate_selector
            .is_some()
            .then_some(exe_path.clone())
            .into_iter()
            .collect();
        ProcessTrafficSelector {
            selector: Some(selector_for_exe_path(exe_path)),
            unknown_process_candidate_selector,
            unknown_process_candidate_scope: None,
            unknown_process_candidate_exe_paths,
        }
    }

    pub(crate) fn selector_for_exe_paths(
        &self,
        exe_paths: impl IntoIterator<Item = String>,
    ) -> Option<ProcessTrafficSelector> {
        let selector_sets = exe_paths
            .into_iter()
            .map(|exe_path| self.selector_for_exe_path(exe_path))
            .collect::<Vec<_>>();
        (!selector_sets.is_empty()).then(|| merge_selector_sets(selector_sets))
    }

    #[cfg(test)]
    pub(crate) fn with_listener_ports(
        mut self,
        exe_path: impl Into<String>,
        ports: impl IntoIterator<Item = u16>,
    ) -> Self {
        let ports = sorted_ports(ports);
        self.listener_ports_by_exe_path
            .insert(exe_path.into(), ports);
        self
    }

    fn from_lookup(lookup: TcpListenerProcessLookup) -> Self {
        let mut scope = Self::default();
        let raw_ports = listener_ports_by_exe_path(lookup);
        for (exe_path, ports) in raw_ports {
            match UnknownProcessCandidateSelector::try_from_listener_ports(ports.clone()) {
                Ok(Some(_)) => {
                    scope.listener_ports_by_exe_path.insert(exe_path, ports);
                }
                Ok(None) => {}
                Err(error) => {
                    scope.diagnostics.push(format!(
                        "libpcap weak process candidates disabled for {exe_path}: {error}"
                    ));
                }
            }
        }
        scope
    }

    fn unknown_process_candidate_selector(
        &self,
        exe_path: &str,
    ) -> Option<UnknownProcessCandidateSelector> {
        self.listener_ports_by_exe_path
            .get(exe_path)
            .and_then(|ports| UnknownProcessCandidateSelector::from_listener_ports(ports.clone()))
    }
}

impl ProcessTrafficSelector {
    pub(crate) fn all_processes() -> Self {
        Self {
            selector: None,
            unknown_process_candidate_selector: None,
            unknown_process_candidate_scope: None,
            unknown_process_candidate_exe_paths: Vec::new(),
        }
    }
}

fn listener_ports_by_exe_path(lookup: TcpListenerProcessLookup) -> BTreeMap<String, Vec<u16>> {
    let mut ports_by_exe_path = BTreeMap::<String, BTreeSet<u16>>::new();
    for listener in lookup.listeners {
        let exe_path = &listener.owner.process.identity.exe_path;
        if exe_path.is_empty() {
            continue;
        }
        let ports = ports_by_exe_path.entry(exe_path.clone()).or_default();
        ports.insert(listener.observed.local.port);
        if let TcpListenerOwnerSource::DockerProxyTarget { target_local, .. } =
            listener.owner.source
        {
            ports.insert(target_local.port);
        }
    }
    ports_by_exe_path
        .into_iter()
        .map(|(exe_path, ports)| (exe_path, ports.into_iter().collect()))
        .collect()
}

fn merge_selector_sets(selector_sets: Vec<ProcessTrafficSelector>) -> ProcessTrafficSelector {
    let mut selectors = Vec::with_capacity(selector_sets.len());
    let mut unknown_process_candidate_selectors = Vec::new();
    let mut unknown_process_candidate_exe_paths = Vec::new();
    for selector_set in selector_sets {
        selectors.push(selector_set.selector);
        if let Some(unknown_process_candidate_selector) =
            selector_set.unknown_process_candidate_selector
        {
            unknown_process_candidate_selectors.push(unknown_process_candidate_selector);
        }
        unknown_process_candidate_exe_paths
            .extend(selector_set.unknown_process_candidate_exe_paths);
    }
    let unknown_process_candidate_selector =
        merge_unknown_process_candidate_selectors(unknown_process_candidate_selectors);
    if unknown_process_candidate_selector.is_none() {
        unknown_process_candidate_exe_paths.clear();
    }
    ProcessTrafficSelector {
        selector: merge_optional_selectors(selectors),
        unknown_process_candidate_selector,
        unknown_process_candidate_scope: None,
        unknown_process_candidate_exe_paths,
    }
}

fn merge_unknown_process_candidate_selectors(
    selectors: Vec<UnknownProcessCandidateSelector>,
) -> Option<UnknownProcessCandidateSelector> {
    UnknownProcessCandidateSelector::try_from_listener_ports(
        selectors
            .into_iter()
            .flat_map(|selector| selector.listener_ports().to_vec()),
    )
    .ok()
    .flatten()
}

fn merge_selectors(selectors: Vec<Selector>) -> Selector {
    let mut selectors = selectors.into_iter();
    let first = selectors
        .next()
        .expect("merge_selectors requires at least one selector");
    match selectors.next() {
        Some(second) => Selector::Any {
            selectors: std::iter::once(first)
                .chain(std::iter::once(second))
                .chain(selectors)
                .collect(),
        },
        None => first,
    }
}

fn merge_optional_selectors(selectors: Vec<Option<Selector>>) -> Option<Selector> {
    let selectors = selectors.into_iter().flatten().collect::<Vec<_>>();
    (!selectors.is_empty()).then(|| merge_selectors(selectors))
}

#[cfg(test)]
fn sorted_ports(ports: impl IntoIterator<Item = u16>) -> Vec<u16> {
    ports
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listener_port_index_includes_docker_proxy_host_and_target_ports()
    -> Result<(), Box<dyn std::error::Error>> {
        use attribution::{
            TcpListenerObservedSocket, TcpListenerOwnerContext, TcpListenerProcessContext,
        };

        let owner = process_context(42, "backend", "/app/backend");
        let lookup = TcpListenerProcessLookup {
            listeners: vec![TcpListenerProcessContext {
                observed: TcpListenerObservedSocket {
                    process: process_context(7, "docker-proxy", "/usr/bin/docker-proxy"),
                    confidence: 60,
                    socket_inode: 700,
                    local: probe_core::TcpEndpoint::new("0.0.0.0".parse()?, 8081),
                },
                owner: TcpListenerOwnerContext {
                    process: owner,
                    confidence: 55,
                    source: TcpListenerOwnerSource::DockerProxyTarget {
                        target_local: probe_core::TcpEndpoint::new("172.19.0.3".parse()?, 8080),
                        target_socket_inode: 420,
                    },
                },
            }],
            unattributed_listeners: Vec::new(),
        };

        let scope = ProcessTrafficScope::from_lookup(lookup);

        assert_eq!(
            scope
                .listener_ports_by_exe_path
                .get("/app/backend")
                .map(Vec::as_slice),
            Some([8080, 8081].as_slice())
        );
        Ok(())
    }

    #[test]
    fn oversized_listener_port_index_disables_weak_candidates_with_diagnostic() {
        let max_ports = UnknownProcessCandidateSelector::MAX_LISTENER_PORTS;
        let lookup = TcpListenerProcessLookup {
            listeners: (0..=max_ports)
                .map(|index| {
                    use attribution::{
                        TcpListenerObservedSocket, TcpListenerOwnerContext,
                        TcpListenerProcessContext,
                    };

                    TcpListenerProcessContext {
                        observed: TcpListenerObservedSocket {
                            process: process_context(42, "backend", "/app/backend"),
                            confidence: 60,
                            socket_inode: u64::try_from(index).expect("index fits u64"),
                            local: probe_core::TcpEndpoint::new(
                                "0.0.0.0".parse().expect("valid address"),
                                u16::try_from(index + 1).expect("test port fits u16"),
                            ),
                        },
                        owner: TcpListenerOwnerContext {
                            process: process_context(42, "backend", "/app/backend"),
                            confidence: 60,
                            source: TcpListenerOwnerSource::SocketHolder,
                        },
                    }
                })
                .collect(),
            unattributed_listeners: Vec::new(),
        };

        let scope = ProcessTrafficScope::from_lookup(lookup);

        assert!(scope.listener_ports_by_exe_path.is_empty());
        assert!(scope.diagnostics[0].contains("weak process candidates disabled"));
    }

    #[test]
    fn merged_unknown_process_candidate_selector_respects_port_budget() {
        let max_ports = UnknownProcessCandidateSelector::MAX_LISTENER_PORTS;
        let max_ports_u16 = u16::try_from(max_ports).expect("max port count fits u16");
        let scope = ProcessTrafficScope::default()
            .with_listener_ports("/app/a", 1..=max_ports_u16)
            .with_listener_ports("/app/b", 10_000_u16..10_000_u16 + max_ports_u16);

        let selector = scope
            .selector_for_exe_paths(["/app/a".to_string(), "/app/b".to_string()])
            .expect("watched processes should produce strong selector");

        assert!(selector.unknown_process_candidate_selector.is_none());
        assert!(selector.unknown_process_candidate_exe_paths.is_empty());
    }

    fn process_context(pid: u32, name: &str, exe_path: &str) -> probe_core::ProcessContext {
        probe_core::ProcessContext {
            identity: probe_core::ProcessIdentity {
                pid,
                tgid: pid,
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
            name: name.to_string(),
            cmdline: vec![name.to_string()],
        }
    }
}
