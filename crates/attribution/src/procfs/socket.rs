use std::{
    collections::{HashMap, HashSet},
    fs, io,
    net::IpAddr,
    path::Path,
    time::{Duration, Instant},
};

use probe_core::{CapabilityKind, CapabilityState, ProcessContext, TcpConnection, TcpEndpoint};

use super::{
    AttributionError,
    inode_scan::{
        SocketFdCandidate, SocketFdCandidateSource, read_socket_cookie_for_pid_fd,
        socket_fd_candidates_for_lookup, socket_inode_owner_scan,
    },
    io::read_tcp_table_to_string,
    listener::{
        DOCKER_PROXY_TARGET_CONFIDENCE, PROCFS_SOCKET_CONFIDENCE, TcpListenerObservedSocket,
        TcpListenerOwnerContext, TcpListenerOwnerSource, TcpListenerProcessContext,
        docker_proxy_target_endpoint,
    },
    pid_scan::{ProcfsPidEntry, numeric_pid_dirs},
    process::{ProcessAttributor, ProcfsAttributor},
    tcp_table::{
        ProcfsTcpListenerEntry, ProcfsTcpTableFamily, ProcfsTcpTablePolicy, connection_uses_family,
        connections_by_inode, endpoint_uses_family, procfs_tcp_tables, tcp_entries_from_table,
        tcp_inode_map_from_entries, tcp_listener_entries_from_entries,
        tcp_listener_entries_from_entries_with_namespace, tcp_local_addresses_from_entries,
    },
};

const PROCFS_HINTED_FD_CONFIDENCE: u8 = 50;
const DEFAULT_PROCFS_SOCKET_SNAPSHOT_TTL: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketProcessContext {
    pub process: ProcessContext,
    pub confidence: u8,
    pub socket_inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpListenerProcessLookup {
    pub listeners: Vec<TcpListenerProcessContext>,
    pub unattributed_listeners: Vec<TcpUnattributedListener>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpUnattributedListener {
    pub socket_inode: u64,
    pub local: TcpEndpoint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TcpListenerEndpointCandidate {
    source: TcpListenerEndpointCandidateSource,
    local: TcpEndpoint,
    socket_inode: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TcpListenerEndpointCandidateSource {
    Attributed(usize),
    Unattributed(usize),
}

impl TcpListenerProcessLookup {
    fn endpoint_candidates(&self) -> Vec<TcpListenerEndpointCandidate> {
        self.listeners
            .iter()
            .enumerate()
            .map(|(index, listener)| TcpListenerEndpointCandidate {
                source: TcpListenerEndpointCandidateSource::Attributed(index),
                local: listener.observed.local,
                socket_inode: listener.observed.socket_inode,
            })
            .chain(
                self.unattributed_listeners
                    .iter()
                    .enumerate()
                    .map(|(index, listener)| TcpListenerEndpointCandidate {
                        source: TcpListenerEndpointCandidateSource::Unattributed(index),
                        local: listener.local,
                        socket_inode: listener.socket_inode,
                    }),
            )
            .collect()
    }

    fn select_endpoint_candidates(self, candidates: &[TcpListenerEndpointCandidate]) -> Self {
        let mut selected_listeners = vec![false; self.listeners.len()];
        let mut selected_unattributed_listeners = vec![false; self.unattributed_listeners.len()];
        for candidate in candidates {
            match candidate.source {
                TcpListenerEndpointCandidateSource::Attributed(index) => {
                    selected_listeners[index] = true;
                }
                TcpListenerEndpointCandidateSource::Unattributed(index) => {
                    selected_unattributed_listeners[index] = true;
                }
            }
        }
        let listeners = self
            .listeners
            .into_iter()
            .enumerate()
            .filter_map(|(index, listener)| selected_listeners[index].then_some(listener))
            .collect();
        let unattributed_listeners = self
            .unattributed_listeners
            .into_iter()
            .enumerate()
            .filter_map(|(index, listener)| {
                selected_unattributed_listeners[index].then_some(listener)
            })
            .collect();
        Self {
            listeners,
            unattributed_listeners,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketFdConnectionContext {
    pub process: ProcessContext,
    pub confidence: u8,
    pub socket_inode: u64,
    pub socket_cookie: Option<u64>,
    pub connection: TcpConnection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketFdLookup {
    pub tgid: u32,
    pub thread_pid: u32,
    pub fd: i32,
    pub expected_remote_endpoint: Option<TcpEndpoint>,
    pub process_hint: Option<SocketProcessHint>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketProcessHint {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Clone)]
struct ProcfsSocketSnapshot {
    tcp_inodes: HashMap<TcpConnection, u64>,
    tcp_listeners: Vec<ProcfsTcpListenerEntry>,
    namespace_local_addresses: HashMap<String, HashSet<IpAddr>>,
    connections_by_inode: HashMap<u64, Vec<TcpConnection>>,
    inode_pids: HashMap<u64, Vec<u32>>,
    inode_owner_scan_complete: bool,
    listener_snapshot_loaded: bool,
    listener_namespace_scan_complete: bool,
    optional_table_errors: HashMap<ProcfsTcpTableFamily, AttributionError>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessNamespaceTcpListenerScan {
    listeners: Vec<ProcfsTcpListenerEntry>,
    namespace_local_addresses: HashMap<String, HashSet<IpAddr>>,
    complete: bool,
}

#[derive(Debug)]
pub struct ProcfsSocketResolver {
    attributor: ProcfsSocketAttributor,
    cache_ttl: Duration,
    snapshot: Option<CachedProcfsSocketSnapshot>,
}

#[derive(Debug)]
struct CachedProcfsSocketSnapshot {
    loaded_at: Instant,
    snapshot: ProcfsSocketSnapshot,
}

impl ProcfsSocketResolver {
    pub fn new() -> Self {
        Self {
            attributor: ProcfsSocketAttributor::new(),
            cache_ttl: DEFAULT_PROCFS_SOCKET_SNAPSHOT_TTL,
            snapshot: None,
        }
    }

    pub fn with_paths(
        proc_root: impl Into<std::path::PathBuf>,
        boot_id_path: impl Into<std::path::PathBuf>,
    ) -> Self {
        Self {
            attributor: ProcfsSocketAttributor::with_paths(proc_root, boot_id_path),
            cache_ttl: DEFAULT_PROCFS_SOCKET_SNAPSHOT_TTL,
            snapshot: None,
        }
    }

    pub fn with_cache_ttl(mut self, cache_ttl: Duration) -> Self {
        self.cache_ttl = cache_ttl;
        self
    }

    pub fn invalidate_snapshot(&mut self) {
        self.snapshot = None;
    }

    pub fn capabilities(&self) -> Vec<CapabilityState> {
        self.attributor.capabilities()
    }

    pub fn probe(&self) -> Result<(), AttributionError> {
        self.attributor.probe()
    }

    pub fn probe_tcp_listener_process_attribution(&self) -> Result<(), AttributionError> {
        self.attributor.probe_tcp_listener_process_attribution()
    }

    pub fn resolve_tcp_connection(
        &mut self,
        connection: TcpConnection,
    ) -> Result<Option<SocketProcessContext>, AttributionError> {
        self.refresh_snapshot_if_needed()?;
        let Some(snapshot) = self.snapshot.as_ref().map(|cached| &cached.snapshot) else {
            return Ok(None);
        };
        self.attributor
            .identify_tcp_connection_in_snapshot(connection, snapshot)
    }

    pub fn resolve_tcp_listeners_by_local_port(
        &mut self,
        local_port: u16,
    ) -> Result<TcpListenerProcessLookup, AttributionError> {
        self.refresh_listener_snapshot_if_needed()?;
        let Some(snapshot) = self.snapshot.as_ref().map(|cached| &cached.snapshot) else {
            return Ok(TcpListenerProcessLookup {
                listeners: Vec::new(),
                unattributed_listeners: Vec::new(),
            });
        };
        self.attributor
            .identify_tcp_listeners_by_local_port_in_snapshot(local_port, snapshot)
    }

    pub fn resolve_tcp_listeners_by_local_endpoint(
        &mut self,
        local_endpoint: TcpEndpoint,
    ) -> Result<TcpListenerProcessLookup, AttributionError> {
        self.refresh_listener_snapshot_if_needed()?;
        let Some(snapshot) = self.snapshot.as_ref().map(|cached| &cached.snapshot) else {
            return Ok(TcpListenerProcessLookup {
                listeners: Vec::new(),
                unattributed_listeners: Vec::new(),
            });
        };
        self.attributor
            .identify_tcp_listeners_by_local_endpoint_in_snapshot(local_endpoint, snapshot)
    }

    pub fn resolve_tcp_listeners(&mut self) -> Result<TcpListenerProcessLookup, AttributionError> {
        self.refresh_listener_snapshot_if_needed()?;
        let Some(snapshot) = self.snapshot.as_ref().map(|cached| &cached.snapshot) else {
            return Ok(TcpListenerProcessLookup {
                listeners: Vec::new(),
                unattributed_listeners: Vec::new(),
            });
        };
        self.attributor
            .identify_tcp_listeners_in_snapshot(None, snapshot)
    }

    pub fn resolve_tcp_fd(
        &mut self,
        lookup: SocketFdLookup,
    ) -> Result<Option<SocketFdConnectionContext>, AttributionError> {
        self.refresh_snapshot_if_needed()?;
        let Some(snapshot) = self.snapshot.as_ref().map(|cached| &cached.snapshot) else {
            return Ok(None);
        };
        self.attributor
            .identify_tcp_fd_in_snapshot(lookup, snapshot)
    }

    pub fn resolve_process(&self, pid: u32) -> Result<Option<ProcessContext>, AttributionError> {
        self.attributor.identify_process(pid)
    }

    pub fn resolve_processes_by_hint(
        &self,
        hint: SocketProcessHint,
    ) -> Result<Vec<ProcessContext>, AttributionError> {
        self.attributor.identify_processes_by_hint(&hint)
    }

    fn refresh_snapshot_if_needed(&mut self) -> Result<(), AttributionError> {
        if self.snapshot_needs_refresh() {
            self.snapshot = Some(CachedProcfsSocketSnapshot {
                loaded_at: Instant::now(),
                snapshot: self.attributor.base_snapshot()?,
            });
        }
        Ok(())
    }

    fn refresh_listener_snapshot_if_needed(&mut self) -> Result<(), AttributionError> {
        if self.snapshot_needs_refresh()
            || !self
                .snapshot
                .as_ref()
                .is_some_and(|cached| cached.snapshot.listener_snapshot_loaded)
        {
            self.snapshot = Some(CachedProcfsSocketSnapshot {
                loaded_at: Instant::now(),
                snapshot: self.attributor.listener_snapshot()?,
            });
        }
        Ok(())
    }

    fn snapshot_needs_refresh(&self) -> bool {
        self.snapshot
            .as_ref()
            .map(|snapshot| snapshot.loaded_at.elapsed() >= self.cache_ttl)
            .unwrap_or(true)
    }
}

impl Default for ProcfsSocketResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct ProcfsSocketAttributor {
    process_attributor: ProcfsAttributor,
}

impl ProcfsSocketAttributor {
    fn new() -> Self {
        Self {
            process_attributor: ProcfsAttributor::new(),
        }
    }

    fn with_paths(
        proc_root: impl Into<std::path::PathBuf>,
        boot_id_path: impl Into<std::path::PathBuf>,
    ) -> Self {
        Self {
            process_attributor: ProcfsAttributor::with_paths(proc_root, boot_id_path),
        }
    }

    fn identify_tcp_connection_in_snapshot(
        &self,
        connection: TcpConnection,
        snapshot: &ProcfsSocketSnapshot,
    ) -> Result<Option<SocketProcessContext>, AttributionError> {
        let Some(inode) = snapshot.tcp_inodes.get(&connection).copied() else {
            if connection_uses_family(connection, ProcfsTcpTableFamily::Ipv6)
                && let Some(error) = snapshot
                    .optional_table_errors
                    .get(&ProcfsTcpTableFamily::Ipv6)
                    .cloned()
            {
                return Err(error);
            }
            return Ok(None);
        };
        let Some(pid) = unique_inode_pid(&snapshot.inode_pids, inode) else {
            return Ok(None);
        };
        let process = match self.process_attributor.identify(pid) {
            Ok(process) => process,
            Err(error)
                if is_disappearing_process_error(
                    &error,
                    &self.process_attributor.proc_root,
                    pid,
                ) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        Ok(Some(SocketProcessContext {
            process,
            confidence: PROCFS_SOCKET_CONFIDENCE,
            socket_inode: inode,
        }))
    }

    fn identify_tcp_listeners_by_local_port_in_snapshot(
        &self,
        local_port: u16,
        snapshot: &ProcfsSocketSnapshot,
    ) -> Result<TcpListenerProcessLookup, AttributionError> {
        self.resolve_logical_listener_owners(
            self.identify_observed_tcp_listeners_in_snapshot(Some(local_port), snapshot)?,
            snapshot,
        )
    }

    fn identify_tcp_listeners_by_local_endpoint_in_snapshot(
        &self,
        local_endpoint: TcpEndpoint,
        snapshot: &ProcfsSocketSnapshot,
    ) -> Result<TcpListenerProcessLookup, AttributionError> {
        let lookup =
            self.identify_observed_tcp_listeners_in_snapshot(Some(local_endpoint.port), snapshot)?;
        let lookup = filter_listener_lookup_by_endpoint(lookup, local_endpoint, snapshot);
        self.resolve_logical_listener_owners(lookup, snapshot)
    }

    fn identify_tcp_listeners_in_snapshot(
        &self,
        local_port: Option<u16>,
        snapshot: &ProcfsSocketSnapshot,
    ) -> Result<TcpListenerProcessLookup, AttributionError> {
        self.resolve_logical_listener_owners(
            self.identify_observed_tcp_listeners_in_snapshot(local_port, snapshot)?,
            snapshot,
        )
    }

    fn identify_observed_tcp_listeners_in_snapshot(
        &self,
        local_port: Option<u16>,
        snapshot: &ProcfsSocketSnapshot,
    ) -> Result<TcpListenerProcessLookup, AttributionError> {
        if let Some(error) = snapshot
            .optional_table_errors
            .get(&ProcfsTcpTableFamily::Ipv6)
            .cloned()
        {
            return Err(error);
        }
        if !snapshot.inode_owner_scan_complete {
            return Err(AttributionError::IncompleteSocketOwnerScan {
                reason: "procfs fd scan skipped at least one process or socket fd because it was not readable".to_string(),
            });
        }

        let mut listeners = Vec::new();
        let mut unattributed_listeners = Vec::new();
        for listener in snapshot
            .tcp_listeners
            .iter()
            .filter(|listener| local_port.is_none_or(|port| listener.local.port == port))
        {
            let Some(pids) = snapshot.inode_pids.get(&listener.inode) else {
                push_unique_unattributed_listener(&mut unattributed_listeners, listener);
                continue;
            };
            for pid in pids {
                let process = match self.process_attributor.identify(*pid) {
                    Ok(process) => process,
                    Err(error)
                        if is_disappearing_process_error(
                            &error,
                            &self.process_attributor.proc_root,
                            *pid,
                        ) =>
                    {
                        push_unique_unattributed_listener(&mut unattributed_listeners, listener);
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                let observed = TcpListenerObservedSocket {
                    process,
                    confidence: PROCFS_SOCKET_CONFIDENCE,
                    socket_inode: listener.inode,
                    local: listener.local,
                };
                listeners.push(TcpListenerProcessContext::from_observed_socket(observed));
            }
        }
        Ok(TcpListenerProcessLookup {
            listeners,
            unattributed_listeners,
        })
    }

    fn resolve_docker_proxy_target_owner(
        &self,
        listener: &TcpListenerProcessContext,
        snapshot: &ProcfsSocketSnapshot,
    ) -> Result<Option<TcpListenerOwnerContext>, AttributionError> {
        let Some(target_endpoint) = docker_proxy_target_endpoint(&listener.observed.process) else {
            return Ok(None);
        };
        let lookup =
            self.identify_observed_tcp_listeners_in_snapshot(Some(target_endpoint.port), snapshot)?;
        let lookup = filter_listener_lookup_by_endpoint(lookup, target_endpoint, snapshot);
        if !lookup.unattributed_listeners.is_empty() {
            return Ok(None);
        }
        let [target] = lookup.listeners.as_slice() else {
            return Ok(None);
        };
        Ok(Some(TcpListenerOwnerContext {
            process: target.observed.process.clone(),
            confidence: target
                .observed
                .confidence
                .min(DOCKER_PROXY_TARGET_CONFIDENCE),
            source: TcpListenerOwnerSource::DockerProxyTarget {
                target_local: target_endpoint,
                target_socket_inode: target.observed.socket_inode,
            },
        }))
    }

    fn resolve_logical_listener_owners(
        &self,
        lookup: TcpListenerProcessLookup,
        snapshot: &ProcfsSocketSnapshot,
    ) -> Result<TcpListenerProcessLookup, AttributionError> {
        let mut listeners = Vec::with_capacity(lookup.listeners.len());
        for listener in lookup.listeners {
            if let Some(owner) = self.resolve_docker_proxy_target_owner(&listener, snapshot)? {
                listeners.push(listener.with_owner(owner));
            } else {
                listeners.push(listener);
            }
        }
        Ok(TcpListenerProcessLookup {
            listeners,
            unattributed_listeners: lookup.unattributed_listeners,
        })
    }

    fn identify_tcp_fd_in_snapshot(
        &self,
        lookup: SocketFdLookup,
        snapshot: &ProcfsSocketSnapshot,
    ) -> Result<Option<SocketFdConnectionContext>, AttributionError> {
        let candidate_scan =
            socket_fd_candidates_for_lookup(&self.process_attributor.proc_root, &lookup)?;
        if candidate_scan.complete
            && let Some(resolved) = self.identify_fd_candidates_in_snapshot(
                &candidate_scan.candidates,
                &lookup,
                snapshot,
            )?
        {
            return Ok(Some(resolved));
        }
        if !candidate_scan.candidates.is_empty() {
            if let Some(error) = optional_error_for_expected_remote(snapshot, &lookup) {
                return Err(error);
            }
            return Ok(None);
        }
        if let Some(error) = optional_error_for_expected_remote(snapshot, &lookup) {
            return Err(error);
        }
        Ok(None)
    }

    fn identify_process(&self, pid: u32) -> Result<Option<ProcessContext>, AttributionError> {
        self.process_attributor.identify_if_present(pid)
    }

    fn identify_processes_by_hint(
        &self,
        hint: &SocketProcessHint,
    ) -> Result<Vec<ProcessContext>, AttributionError> {
        let mut processes = Vec::new();
        for pid in self.process_attributor.process_ids()? {
            let Some(process) = self.process_attributor.identify_if_present(pid)? else {
                continue;
            };
            if !process_matches_hint(&process, hint) {
                continue;
            }
            if !processes
                .iter()
                .any(|existing: &ProcessContext| existing.identity == process.identity)
            {
                processes.push(process);
            }
        }
        Ok(processes)
    }

    fn identify_fd_candidates_in_snapshot(
        &self,
        candidates: &[SocketFdCandidate],
        lookup: &SocketFdLookup,
        snapshot: &ProcfsSocketSnapshot,
    ) -> Result<Option<SocketFdConnectionContext>, AttributionError> {
        let mut matched = None;
        for candidate in candidates {
            if candidate.source != SocketFdCandidateSource::Direct
                && lookup.expected_remote_endpoint.is_none()
            {
                continue;
            }
            let Some(connection) = tcp_connection_for_inode(
                snapshot,
                candidate.inode,
                lookup.expected_remote_endpoint,
            ) else {
                continue;
            };
            let Some(process) = self.identify_fd_candidate_process(candidate, lookup)? else {
                continue;
            };
            if let Some(hint) = &lookup.process_hint
                && !process_matches_hint(&process, hint)
            {
                continue;
            }
            let resolved = (
                process,
                candidate.source,
                candidate.inode,
                candidate.fd_pid,
                connection,
            );
            if matched.replace(resolved).is_some() {
                return Ok(None);
            }
        }
        Ok(
            matched.map(|(process, source, socket_inode, fd_pid, connection)| {
                SocketFdConnectionContext {
                    process,
                    confidence: fd_candidate_confidence(source),
                    socket_inode,
                    socket_cookie: read_socket_cookie_for_pid_fd(
                        &self.process_attributor.proc_root,
                        fd_pid,
                        lookup.fd,
                        socket_inode,
                    ),
                    connection,
                }
            }),
        )
    }

    fn identify_fd_candidate_process(
        &self,
        candidate: &SocketFdCandidate,
        lookup: &SocketFdLookup,
    ) -> Result<Option<ProcessContext>, AttributionError> {
        let Some(process) = self.identify_candidate_pid(candidate.process_pid)? else {
            return Ok(None);
        };
        if candidate.source != SocketFdCandidateSource::Direct
            || candidate.process_pid == lookup.tgid
        {
            return Ok(Some(process));
        }
        if process.identity.tgid != lookup.tgid {
            return Ok(None);
        }
        self.identify_candidate_pid(lookup.tgid)
    }

    fn identify_candidate_pid(&self, pid: u32) -> Result<Option<ProcessContext>, AttributionError> {
        match self.process_attributor.identify(pid) {
            Ok(process) => Ok(Some(process)),
            Err(error)
                if is_disappearing_process_error(
                    &error,
                    &self.process_attributor.proc_root,
                    pid,
                ) =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    fn capabilities(&self) -> Vec<CapabilityState> {
        match self.probe() {
            Ok(()) => vec![CapabilityState::degraded(
                CapabilityKind::ProcfsSocketAttribution,
                "procfs socket attribution can read /proc/net/tcp and proc root, opportunistically reads /proc/net/tcp6, resolves fd lookups through procfs PID namespace aliases, maps docker-proxy published listeners to the target container listener when the command line exposes the container endpoint, captures SO_COOKIE for live socket fd lookups when pidfd_getfd is permitted and the duplicated fd inode still matches, and can use unique fd/process-hint candidates when observed kernel PIDs are hidden or collide with unrelated host PIDs; fd races, hidepid, namespace boundaries, and PID reuse remain possible",
            )],
            Err(error) => vec![CapabilityState::unavailable(
                CapabilityKind::ProcfsSocketAttribution,
                error.to_string(),
            )],
        }
    }

    fn probe(&self) -> Result<(), AttributionError> {
        for table in procfs_tcp_tables(&self.process_attributor.proc_root) {
            if let Err(error) = read_tcp_table_to_string(&table)
                && table.policy == ProcfsTcpTablePolicy::Required
            {
                return Err(error);
            }
        }
        fs::read_dir(&self.process_attributor.proc_root).map_err(|source| {
            AttributionError::Read {
                path: self.process_attributor.proc_root.display().to_string(),
                source,
            }
        })?;
        Ok(())
    }

    fn probe_tcp_listener_process_attribution(&self) -> Result<(), AttributionError> {
        let snapshot = self.listener_snapshot()?;
        if let Some(error) = snapshot
            .optional_table_errors
            .get(&ProcfsTcpTableFamily::Ipv6)
            .cloned()
        {
            return Err(error);
        }
        if !snapshot.inode_owner_scan_complete {
            return Err(AttributionError::IncompleteSocketOwnerScan {
                reason: "procfs fd scan skipped at least one process or socket fd because it was not readable".to_string(),
            });
        }
        if !snapshot.listener_namespace_scan_complete {
            return Err(AttributionError::IncompleteSocketOwnerScan {
                reason: "procfs listener namespace scan skipped at least one process namespace because it was not readable".to_string(),
            });
        }
        Ok(())
    }

    fn base_snapshot(&self) -> Result<ProcfsSocketSnapshot, AttributionError> {
        let mut tcp_inodes = HashMap::new();
        let mut tcp_listeners = Vec::new();
        let mut optional_table_errors = HashMap::new();
        for table in procfs_tcp_tables(&self.process_attributor.proc_root) {
            let content = match read_tcp_table_to_string(&table) {
                Ok(content) => content,
                Err(error) if table.policy == ProcfsTcpTablePolicy::OptionalBestEffort => {
                    optional_table_errors.insert(table.family, error);
                    continue;
                }
                Err(error) => return Err(error),
            };
            match tcp_entries_from_table(&table, &content) {
                Ok(entries) => {
                    tcp_inodes.extend(tcp_inode_map_from_entries(&entries));
                    tcp_listeners.extend(tcp_listener_entries_from_entries(&entries));
                }
                Err(error) if table.policy == ProcfsTcpTablePolicy::OptionalBestEffort => {
                    optional_table_errors.insert(table.family, error);
                }
                Err(error) => return Err(error),
            }
        }
        let owner_scan = socket_inode_owner_scan(&self.process_attributor.proc_root)?;
        Ok(ProcfsSocketSnapshot {
            connections_by_inode: connections_by_inode(&tcp_inodes),
            tcp_inodes,
            tcp_listeners,
            namespace_local_addresses: HashMap::new(),
            inode_pids: owner_scan.pids_by_inode,
            inode_owner_scan_complete: owner_scan.complete,
            listener_snapshot_loaded: false,
            listener_namespace_scan_complete: false,
            optional_table_errors,
        })
    }

    fn listener_snapshot(&self) -> Result<ProcfsSocketSnapshot, AttributionError> {
        let mut snapshot = self.base_snapshot()?;
        let process_namespace_listener_scan =
            process_namespace_tcp_listener_entries(&self.process_attributor.proc_root)?;
        for listener in process_namespace_listener_scan.listeners {
            push_unique_listener(&mut snapshot.tcp_listeners, listener);
        }
        snapshot.namespace_local_addresses =
            process_namespace_listener_scan.namespace_local_addresses;
        snapshot.listener_snapshot_loaded = true;
        snapshot.listener_namespace_scan_complete = process_namespace_listener_scan.complete;
        Ok(snapshot)
    }
}

impl Default for ProcfsSocketAttributor {
    fn default() -> Self {
        Self::new()
    }
}

fn tcp_connection_for_inode(
    snapshot: &ProcfsSocketSnapshot,
    inode: u64,
    expected_remote_endpoint: Option<TcpEndpoint>,
) -> Option<TcpConnection> {
    snapshot
        .connections_by_inode
        .get(&inode)?
        .iter()
        .copied()
        .find(|connection| {
            expected_remote_endpoint
                .map(|remote| connection.remote == remote)
                .unwrap_or(true)
        })
}

fn unique_inode_pid(inode_pids: &HashMap<u64, Vec<u32>>, inode: u64) -> Option<u32> {
    let [pid] = inode_pids.get(&inode)?.as_slice() else {
        return None;
    };
    Some(*pid)
}

fn process_matches_hint(process: &ProcessContext, hint: &SocketProcessHint) -> bool {
    process.identity.uid == hint.uid
        && process.identity.gid == hint.gid
        && process.name == hint.name
}

fn fd_candidate_confidence(source: SocketFdCandidateSource) -> u8 {
    match source {
        SocketFdCandidateSource::Direct => PROCFS_SOCKET_CONFIDENCE,
        SocketFdCandidateSource::NamespaceAlias | SocketFdCandidateSource::ProcessHint => {
            PROCFS_HINTED_FD_CONFIDENCE
        }
    }
}

fn optional_error_for_expected_remote(
    snapshot: &ProcfsSocketSnapshot,
    lookup: &SocketFdLookup,
) -> Option<AttributionError> {
    let remote = lookup.expected_remote_endpoint?;
    endpoint_uses_family(remote, ProcfsTcpTableFamily::Ipv6)
        .then(|| {
            snapshot
                .optional_table_errors
                .get(&ProcfsTcpTableFamily::Ipv6)
                .cloned()
        })
        .flatten()
}

fn push_unique_listener(
    listeners: &mut Vec<ProcfsTcpListenerEntry>,
    listener: ProcfsTcpListenerEntry,
) {
    if let Some(existing) = listeners
        .iter_mut()
        .find(|existing| existing.local == listener.local && existing.inode == listener.inode)
    {
        if existing.namespace.is_none() && listener.namespace.is_some() {
            existing.namespace = listener.namespace;
        }
        return;
    }
    listeners.push(listener);
}

fn push_unique_unattributed_listener(
    listeners: &mut Vec<TcpUnattributedListener>,
    listener: &ProcfsTcpListenerEntry,
) {
    let unattributed = TcpUnattributedListener {
        socket_inode: listener.inode,
        local: listener.local,
    };
    if !listeners.contains(&unattributed) {
        listeners.push(unattributed);
    }
}

fn filter_listener_lookup_by_endpoint(
    lookup: TcpListenerProcessLookup,
    observed: TcpEndpoint,
    snapshot: &ProcfsSocketSnapshot,
) -> TcpListenerProcessLookup {
    let (rank, mut candidates) = best_ranked_listener_matches(&lookup, observed, snapshot);
    if rank.is_some_and(ListenerEndpointMatchRank::requires_unique_logical_listener) {
        retain_unique_logical_listener(&mut candidates);
    }
    lookup.select_endpoint_candidates(&candidates)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ListenerEndpointMatchRank {
    CrossFamilyWildcard,
    SameFamilyWildcard,
    CrossFamilyNamespaceWildcard,
    SameFamilyNamespaceWildcard,
    Exact,
}

impl ListenerEndpointMatchRank {
    fn requires_unique_logical_listener(self) -> bool {
        matches!(self, Self::SameFamilyWildcard | Self::CrossFamilyWildcard)
    }
}

fn best_ranked_listener_matches(
    lookup: &TcpListenerProcessLookup,
    observed: TcpEndpoint,
    snapshot: &ProcfsSocketSnapshot,
) -> (
    Option<ListenerEndpointMatchRank>,
    Vec<TcpListenerEndpointCandidate>,
) {
    let mut best_rank = None;
    let mut best_candidates = Vec::new();
    for candidate in lookup.endpoint_candidates() {
        let Some(rank) = listener_endpoint_match_rank(&candidate, observed, snapshot) else {
            continue;
        };
        if best_rank.is_none_or(|best| rank > best) {
            best_rank = Some(rank);
            best_candidates.clear();
        }
        if best_rank == Some(rank) {
            best_candidates.push(candidate);
        }
    }
    (best_rank, best_candidates)
}

fn listener_endpoint_match_rank(
    candidate: &TcpListenerEndpointCandidate,
    observed: TcpEndpoint,
    snapshot: &ProcfsSocketSnapshot,
) -> Option<ListenerEndpointMatchRank> {
    let listener_local = candidate.local;
    if listener_local.port != observed.port {
        return None;
    }
    if listener_local.address == observed.address {
        return Some(ListenerEndpointMatchRank::Exact);
    }
    if !listener_local.address.is_unspecified()
        || !listener_wildcard_matches_observed_family(listener_local, observed)
    {
        return None;
    }
    let same_family = listener_wildcard_same_family(listener_local, observed);
    if listener_namespace_contains_address(
        listener_local,
        candidate.socket_inode,
        observed.address,
        snapshot,
    ) {
        if same_family {
            Some(ListenerEndpointMatchRank::SameFamilyNamespaceWildcard)
        } else {
            Some(ListenerEndpointMatchRank::CrossFamilyNamespaceWildcard)
        }
    } else if same_family {
        Some(ListenerEndpointMatchRank::SameFamilyWildcard)
    } else {
        Some(ListenerEndpointMatchRank::CrossFamilyWildcard)
    }
}

fn listener_wildcard_same_family(listener_local: TcpEndpoint, observed: TcpEndpoint) -> bool {
    endpoint_uses_family(listener_local, ProcfsTcpTableFamily::Ipv4)
        && endpoint_uses_family(observed, ProcfsTcpTableFamily::Ipv4)
        || endpoint_uses_family(listener_local, ProcfsTcpTableFamily::Ipv6)
            && endpoint_uses_family(observed, ProcfsTcpTableFamily::Ipv6)
}

fn listener_wildcard_matches_observed_family(
    listener_local: TcpEndpoint,
    observed: TcpEndpoint,
) -> bool {
    if endpoint_uses_family(listener_local, ProcfsTcpTableFamily::Ipv4) {
        return endpoint_uses_family(observed, ProcfsTcpTableFamily::Ipv4);
    }
    if endpoint_uses_family(listener_local, ProcfsTcpTableFamily::Ipv6) {
        return true;
    }
    false
}

fn retain_unique_logical_listener(candidates: &mut Vec<TcpListenerEndpointCandidate>) {
    let mut identities = Vec::new();
    for candidate in candidates.iter() {
        let identity = (candidate.local, candidate.socket_inode);
        if !identities.contains(&identity) {
            identities.push(identity);
        }
    }
    if identities.len() != 1 {
        candidates.clear();
    }
}

fn listener_namespace_contains_address(
    listener_local: TcpEndpoint,
    listener_inode: u64,
    observed_address: IpAddr,
    snapshot: &ProcfsSocketSnapshot,
) -> bool {
    snapshot
        .tcp_listeners
        .iter()
        .find(|entry| entry.local == listener_local && entry.inode == listener_inode)
        .and_then(|entry| entry.namespace.as_ref())
        .and_then(|namespace| snapshot.namespace_local_addresses.get(namespace))
        .is_some_and(|addresses| addresses.contains(&observed_address))
}

fn process_namespace_tcp_listener_entries(
    proc_root: &Path,
) -> Result<ProcessNamespaceTcpListenerScan, AttributionError> {
    let mut listeners = Vec::new();
    let mut namespace_local_addresses = HashMap::new();
    let mut seen_namespaces = HashSet::new();
    let mut complete = true;
    for ProcfsPidEntry { path, .. } in numeric_pid_dirs(proc_root)? {
        let namespace_path = path.join("ns/net");
        let namespace = match fs::read_link(&namespace_path) {
            Ok(namespace) => namespace.display().to_string(),
            Err(source) if is_disappearing_process_error_kind(&source) => continue,
            Err(source) if source.kind() == io::ErrorKind::PermissionDenied => {
                complete = false;
                continue;
            }
            Err(source) => {
                return Err(AttributionError::ReadLink {
                    path: namespace_path.display().to_string(),
                    source,
                });
            }
        };
        if !seen_namespaces.insert(namespace.clone()) {
            continue;
        }
        append_process_namespace_tcp_listeners(
            &path,
            &namespace,
            &mut listeners,
            &mut namespace_local_addresses,
        )
        .map(|namespace_complete| {
            complete &= namespace_complete;
        })?;
    }
    Ok(ProcessNamespaceTcpListenerScan {
        listeners,
        namespace_local_addresses,
        complete,
    })
}

fn append_process_namespace_tcp_listeners(
    process_root: &Path,
    namespace: &str,
    listeners: &mut Vec<ProcfsTcpListenerEntry>,
    namespace_local_addresses: &mut HashMap<String, HashSet<IpAddr>>,
) -> Result<bool, AttributionError> {
    let mut complete = true;
    for table in procfs_tcp_tables(process_root) {
        let content = match read_tcp_table_to_string(&table) {
            Ok(content) => content,
            Err(_) if table.policy == ProcfsTcpTablePolicy::OptionalBestEffort => continue,
            Err(AttributionError::Read { source, .. })
                if is_disappearing_process_error_kind(&source) =>
            {
                return Ok(complete);
            }
            Err(AttributionError::Read { source, .. })
                if source.kind() == io::ErrorKind::PermissionDenied =>
            {
                complete = false;
                continue;
            }
            Err(error) => return Err(error),
        };
        match tcp_entries_from_table(&table, &content) {
            Ok(entries) => {
                namespace_local_addresses
                    .entry(namespace.to_string())
                    .or_default()
                    .extend(tcp_local_addresses_from_entries(&entries));
                for listener in tcp_listener_entries_from_entries_with_namespace(
                    &entries,
                    Some(namespace.to_string()),
                ) {
                    push_unique_listener(listeners, listener);
                }
            }
            Err(_) if table.policy == ProcfsTcpTablePolicy::OptionalBestEffort => {}
            Err(error) => return Err(error),
        }
    }
    Ok(complete)
}

fn is_disappearing_process_error(error: &AttributionError, proc_root: &Path, pid: u32) -> bool {
    let pid_path = proc_root.join(pid.to_string());
    match error {
        AttributionError::Read { path, source } | AttributionError::ReadLink { path, source } => {
            source.kind() == io::ErrorKind::NotFound && Path::new(path).starts_with(pid_path)
        }
        AttributionError::InvalidStat { .. }
        | AttributionError::InvalidStatus { .. }
        | AttributionError::InvalidNetTcp { .. }
        | AttributionError::IncompleteSocketOwnerScan { .. } => false,
    }
}

fn is_disappearing_process_error_kind(source: &io::Error) -> bool {
    source.kind() == io::ErrorKind::NotFound || source.raw_os_error() == Some(3)
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::symlink, path::Path};

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn resolves_tcp_listener_process_by_local_port() -> Result<(), Box<dyn std::error::Error>> {
        let proc = FakeProc::new()?;
        proc.write_tcp_table(&[
            tcp_line(0, "0100007F:20FB", "00000000:0000", "0A", 424_242),
            tcp_line(1, "0100007F:20FB", "0100007F:CAFE", "01", 111_111),
        ])?;
        proc.write_process_with_socket(321, "demo-listener", 424_242)?;
        let mut resolver = ProcfsSocketResolver::with_paths(proc.root(), proc.boot_id_path());

        let lookup = resolver.resolve_tcp_listeners_by_local_port(8443)?;

        assert!(lookup.unattributed_listeners.is_empty());
        let [listener] = lookup.listeners.as_slice() else {
            panic!("expected one attributed listener: {lookup:?}");
        };
        assert_eq!(listener.owner.process.identity.pid, 321);
        assert_eq!(listener.owner.process.name, "demo-listener");
        assert_eq!(listener.observed.socket_inode, 424_242);
        assert_eq!(listener.observed.local.port, 8443);
        Ok(())
    }

    #[test]
    fn reports_unattributed_tcp_listener_inode() -> Result<(), Box<dyn std::error::Error>> {
        let proc = FakeProc::new()?;
        proc.write_tcp_table(&[tcp_line(0, "0100007F:20FB", "00000000:0000", "0A", 424_242)])?;
        let mut resolver = ProcfsSocketResolver::with_paths(proc.root(), proc.boot_id_path());

        let lookup = resolver.resolve_tcp_listeners_by_local_port(8443)?;

        assert!(lookup.listeners.is_empty());
        assert_eq!(
            lookup.unattributed_listeners,
            vec![unattributed_listener("127.0.0.1".parse()?, 8443, 424_242)]
        );
        Ok(())
    }

    #[test]
    fn resolves_all_tcp_listener_socket_holders() -> Result<(), Box<dyn std::error::Error>> {
        let proc = FakeProc::new()?;
        proc.write_tcp_table(&[tcp_line(0, "0100007F:20FB", "00000000:0000", "0A", 424_242)])?;
        proc.write_process_with_socket(321, "first-listener", 424_242)?;
        proc.write_process_with_socket(654, "second-listener", 424_242)?;
        let mut resolver = ProcfsSocketResolver::with_paths(proc.root(), proc.boot_id_path());

        let lookup = resolver.resolve_tcp_listeners_by_local_port(8443)?;

        assert!(lookup.unattributed_listeners.is_empty());
        let mut pids = lookup
            .listeners
            .iter()
            .map(|listener| listener.owner.process.identity.pid)
            .collect::<Vec<_>>();
        pids.sort_unstable();
        assert_eq!(pids, vec![321, 654]);
        assert!(
            lookup
                .listeners
                .iter()
                .all(|listener| listener.observed.socket_inode == 424_242)
        );
        Ok(())
    }

    #[test]
    fn resolves_tcp_listener_from_process_network_namespace()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = FakeProc::new()?;
        proc.write_tcp_table(&[])?;
        proc.write_process_with_socket(321, "container-api", 424_242)?;
        proc.write_process_tcp_table(
            321,
            "net:[4026532661]",
            &[tcp_line(0, "00000000:1F90", "00000000:0000", "0A", 424_242)],
        )?;
        let mut resolver = ProcfsSocketResolver::with_paths(proc.root(), proc.boot_id_path());

        let lookup = resolver.resolve_tcp_listeners_by_local_port(8080)?;

        assert!(lookup.unattributed_listeners.is_empty());
        let [listener] = lookup.listeners.as_slice() else {
            panic!("expected one process-namespace listener: {lookup:?}");
        };
        assert_eq!(listener.owner.process.identity.pid, 321);
        assert_eq!(listener.owner.process.name, "container-api");
        assert_eq!(listener.observed.socket_inode, 424_242);
        assert_eq!(listener.observed.local.port, 8080);
        Ok(())
    }

    #[test]
    fn resolves_processes_by_hint_from_visible_procfs_processes()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = FakeProc::new()?;
        proc.write_process_with_socket(321, "python3", 424_242)?;
        proc.write_process_with_socket(654, "other-worker", 535_353)?;
        let resolver = ProcfsSocketResolver::with_paths(proc.root(), proc.boot_id_path());

        let processes = resolver.resolve_processes_by_hint(SocketProcessHint {
            name: "python3".to_string(),
            uid: 1000,
            gid: 1000,
        })?;

        let [process] = processes.as_slice() else {
            panic!("expected one process from hint: {processes:?}");
        };
        assert_eq!(process.identity.pid, 321);
        assert_eq!(process.name, "python3");
        Ok(())
    }

    #[test]
    fn tcp_fd_lookup_uses_process_hint_when_observed_tgid_collides_with_visible_host_pid()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = FakeProc::new()?;
        proc.write_tcp_table(&[
            tcp_line(0, "0100007F:1F90", "0100007F:CAFE", "01", 111_111),
            tcp_line(1, "0100007F:20FB", "0100007F:CAFE", "01", 424_242),
        ])?;
        proc.write_process_with_socket(832, "unrelated-host", 111_111)?;
        proc.write_process_with_socket(321, "traffic-probe-e", 424_242)?;
        let mut resolver = ProcfsSocketResolver::with_paths(proc.root(), proc.boot_id_path());

        let resolved = resolver
            .resolve_tcp_fd(SocketFdLookup {
                tgid: 832,
                thread_pid: 832,
                fd: 7,
                expected_remote_endpoint: Some(TcpEndpoint::new("127.0.0.1".parse()?, 51966)),
                process_hint: Some(SocketProcessHint {
                    name: "traffic-probe-e".to_string(),
                    uid: 1000,
                    gid: 1000,
                }),
            })?
            .expect("hinted host-visible process fd should resolve");

        assert_eq!(resolved.process.identity.pid, 321);
        assert_eq!(resolved.process.name, "traffic-probe-e");
        assert_eq!(resolved.socket_inode, 424_242);
        assert_eq!(resolved.connection.local.port, 8443);
        assert_eq!(resolved.connection.remote.port, 51966);
        Ok(())
    }

    #[test]
    fn tcp_fd_lookup_does_not_splice_thread_fd_with_tgid_process_hint()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = FakeProc::new()?;
        proc.write_tcp_table(&[
            tcp_line(0, "0100007F:1F90", "0100007F:CAFE", "01", 111_111),
            tcp_line(1, "0100007F:20FB", "0100007F:BEEF", "01", 424_242),
        ])?;
        proc.write_process_with_socket(832, "traffic-probe-e", 424_242)?;
        proc.write_process_with_socket(900, "unrelated-thread", 111_111)?;
        let mut resolver = ProcfsSocketResolver::with_paths(proc.root(), proc.boot_id_path());

        let resolved = resolver.resolve_tcp_fd(SocketFdLookup {
            tgid: 832,
            thread_pid: 900,
            fd: 7,
            expected_remote_endpoint: Some(TcpEndpoint::new("127.0.0.1".parse()?, 51966)),
            process_hint: Some(SocketProcessHint {
                name: "traffic-probe-e".to_string(),
                uid: 1000,
                gid: 1000,
            }),
        })?;

        assert!(resolved.is_none());
        Ok(())
    }

    #[test]
    fn tcp_fd_lookup_normalizes_verified_thread_fd_to_tgid_process()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = FakeProc::new()?;
        proc.write_tcp_table(&[
            tcp_line(0, "0100007F:1F90", "0100007F:CAFE", "01", 111_111),
            tcp_line(1, "0100007F:20FB", "0100007F:BEEF", "01", 424_242),
        ])?;
        proc.write_process_with_socket(832, "traffic-probe-e", 424_242)?;
        proc.write_process_thread_with_socket(900, 832, "worker-thread", 111_111)?;
        let mut resolver = ProcfsSocketResolver::with_paths(proc.root(), proc.boot_id_path());

        let resolved = resolver
            .resolve_tcp_fd(SocketFdLookup {
                tgid: 832,
                thread_pid: 900,
                fd: 7,
                expected_remote_endpoint: Some(TcpEndpoint::new("127.0.0.1".parse()?, 51966)),
                process_hint: Some(SocketProcessHint {
                    name: "traffic-probe-e".to_string(),
                    uid: 1000,
                    gid: 1000,
                }),
            })?
            .expect("verified thread fd should resolve to the process identity");

        assert_eq!(resolved.process.identity.pid, 832);
        assert_eq!(resolved.process.identity.tgid, 832);
        assert_eq!(resolved.process.name, "traffic-probe-e");
        assert_eq!(resolved.socket_inode, 111_111);
        assert_eq!(resolved.connection.local.port, 8080);
        assert_eq!(resolved.connection.remote.port, 51966);
        Ok(())
    }

    #[test]
    fn endpoint_listener_lookup_uses_process_namespace_addresses()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = FakeProc::new()?;
        proc.write_tcp_table(&[])?;
        proc.write_process_with_socket(321, "target-api", 424_242)?;
        proc.write_process_tcp_table(
            321,
            "net:[4026532661]",
            &[
                tcp_line(0, "00000000:1F90", "00000000:0000", "0A", 424_242),
                tcp_line(1, "030013AC:1F90", "010013AC:C001", "01", 111_111),
            ],
        )?;
        proc.write_process_with_socket(654, "other-api", 535_353)?;
        proc.write_process_tcp_table(
            654,
            "net:[4026532777]",
            &[
                tcp_line(0, "00000000:1F90", "00000000:0000", "0A", 535_353),
                tcp_line(1, "020014AC:1F90", "010014AC:C001", "01", 222_222),
            ],
        )?;
        let mut resolver = ProcfsSocketResolver::with_paths(proc.root(), proc.boot_id_path());

        let lookup = resolver.resolve_tcp_listeners_by_local_endpoint(TcpEndpoint::new(
            "172.19.0.3".parse()?,
            8080,
        ))?;

        let [listener] = lookup.listeners.as_slice() else {
            panic!("expected one endpoint-matched listener: {lookup:?}");
        };
        assert_eq!(listener.owner.process.identity.pid, 321);
        assert_eq!(listener.owner.process.name, "target-api");
        assert_eq!(listener.observed.socket_inode, 424_242);
        Ok(())
    }

    #[test]
    fn endpoint_listener_lookup_filters_unattributed_listeners_by_endpoint()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = FakeProc::new()?;
        proc.write_tcp_table(&[
            tcp_line(0, "0100007F:1F90", "00000000:0000", "0A", 424_242),
            tcp_line(1, "0200007F:1F90", "00000000:0000", "0A", 535_353),
        ])?;
        proc.write_process_with_socket(321, "target-api", 424_242)?;
        let mut resolver = ProcfsSocketResolver::with_paths(proc.root(), proc.boot_id_path());

        let lookup = resolver.resolve_tcp_listeners_by_local_endpoint(TcpEndpoint::new(
            "127.0.0.1".parse()?,
            8080,
        ))?;

        assert!(lookup.unattributed_listeners.is_empty());
        let [listener] = lookup.listeners.as_slice() else {
            panic!("expected endpoint-matched listener: {lookup:?}");
        };
        assert_eq!(listener.owner.process.identity.pid, 321);
        assert_eq!(listener.owner.process.name, "target-api");
        assert_eq!(listener.observed.socket_inode, 424_242);
        Ok(())
    }

    #[test]
    fn endpoint_listener_lookup_prefers_exact_listener_over_unattributed_wildcard()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = FakeProc::new()?;
        proc.write_tcp_table(&[
            tcp_line(0, "0100007F:1F90", "00000000:0000", "0A", 424_242),
            tcp_line(1, "00000000:1F90", "00000000:0000", "0A", 535_353),
        ])?;
        proc.write_process_with_socket(321, "target-api", 424_242)?;
        let mut resolver = ProcfsSocketResolver::with_paths(proc.root(), proc.boot_id_path());

        let lookup = resolver.resolve_tcp_listeners_by_local_endpoint(TcpEndpoint::new(
            "127.0.0.1".parse()?,
            8080,
        ))?;

        assert!(lookup.unattributed_listeners.is_empty());
        let [listener] = lookup.listeners.as_slice() else {
            panic!("expected exact listener to outrank wildcard listener: {lookup:?}");
        };
        assert_eq!(listener.owner.process.identity.pid, 321);
        assert_eq!(listener.owner.process.name, "target-api");
        assert_eq!(listener.observed.socket_inode, 424_242);
        Ok(())
    }

    #[test]
    fn endpoint_listener_lookup_preserves_namespace_wildcard_socket_holders()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = FakeProc::new()?;
        proc.write_tcp_table(&[])?;
        proc.write_process_with_socket(321, "first-worker", 424_242)?;
        proc.write_process_tcp_table(
            321,
            "net:[4026532661]",
            &[
                tcp_line(0, "00000000:1F90", "00000000:0000", "0A", 424_242),
                tcp_line(1, "030013AC:1F90", "010013AC:C001", "01", 111_111),
            ],
        )?;
        proc.write_process_with_socket(654, "second-worker", 424_242)?;
        proc.write_process_tcp_table(
            654,
            "net:[4026532661]",
            &[tcp_line(0, "00000000:1F90", "00000000:0000", "0A", 424_242)],
        )?;
        let mut resolver = ProcfsSocketResolver::with_paths(proc.root(), proc.boot_id_path());

        let lookup = resolver.resolve_tcp_listeners_by_local_endpoint(TcpEndpoint::new(
            "172.19.0.3".parse()?,
            8080,
        ))?;

        let mut pids = lookup
            .listeners
            .iter()
            .map(|listener| listener.owner.process.identity.pid)
            .collect::<Vec<_>>();
        pids.sort_unstable();
        assert_eq!(pids, vec![321, 654]);
        assert!(
            lookup
                .listeners
                .iter()
                .all(|listener| listener.observed.socket_inode == 424_242)
        );
        Ok(())
    }

    #[test]
    fn endpoint_listener_lookup_merges_namespace_for_host_table_listener()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = FakeProc::new()?;
        proc.write_tcp_table(&[tcp_line(0, "00000000:1F90", "00000000:0000", "0A", 424_242)])?;
        proc.write_process_with_socket(321, "host-api", 424_242)?;
        proc.write_process_tcp_table(
            321,
            "net:[4026532661]",
            &[
                tcp_line(0, "00000000:1F90", "00000000:0000", "0A", 424_242),
                tcp_line(1, "030013AC:1F90", "010013AC:C001", "01", 111_111),
            ],
        )?;
        let mut resolver = ProcfsSocketResolver::with_paths(proc.root(), proc.boot_id_path());

        let lookup = resolver.resolve_tcp_listeners_by_local_endpoint(TcpEndpoint::new(
            "172.19.0.3".parse()?,
            8080,
        ))?;

        let [listener] = lookup.listeners.as_slice() else {
            panic!("expected namespace-merged listener: {lookup:?}");
        };
        assert_eq!(listener.owner.process.identity.pid, 321);
        assert_eq!(listener.owner.process.name, "host-api");
        assert_eq!(listener.observed.socket_inode, 424_242);
        Ok(())
    }

    #[test]
    fn endpoint_listener_lookup_uses_unique_wildcard_socket_with_multiple_holders()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = FakeProc::new()?;
        proc.write_tcp_table(&[tcp_line(0, "00000000:1F90", "00000000:0000", "0A", 424_242)])?;
        proc.write_process_with_socket(321, "first-worker", 424_242)?;
        proc.write_process_with_socket(654, "second-worker", 424_242)?;
        let mut resolver = ProcfsSocketResolver::with_paths(proc.root(), proc.boot_id_path());

        let lookup = resolver.resolve_tcp_listeners_by_local_endpoint(TcpEndpoint::new(
            "172.19.0.3".parse()?,
            8080,
        ))?;

        let mut pids = lookup
            .listeners
            .iter()
            .map(|listener| listener.owner.process.identity.pid)
            .collect::<Vec<_>>();
        pids.sort_unstable();
        assert_eq!(pids, vec![321, 654]);
        assert!(
            lookup
                .listeners
                .iter()
                .all(|listener| listener.observed.socket_inode == 424_242)
        );
        Ok(())
    }

    #[test]
    fn endpoint_listener_lookup_uses_unique_wildcard_listener_when_address_is_unknown()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = FakeProc::new()?;
        proc.write_tcp_table(&[tcp_line(0, "00000000:1F90", "00000000:0000", "0A", 424_242)])?;
        proc.write_process_with_socket(321, "wildcard-api", 424_242)?;
        let mut resolver = ProcfsSocketResolver::with_paths(proc.root(), proc.boot_id_path());

        let lookup = resolver.resolve_tcp_listeners_by_local_endpoint(TcpEndpoint::new(
            "172.19.0.3".parse()?,
            8080,
        ))?;

        let [listener] = lookup.listeners.as_slice() else {
            panic!("expected unique wildcard listener fallback: {lookup:?}");
        };
        assert_eq!(listener.owner.process.identity.pid, 321);
        assert_eq!(listener.owner.process.name, "wildcard-api");
        assert_eq!(listener.observed.socket_inode, 424_242);
        Ok(())
    }

    #[test]
    fn endpoint_listener_lookup_accepts_ipv6_wildcard_for_ipv4_endpoint()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = FakeProc::new()?;
        proc.write_tcp_table(&[])?;
        proc.write_tcp6_table(&[tcp_line(
            0,
            "00000000000000000000000000000000:1F90",
            "00000000000000000000000000000000:0000",
            "0A",
            424_242,
        )])?;
        proc.write_process_with_socket(321, "dual-stack-api", 424_242)?;
        let mut resolver = ProcfsSocketResolver::with_paths(proc.root(), proc.boot_id_path());

        let lookup = resolver.resolve_tcp_listeners_by_local_endpoint(TcpEndpoint::new(
            "172.19.0.3".parse()?,
            8080,
        ))?;

        let [listener] = lookup.listeners.as_slice() else {
            panic!("expected dual-stack wildcard listener fallback: {lookup:?}");
        };
        assert_eq!(listener.owner.process.identity.pid, 321);
        assert_eq!(listener.owner.process.name, "dual-stack-api");
        assert_eq!(listener.observed.socket_inode, 424_242);
        Ok(())
    }

    #[test]
    fn endpoint_listener_lookup_prefers_same_family_wildcard_for_ipv4_endpoint()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = FakeProc::new()?;
        proc.write_tcp_table(&[tcp_line(0, "00000000:1F90", "00000000:0000", "0A", 424_242)])?;
        proc.write_tcp6_table(&[tcp_line(
            0,
            "00000000000000000000000000000000:1F90",
            "00000000000000000000000000000000:0000",
            "0A",
            535_353,
        )])?;
        proc.write_process_with_socket(321, "ipv4-api", 424_242)?;
        proc.write_process_with_socket(654, "ipv6-api", 535_353)?;
        let mut resolver = ProcfsSocketResolver::with_paths(proc.root(), proc.boot_id_path());

        let lookup = resolver.resolve_tcp_listeners_by_local_endpoint(TcpEndpoint::new(
            "172.19.0.3".parse()?,
            8080,
        ))?;

        let [listener] = lookup.listeners.as_slice() else {
            panic!("expected IPv4 wildcard listener preference: {lookup:?}");
        };
        assert_eq!(listener.owner.process.identity.pid, 321);
        assert_eq!(listener.owner.process.name, "ipv4-api");
        assert_eq!(listener.observed.socket_inode, 424_242);
        Ok(())
    }

    #[test]
    fn docker_proxy_listener_resolution_prefers_container_process_owner()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = FakeProc::new()?;
        proc.write_tcp_table(&[tcp_line(0, "00000000:1F91", "00000000:0000", "0A", 909_090)])?;
        proc.write_process_with_socket_and_cmdline(
            123,
            "docker-proxy",
            909_090,
            &[
                "/usr/bin/docker-proxy",
                "-proto",
                "tcp",
                "-host-ip",
                "0.0.0.0",
                "-host-port",
                "8081",
                "-container-ip",
                "172.19.0.3",
                "-container-port",
                "8080",
                "-use-listen-fd",
            ],
        )?;
        proc.write_process_with_socket(321, "demo-backend", 424_242)?;
        proc.write_process_tcp_table(
            321,
            "net:[4026532661]",
            &[
                tcp_line(0, "00000000:1F90", "00000000:0000", "0A", 424_242),
                tcp_line(1, "030013AC:1F90", "010013AC:C001", "01", 111_111),
            ],
        )?;
        let mut resolver = ProcfsSocketResolver::with_paths(proc.root(), proc.boot_id_path());

        let lookup = resolver.resolve_tcp_listeners_by_local_endpoint(TcpEndpoint::new(
            "10.10.0.170".parse()?,
            8081,
        ))?;

        let [listener] = lookup.listeners.as_slice() else {
            panic!("expected docker-proxy target listener: {lookup:?}");
        };
        assert_eq!(listener.observed.process.identity.pid, 123);
        assert_eq!(listener.observed.process.name, "docker-proxy");
        assert_eq!(listener.observed.socket_inode, 909_090);
        assert_eq!(listener.observed.local.port, 8081);
        assert_eq!(listener.owner.process.identity.pid, 321);
        assert_eq!(listener.owner.process.name, "demo-backend");
        assert_eq!(listener.owner.confidence, DOCKER_PROXY_TARGET_CONFIDENCE);
        assert_eq!(
            listener.owner.source,
            TcpListenerOwnerSource::DockerProxyTarget {
                target_local: TcpEndpoint::new("172.19.0.3".parse()?, 8080),
                target_socket_inode: 424_242,
            }
        );

        let lookup = resolver.resolve_tcp_listeners_by_local_port(8081)?;
        let [listener] = lookup.listeners.as_slice() else {
            panic!("expected docker-proxy target listener by port: {lookup:?}");
        };
        assert_eq!(listener.observed.process.identity.pid, 123);
        assert_eq!(listener.observed.process.name, "docker-proxy");
        assert_eq!(listener.observed.socket_inode, 909_090);
        assert_eq!(listener.observed.local.port, 8081);
        assert_eq!(listener.owner.process.identity.pid, 321);
        assert_eq!(listener.owner.process.name, "demo-backend");
        assert_eq!(listener.owner.confidence, DOCKER_PROXY_TARGET_CONFIDENCE);
        Ok(())
    }

    #[test]
    fn docker_proxy_listener_resolution_handles_dual_stack_host_publish()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = FakeProc::new()?;
        proc.write_tcp_table(&[tcp_line(0, "00000000:1F91", "00000000:0000", "0A", 909_090)])?;
        proc.write_tcp6_table(&[tcp_line(
            0,
            "00000000000000000000000000000000:1F91",
            "00000000000000000000000000000000:0000",
            "0A",
            909_091,
        )])?;
        let proxy_cmdline = [
            "/usr/bin/docker-proxy",
            "-proto",
            "tcp",
            "-host-ip",
            "0.0.0.0",
            "-host-port",
            "8081",
            "-container-ip",
            "172.19.0.3",
            "-container-port",
            "8080",
            "-use-listen-fd",
        ];
        proc.write_process_with_socket_and_cmdline(123, "docker-proxy", 909_090, &proxy_cmdline)?;
        proc.write_process_with_socket_and_cmdline(124, "docker-proxy", 909_091, &proxy_cmdline)?;
        proc.write_process_with_socket(321, "demo-backend", 424_242)?;
        proc.write_process_tcp_table(
            321,
            "net:[4026532661]",
            &[
                tcp_line(0, "00000000:1F90", "00000000:0000", "0A", 424_242),
                tcp_line(1, "030013AC:1F90", "010013AC:C001", "01", 111_111),
            ],
        )?;
        let mut resolver = ProcfsSocketResolver::with_paths(proc.root(), proc.boot_id_path());

        let lookup = resolver.resolve_tcp_listeners_by_local_endpoint(TcpEndpoint::new(
            "10.10.0.170".parse()?,
            8081,
        ))?;

        let [listener] = lookup.listeners.as_slice() else {
            panic!("expected docker-proxy target listener: {lookup:?}");
        };
        assert_eq!(listener.observed.process.identity.pid, 123);
        assert_eq!(listener.observed.process.name, "docker-proxy");
        assert_eq!(listener.observed.socket_inode, 909_090);
        assert_eq!(listener.owner.process.identity.pid, 321);
        assert_eq!(listener.owner.process.name, "demo-backend");
        assert_eq!(listener.owner.confidence, DOCKER_PROXY_TARGET_CONFIDENCE);
        Ok(())
    }

    #[test]
    fn docker_proxy_listener_resolution_keeps_proxy_owner_when_target_has_unattributed_listener()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = FakeProc::new()?;
        proc.write_tcp_table(&[tcp_line(0, "00000000:1F91", "00000000:0000", "0A", 909_090)])?;
        proc.write_process_with_socket_and_cmdline(
            123,
            "docker-proxy",
            909_090,
            &[
                "/usr/bin/docker-proxy",
                "-proto",
                "tcp",
                "-host-ip",
                "0.0.0.0",
                "-host-port",
                "8081",
                "-container-ip",
                "172.19.0.3",
                "-container-port",
                "8080",
                "-use-listen-fd",
            ],
        )?;
        proc.write_process_with_socket(321, "demo-backend", 424_242)?;
        proc.write_process_tcp_table(
            321,
            "net:[4026532661]",
            &[
                tcp_line(0, "030013AC:1F90", "00000000:0000", "0A", 424_242),
                tcp_line(1, "030013AC:1F90", "00000000:0000", "0A", 535_353),
            ],
        )?;
        let mut resolver = ProcfsSocketResolver::with_paths(proc.root(), proc.boot_id_path());

        let lookup = resolver.resolve_tcp_listeners_by_local_endpoint(TcpEndpoint::new(
            "10.10.0.170".parse()?,
            8081,
        ))?;

        let [listener] = lookup.listeners.as_slice() else {
            panic!("expected docker-proxy listener: {lookup:?}");
        };
        assert!(lookup.unattributed_listeners.is_empty());
        assert_eq!(listener.observed.process.identity.pid, 123);
        assert_eq!(listener.observed.process.name, "docker-proxy");
        assert_eq!(listener.owner.process.identity.pid, 123);
        assert_eq!(listener.owner.process.name, "docker-proxy");
        assert_eq!(listener.owner.source, TcpListenerOwnerSource::SocketHolder);
        Ok(())
    }

    #[test]
    fn endpoint_listener_lookup_rejects_ambiguous_wildcard_listeners()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = FakeProc::new()?;
        proc.write_tcp_table(&[
            tcp_line(0, "00000000:1F90", "00000000:0000", "0A", 424_242),
            tcp_line(1, "00000000:1F90", "00000000:0000", "0A", 535_353),
        ])?;
        proc.write_process_with_socket(321, "first-api", 424_242)?;
        proc.write_process_with_socket(654, "second-api", 535_353)?;
        let mut resolver = ProcfsSocketResolver::with_paths(proc.root(), proc.boot_id_path());

        let lookup = resolver.resolve_tcp_listeners_by_local_endpoint(TcpEndpoint::new(
            "172.19.0.3".parse()?,
            8080,
        ))?;

        assert!(lookup.listeners.is_empty());
        Ok(())
    }

    #[test]
    fn resolves_tcp_listeners_across_all_local_ports() -> Result<(), Box<dyn std::error::Error>> {
        let proc = FakeProc::new()?;
        proc.write_tcp_table(&[
            tcp_line(0, "0100007F:20FB", "00000000:0000", "0A", 424_242),
            tcp_line(1, "0100007F:24E3", "00000000:0000", "0A", 535_353),
            tcp_line(2, "0100007F:2AFB", "00000000:0000", "0A", 646_464),
        ])?;
        proc.write_process_with_socket(321, "first-listener", 424_242)?;
        proc.write_process_with_socket(654, "second-listener", 535_353)?;
        let mut resolver = ProcfsSocketResolver::with_paths(proc.root(), proc.boot_id_path());

        let lookup = resolver.resolve_tcp_listeners()?;

        assert_eq!(
            lookup.unattributed_listeners,
            vec![unattributed_listener("127.0.0.1".parse()?, 11003, 646_464)]
        );
        let mut listeners = lookup
            .listeners
            .iter()
            .map(|listener| {
                (
                    listener.observed.local.port,
                    listener.owner.process.identity.pid,
                )
            })
            .collect::<Vec<_>>();
        listeners.sort_unstable();
        assert_eq!(listeners, vec![(8443, 321), (9443, 654)]);
        Ok(())
    }

    #[test]
    fn tcp_connection_lookup_does_not_scan_process_listener_namespaces()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = FakeProc::new()?;
        proc.write_tcp_table(&[tcp_line(0, "0100007F:20FB", "0100007F:CAFE", "01", 424_242)])?;
        proc.write_process_with_socket(321, "connected-api", 424_242)?;
        proc.write_invalid_process_namespace_marker(321)?;
        let mut resolver = ProcfsSocketResolver::with_paths(proc.root(), proc.boot_id_path());

        let process = resolver
            .resolve_tcp_connection(TcpConnection::new(
                TcpEndpoint::new("127.0.0.1".parse()?, 8443),
                TcpEndpoint::new("127.0.0.1".parse()?, 51966),
            ))?
            .expect("connection should resolve without listener namespace scan");

        assert_eq!(process.process.identity.pid, 321);
        assert_eq!(process.process.name, "connected-api");
        assert_eq!(process.socket_inode, 424_242);
        Ok(())
    }

    struct FakeProc {
        root: TempDir,
        boot_id_path: std::path::PathBuf,
    }

    impl FakeProc {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let root = tempfile::tempdir()?;
            fs::create_dir(root.path().join("net"))?;
            fs::write(root.path().join("net/tcp6"), tcp_header())?;
            let boot_id_path = root.path().join("boot_id");
            fs::write(&boot_id_path, "boot-test\n")?;
            Ok(Self { root, boot_id_path })
        }

        fn root(&self) -> &Path {
            self.root.path()
        }

        fn boot_id_path(&self) -> &Path {
            &self.boot_id_path
        }

        fn write_tcp_table(&self, lines: &[String]) -> Result<(), std::io::Error> {
            fs::write(
                self.root.path().join("net/tcp"),
                format!("{}{}", tcp_header(), lines.join("")),
            )
        }

        fn write_tcp6_table(&self, lines: &[String]) -> Result<(), std::io::Error> {
            fs::write(
                self.root.path().join("net/tcp6"),
                format!("{}{}", tcp_header(), lines.join("")),
            )
        }

        fn write_process_with_socket(
            &self,
            pid: u32,
            name: &str,
            inode: u64,
        ) -> Result<(), Box<dyn std::error::Error>> {
            self.write_process_with_socket_and_cmdline(pid, name, inode, &[name, "--serve"])
        }

        fn write_process_with_socket_and_cmdline(
            &self,
            pid: u32,
            name: &str,
            inode: u64,
            cmdline: &[&str],
        ) -> Result<(), Box<dyn std::error::Error>> {
            let process_root = self.root.path().join(pid.to_string());
            fs::create_dir(&process_root)?;
            fs::create_dir(process_root.join("fd"))?;
            fs::write(process_root.join("stat"), stat(pid, name, 99))?;
            fs::write(
                process_root.join("status"),
                format!(
                    "Name:\t{name}\nTgid:\t{pid}\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n"
                ),
            )?;
            fs::write(process_root.join("cmdline"), nul_joined(cmdline))?;
            fs::write(
                process_root.join("cgroup"),
                "0::/system.slice/demo.service\n",
            )?;
            symlink("/usr/bin/demo-listener", process_root.join("exe"))?;
            symlink(format!("socket:[{inode}]"), process_root.join("fd/7"))?;
            Ok(())
        }

        fn write_process_thread_with_socket(
            &self,
            pid: u32,
            tgid: u32,
            name: &str,
            inode: u64,
        ) -> Result<(), Box<dyn std::error::Error>> {
            let process_root = self.root.path().join(pid.to_string());
            fs::create_dir(&process_root)?;
            fs::create_dir(process_root.join("fd"))?;
            fs::write(process_root.join("stat"), stat(pid, name, 99))?;
            fs::write(
                process_root.join("status"),
                format!(
                    "Name:\t{name}\nTgid:\t{tgid}\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n"
                ),
            )?;
            fs::write(
                process_root.join("cmdline"),
                nul_joined(&[name, "--worker"]),
            )?;
            fs::write(
                process_root.join("cgroup"),
                "0::/system.slice/demo.service\n",
            )?;
            symlink("/usr/bin/demo-listener", process_root.join("exe"))?;
            symlink(format!("socket:[{inode}]"), process_root.join("fd/7"))?;
            Ok(())
        }

        fn write_invalid_process_namespace_marker(
            &self,
            pid: u32,
        ) -> Result<(), Box<dyn std::error::Error>> {
            let process_root = self.root.path().join(pid.to_string());
            fs::create_dir_all(process_root.join("ns"))?;
            fs::write(process_root.join("ns/net"), "not a symlink")?;
            Ok(())
        }

        fn write_process_tcp_table(
            &self,
            pid: u32,
            network_namespace: &str,
            lines: &[String],
        ) -> Result<(), Box<dyn std::error::Error>> {
            let process_root = self.root.path().join(pid.to_string());
            fs::create_dir_all(process_root.join("net"))?;
            fs::create_dir_all(process_root.join("ns"))?;
            let namespace_path = process_root.join("ns/net");
            if !namespace_path.exists() {
                symlink(network_namespace, &namespace_path)?;
            }
            fs::write(
                process_root.join("net/tcp"),
                format!("{}{}", tcp_header(), lines.join("")),
            )?;
            fs::write(process_root.join("net/tcp6"), tcp_header())?;
            Ok(())
        }
    }

    fn tcp_header() -> &'static str {
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    }

    fn tcp_line(index: u32, local: &str, remote: &str, state: &str, inode: u64) -> String {
        format!(
            "{index:4}: {local} {remote} {state} 00000000:00000000 00:00000000 00000000 1000 0 {inode} 1 0000000000000000\n"
        )
    }

    fn unattributed_listener(
        address: IpAddr,
        port: u16,
        socket_inode: u64,
    ) -> TcpUnattributedListener {
        TcpUnattributedListener {
            socket_inode,
            local: TcpEndpoint::new(address, port),
        }
    }

    fn stat(pid: u32, name: &str, start_time_ticks: u64) -> String {
        format!(
            "{pid} ({name}) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 {start_time_ticks} 20\n"
        )
    }

    fn nul_joined(values: &[&str]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|value| value.as_bytes().iter().copied().chain([0]))
            .collect()
    }
}
