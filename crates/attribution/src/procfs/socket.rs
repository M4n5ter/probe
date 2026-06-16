use std::{
    collections::HashMap,
    fs, io,
    path::Path,
    time::{Duration, Instant},
};

use probe_core::{CapabilityKind, CapabilityState, ProcessContext, TcpConnection, TcpEndpoint};

use super::{
    AttributionError,
    inode_scan::{
        SocketFdInode, SocketFdInodeSource, hinted_socket_fd_candidates, inode_pid_map,
        socket_fd_candidates_for_lookup,
    },
    io::read_tcp_table_to_string,
    process::{ProcessAttributor, ProcfsAttributor},
    tcp_table::{
        ProcfsTcpTableFamily, ProcfsTcpTablePolicy, connection_uses_family, connections_by_inode,
        endpoint_uses_family, procfs_tcp_tables, tcp_inode_map_from_table,
    },
};

const PROCFS_SOCKET_CONFIDENCE: u8 = 60;
const PROCFS_HINTED_FD_CONFIDENCE: u8 = 50;
const DEFAULT_PROCFS_SOCKET_SNAPSHOT_TTL: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketProcessContext {
    pub process: ProcessContext,
    pub confidence: u8,
    pub socket_inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketFdConnectionContext {
    pub process: ProcessContext,
    pub confidence: u8,
    pub socket_inode: u64,
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
    connections_by_inode: HashMap<u64, Vec<TcpConnection>>,
    inode_pids: HashMap<u64, u32>,
    optional_table_errors: HashMap<ProcfsTcpTableFamily, AttributionError>,
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

    fn refresh_snapshot_if_needed(&mut self) -> Result<(), AttributionError> {
        if self.snapshot_needs_refresh() {
            self.snapshot = Some(CachedProcfsSocketSnapshot {
                loaded_at: Instant::now(),
                snapshot: self.attributor.snapshot()?,
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
        let Some(pid) = snapshot.inode_pids.get(&inode).copied() else {
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
        self.identify_hinted_fd_in_snapshot(&lookup, snapshot)
    }

    fn identify_fd_candidates_in_snapshot(
        &self,
        candidates: &[SocketFdInode],
        lookup: &SocketFdLookup,
        snapshot: &ProcfsSocketSnapshot,
    ) -> Result<Option<SocketFdConnectionContext>, AttributionError> {
        let mut matched = None;
        for candidate in candidates {
            if candidate.source != SocketFdInodeSource::Direct
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
            let process = match self.process_attributor.identify(candidate.process_pid) {
                Ok(process) => process,
                Err(error)
                    if is_disappearing_process_error(
                        &error,
                        &self.process_attributor.proc_root,
                        candidate.process_pid,
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            };
            if candidate.source == SocketFdInodeSource::ProcessHint
                && !lookup
                    .process_hint
                    .as_ref()
                    .is_some_and(|hint| process_matches_hint(&process, hint))
            {
                continue;
            }
            let resolved = SocketFdConnectionContext {
                process,
                confidence: fd_candidate_confidence(candidate.source),
                socket_inode: candidate.inode,
                connection,
            };
            if matched.replace(resolved).is_some() {
                return Ok(None);
            }
        }
        Ok(matched)
    }

    fn identify_hinted_fd_in_snapshot(
        &self,
        lookup: &SocketFdLookup,
        snapshot: &ProcfsSocketSnapshot,
    ) -> Result<Option<SocketFdConnectionContext>, AttributionError> {
        if lookup.process_hint.is_none() || lookup.expected_remote_endpoint.is_none() {
            return Ok(None);
        }
        let candidate_scan =
            hinted_socket_fd_candidates(&self.process_attributor.proc_root, lookup)?;
        if !candidate_scan.complete {
            return Ok(None);
        }
        if let Some(resolved) =
            self.identify_fd_candidates_in_snapshot(&candidate_scan.candidates, lookup, snapshot)?
        {
            return Ok(Some(resolved));
        }
        if !candidate_scan.candidates.is_empty()
            && let Some(error) = optional_error_for_expected_remote(snapshot, lookup)
        {
            return Err(error);
        }
        Ok(None)
    }

    fn capabilities(&self) -> Vec<CapabilityState> {
        match self.probe() {
            Ok(()) => vec![CapabilityState::degraded(
                CapabilityKind::ProcfsSocketAttribution,
                "procfs socket attribution can read /proc/net/tcp and proc root, opportunistically reads /proc/net/tcp6, resolves fd lookups through procfs PID namespace aliases, and can use unique fd/process-hint candidates when kernel PIDs are hidden; fd races, hidepid, namespace boundaries, and PID reuse remain possible",
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

    fn snapshot(&self) -> Result<ProcfsSocketSnapshot, AttributionError> {
        let mut tcp_inodes = HashMap::new();
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
            match tcp_inode_map_from_table(&table, &content) {
                Ok(inodes) => tcp_inodes.extend(inodes),
                Err(error) if table.policy == ProcfsTcpTablePolicy::OptionalBestEffort => {
                    optional_table_errors.insert(table.family, error);
                }
                Err(error) => return Err(error),
            }
        }
        Ok(ProcfsSocketSnapshot {
            connections_by_inode: connections_by_inode(&tcp_inodes),
            tcp_inodes,
            inode_pids: inode_pid_map(&self.process_attributor.proc_root)?,
            optional_table_errors,
        })
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

fn process_matches_hint(process: &ProcessContext, hint: &SocketProcessHint) -> bool {
    process.identity.uid == hint.uid
        && process.identity.gid == hint.gid
        && process.name == hint.name
}

fn fd_candidate_confidence(source: SocketFdInodeSource) -> u8 {
    match source {
        SocketFdInodeSource::Direct => PROCFS_SOCKET_CONFIDENCE,
        SocketFdInodeSource::NamespaceAlias | SocketFdInodeSource::ProcessHint => {
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

fn is_disappearing_process_error(error: &AttributionError, proc_root: &Path, pid: u32) -> bool {
    let pid_path = proc_root.join(pid.to_string());
    match error {
        AttributionError::Read { path, source } | AttributionError::ReadLink { path, source } => {
            source.kind() == io::ErrorKind::NotFound && Path::new(path).starts_with(pid_path)
        }
        AttributionError::InvalidStat { .. }
        | AttributionError::InvalidStatus { .. }
        | AttributionError::InvalidNetTcp { .. } => false,
    }
}
