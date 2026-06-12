use std::{
    collections::HashMap,
    fs, io,
    path::Path,
    time::{Duration, Instant},
};

use probe_core::{CapabilityKind, CapabilityState, ProcessContext, TcpConnection, TcpEndpoint};

use super::{
    AttributionError,
    inode_scan::{inode_pid_map, read_socket_inode_for_lookup_fd},
    io::read_tcp_table_to_string,
    process::{ProcessAttributor, ProcfsAttributor},
    tcp_table::{
        ProcfsTcpTableFamily, ProcfsTcpTablePolicy, connection_uses_family, connections_by_inode,
        endpoint_uses_family, procfs_tcp_tables, tcp_inode_map_from_table,
    },
};

const PROCFS_SOCKET_CONFIDENCE: u8 = 60;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketFdLookup {
    pub tgid: u32,
    pub thread_pid: u32,
    pub fd: i32,
    pub expected_remote_endpoint: Option<TcpEndpoint>,
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
        let Some(inode) =
            read_socket_inode_for_lookup_fd(&self.process_attributor.proc_root, lookup)?
        else {
            if let Some(error) = optional_error_for_expected_remote(snapshot, lookup) {
                return Err(error);
            }
            return Ok(None);
        };
        let Some(connection) =
            tcp_connection_for_inode(snapshot, inode, lookup.expected_remote_endpoint)
        else {
            if let Some(error) = optional_error_for_expected_remote(snapshot, lookup) {
                return Err(error);
            }
            return Ok(None);
        };
        let process = match self.process_attributor.identify(lookup.tgid) {
            Ok(process) => process,
            Err(error)
                if is_disappearing_process_error(
                    &error,
                    &self.process_attributor.proc_root,
                    lookup.tgid,
                ) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        Ok(Some(SocketFdConnectionContext {
            process,
            confidence: PROCFS_SOCKET_CONFIDENCE,
            socket_inode: inode,
            connection,
        }))
    }

    fn capabilities(&self) -> Vec<CapabilityState> {
        match self.probe() {
            Ok(()) => vec![CapabilityState::degraded(
                CapabilityKind::ProcfsSocketAttribution,
                "procfs socket attribution can read /proc/net/tcp and proc root, and opportunistically reads /proc/net/tcp6 when available; fd races, hidepid, namespace boundaries, and PID reuse remain possible",
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

fn optional_error_for_expected_remote(
    snapshot: &ProcfsSocketSnapshot,
    lookup: SocketFdLookup,
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
