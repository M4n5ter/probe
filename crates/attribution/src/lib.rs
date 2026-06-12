use std::{
    collections::HashMap,
    fs, io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use probe_core::{
    CapabilityKind, CapabilityState, ProcessContext, ProcessIdentity, TcpConnection, TcpEndpoint,
};
use thiserror::Error;

const PROCFS_SOCKET_CONFIDENCE: u8 = 60;
const DEFAULT_PROCFS_SOCKET_SNAPSHOT_TTL: Duration = Duration::from_millis(250);

#[derive(Debug, Error)]
pub enum AttributionError {
    #[error("failed to read {path}: {source}")]
    Read { path: String, source: io::Error },
    #[error("failed to read symlink {path}: {source}")]
    ReadLink { path: String, source: io::Error },
    #[error("invalid proc stat for pid {pid}: {reason}")]
    InvalidStat { pid: u32, reason: String },
    #[error("invalid proc status for pid {pid}: {reason}")]
    InvalidStatus { pid: u32, reason: String },
    #[error("invalid proc net tcp entry in {path}: {reason}")]
    InvalidNetTcp { path: String, reason: String },
}

impl Clone for AttributionError {
    fn clone(&self) -> Self {
        match self {
            Self::Read { path, source } => Self::Read {
                path: path.clone(),
                source: clone_io_error(source),
            },
            Self::ReadLink { path, source } => Self::ReadLink {
                path: path.clone(),
                source: clone_io_error(source),
            },
            Self::InvalidStat { pid, reason } => Self::InvalidStat {
                pid: *pid,
                reason: reason.clone(),
            },
            Self::InvalidStatus { pid, reason } => Self::InvalidStatus {
                pid: *pid,
                reason: reason.clone(),
            },
            Self::InvalidNetTcp { path, reason } => Self::InvalidNetTcp {
                path: path.clone(),
                reason: reason.clone(),
            },
        }
    }
}

fn clone_io_error(source: &io::Error) -> io::Error {
    io::Error::new(source.kind(), source.to_string())
}

pub trait ProcessAttributor {
    fn name(&self) -> &'static str;

    fn capabilities(&self) -> Vec<CapabilityState>;

    fn identify(&self, pid: u32) -> Result<ProcessContext, AttributionError>;
}

#[derive(Debug, Clone)]
pub struct ProcfsAttributor {
    proc_root: PathBuf,
    boot_id_path: PathBuf,
}

impl ProcfsAttributor {
    pub fn new() -> Self {
        Self {
            proc_root: PathBuf::from("/proc"),
            boot_id_path: PathBuf::from("/proc/sys/kernel/random/boot_id"),
        }
    }

    pub fn with_paths(proc_root: impl Into<PathBuf>, boot_id_path: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: proc_root.into(),
            boot_id_path: boot_id_path.into(),
        }
    }

    pub fn probe(&self) -> Result<(), AttributionError> {
        read_to_string(&self.boot_id_path)?;
        Ok(())
    }
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ProcfsTcpTableFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcfsTcpTablePolicy {
    Required,
    OptionalBestEffort,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcfsTcpTable {
    family: ProcfsTcpTableFamily,
    path: PathBuf,
    policy: ProcfsTcpTablePolicy,
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

    pub fn with_paths(proc_root: impl Into<PathBuf>, boot_id_path: impl Into<PathBuf>) -> Self {
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
    pub fn new() -> Self {
        Self {
            process_attributor: ProcfsAttributor::new(),
        }
    }

    pub fn with_paths(proc_root: impl Into<PathBuf>, boot_id_path: impl Into<PathBuf>) -> Self {
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

    pub fn capabilities(&self) -> Vec<CapabilityState> {
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

    pub fn probe(&self) -> Result<(), AttributionError> {
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
                Ok(Some(content)) => content,
                Ok(None) => continue,
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

impl Default for ProcfsAttributor {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessAttributor for ProcfsAttributor {
    fn name(&self) -> &'static str {
        "procfs"
    }

    fn capabilities(&self) -> Vec<CapabilityState> {
        match self.probe() {
            Ok(()) => vec![CapabilityState::degraded(
                CapabilityKind::ProcfsAttribution,
                "procfs attribution is available as a best-effort fallback; PID reuse and permission races remain possible",
            )],
            Err(error) => vec![CapabilityState::unavailable(
                CapabilityKind::ProcfsAttribution,
                error.to_string(),
            )],
        }
    }

    fn identify(&self, pid: u32) -> Result<ProcessContext, AttributionError> {
        let pid_dir = self.proc_root.join(pid.to_string());
        let stat = parse_stat(pid, &read_to_string(&pid_dir.join("stat"))?)?;
        let status = parse_status(pid, &read_to_string(&pid_dir.join("status"))?)?;
        let cmdline_bytes = read_bytes(&pid_dir.join("cmdline"))?;
        let cmdline = parse_cmdline(&cmdline_bytes);
        let cgroup = read_optional_to_string(&pid_dir.join("cgroup"))?;
        let boot_id = read_to_string(&self.boot_id_path)?.trim().to_string();
        let exe_path = read_link_to_string(&pid_dir.join("exe"))?;
        let stat_after = parse_stat(pid, &read_to_string(&pid_dir.join("stat"))?)?;
        if stat_after.start_time_ticks != stat.start_time_ticks {
            return Err(AttributionError::InvalidStat {
                pid,
                reason: "process starttime changed while reading procfs identity".to_string(),
            });
        }
        let cmdline_hash = blake3::hash(&cmdline_bytes).to_hex().to_string();
        let cgroup_path = cgroup.as_deref().and_then(first_cgroup_path);

        Ok(ProcessContext {
            identity: ProcessIdentity {
                pid,
                tgid: status.tgid.unwrap_or(pid),
                start_time_ticks: stat.start_time_ticks,
                boot_id,
                exe_path,
                cmdline_hash,
                uid: status.uid.unwrap_or(0),
                gid: status.gid.unwrap_or(0),
                cgroup: cgroup_path.map(str::to_string),
                systemd_service: cgroup_path.and_then(extract_systemd_service),
                container_id: cgroup_path.and_then(extract_container_id),
                runtime_hint: cgroup_path.and_then(extract_runtime_hint),
            },
            name: stat.comm,
            cmdline,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedStat {
    comm: String,
    start_time_ticks: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct ParsedStatus {
    tgid: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
}

fn parse_stat(pid: u32, content: &str) -> Result<ParsedStat, AttributionError> {
    let open = content
        .find('(')
        .ok_or_else(|| AttributionError::InvalidStat {
            pid,
            reason: "missing opening comm delimiter".to_string(),
        })?;
    let close = content
        .rfind(')')
        .ok_or_else(|| AttributionError::InvalidStat {
            pid,
            reason: "missing closing comm delimiter".to_string(),
        })?;
    if close <= open {
        return Err(AttributionError::InvalidStat {
            pid,
            reason: "invalid comm delimiters".to_string(),
        });
    }
    let comm = content[open + 1..close].to_string();
    let rest = content[close + 1..].trim();
    let start_time = rest
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| AttributionError::InvalidStat {
            pid,
            reason: "missing starttime field".to_string(),
        })?
        .parse::<u64>()
        .map_err(|source| AttributionError::InvalidStat {
            pid,
            reason: format!("invalid starttime field: {source}"),
        })?;
    Ok(ParsedStat {
        comm,
        start_time_ticks: start_time,
    })
}

fn parse_status(pid: u32, content: &str) -> Result<ParsedStatus, AttributionError> {
    let mut status = ParsedStatus::default();
    for line in content.lines() {
        if let Some(value) = line.strip_prefix("Tgid:") {
            status.tgid = Some(parse_status_u32(pid, "Tgid", value)?);
        } else if let Some(value) = line.strip_prefix("Uid:") {
            status.uid = Some(parse_status_u32(pid, "Uid", value)?);
        } else if let Some(value) = line.strip_prefix("Gid:") {
            status.gid = Some(parse_status_u32(pid, "Gid", value)?);
        }
    }
    Ok(status)
}

fn parse_status_u32(pid: u32, field: &str, value: &str) -> Result<u32, AttributionError> {
    value
        .split_whitespace()
        .next()
        .ok_or_else(|| AttributionError::InvalidStatus {
            pid,
            reason: format!("missing {field} value"),
        })?
        .parse::<u32>()
        .map_err(|source| AttributionError::InvalidStatus {
            pid,
            reason: format!("invalid {field} value: {source}"),
        })
}

fn parse_cmdline(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect()
}

fn first_cgroup_path(content: &str) -> Option<&str> {
    content.lines().find_map(|line| {
        let mut fields = line.splitn(3, ':');
        let _hierarchy = fields.next()?;
        let _controllers = fields.next()?;
        let path = fields.next()?.trim();
        (!path.is_empty()).then_some(path)
    })
}

fn extract_systemd_service(cgroup: &str) -> Option<String> {
    cgroup
        .split('/')
        .find(|segment| segment.ends_with(".service"))
        .map(str::to_string)
}

fn extract_container_id(cgroup: &str) -> Option<String> {
    cgroup
        .split(['/', ':'])
        .map(strip_container_suffix)
        .find(|segment| is_hex_id(segment, 64) || is_hex_id(segment, 32))
        .map(str::to_string)
}

fn extract_runtime_hint(cgroup: &str) -> Option<String> {
    if cgroup.contains("containerd") {
        Some("containerd".to_string())
    } else if cgroup.contains("docker") {
        Some("docker".to_string())
    } else if cgroup.contains("kubepods") {
        Some("kubernetes".to_string())
    } else {
        None
    }
}

fn strip_container_suffix(segment: &str) -> &str {
    let without_suffix = segment.strip_suffix(".scope").unwrap_or(segment);
    without_suffix
        .strip_prefix("docker-")
        .or_else(|| without_suffix.strip_prefix("cri-containerd-"))
        .unwrap_or(without_suffix)
}

fn is_hex_id(value: &str, len: usize) -> bool {
    value.len() == len && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn procfs_tcp_tables(proc_root: &Path) -> [ProcfsTcpTable; 2] {
    [
        ProcfsTcpTable {
            family: ProcfsTcpTableFamily::Ipv4,
            path: proc_root.join("net/tcp"),
            policy: ProcfsTcpTablePolicy::Required,
        },
        ProcfsTcpTable {
            family: ProcfsTcpTableFamily::Ipv6,
            path: proc_root.join("net/tcp6"),
            policy: ProcfsTcpTablePolicy::OptionalBestEffort,
        },
    ]
}

fn connection_uses_family(connection: TcpConnection, family: ProcfsTcpTableFamily) -> bool {
    endpoint_uses_family(connection.local, family)
        || endpoint_uses_family(connection.remote, family)
}

fn endpoint_uses_family(endpoint: TcpEndpoint, family: ProcfsTcpTableFamily) -> bool {
    matches!(
        (endpoint.address, family),
        (IpAddr::V4(_), ProcfsTcpTableFamily::Ipv4) | (IpAddr::V6(_), ProcfsTcpTableFamily::Ipv6)
    )
}

fn tcp_inode_map_from_table(
    table: &ProcfsTcpTable,
    content: &str,
) -> Result<HashMap<TcpConnection, u64>, AttributionError> {
    let mut inodes = HashMap::new();
    for line in content.lines().skip(1) {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() <= 9 {
            continue;
        }
        let local = parse_tcp_endpoint(table, fields[1])?;
        let remote = parse_tcp_endpoint(table, fields[2])?;
        let inode = fields[9]
            .parse::<u64>()
            .map_err(|source| AttributionError::InvalidNetTcp {
                path: table.path.display().to_string(),
                reason: format!("invalid socket inode: {source}"),
            })?;
        inodes.insert(TcpConnection::new(local, remote), inode);
    }
    Ok(inodes)
}

fn connections_by_inode(
    tcp_inodes: &HashMap<TcpConnection, u64>,
) -> HashMap<u64, Vec<TcpConnection>> {
    let mut connections = HashMap::<u64, Vec<TcpConnection>>::new();
    for (connection, inode) in tcp_inodes {
        connections.entry(*inode).or_default().push(*connection);
    }
    connections
}

fn parse_tcp_endpoint(
    table: &ProcfsTcpTable,
    value: &str,
) -> Result<TcpEndpoint, AttributionError> {
    let (address, port) = value
        .split_once(':')
        .ok_or_else(|| AttributionError::InvalidNetTcp {
            path: table.path.display().to_string(),
            reason: format!("invalid endpoint {value:?}"),
        })?;
    let address = parse_proc_net_tcp_address(table, address)?;
    let port = u16::from_str_radix(port, 16).map_err(|source| AttributionError::InvalidNetTcp {
        path: table.path.display().to_string(),
        reason: format!("invalid TCP endpoint port: {source}"),
    })?;
    Ok(TcpEndpoint::new(address, port))
}

fn parse_proc_net_tcp_address(
    table: &ProcfsTcpTable,
    address: &str,
) -> Result<IpAddr, AttributionError> {
    match table.family {
        ProcfsTcpTableFamily::Ipv4 => parse_proc_net_tcp4_address(&table.path, address),
        ProcfsTcpTableFamily::Ipv6 => parse_proc_net_tcp6_address(&table.path, address),
    }
}

fn parse_proc_net_tcp4_address(path: &Path, address: &str) -> Result<IpAddr, AttributionError> {
    if address.len() != 8 {
        return Err(AttributionError::InvalidNetTcp {
            path: path.display().to_string(),
            reason: format!("invalid IPv4 endpoint address {address:?}"),
        });
    }
    let raw_address =
        u32::from_str_radix(address, 16).map_err(|source| AttributionError::InvalidNetTcp {
            path: path.display().to_string(),
            reason: format!("invalid IPv4 endpoint address: {source}"),
        })?;
    Ok(IpAddr::V4(Ipv4Addr::from(raw_address.to_le_bytes())))
}

fn parse_proc_net_tcp6_address(path: &Path, address: &str) -> Result<IpAddr, AttributionError> {
    if address.len() != 32 {
        return Err(AttributionError::InvalidNetTcp {
            path: path.display().to_string(),
            reason: format!("invalid IPv6 endpoint address {address:?}"),
        });
    }
    let mut bytes = [0u8; 16];
    for (index, chunk) in address.as_bytes().chunks_exact(8).enumerate() {
        let chunk =
            std::str::from_utf8(chunk).map_err(|source| AttributionError::InvalidNetTcp {
                path: path.display().to_string(),
                reason: format!("invalid IPv6 endpoint address: {source}"),
            })?;
        let word =
            u32::from_str_radix(chunk, 16).map_err(|source| AttributionError::InvalidNetTcp {
                path: path.display().to_string(),
                reason: format!("invalid IPv6 endpoint address: {source}"),
            })?;
        bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    if bytes[..10].iter().all(|byte| *byte == 0) && bytes[10] == 0xff && bytes[11] == 0xff {
        return Ok(IpAddr::V4(Ipv4Addr::new(
            bytes[12], bytes[13], bytes[14], bytes[15],
        )));
    }
    Ok(IpAddr::V6(Ipv6Addr::from(bytes)))
}

fn inode_pid_map(proc_root: &Path) -> Result<HashMap<u64, u32>, AttributionError> {
    let mut inodes = HashMap::new();
    let entries = fs::read_dir(proc_root).map_err(|source| AttributionError::Read {
        path: proc_root.display().to_string(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| AttributionError::Read {
            path: proc_root.display().to_string(),
            source,
        })?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        read_pid_socket_inodes(&entry.path().join("fd"), pid, &mut inodes)?;
    }
    Ok(inodes)
}

fn read_pid_socket_inodes(
    fd_dir: &Path,
    pid: u32,
    inodes: &mut HashMap<u64, u32>,
) -> Result<(), AttributionError> {
    let entries = match fs::read_dir(fd_dir) {
        Ok(entries) => entries,
        Err(source) if is_skippable_socket_scan_error(&source) => return Ok(()),
        Err(source) => {
            return Err(AttributionError::Read {
                path: fd_dir.display().to_string(),
                source,
            });
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(source) if is_skippable_socket_scan_error(&source) => continue,
            Err(source) => {
                return Err(AttributionError::Read {
                    path: fd_dir.display().to_string(),
                    source,
                });
            }
        };
        let link_path = entry.path();
        let target = match fs::read_link(&link_path) {
            Ok(target) => target,
            Err(source) if is_skippable_socket_scan_error(&source) => continue,
            Err(source) => {
                return Err(AttributionError::ReadLink {
                    path: link_path.display().to_string(),
                    source,
                });
            }
        };
        let Some(inode) = socket_inode_from_link(&target) else {
            continue;
        };
        inodes.entry(inode).or_insert(pid);
    }
    Ok(())
}

fn read_socket_inode_for_pid_fd(
    proc_root: &Path,
    pid: u32,
    fd: i32,
) -> Result<Option<u64>, AttributionError> {
    if fd < 0 {
        return Ok(None);
    }
    let link_path = proc_root
        .join(pid.to_string())
        .join("fd")
        .join(fd.to_string());
    let target = match fs::read_link(&link_path) {
        Ok(target) => target,
        Err(source) if is_skippable_socket_scan_error(&source) => return Ok(None),
        Err(source) => {
            return Err(AttributionError::ReadLink {
                path: link_path.display().to_string(),
                source,
            });
        }
    };
    Ok(socket_inode_from_link(&target))
}

fn read_socket_inode_for_lookup_fd(
    proc_root: &Path,
    lookup: SocketFdLookup,
) -> Result<Option<u64>, AttributionError> {
    let thread_inode = read_socket_inode_for_pid_fd(proc_root, lookup.thread_pid, lookup.fd)?;
    if thread_inode.is_some() || lookup.thread_pid == lookup.tgid {
        return Ok(thread_inode);
    }
    read_socket_inode_for_pid_fd(proc_root, lookup.tgid, lookup.fd)
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

fn is_skippable_socket_scan_error(source: &io::Error) -> bool {
    matches!(
        source.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
    )
}

fn socket_inode_from_link(target: &Path) -> Option<u64> {
    let target = target.to_str()?;
    target
        .strip_prefix("socket:[")
        .and_then(|value| value.strip_suffix(']'))
        .and_then(|value| value.parse::<u64>().ok())
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

fn read_to_string(path: &Path) -> Result<String, AttributionError> {
    fs::read_to_string(path).map_err(|source| AttributionError::Read {
        path: path.display().to_string(),
        source,
    })
}

fn read_tcp_table_to_string(table: &ProcfsTcpTable) -> Result<Option<String>, AttributionError> {
    match fs::read_to_string(&table.path) {
        Ok(content) => Ok(Some(content)),
        Err(source) if table.policy == ProcfsTcpTablePolicy::OptionalBestEffort => {
            Err(AttributionError::Read {
                path: table.path.display().to_string(),
                source,
            })
        }
        Err(source) => Err(AttributionError::Read {
            path: table.path.display().to_string(),
            source,
        }),
    }
}

fn read_optional_to_string(path: &Path) -> Result<Option<String>, AttributionError> {
    match fs::read_to_string(path) {
        Ok(content) => Ok(Some(content)),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(AttributionError::Read {
            path: path.display().to_string(),
            source,
        }),
    }
}

fn read_bytes(path: &Path) -> Result<Vec<u8>, AttributionError> {
    fs::read(path).map_err(|source| AttributionError::Read {
        path: path.display().to_string(),
        source,
    })
}

fn read_link_to_string(path: &Path) -> Result<String, AttributionError> {
    fs::read_link(path)
        .map(|path| path.display().to_string())
        .map_err(|source| AttributionError::ReadLink {
            path: path.display().to_string(),
            source,
        })
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, fs, io, os::unix::fs::PermissionsExt};

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn parse_stat_handles_comm_with_parenthesis() -> Result<(), Box<dyn std::error::Error>> {
        let stat = parse_stat(
            7,
            "7 (worker) odd) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 99 21",
        )?;

        assert_eq!(stat.comm, "worker) odd");
        assert_eq!(stat.start_time_ticks, 99);
        Ok(())
    }

    #[test]
    fn procfs_socket_scan_treats_permission_denied_as_best_effort_skip() {
        let permission_denied = io::Error::from(io::ErrorKind::PermissionDenied);

        assert!(is_skippable_socket_scan_error(&permission_denied));
    }

    #[test]
    fn procfs_socket_scan_skips_unreadable_pid_fd_dir() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let fd_dir = temp.path().join("fd");
        fs::create_dir(&fd_dir)?;
        fs::set_permissions(&fd_dir, fs::Permissions::from_mode(0o000))?;
        let mut inodes = HashMap::new();

        let result = read_pid_socket_inodes(&fd_dir, 321, &mut inodes);

        fs::set_permissions(&fd_dir, fs::Permissions::from_mode(0o700))?;
        result?;
        assert!(inodes.is_empty());
        Ok(())
    }
}
