use std::{
    collections::HashMap,
    fs, io,
    net::{IpAddr, Ipv4Addr},
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
struct ProcfsSocketSnapshot {
    tcp_inodes: HashMap<TcpConnection, u64>,
    inode_pids: HashMap<u64, u32>,
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
        if self.snapshot_needs_refresh() {
            self.snapshot = Some(CachedProcfsSocketSnapshot {
                loaded_at: Instant::now(),
                snapshot: self.attributor.snapshot()?,
            });
        }
        let Some(snapshot) = self.snapshot.as_ref().map(|cached| &cached.snapshot) else {
            return Ok(None);
        };
        self.attributor
            .identify_tcp_connection_in_snapshot(connection, snapshot)
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

    pub fn capabilities(&self) -> Vec<CapabilityState> {
        match self.probe() {
            Ok(()) => vec![CapabilityState::degraded(
                CapabilityKind::ProcfsSocketAttribution,
                "procfs socket attribution can read /proc/net/tcp and proc root, but fd races, hidepid, namespace boundaries, and PID reuse remain possible",
            )],
            Err(error) => vec![CapabilityState::unavailable(
                CapabilityKind::ProcfsSocketAttribution,
                error.to_string(),
            )],
        }
    }

    pub fn probe(&self) -> Result<(), AttributionError> {
        let tcp_path = self.process_attributor.proc_root.join("net/tcp");
        read_to_string(&tcp_path)?;
        fs::read_dir(&self.process_attributor.proc_root).map_err(|source| {
            AttributionError::Read {
                path: self.process_attributor.proc_root.display().to_string(),
                source,
            }
        })?;
        Ok(())
    }

    fn snapshot(&self) -> Result<ProcfsSocketSnapshot, AttributionError> {
        let path = self.process_attributor.proc_root.join("net/tcp");
        Ok(ProcfsSocketSnapshot {
            tcp_inodes: tcp_inode_map_from_table(&path, &read_to_string(&path)?)?,
            inode_pids: inode_pid_map(&self.process_attributor.proc_root)?,
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

fn tcp_inode_map_from_table(
    path: &Path,
    content: &str,
) -> Result<HashMap<TcpConnection, u64>, AttributionError> {
    let mut inodes = HashMap::new();
    for line in content.lines().skip(1) {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() <= 9 {
            continue;
        }
        let local = parse_tcp_endpoint(path, fields[1])?;
        let remote = parse_tcp_endpoint(path, fields[2])?;
        let inode = fields[9]
            .parse::<u64>()
            .map_err(|source| AttributionError::InvalidNetTcp {
                path: path.display().to_string(),
                reason: format!("invalid socket inode: {source}"),
            })?;
        inodes.insert(TcpConnection::new(local, remote), inode);
    }
    Ok(inodes)
}

fn parse_tcp_endpoint(path: &Path, value: &str) -> Result<TcpEndpoint, AttributionError> {
    let (address, port) = value
        .split_once(':')
        .ok_or_else(|| AttributionError::InvalidNetTcp {
            path: path.display().to_string(),
            reason: format!("invalid endpoint {value:?}"),
        })?;
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
    let port = u16::from_str_radix(port, 16).map_err(|source| AttributionError::InvalidNetTcp {
        path: path.display().to_string(),
        reason: format!("invalid TCP endpoint port: {source}"),
    })?;
    Ok(TcpEndpoint::new(
        IpAddr::V4(Ipv4Addr::from(raw_address.to_le_bytes())),
        port,
    ))
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
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(()),
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
            Err(source) if source.kind() == io::ErrorKind::NotFound => continue,
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
            Err(source) if source.kind() == io::ErrorKind::NotFound => continue,
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
    use std::{fs, net::Ipv4Addr, os::unix::fs::symlink, time::Duration};

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn procfs_attributor_builds_stable_process_context() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let proc_root = temp.path().join("proc");
        let pid_dir = proc_root.join("123");
        let boot_id_path = proc_root.join("sys/kernel/random/boot_id");
        fs::create_dir_all(&pid_dir)?;
        fs::create_dir_all(boot_id_path.parent().expect("boot id parent"))?;
        fs::write(&boot_id_path, "boot-1\n")?;
        fs::write(
            pid_dir.join("stat"),
            "123 (demo worker) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 4242 21\n",
        )?;
        fs::write(
            pid_dir.join("status"),
            "Name:\tdemo\nTgid:\t120\nUid:\t1000\t1000\t1000\t1000\nGid:\t1001\t1001\t1001\t1001\n",
        )?;
        fs::write(pid_dir.join("cmdline"), b"/usr/bin/demo\0--serve\0")?;
        fs::write(
            pid_dir.join("cgroup"),
            "0::/system.slice/demo.service/docker-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope\n",
        )?;
        symlink("/usr/bin/demo", pid_dir.join("exe"))?;

        let attributor = ProcfsAttributor::with_paths(proc_root, boot_id_path);
        let process = attributor.identify(123)?;

        assert_eq!(process.name, "demo worker");
        assert_eq!(process.cmdline, vec!["/usr/bin/demo", "--serve"]);
        assert_eq!(process.identity.pid, 123);
        assert_eq!(process.identity.tgid, 120);
        assert_eq!(process.identity.start_time_ticks, 4242);
        assert_eq!(process.identity.boot_id, "boot-1");
        assert_eq!(process.identity.exe_path, "/usr/bin/demo");
        assert_eq!(process.identity.uid, 1000);
        assert_eq!(process.identity.gid, 1001);
        assert_eq!(
            process.identity.systemd_service.as_deref(),
            Some("demo.service")
        );
        assert_eq!(process.identity.runtime_hint.as_deref(), Some("docker"));
        assert_eq!(
            process.identity.container_id.as_deref(),
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );
        Ok(())
    }

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
    fn procfs_socket_attributor_maps_tcp_connection_to_process()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let proc_root = temp.path().join("proc");
        let pid_dir = proc_root.join("321");
        let fd_dir = pid_dir.join("fd");
        let net_dir = proc_root.join("net");
        let boot_id_path = proc_root.join("sys/kernel/random/boot_id");
        fs::create_dir_all(&fd_dir)?;
        fs::create_dir_all(&net_dir)?;
        fs::create_dir_all(boot_id_path.parent().expect("boot id parent"))?;
        fs::write(&boot_id_path, "boot-2\n")?;
        fs::write(
            pid_dir.join("stat"),
            "321 (server) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 9000 21\n",
        )?;
        fs::write(
            pid_dir.join("status"),
            "Name:\tserver\nTgid:\t321\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n",
        )?;
        fs::write(pid_dir.join("cmdline"), b"/usr/bin/server\0")?;
        fs::write(pid_dir.join("cgroup"), "0::/system.slice/server.service\n")?;
        symlink("/usr/bin/server", pid_dir.join("exe"))?;
        symlink("socket:[424242]", fd_dir.join("7"))?;
        fs::write(
            net_dir.join("tcp"),
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:1F90 0200007F:C350 01 00000000:00000000 00:00000000 00000000 1000 0 424242 1 0000000000000000 100 0 0 10 0\n",
        )?;

        let mut resolver = ProcfsSocketResolver::with_paths(proc_root, boot_id_path);
        let process = resolver
            .resolve_tcp_connection(TcpConnection::new(
                TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8080),
                TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 2).into(), 50_000),
            ))?
            .expect("expected socket process");

        assert_eq!(process.process.identity.pid, 321);
        assert_eq!(process.process.name, "server");
        assert_eq!(process.socket_inode, 424242);
        assert_eq!(process.confidence, 60);
        Ok(())
    }

    #[test]
    fn procfs_socket_resolver_preserves_process_identity_errors()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let proc_root = temp.path().join("proc");
        let pid_dir = proc_root.join("321");
        let fd_dir = pid_dir.join("fd");
        let net_dir = proc_root.join("net");
        let boot_id_path = proc_root.join("sys/kernel/random/boot_id");
        fs::create_dir_all(&fd_dir)?;
        fs::create_dir_all(&net_dir)?;
        fs::create_dir_all(boot_id_path.parent().expect("boot id parent"))?;
        fs::write(&boot_id_path, "boot-2\n")?;
        fs::write(
            pid_dir.join("stat"),
            "321 (server) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 9000 21\n",
        )?;
        fs::write(
            pid_dir.join("status"),
            "Name:\tserver\nTgid:\t321\nUid:\tnot-a-uid\nGid:\t1000\t1000\t1000\t1000\n",
        )?;
        symlink("socket:[424242]", fd_dir.join("7"))?;
        fs::write(
            net_dir.join("tcp"),
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:1F90 0200007F:C350 01 00000000:00000000 00:00000000 00000000 1000 0 424242 1 0000000000000000 100 0 0 10 0\n",
        )?;

        let mut resolver = ProcfsSocketResolver::with_paths(proc_root, boot_id_path);
        let error = resolver
            .resolve_tcp_connection(TcpConnection::new(
                TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8080),
                TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 2).into(), 50_000),
            ))
            .expect_err("invalid process status must be observable");

        assert!(matches!(
            error,
            AttributionError::InvalidStatus { pid: 321, .. }
        ));
        Ok(())
    }

    #[test]
    fn procfs_socket_resolver_reuses_snapshot_within_cache_ttl_until_invalidated()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let proc_root = temp.path().join("proc");
        let pid_dir = proc_root.join("321");
        let fd_dir = pid_dir.join("fd");
        let net_dir = proc_root.join("net");
        let tcp_path = net_dir.join("tcp");
        let boot_id_path = proc_root.join("sys/kernel/random/boot_id");
        fs::create_dir_all(&fd_dir)?;
        fs::create_dir_all(&net_dir)?;
        fs::create_dir_all(boot_id_path.parent().expect("boot id parent"))?;
        fs::write(&boot_id_path, "boot-2\n")?;
        fs::write(
            pid_dir.join("stat"),
            "321 (server) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 9000 21\n",
        )?;
        fs::write(
            pid_dir.join("status"),
            "Name:\tserver\nTgid:\t321\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n",
        )?;
        fs::write(pid_dir.join("cmdline"), b"/usr/bin/server\0")?;
        fs::write(pid_dir.join("cgroup"), "0::/system.slice/server.service\n")?;
        symlink("/usr/bin/server", pid_dir.join("exe"))?;
        symlink("socket:[424242]", fd_dir.join("7"))?;
        fs::write(
            &tcp_path,
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:1F90 0200007F:C350 01 00000000:00000000 00:00000000 00000000 1000 0 424242 1 0000000000000000 100 0 0 10 0\n",
        )?;
        let connection = TcpConnection::new(
            TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8080),
            TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 2).into(), 50_000),
        );
        let mut resolver = ProcfsSocketResolver::with_paths(proc_root, boot_id_path)
            .with_cache_ttl(Duration::from_secs(60));

        let first = resolver
            .resolve_tcp_connection(connection)?
            .expect("expected first socket process");
        fs::write(
            &tcp_path,
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:1F90 0200007F:C350 01 00000000:00000000 00:00000000 00000000 1000 0 999999 1 0000000000000000 100 0 0 10 0\n",
        )?;
        let second = resolver
            .resolve_tcp_connection(connection)?
            .expect("expected cached socket process");
        resolver.invalidate_snapshot();
        let refreshed = resolver.resolve_tcp_connection(connection)?;

        assert_eq!(first.socket_inode, 424242);
        assert_eq!(second.socket_inode, 424242);
        assert!(refreshed.is_none());
        Ok(())
    }

    #[test]
    fn tcp_table_endpoint_parser_uses_procfs_little_endian_ipv4()
    -> Result<(), Box<dyn std::error::Error>> {
        let endpoint = parse_tcp_endpoint(Path::new("/proc/net/tcp"), "0100007F:1F90")?;

        assert_eq!(
            endpoint,
            TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 8080)
        );
        Ok(())
    }
}
