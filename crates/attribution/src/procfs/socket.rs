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
        SocketFdCandidate, SocketFdCandidateSource, hinted_socket_fd_candidates,
        read_socket_cookie_for_pid_fd, socket_fd_candidates_for_lookup, socket_inode_owner_scan,
    },
    io::read_tcp_table_to_string,
    process::{ProcessAttributor, ProcfsAttributor},
    tcp_table::{
        ProcfsTcpListenerEntry, ProcfsTcpTableFamily, ProcfsTcpTablePolicy, connection_uses_family,
        connections_by_inode, endpoint_uses_family, procfs_tcp_tables, tcp_entries_from_table,
        tcp_inode_map_from_entries, tcp_listener_entries_from_entries,
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
pub struct TcpListenerProcessContext {
    pub process: ProcessContext,
    pub confidence: u8,
    pub socket_inode: u64,
    pub local: TcpEndpoint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpListenerProcessLookup {
    pub listeners: Vec<TcpListenerProcessContext>,
    pub unattributed_socket_inodes: Vec<u64>,
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
    connections_by_inode: HashMap<u64, Vec<TcpConnection>>,
    inode_pids: HashMap<u64, Vec<u32>>,
    inode_owner_scan_complete: bool,
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
        self.refresh_snapshot_if_needed()?;
        let Some(snapshot) = self.snapshot.as_ref().map(|cached| &cached.snapshot) else {
            return Ok(TcpListenerProcessLookup {
                listeners: Vec::new(),
                unattributed_socket_inodes: Vec::new(),
            });
        };
        self.attributor
            .identify_tcp_listeners_by_local_port_in_snapshot(local_port, snapshot)
    }

    pub fn resolve_tcp_listeners(&mut self) -> Result<TcpListenerProcessLookup, AttributionError> {
        self.refresh_snapshot_if_needed()?;
        let Some(snapshot) = self.snapshot.as_ref().map(|cached| &cached.snapshot) else {
            return Ok(TcpListenerProcessLookup {
                listeners: Vec::new(),
                unattributed_socket_inodes: Vec::new(),
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
        self.identify_tcp_listeners_in_snapshot(Some(local_port), snapshot)
    }

    fn identify_tcp_listeners_in_snapshot(
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
        let mut unattributed_socket_inodes = Vec::new();
        for listener in snapshot
            .tcp_listeners
            .iter()
            .filter(|listener| local_port.is_none_or(|port| listener.local.port == port))
        {
            let Some(pids) = snapshot.inode_pids.get(&listener.inode) else {
                push_unique(&mut unattributed_socket_inodes, listener.inode);
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
                        push_unique(&mut unattributed_socket_inodes, listener.inode);
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                listeners.push(TcpListenerProcessContext {
                    process,
                    confidence: PROCFS_SOCKET_CONFIDENCE,
                    socket_inode: listener.inode,
                    local: listener.local,
                });
            }
        }
        Ok(TcpListenerProcessLookup {
            listeners,
            unattributed_socket_inodes,
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
        self.identify_hinted_fd_in_snapshot(&lookup, snapshot)
    }

    fn identify_process(&self, pid: u32) -> Result<Option<ProcessContext>, AttributionError> {
        self.process_attributor.identify_if_present(pid)
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
            if candidate.source == SocketFdCandidateSource::ProcessHint
                && !lookup
                    .process_hint
                    .as_ref()
                    .is_some_and(|hint| process_matches_hint(&process, hint))
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
                "procfs socket attribution can read /proc/net/tcp and proc root, opportunistically reads /proc/net/tcp6, resolves fd lookups through procfs PID namespace aliases, captures SO_COOKIE for live socket fd lookups when pidfd_getfd is permitted and the duplicated fd inode still matches, and can use unique fd/process-hint candidates when kernel PIDs are hidden; fd races, hidepid, namespace boundaries, and PID reuse remain possible",
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
        let snapshot = self.snapshot()?;
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
        Ok(())
    }

    fn snapshot(&self) -> Result<ProcfsSocketSnapshot, AttributionError> {
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
            inode_pids: owner_scan.pids_by_inode,
            inode_owner_scan_complete: owner_scan.complete,
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

fn push_unique(values: &mut Vec<u64>, value: u64) {
    if !values.contains(&value) {
        values.push(value);
    }
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

        assert_eq!(lookup.unattributed_socket_inodes, Vec::<u64>::new());
        let [listener] = lookup.listeners.as_slice() else {
            panic!("expected one attributed listener: {lookup:?}");
        };
        assert_eq!(listener.process.identity.pid, 321);
        assert_eq!(listener.process.name, "demo-listener");
        assert_eq!(listener.socket_inode, 424_242);
        assert_eq!(listener.local.port, 8443);
        Ok(())
    }

    #[test]
    fn reports_unattributed_tcp_listener_inode() -> Result<(), Box<dyn std::error::Error>> {
        let proc = FakeProc::new()?;
        proc.write_tcp_table(&[tcp_line(0, "0100007F:20FB", "00000000:0000", "0A", 424_242)])?;
        let mut resolver = ProcfsSocketResolver::with_paths(proc.root(), proc.boot_id_path());

        let lookup = resolver.resolve_tcp_listeners_by_local_port(8443)?;

        assert!(lookup.listeners.is_empty());
        assert_eq!(lookup.unattributed_socket_inodes, vec![424_242]);
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

        assert_eq!(lookup.unattributed_socket_inodes, Vec::<u64>::new());
        let mut pids = lookup
            .listeners
            .iter()
            .map(|listener| listener.process.identity.pid)
            .collect::<Vec<_>>();
        pids.sort_unstable();
        assert_eq!(pids, vec![321, 654]);
        assert!(
            lookup
                .listeners
                .iter()
                .all(|listener| listener.socket_inode == 424_242)
        );
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

        assert_eq!(lookup.unattributed_socket_inodes, vec![646_464]);
        let mut listeners = lookup
            .listeners
            .iter()
            .map(|listener| (listener.local.port, listener.process.identity.pid))
            .collect::<Vec<_>>();
        listeners.sort_unstable();
        assert_eq!(listeners, vec![(8443, 321), (9443, 654)]);
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

        fn write_process_with_socket(
            &self,
            pid: u32,
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
                    "Name:\t{name}\nTgid:\t{pid}\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n"
                ),
            )?;
            fs::write(process_root.join("cmdline"), format!("{name}\0--serve\0"))?;
            fs::write(
                process_root.join("cgroup"),
                "0::/system.slice/demo.service\n",
            )?;
            symlink("/usr/bin/demo-listener", process_root.join("exe"))?;
            symlink(format!("socket:[{inode}]"), process_root.join("fd/7"))?;
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

    fn stat(pid: u32, name: &str, start_time_ticks: u64) -> String {
        format!(
            "{pid} ({name}) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 {start_time_ticks} 20\n"
        )
    }
}
