use std::{
    collections::{BTreeSet, HashMap, VecDeque},
    sync::{Arc, Mutex},
};

use attribution::{ProcfsSocketResolver, SocketFdConnectionContext, SocketFdLookup};
use capture::{
    CaptureError, LibsslResolvedFlow, LibsslUprobeFlowLookup, LibsslUprobeFlowResolver,
    LibsslUprobePlaintextReconcile,
};
use probe_core::{ProcessContext, ProcessGeneration, TcpConnection};

const MAX_TRACKED_LIBSSL_FLOWS: usize = 8192;

pub(super) struct ProcfsLibsslFlowResolver {
    resolver: ProcfsSocketResolver,
    starts: TrackedLibsslFlowStarts,
    attached_processes: AttachedLibsslProcessRegistry,
}

impl ProcfsLibsslFlowResolver {
    pub(super) fn new(attached_processes: AttachedLibsslProcessRegistry) -> Self {
        Self {
            resolver: ProcfsSocketResolver::default(),
            starts: TrackedLibsslFlowStarts::default(),
            attached_processes,
        }
    }

    fn resolve_fd(
        &mut self,
        lookup: &LibsslUprobeFlowLookup,
        tgid: u32,
        thread_pid: u32,
    ) -> Result<Option<SocketFdConnectionContext>, CaptureError> {
        let Some(fd) = lookup.fd else {
            return Ok(None);
        };
        self.resolver
            .resolve_tcp_fd(SocketFdLookup {
                tgid,
                thread_pid,
                fd,
                expected_remote_endpoint: None,
                process_hint: None,
            })
            .map_err(|error| {
                CaptureError::provider("libssl_uprobe_flow_resolver", error.to_string())
            })
    }

    fn resolve_attached_process_fd(
        &mut self,
        lookup: &LibsslUprobeFlowLookup,
    ) -> Result<Option<SocketFdConnectionContext>, CaptureError> {
        let mut matched = None;
        for process in self.attached_processes.processes() {
            let Some(resolved) = self.resolve_fd(lookup, process.pid, process.pid)? else {
                continue;
            };
            if resolved.process.identity.start_time_ticks != process.start_time_ticks {
                continue;
            }
            if !process_matches_libssl_lookup(&resolved.process, lookup) {
                continue;
            }
            if matched.replace(resolved).is_some() {
                return Ok(None);
            }
        }
        Ok(matched)
    }

    fn resolved_flow(
        &mut self,
        lookup: LibsslUprobeFlowLookup,
        resolved: SocketFdConnectionContext,
    ) -> LibsslResolvedFlow {
        let key = LibsslFlowStartKey {
            pid: resolved.process.identity.pid,
            start_time_ticks: resolved.process.identity.start_time_ticks,
            ssl_pointer: lookup.ssl_pointer,
            connection: resolved.connection,
        };
        let start = self.starts.start_for(key, resolved.socket_cookie);
        LibsslResolvedFlow {
            process: resolved.process,
            confidence: resolved.confidence,
            connection: resolved.connection,
            socket_cookie: start.socket_cookie,
            start_monotonic_ns: start.monotonic_ns,
        }
    }
}

impl LibsslUprobeFlowResolver for ProcfsLibsslFlowResolver {
    fn resolve_libssl_uprobe_flow(
        &mut self,
        lookup: LibsslUprobeFlowLookup,
    ) -> Result<Option<LibsslResolvedFlow>, CaptureError> {
        if let Some(resolved) = self.resolve_fd(&lookup, lookup.tgid, lookup.thread_pid)? {
            return Ok(Some(self.resolved_flow(lookup, resolved)));
        }
        let Some(resolved) = self.resolve_attached_process_fd(&lookup)? else {
            return Ok(None);
        };
        Ok(Some(self.resolved_flow(lookup, resolved)))
    }
}

#[derive(Debug, Clone, Default)]
pub(super) struct AttachedLibsslProcessRegistry {
    inner: Arc<Mutex<Vec<ProcessGeneration>>>,
}

impl AttachedLibsslProcessRegistry {
    fn processes(&self) -> Vec<ProcessGeneration> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn replace(&self, processes: Vec<ProcessGeneration>) {
        let mut unique = BTreeSet::new();
        let processes = processes
            .into_iter()
            .filter(|process| unique.insert(*process))
            .collect();
        *self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = processes;
    }

    pub(super) fn replace_from_reconcile(&self, result: &LibsslUprobePlaintextReconcile) {
        if result.active_targets.omitted_count() > 0 {
            self.replace(Vec::new());
            return;
        }
        self.replace(
            result
                .active_targets
                .targets()
                .iter()
                .map(|target| ProcessGeneration {
                    pid: target.pid,
                    start_time_ticks: target.start_time_ticks,
                })
                .collect(),
        );
    }
}

fn process_matches_libssl_lookup(
    process: &ProcessContext,
    lookup: &LibsslUprobeFlowLookup,
) -> bool {
    !lookup.command.is_empty()
        && process.identity.uid == lookup.uid
        && process.identity.gid == lookup.gid
        && process.name == lookup.command
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct LibsslFlowStartKey {
    pid: u32,
    start_time_ticks: u64,
    ssl_pointer: u64,
    connection: TcpConnection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LibsslFlowStart {
    monotonic_ns: u64,
    socket_cookie: Option<u64>,
}

struct TrackedLibsslFlowStarts {
    by_key: HashMap<LibsslFlowStartKey, LibsslFlowStart>,
    recency: VecDeque<LibsslFlowStartKey>,
    next_start_monotonic_ns: u64,
    max_tracked_flows: usize,
}

impl Default for TrackedLibsslFlowStarts {
    fn default() -> Self {
        Self {
            by_key: HashMap::new(),
            recency: VecDeque::new(),
            next_start_monotonic_ns: 0,
            max_tracked_flows: MAX_TRACKED_LIBSSL_FLOWS,
        }
    }
}

impl TrackedLibsslFlowStarts {
    fn start_for(
        &mut self,
        key: LibsslFlowStartKey,
        socket_cookie: Option<u64>,
    ) -> LibsslFlowStart {
        if let Some(start) = self.by_key.get(&key).copied() {
            self.refresh(key);
            return start;
        }
        self.next_start_monotonic_ns = self.next_start_monotonic_ns.saturating_add(1);
        self.evict_until_available();
        let start = LibsslFlowStart {
            monotonic_ns: self.next_start_monotonic_ns,
            socket_cookie,
        };
        self.recency.push_back(key);
        self.by_key.insert(key, start);
        start
    }

    fn refresh(&mut self, key: LibsslFlowStartKey) {
        self.recency.retain(|tracked| *tracked != key);
        self.recency.push_back(key);
    }

    fn evict_until_available(&mut self) {
        if self.max_tracked_flows == 0 {
            self.by_key.clear();
            self.recency.clear();
            return;
        }
        while self.by_key.len() >= self.max_tracked_flows {
            let Some(evicted) = self.recency.pop_front() else {
                self.by_key.clear();
                break;
            };
            if self.by_key.remove(&evicted).is_some() {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use capture::{
        LibsslUprobeAttachTargetSnapshot, LibsslUprobeReconcileTargetBucket,
        MAX_LIBSSL_RECONCILE_TARGET_SNAPSHOTS_PER_BUCKET,
    };
    use probe_core::{ProcessGeneration, TcpConnection, TcpEndpoint};

    use super::*;

    #[test]
    fn tracked_flow_starts_keep_identity_stable_for_same_ssl_connection() {
        let mut starts = TrackedLibsslFlowStarts::default();
        let key = flow_key(1, 0xfeed, connection(443));

        let first = starts.start_for(key, Some(11));
        let second = starts.start_for(key, Some(11));
        let other = starts.start_for(flow_key(1, 0xbeef, connection(443)), Some(11));

        assert_eq!(first, second);
        assert_ne!(first, other);
    }

    #[test]
    fn tracked_flow_starts_pin_first_socket_cookie_state() {
        let mut starts = TrackedLibsslFlowStarts::default();
        let key = flow_key(1, 0xfeed, connection(443));

        let first = starts.start_for(key, None);
        let second = starts.start_for(key, Some(99));
        let other_key = flow_key(1, 0xbeef, connection(443));
        let third = starts.start_for(other_key, Some(123));
        let fourth = starts.start_for(other_key, None);

        assert_eq!(first.monotonic_ns, second.monotonic_ns);
        assert_eq!(second.socket_cookie, None);
        assert_eq!(third.monotonic_ns, fourth.monotonic_ns);
        assert_eq!(fourth.socket_cookie, Some(123));
    }

    #[test]
    fn tracked_flow_starts_include_process_generation_and_connection() {
        let mut starts = TrackedLibsslFlowStarts::default();
        let first = starts.start_for(flow_key(1, 0xfeed, connection(443)), Some(11));
        let reused_pid = starts.start_for(flow_key(2, 0xfeed, connection(443)), Some(11));
        let reused_ssl = starts.start_for(flow_key(1, 0xfeed, connection(8443)), Some(11));

        assert_ne!(first, reused_pid);
        assert_ne!(first, reused_ssl);
    }

    #[test]
    fn attached_process_registry_tracks_unique_reconcile_active_processes() {
        let registry = AttachedLibsslProcessRegistry::default();
        registry.replace(vec![process_generation(7, 70), process_generation(7, 70)]);

        assert_eq!(registry.processes(), vec![process_generation(7, 70)]);

        registry.replace_from_reconcile(&reconcile_result(0, 0, 2));

        assert_eq!(
            registry.processes(),
            vec![
                process_generation(3_000, 300_000),
                process_generation(3_001, 300_100)
            ]
        );
    }

    #[test]
    fn attached_process_registry_clears_truncated_reconcile_active_processes() {
        let registry = AttachedLibsslProcessRegistry::default();
        registry.replace(vec![process_generation(7, 70)]);

        registry.replace_from_reconcile(&reconcile_result(
            0,
            0,
            MAX_LIBSSL_RECONCILE_TARGET_SNAPSHOTS_PER_BUCKET + 1,
        ));

        assert!(registry.processes().is_empty());
    }

    fn flow_key(
        start_time_ticks: u64,
        ssl_pointer: u64,
        connection: TcpConnection,
    ) -> LibsslFlowStartKey {
        LibsslFlowStartKey {
            pid: 7,
            start_time_ticks,
            ssl_pointer,
            connection,
        }
    }

    fn connection(remote_port: u16) -> TcpConnection {
        TcpConnection::new(
            TcpEndpoint::new("127.0.0.1".parse().expect("valid local address"), 50_000),
            TcpEndpoint::new(
                "127.0.0.1".parse().expect("valid remote address"),
                remote_port,
            ),
        )
    }

    fn process_generation(pid: u32, start_time_ticks: u64) -> ProcessGeneration {
        ProcessGeneration {
            pid,
            start_time_ticks,
        }
    }

    fn reconcile_result(
        attached: usize,
        detached: usize,
        active: usize,
    ) -> LibsslUprobePlaintextReconcile {
        LibsslUprobePlaintextReconcile {
            attached_targets: target_snapshots("attached", 1_000, attached),
            detached_targets: target_snapshots("detached", 2_000, detached),
            active_targets: target_snapshots("active", 3_000, active),
        }
    }

    fn target_snapshots(
        kind: &str,
        first_pid: u32,
        count: usize,
    ) -> LibsslUprobeReconcileTargetBucket {
        let targets = (0..count)
            .map(|index| {
                let pid = first_pid + index as u32;
                LibsslUprobeAttachTargetSnapshot {
                    pid,
                    start_time_ticks: u64::from(pid) * 100,
                    mapped_path: format!("/usr/lib/{kind}-{pid}.so").into(),
                    read_path: format!("/proc/{pid}/root/usr/lib/{kind}.so").into(),
                    device_major: 8,
                    device_minor: 1,
                    inode: u64::from(pid),
                    deleted: false,
                    link_ownership: capture::LibsslUprobeAttachLinkOwnershipSnapshot::unreported(),
                }
            })
            .collect::<Vec<_>>();
        LibsslUprobeReconcileTargetBucket::new(targets)
    }
}
