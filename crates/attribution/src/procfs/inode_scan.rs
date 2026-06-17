use std::{collections::HashMap, fs, io, os::fd::AsRawFd, path::Path};

use super::{
    AttributionError,
    pid_scan::{ProcfsPidEntry, numeric_pid_dirs},
    socket::SocketFdLookup,
};

const LINUX_ESRCH: i32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SocketFdCandidate {
    pub(super) inode: u64,
    pub(super) fd_pid: u32,
    pub(super) process_pid: u32,
    pub(super) source: SocketFdCandidateSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SocketFdCandidateSource {
    Direct,
    NamespaceAlias,
    ProcessHint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SocketFdCandidateScan {
    pub(super) candidates: Vec<SocketFdCandidate>,
    pub(super) complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NamespaceTgidCandidateScan {
    pids: Vec<u32>,
    complete: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SocketFdRead {
    Present(u64),
    Absent,
    Unknown,
}

pub(super) fn inode_pid_map(proc_root: &Path) -> Result<HashMap<u64, u32>, AttributionError> {
    let mut inodes = HashMap::new();
    for ProcfsPidEntry { pid, path } in numeric_pid_dirs(proc_root)? {
        read_pid_socket_inodes(&path.join("fd"), pid, &mut inodes)?;
    }
    Ok(inodes)
}

pub(super) fn read_pid_socket_inodes(
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

pub(super) fn read_socket_inode_for_pid_fd(
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

pub(super) fn socket_fd_candidates_for_lookup(
    proc_root: &Path,
    lookup: &SocketFdLookup,
) -> Result<SocketFdCandidateScan, AttributionError> {
    let mut candidates = Vec::new();
    let thread_inode = read_socket_inode_for_pid_fd(proc_root, lookup.thread_pid, lookup.fd)?;
    if let Some(inode) = thread_inode {
        push_socket_fd_candidate(
            &mut candidates,
            SocketFdCandidate {
                inode,
                fd_pid: lookup.thread_pid,
                process_pid: lookup.tgid,
                source: SocketFdCandidateSource::Direct,
            },
        );
    }
    if lookup.thread_pid != lookup.tgid
        && let Some(inode) = read_socket_inode_for_pid_fd(proc_root, lookup.tgid, lookup.fd)?
    {
        push_socket_fd_candidate(
            &mut candidates,
            SocketFdCandidate {
                inode,
                fd_pid: lookup.tgid,
                process_pid: lookup.tgid,
                source: SocketFdCandidateSource::Direct,
            },
        );
    }
    if !candidates.is_empty() || pid_dir_is_visible(proc_root, lookup.tgid) {
        return Ok(SocketFdCandidateScan {
            candidates,
            complete: true,
        });
    }

    let mut complete = true;
    let namespace_scan = namespace_tgid_candidates(proc_root, lookup.tgid)?;
    complete &= namespace_scan.complete;
    for process_pid in namespace_scan.pids {
        if process_pid == lookup.tgid {
            continue;
        }
        match read_socket_inode_for_candidate_pid_fd(proc_root, process_pid, lookup.fd)? {
            SocketFdRead::Present(inode) => {
                push_socket_fd_candidate(
                    &mut candidates,
                    SocketFdCandidate {
                        inode,
                        fd_pid: process_pid,
                        process_pid,
                        source: SocketFdCandidateSource::NamespaceAlias,
                    },
                );
            }
            SocketFdRead::Absent => {}
            SocketFdRead::Unknown => complete = false,
        }
    }
    Ok(SocketFdCandidateScan {
        candidates,
        complete,
    })
}

pub(super) fn hinted_socket_fd_candidates(
    proc_root: &Path,
    lookup: &SocketFdLookup,
) -> Result<SocketFdCandidateScan, AttributionError> {
    if pid_dir_is_visible(proc_root, lookup.tgid) {
        return Ok(SocketFdCandidateScan {
            candidates: Vec::new(),
            complete: true,
        });
    }

    let mut candidates = Vec::new();
    let mut complete = true;
    for ProcfsPidEntry { pid, .. } in numeric_pid_dirs(proc_root)? {
        if pid == lookup.tgid || pid == lookup.thread_pid {
            continue;
        }
        match read_socket_inode_for_candidate_pid_fd(proc_root, pid, lookup.fd)? {
            SocketFdRead::Present(inode) => {
                push_socket_fd_candidate(
                    &mut candidates,
                    SocketFdCandidate {
                        inode,
                        fd_pid: pid,
                        process_pid: pid,
                        source: SocketFdCandidateSource::ProcessHint,
                    },
                );
            }
            SocketFdRead::Absent => {}
            SocketFdRead::Unknown => complete = false,
        }
    }
    Ok(SocketFdCandidateScan {
        candidates,
        complete,
    })
}

fn push_socket_fd_candidate(candidates: &mut Vec<SocketFdCandidate>, candidate: SocketFdCandidate) {
    if let Some(existing) = candidates.iter_mut().find(|existing| {
        existing.inode == candidate.inode && existing.process_pid == candidate.process_pid
    }) {
        if existing.fd_pid != existing.process_pid && candidate.fd_pid == candidate.process_pid {
            existing.fd_pid = candidate.fd_pid;
        }
        return;
    }
    candidates.push(candidate);
}

fn pid_dir_is_visible(proc_root: &Path, pid: u32) -> bool {
    match fs::metadata(proc_root.join(pid.to_string())) {
        Ok(_) => true,
        Err(source) => !is_absent_pid_dir_error(&source),
    }
}

fn is_absent_pid_dir_error(source: &io::Error) -> bool {
    source.kind() == io::ErrorKind::NotFound || source.raw_os_error() == Some(LINUX_ESRCH)
}

fn namespace_tgid_candidates(
    proc_root: &Path,
    observed_tgid: u32,
) -> Result<NamespaceTgidCandidateScan, AttributionError> {
    let mut pids = vec![observed_tgid];
    let mut complete = true;
    for ProcfsPidEntry { pid, path } in numeric_pid_dirs(proc_root)? {
        let status_path = path.join("status");
        let status = match fs::read_to_string(&status_path) {
            Ok(status) => status,
            Err(source) if is_absent_pid_dir_error(&source) => continue,
            Err(source) if source.kind() == io::ErrorKind::PermissionDenied => {
                complete = false;
                continue;
            }
            Err(source) => {
                return Err(AttributionError::Read {
                    path: status_path.display().to_string(),
                    source,
                });
            }
        };
        if parse_nstgid_chain(&status).contains(&observed_tgid) && !pids.contains(&pid) {
            pids.push(pid);
        }
    }
    Ok(NamespaceTgidCandidateScan { pids, complete })
}

fn parse_nstgid_chain(status: &str) -> Vec<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("NStgid:"))
        .into_iter()
        .flat_map(str::split_whitespace)
        .filter_map(|value| value.parse::<u32>().ok())
        .collect()
}

fn read_socket_inode_for_candidate_pid_fd(
    proc_root: &Path,
    pid: u32,
    fd: i32,
) -> Result<SocketFdRead, AttributionError> {
    if fd < 0 {
        return Ok(SocketFdRead::Absent);
    }
    let link_path = proc_root
        .join(pid.to_string())
        .join("fd")
        .join(fd.to_string());
    let target = match fs::read_link(&link_path) {
        Ok(target) => target,
        Err(source) if is_absent_pid_dir_error(&source) => return Ok(SocketFdRead::Absent),
        Err(source) if source.kind() == io::ErrorKind::PermissionDenied => {
            return Ok(SocketFdRead::Unknown);
        }
        Err(source) => {
            return Err(AttributionError::ReadLink {
                path: link_path.display().to_string(),
                source,
            });
        }
    };
    Ok(socket_inode_from_link(&target)
        .map(SocketFdRead::Present)
        .unwrap_or(SocketFdRead::Absent))
}

pub(super) fn read_socket_cookie_for_pid_fd(
    proc_root: &Path,
    pid: u32,
    fd: i32,
    expected_inode: u64,
) -> Option<u64> {
    if !proc_root_is_host_proc(proc_root) {
        return None;
    }
    let pid = i32::try_from(pid)
        .ok()
        .and_then(rustix::process::Pid::from_raw)?;
    let pidfd = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).ok()?;
    let socket =
        rustix::process::pidfd_getfd(pidfd, fd, rustix::process::PidfdGetfdFlags::empty()).ok()?;
    let duplicated_inode = socket_inode_for_current_process_fd(socket.as_raw_fd())?;
    if duplicated_inode != expected_inode {
        return None;
    }
    rustix::net::sockopt::socket_cookie(&socket)
        .ok()
        .filter(|cookie| *cookie != 0)
}

fn proc_root_is_host_proc(proc_root: &Path) -> bool {
    proc_root == Path::new("/proc")
}

fn socket_inode_for_current_process_fd(fd: i32) -> Option<u64> {
    let target = fs::read_link(Path::new("/proc/self/fd").join(fd.to_string())).ok()?;
    socket_inode_from_link(&target)
}

pub(super) fn is_skippable_socket_scan_error(source: &io::Error) -> bool {
    matches!(
        source.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
    ) || source.raw_os_error() == Some(LINUX_ESRCH)
}

fn socket_inode_from_link(target: &Path) -> Option<u64> {
    let target = target.to_str()?;
    target
        .strip_prefix("socket:[")
        .and_then(|value| value.strip_suffix(']'))
        .and_then(|value| value.parse::<u64>().ok())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        fs, io,
        net::TcpListener,
        os::{fd::AsRawFd, unix::fs::PermissionsExt},
        path::Path,
    };

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn procfs_socket_scan_treats_permission_denied_as_best_effort_skip() {
        let permission_denied = io::Error::from(io::ErrorKind::PermissionDenied);

        assert!(is_skippable_socket_scan_error(&permission_denied));
    }

    #[test]
    fn procfs_socket_scan_treats_esrch_as_best_effort_skip() {
        let disappeared = io::Error::from_raw_os_error(LINUX_ESRCH);

        assert!(is_skippable_socket_scan_error(&disappeared));
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

    #[test]
    fn socket_fd_candidates_prefer_tgid_fd_evidence_for_duplicate_direct_inode()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let proc_root = temp.path().join("proc");
        let thread_fd_dir = proc_root.join("123").join("fd");
        let tgid_fd_dir = proc_root.join("321").join("fd");
        fs::create_dir_all(&thread_fd_dir)?;
        fs::create_dir_all(&tgid_fd_dir)?;
        std::os::unix::fs::symlink("socket:[424242]", thread_fd_dir.join("7"))?;
        std::os::unix::fs::symlink("socket:[424242]", tgid_fd_dir.join("7"))?;

        let candidates = socket_fd_candidates_for_lookup(
            &proc_root,
            &SocketFdLookup {
                tgid: 321,
                thread_pid: 123,
                fd: 7,
                expected_remote_endpoint: None,
                process_hint: None,
            },
        )?;

        assert!(candidates.complete);
        assert_eq!(candidates.candidates.len(), 1);
        assert_eq!(candidates.candidates[0].inode, 424242);
        assert_eq!(candidates.candidates[0].process_pid, 321);
        assert_eq!(candidates.candidates[0].fd_pid, 321);
        Ok(())
    }

    #[test]
    fn socket_inode_lookup_guards_linux_socket_cookie_when_available()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        let inode = read_socket_inode_for_pid_fd(
            Path::new("/proc"),
            std::process::id(),
            listener.as_raw_fd(),
        )?
        .expect("live listener fd should resolve to a socket identity");

        assert!(inode > 0);
        if let Some(socket_cookie) = read_socket_cookie_for_pid_fd(
            Path::new("/proc"),
            std::process::id(),
            listener.as_raw_fd(),
            inode,
        ) {
            assert!(socket_cookie > 0);
            assert_eq!(
                read_socket_cookie_for_pid_fd(
                    Path::new("/proc"),
                    std::process::id(),
                    listener.as_raw_fd(),
                    inode.saturating_add(1),
                ),
                None
            );
        }
        Ok(())
    }
}
