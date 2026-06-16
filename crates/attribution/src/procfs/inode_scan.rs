use std::{collections::HashMap, fs, io, path::Path};

use super::{
    AttributionError,
    pid_scan::{ProcfsPidEntry, numeric_pid_dirs},
    socket::SocketFdLookup,
};

const LINUX_ESRCH: i32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SocketFdInode {
    pub(super) inode: u64,
    pub(super) process_pid: u32,
    pub(super) source: SocketFdInodeSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SocketFdInodeSource {
    Direct,
    NamespaceAlias,
    ProcessHint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SocketFdCandidateScan {
    pub(super) candidates: Vec<SocketFdInode>,
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
            SocketFdInode {
                inode,
                process_pid: lookup.tgid,
                source: SocketFdInodeSource::Direct,
            },
        );
    }
    if lookup.thread_pid != lookup.tgid
        && let Some(inode) = read_socket_inode_for_pid_fd(proc_root, lookup.tgid, lookup.fd)?
    {
        push_socket_fd_candidate(
            &mut candidates,
            SocketFdInode {
                inode,
                process_pid: lookup.tgid,
                source: SocketFdInodeSource::Direct,
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
                    SocketFdInode {
                        inode,
                        process_pid,
                        source: SocketFdInodeSource::NamespaceAlias,
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
                    SocketFdInode {
                        inode,
                        process_pid: pid,
                        source: SocketFdInodeSource::ProcessHint,
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

fn push_socket_fd_candidate(candidates: &mut Vec<SocketFdInode>, candidate: SocketFdInode) {
    if !candidates.iter().any(|existing| {
        existing.inode == candidate.inode && existing.process_pid == candidate.process_pid
    }) {
        candidates.push(candidate);
    }
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
    use std::{collections::HashMap, fs, io, os::unix::fs::PermissionsExt};

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
}
