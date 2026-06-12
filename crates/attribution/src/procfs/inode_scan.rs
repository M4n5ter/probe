use std::{collections::HashMap, fs, io, path::Path};

use super::{AttributionError, socket::SocketFdLookup};

pub(super) fn inode_pid_map(proc_root: &Path) -> Result<HashMap<u64, u32>, AttributionError> {
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

pub(super) fn read_socket_inode_for_lookup_fd(
    proc_root: &Path,
    lookup: SocketFdLookup,
) -> Result<Option<u64>, AttributionError> {
    let thread_inode = read_socket_inode_for_pid_fd(proc_root, lookup.thread_pid, lookup.fd)?;
    if thread_inode.is_some() || lookup.thread_pid == lookup.tgid {
        return Ok(thread_inode);
    }
    read_socket_inode_for_pid_fd(proc_root, lookup.tgid, lookup.fd)
}

pub(super) fn is_skippable_socket_scan_error(source: &io::Error) -> bool {
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
