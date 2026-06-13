use std::{
    fs, io,
    path::{Path, PathBuf},
};

use super::AttributionError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProcfsPidEntry {
    pub(super) pid: u32,
    pub(super) path: PathBuf,
}

pub(super) fn numeric_pid_dirs(proc_root: &Path) -> Result<Vec<ProcfsPidEntry>, AttributionError> {
    let entries = fs::read_dir(proc_root).map_err(|source| AttributionError::Read {
        path: proc_root.display().to_string(),
        source,
    })?;
    let mut pids = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(source) if is_skippable_pid_scan_error(&source) => continue,
            Err(source) => {
                return Err(AttributionError::Read {
                    path: proc_root.display().to_string(),
                    source,
                });
            }
        };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(source) if is_skippable_pid_scan_error(&source) => continue,
            Err(source) => {
                return Err(AttributionError::Read {
                    path: path.display().to_string(),
                    source,
                });
            }
        };
        if file_type.is_dir() {
            pids.push(ProcfsPidEntry { pid, path });
        }
    }
    pids.sort_unstable_by_key(|entry| entry.pid);
    Ok(pids)
}

fn is_skippable_pid_scan_error(source: &io::Error) -> bool {
    matches!(
        source.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
    )
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn numeric_pid_dirs_lists_pid_directories_in_stable_order()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = tempdir()?;
        fs::create_dir(proc.path().join("42"))?;
        fs::create_dir(proc.path().join("7"))?;
        fs::create_dir(proc.path().join("self"))?;
        fs::write(proc.path().join("99"), "not a directory")?;

        let pids = numeric_pid_dirs(proc.path())?
            .into_iter()
            .map(|entry| entry.pid)
            .collect::<Vec<_>>();

        assert_eq!(pids, vec![7, 42]);
        Ok(())
    }

    #[test]
    fn numeric_pid_dirs_fails_when_proc_root_is_missing() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = tempdir()?;
        let proc = temp.path().join("missing");

        let error = numeric_pid_dirs(&proc).expect_err("missing proc root must fail");

        assert!(matches!(error, AttributionError::Read { .. }));
        Ok(())
    }
}
