use std::{
    fs, io,
    path::{Path, PathBuf},
};

use probe_core::{CapabilityKind, CapabilityState, ProcessContext, ProcessIdentity};
use thiserror::Error;

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
    use std::{fs, os::unix::fs::symlink};

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
}
