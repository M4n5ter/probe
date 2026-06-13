use std::path::PathBuf;

use probe_core::{
    CapabilityKind, CapabilityState, LinuxProcStat, ProcessContext, ProcessIdentity,
    parse_linux_proc_stat,
};

use super::{
    AttributionError,
    io::{read_bytes, read_link_to_string, read_optional_to_string, read_to_string},
    pid_scan::numeric_pid_dirs,
};

pub trait ProcessAttributor {
    fn name(&self) -> &'static str;

    fn capabilities(&self) -> Vec<CapabilityState>;

    fn identify(&self, pid: u32) -> Result<ProcessContext, AttributionError>;
}

#[derive(Debug, Clone)]
pub struct ProcfsAttributor {
    pub(super) proc_root: PathBuf,
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

    pub fn process_ids(&self) -> Result<Vec<u32>, AttributionError> {
        numeric_pid_dirs(&self.proc_root)
            .map(|entries| entries.into_iter().map(|entry| entry.pid).collect())
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

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct ParsedStatus {
    tgid: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
}

fn parse_stat(pid: u32, content: &str) -> Result<LinuxProcStat, AttributionError> {
    parse_linux_proc_stat(content).map_err(|source| AttributionError::InvalidStat {
        pid,
        reason: source.to_string(),
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
