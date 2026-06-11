use std::{
    fmt,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

#[cfg(target_os = "linux")]
const BPF_FS_MAGIC: u64 = 0xcafe_4a11;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfHostProbeConfig {
    pub btf_vmlinux_path: PathBuf,
    pub bpffs_path: PathBuf,
    pub unprivileged_bpf_disabled_path: PathBuf,
}

impl Default for EbpfHostProbeConfig {
    fn default() -> Self {
        Self {
            btf_vmlinux_path: PathBuf::from("/sys/kernel/btf/vmlinux"),
            bpffs_path: PathBuf::from("/sys/fs/bpf"),
            unprivileged_bpf_disabled_path: PathBuf::from(
                "/proc/sys/kernel/unprivileged_bpf_disabled",
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EbpfHostProbeReport {
    pub linux: bool,
    pub btf_vmlinux: EbpfProbeCheck,
    pub bpffs: EbpfProbeCheck,
    pub unprivileged_bpf: UnprivilegedBpfStatus,
}

impl EbpfHostProbeReport {
    pub fn kernel_prerequisites_available(&self) -> bool {
        self.linux && self.btf_vmlinux.is_available() && self.bpffs.is_available()
    }

    pub fn summary(&self) -> String {
        if !self.linux {
            return "eBPF capture requires Linux".to_string();
        }
        format!(
            "btf_vmlinux={}, bpffs={}, unprivileged_bpf={}",
            self.btf_vmlinux.summary(),
            self.bpffs.summary(),
            self.unprivileged_bpf
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum EbpfProbeCheck {
    Available,
    Unavailable { reason: String },
}

impl EbpfProbeCheck {
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available)
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Available => None,
            Self::Unavailable { reason } => Some(reason),
        }
    }

    fn available() -> Self {
        Self::Available
    }

    fn unavailable(reason: impl Into<String>) -> Self {
        Self::Unavailable {
            reason: reason.into(),
        }
    }

    fn summary(&self) -> String {
        match self {
            Self::Available => "available".to_string(),
            Self::Unavailable { reason } => reason.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum UnprivilegedBpfStatus {
    Enabled,
    Disabled,
    PermanentlyDisabled,
    Unknown { reason: String },
}

impl fmt::Display for UnprivilegedBpfStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Enabled => formatter.write_str("enabled"),
            Self::Disabled => formatter.write_str("disabled"),
            Self::PermanentlyDisabled => formatter.write_str("permanently_disabled"),
            Self::Unknown { reason } => write!(formatter, "unknown({reason})"),
        }
    }
}

pub struct EbpfHostProbe;

impl EbpfHostProbe {
    pub fn probe(config: &EbpfHostProbeConfig) -> EbpfHostProbeReport {
        Self::probe_with_linux(config, cfg!(target_os = "linux"))
    }

    fn probe_with_linux(config: &EbpfHostProbeConfig, linux: bool) -> EbpfHostProbeReport {
        if !linux {
            return EbpfHostProbeReport {
                linux,
                btf_vmlinux: EbpfProbeCheck::unavailable("not running on Linux"),
                bpffs: EbpfProbeCheck::unavailable("not running on Linux"),
                unprivileged_bpf: UnprivilegedBpfStatus::Unknown {
                    reason: "not running on Linux".to_string(),
                },
            };
        }

        EbpfHostProbeReport {
            linux,
            btf_vmlinux: probe_regular_file(&config.btf_vmlinux_path, "BTF vmlinux"),
            bpffs: probe_bpffs(&config.bpffs_path),
            unprivileged_bpf: probe_unprivileged_bpf(&config.unprivileged_bpf_disabled_path),
        }
    }
}

fn probe_regular_file(path: &Path, label: &str) -> EbpfProbeCheck {
    match path.symlink_metadata() {
        Ok(metadata) if metadata.file_type().is_file() => EbpfProbeCheck::available(),
        Ok(metadata) if metadata.file_type().is_symlink() => {
            EbpfProbeCheck::unavailable(format!("{label} path {} is a symlink", path.display()))
        }
        Ok(metadata) if metadata.is_dir() => {
            EbpfProbeCheck::unavailable(format!("{label} path {} is a directory", path.display()))
        }
        Ok(_) => EbpfProbeCheck::unavailable(format!(
            "{label} path {} is not a regular file",
            path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            EbpfProbeCheck::unavailable(format!("{label} path {} does not exist", path.display()))
        }
        Err(error) => EbpfProbeCheck::unavailable(format!(
            "failed to inspect {label} path {}: {error}",
            path.display()
        )),
    }
}

fn probe_bpffs(path: &Path) -> EbpfProbeCheck {
    match path.symlink_metadata() {
        Ok(metadata) if metadata.is_dir() => probe_bpffs_filesystem(path),
        Ok(metadata) if metadata.file_type().is_symlink() => {
            EbpfProbeCheck::unavailable(format!("bpffs path {} is a symlink", path.display()))
        }
        Ok(_) => {
            EbpfProbeCheck::unavailable(format!("bpffs path {} is not a directory", path.display()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            EbpfProbeCheck::unavailable(format!("bpffs path {} does not exist", path.display()))
        }
        Err(error) => EbpfProbeCheck::unavailable(format!(
            "failed to inspect bpffs path {}: {error}",
            path.display()
        )),
    }
}

#[cfg(target_os = "linux")]
fn probe_bpffs_filesystem(path: &Path) -> EbpfProbeCheck {
    match rustix::fs::statfs(path) {
        Ok(statfs) if statfs_type_is_bpffs(statfs.f_type as u64) => EbpfProbeCheck::available(),
        Ok(statfs) => EbpfProbeCheck::unavailable(format!(
            "bpffs path {} is mounted as filesystem type 0x{:x}, not bpffs",
            path.display(),
            statfs.f_type as u64 & 0xffff_ffff
        )),
        Err(error) => EbpfProbeCheck::unavailable(format!(
            "failed to inspect bpffs filesystem {}: {error}",
            path.display()
        )),
    }
}

#[cfg(not(target_os = "linux"))]
fn probe_bpffs_filesystem(path: &Path) -> EbpfProbeCheck {
    EbpfProbeCheck::unavailable(format!(
        "bpffs filesystem check requires Linux target for {}",
        path.display()
    ))
}

#[cfg(target_os = "linux")]
fn statfs_type_is_bpffs(statfs_type: u64) -> bool {
    statfs_type == BPF_FS_MAGIC || (statfs_type & 0xffff_ffff) == BPF_FS_MAGIC
}

fn probe_unprivileged_bpf(path: &Path) -> UnprivilegedBpfStatus {
    match std::fs::read_to_string(path) {
        Ok(value) => match value.trim() {
            "0" => UnprivilegedBpfStatus::Enabled,
            "1" => UnprivilegedBpfStatus::PermanentlyDisabled,
            "2" => UnprivilegedBpfStatus::Disabled,
            other => UnprivilegedBpfStatus::Unknown {
                reason: format!(
                    "unexpected unprivileged_bpf_disabled value at {}: {other}",
                    path.display()
                ),
            },
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            UnprivilegedBpfStatus::Unknown {
                reason: format!(
                    "unprivileged_bpf_disabled path {} does not exist",
                    path.display()
                ),
            }
        }
        Err(error) => UnprivilegedBpfStatus::Unknown {
            reason: format!(
                "failed to read unprivileged_bpf_disabled path {}: {error}",
                path.display()
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use tempfile::tempdir;

    #[test]
    fn report_marks_available_kernel_prerequisites() {
        let report = EbpfHostProbeReport {
            linux: true,
            btf_vmlinux: EbpfProbeCheck::available(),
            bpffs: EbpfProbeCheck::available(),
            unprivileged_bpf: UnprivilegedBpfStatus::Disabled,
        };

        assert!(report.kernel_prerequisites_available());
        assert!(report.summary().contains("btf_vmlinux=available"));
        assert!(report.summary().contains("bpffs=available"));
    }

    #[test]
    fn host_probe_reports_unprivileged_bpf_states() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let bpf_sysctl = temp.path().join("unprivileged_bpf_disabled");
        fs::write(&bpf_sysctl, b"1\n")?;

        assert_eq!(
            probe_unprivileged_bpf(&bpf_sysctl),
            UnprivilegedBpfStatus::PermanentlyDisabled
        );

        fs::write(&bpf_sysctl, b"2\n")?;
        assert_eq!(
            probe_unprivileged_bpf(&bpf_sysctl),
            UnprivilegedBpfStatus::Disabled
        );
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn host_probe_reports_non_bpffs_directory() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let btf = temp.path().join("vmlinux");
        let bpffs = temp.path().join("bpffs");
        let unprivileged = temp.path().join("unprivileged_bpf_disabled");
        fs::write(&btf, b"btf")?;
        fs::create_dir(&bpffs)?;
        fs::write(&unprivileged, b"2\n")?;
        let config = EbpfHostProbeConfig {
            btf_vmlinux_path: btf,
            bpffs_path: bpffs,
            unprivileged_bpf_disabled_path: unprivileged,
        };

        let report = EbpfHostProbe::probe_with_linux(&config, true);

        assert!(!report.kernel_prerequisites_available());
        assert!(report.btf_vmlinux.is_available());
        assert!(!report.bpffs.is_available());
        assert!(
            report
                .bpffs
                .reason()
                .is_some_and(|reason| reason.contains("not bpffs"))
        );
        assert_eq!(report.unprivileged_bpf, UnprivilegedBpfStatus::Disabled);
        Ok(())
    }

    #[test]
    fn host_probe_reports_missing_btf_and_bpffs() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let config = EbpfHostProbeConfig {
            btf_vmlinux_path: temp.path().join("missing-vmlinux"),
            bpffs_path: temp.path().join("missing-bpffs"),
            unprivileged_bpf_disabled_path: temp.path().join("missing-unprivileged"),
        };

        let report = EbpfHostProbe::probe_with_linux(&config, true);

        assert!(!report.kernel_prerequisites_available());
        assert!(!report.btf_vmlinux.is_available());
        assert!(!report.bpffs.is_available());
        assert!(matches!(
            report.unprivileged_bpf,
            UnprivilegedBpfStatus::Unknown { .. }
        ));
        Ok(())
    }

    #[test]
    fn host_probe_reports_non_linux_as_unavailable() {
        let report = EbpfHostProbe::probe_with_linux(&EbpfHostProbeConfig::default(), false);

        assert!(!report.kernel_prerequisites_available());
        assert_eq!(report.summary(), "eBPF capture requires Linux");
    }
}
