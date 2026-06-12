use std::path::PathBuf;

use attribution::ProcfsSocketResolver;
use probe_core::{CapabilityKind, CapabilityState};

use super::ss::{find_ss_command, is_root, ss_supports_kill};

pub(super) struct LinuxSocketDestroyProbe {
    command: Option<PathBuf>,
    running_as_root: bool,
    procfs_socket_attribution: Result<(), String>,
}

impl Default for LinuxSocketDestroyProbe {
    fn default() -> Self {
        Self {
            command: find_ss_command(),
            running_as_root: is_root(),
            procfs_socket_attribution: ProcfsSocketResolver::new()
                .probe()
                .map_err(|error| error.to_string()),
        }
    }
}

pub(super) enum LinuxSocketDestroyProbeResult {
    Available { command: PathBuf },
    Unavailable(CapabilityState),
}

impl LinuxSocketDestroyProbe {
    pub(super) fn resolve(&self) -> LinuxSocketDestroyProbeResult {
        if !cfg!(target_os = "linux") {
            return LinuxSocketDestroyProbeResult::Unavailable(CapabilityState::unavailable(
                CapabilityKind::ConnectionEnforcement,
                "linux socket destroy enforcement requires Linux",
            ));
        }

        let Some(command) = self.command.clone() else {
            return LinuxSocketDestroyProbeResult::Unavailable(CapabilityState::unavailable(
                CapabilityKind::ConnectionEnforcement,
                "linux socket destroy enforcement requires ss at a trusted system path",
            ));
        };

        if !self.running_as_root {
            return LinuxSocketDestroyProbeResult::Unavailable(CapabilityState::unavailable(
                CapabilityKind::ConnectionEnforcement,
                "linux socket destroy enforcement requires root because the ss child process must retain socket destroy privileges after exec",
            ));
        }

        if let Err(error) = &self.procfs_socket_attribution {
            return LinuxSocketDestroyProbeResult::Unavailable(CapabilityState::unavailable(
                CapabilityKind::ConnectionEnforcement,
                format!(
                    "linux socket destroy enforcement requires procfs socket attribution before destructive socket close: {error}"
                ),
            ));
        }

        if !ss_supports_kill(&command) {
            return LinuxSocketDestroyProbeResult::Unavailable(CapabilityState::unavailable(
                CapabilityKind::ConnectionEnforcement,
                format!(
                    "ss command at {} does not advertise -K/--kill socket destroy support",
                    command.display()
                ),
            ));
        }

        LinuxSocketDestroyProbeResult::Available { command }
    }
}

#[cfg(test)]
mod tests {
    use probe_core::RuntimeMode;

    use super::*;

    #[test]
    fn linux_socket_destroy_probe_reports_missing_command_root_and_procfs_reasons() {
        let missing_command = unavailable_probe_reason(LinuxSocketDestroyProbe {
            command: None,
            running_as_root: true,
            procfs_socket_attribution: Ok(()),
        });
        assert!(missing_command.contains("trusted system path"));

        let missing_root = unavailable_probe_reason(LinuxSocketDestroyProbe {
            command: Some(PathBuf::from("/not/executed")),
            running_as_root: false,
            procfs_socket_attribution: Ok(()),
        });
        assert!(missing_root.contains("requires root"));

        let missing_procfs = unavailable_probe_reason(LinuxSocketDestroyProbe {
            command: Some(PathBuf::from("/not/executed")),
            running_as_root: true,
            procfs_socket_attribution: Err("procfs unavailable".to_string()),
        });
        assert!(missing_procfs.contains("requires procfs socket attribution"));
    }

    fn unavailable_probe_reason(probe: LinuxSocketDestroyProbe) -> String {
        match probe.resolve() {
            LinuxSocketDestroyProbeResult::Available { .. } => {
                panic!("probe should be unavailable")
            }
            LinuxSocketDestroyProbeResult::Unavailable(capability) => {
                assert_eq!(capability.kind, CapabilityKind::ConnectionEnforcement);
                assert_eq!(capability.mode, RuntimeMode::Unavailable);
                capability.reason.expect("unavailable reason")
            }
        }
    }
}
