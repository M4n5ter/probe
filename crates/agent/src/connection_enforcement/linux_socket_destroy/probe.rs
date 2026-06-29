use std::path::PathBuf;

use attribution::ProcfsSocketResolver;
use enforcement::linux_socket_destroy::{
    check_loopback_socket_destroy_support, find_ss_command, ss_supports_kill,
};
use probe_core::{CapabilityKind, CapabilityState};

pub(super) struct LinuxSocketDestroyProbe {
    command: Option<PathBuf>,
    running_as_root: bool,
    procfs_socket_attribution: Result<(), String>,
    active_socket_destroy: Option<Result<(), String>>,
}

impl Default for LinuxSocketDestroyProbe {
    fn default() -> Self {
        Self {
            command: find_ss_command(),
            running_as_root: is_root(),
            procfs_socket_attribution: ProcfsSocketResolver::new()
                .probe()
                .map_err(|error| error.to_string()),
            active_socket_destroy: None,
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

        let active_socket_destroy = self
            .active_socket_destroy
            .clone()
            .unwrap_or_else(|| check_loopback_socket_destroy_support(&command));
        if let Err(error) = active_socket_destroy {
            return LinuxSocketDestroyProbeResult::Unavailable(CapabilityState::unavailable(
                CapabilityKind::ConnectionEnforcement,
                format!("linux socket destroy enforcement active self-test failed: {error}"),
            ));
        }

        LinuxSocketDestroyProbeResult::Available { command }
    }
}

fn is_root() -> bool {
    rustix::process::geteuid().as_raw() == 0
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use probe_core::RuntimeMode;

    use super::*;

    #[test]
    fn linux_socket_destroy_probe_reports_missing_command_root_and_procfs_reasons() {
        let missing_command = unavailable_probe_reason(LinuxSocketDestroyProbe {
            command: None,
            running_as_root: true,
            procfs_socket_attribution: Ok(()),
            active_socket_destroy: Some(Ok(())),
        });
        assert!(missing_command.contains("trusted system path"));

        let missing_root = unavailable_probe_reason(LinuxSocketDestroyProbe {
            command: Some(PathBuf::from("/not/executed")),
            running_as_root: false,
            procfs_socket_attribution: Ok(()),
            active_socket_destroy: Some(Ok(())),
        });
        assert!(missing_root.contains("requires root"));

        let missing_procfs = unavailable_probe_reason(LinuxSocketDestroyProbe {
            command: Some(PathBuf::from("/not/executed")),
            running_as_root: true,
            procfs_socket_attribution: Err("procfs unavailable".to_string()),
            active_socket_destroy: Some(Ok(())),
        });
        assert!(missing_procfs.contains("requires procfs socket attribution"));

        let missing_kill_support = unavailable_probe_reason(LinuxSocketDestroyProbe {
            command: Some(PathBuf::from("/not/executed")),
            running_as_root: true,
            procfs_socket_attribution: Ok(()),
            active_socket_destroy: Some(Ok(())),
        });
        assert!(missing_kill_support.contains("does not advertise"));
    }

    #[test]
    fn linux_socket_destroy_probe_reports_active_self_test_failure()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let command = temp.path().join("ss");
        fs::write(&command, "#!/bin/sh\nprintf '%s\n' '-K --kill'\n")?;
        let mut permissions = fs::metadata(&command)?.permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&command, permissions)?;

        let reason = unavailable_probe_reason(LinuxSocketDestroyProbe {
            command: Some(command),
            running_as_root: true,
            procfs_socket_attribution: Ok(()),
            active_socket_destroy: Some(Err("self-test socket survived".to_string())),
        });

        assert!(reason.contains("active self-test failed"));
        assert!(reason.contains("self-test socket survived"));
        Ok(())
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
