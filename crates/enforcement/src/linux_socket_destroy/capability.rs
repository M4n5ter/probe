use attribution::ProcfsSocketResolver;

use super::{check_loopback_socket_destroy_support, check_socket_destroy_prerequisites};

pub fn check_socket_destroy_capability() -> Result<(), String> {
    SocketDestroyCapabilityCheck::probe_host().check()
}

#[derive(Debug, Clone)]
pub struct SocketDestroyCapabilityCheck {
    source: SocketDestroyCapabilitySource,
}

#[derive(Debug, Clone)]
enum SocketDestroyCapabilitySource {
    Host,
    Snapshot {
        running_as_root: bool,
        procfs_socket_attribution: Result<(), String>,
        socket_destroy_prerequisites: Result<(), String>,
        active_socket_destroy: Result<(), String>,
    },
}

impl SocketDestroyCapabilityCheck {
    pub fn probe_host() -> Self {
        Self {
            source: SocketDestroyCapabilitySource::Host,
        }
    }

    pub fn from_results(
        running_as_root: bool,
        procfs_socket_attribution: Result<(), String>,
        socket_destroy_prerequisites: Result<(), String>,
        active_socket_destroy: Result<(), String>,
    ) -> Self {
        Self {
            source: SocketDestroyCapabilitySource::Snapshot {
                running_as_root,
                procfs_socket_attribution,
                socket_destroy_prerequisites,
                active_socket_destroy,
            },
        }
    }

    pub fn check(&self) -> Result<(), String> {
        match &self.source {
            SocketDestroyCapabilitySource::Host => check_host_socket_destroy_capability(),
            SocketDestroyCapabilitySource::Snapshot {
                running_as_root,
                procfs_socket_attribution,
                socket_destroy_prerequisites,
                active_socket_destroy,
            } => check_socket_destroy_capability_snapshot(
                *running_as_root,
                procfs_socket_attribution,
                socket_destroy_prerequisites,
                active_socket_destroy,
            ),
        }
    }
}

fn check_host_socket_destroy_capability() -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Err("linux socket destroy enforcement requires Linux".to_string());
    }

    if !is_root() {
        return Err(
            "linux socket destroy enforcement requires root because SOCK_DESTROY requires host socket destroy privileges"
                .to_string(),
        );
    }

    ProcfsSocketResolver::new().probe().map_err(|error| {
        format!(
            "linux socket destroy enforcement requires procfs socket attribution before destructive socket close: {error}"
        )
    })?;

    check_socket_destroy_prerequisites().map_err(|error| {
        format!("linux socket destroy enforcement requires NETLINK_SOCK_DIAG: {error}")
    })?;

    check_loopback_socket_destroy_support().map_err(|error| {
        format!("linux socket destroy enforcement active self-test failed: {error}")
    })?;

    Ok(())
}

fn check_socket_destroy_capability_snapshot(
    running_as_root: bool,
    procfs_socket_attribution: &Result<(), String>,
    socket_destroy_prerequisites: &Result<(), String>,
    active_socket_destroy: &Result<(), String>,
) -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Err("linux socket destroy enforcement requires Linux".to_string());
    }

    if !running_as_root {
        return Err(
            "linux socket destroy enforcement requires root because SOCK_DESTROY requires host socket destroy privileges"
                .to_string(),
        );
    }

    if let Err(error) = procfs_socket_attribution {
        return Err(format!(
            "linux socket destroy enforcement requires procfs socket attribution before destructive socket close: {error}"
        ));
    }

    if let Err(error) = socket_destroy_prerequisites {
        return Err(format!(
            "linux socket destroy enforcement requires NETLINK_SOCK_DIAG: {error}"
        ));
    }

    if let Err(error) = active_socket_destroy {
        return Err(format!(
            "linux socket destroy enforcement active self-test failed: {error}"
        ));
    }

    Ok(())
}

fn is_root() -> bool {
    rustix::process::geteuid().as_raw() == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_destroy_capability_reports_root_procfs_and_netlink_reasons() {
        assert!(
            capability_reason(SocketDestroyCapabilityCheck::from_results(
                false,
                Ok(()),
                Ok(()),
                Ok(()),
            ))
            .contains("requires root")
        );

        assert!(
            capability_reason(SocketDestroyCapabilityCheck::from_results(
                true,
                Err("procfs unavailable".to_string()),
                Ok(()),
                Ok(()),
            ))
            .contains("requires procfs socket attribution")
        );

        let missing_netlink = capability_reason(SocketDestroyCapabilityCheck::from_results(
            true,
            Ok(()),
            Err("netlink unavailable".to_string()),
            Ok(()),
        ));
        assert!(missing_netlink.contains("requires NETLINK_SOCK_DIAG"));
        assert!(missing_netlink.contains("netlink unavailable"));
    }

    #[test]
    fn socket_destroy_capability_reports_active_self_test_failure() {
        let reason = capability_reason(SocketDestroyCapabilityCheck::from_results(
            true,
            Ok(()),
            Ok(()),
            Err("self-test socket survived".to_string()),
        ));

        assert!(reason.contains("active self-test failed"));
        assert!(reason.contains("self-test socket survived"));
    }

    fn capability_reason(check: SocketDestroyCapabilityCheck) -> String {
        check.check().expect_err("capability should be unavailable")
    }
}
