use enforcement::linux_socket_destroy::SocketDestroyCapabilityCheck;
use probe_core::{CapabilityKind, CapabilityState};

pub(super) struct LinuxSocketDestroyProbe {
    capability: SocketDestroyCapabilityCheck,
}

impl Default for LinuxSocketDestroyProbe {
    fn default() -> Self {
        Self {
            capability: SocketDestroyCapabilityCheck::probe_host(),
        }
    }
}

pub(super) enum LinuxSocketDestroyProbeResult {
    Available,
    Unavailable(CapabilityState),
}

impl LinuxSocketDestroyProbe {
    pub(super) fn resolve(&self) -> LinuxSocketDestroyProbeResult {
        match self.capability.check() {
            Ok(()) => LinuxSocketDestroyProbeResult::Available,
            Err(reason) => LinuxSocketDestroyProbeResult::Unavailable(
                CapabilityState::unavailable(CapabilityKind::ConnectionEnforcement, reason),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use probe_core::RuntimeMode;

    use super::*;

    #[test]
    fn linux_socket_destroy_probe_wraps_canonical_capability_reasons() {
        let missing_root = unavailable_probe_reason(LinuxSocketDestroyProbe {
            capability: SocketDestroyCapabilityCheck::from_results(false, Ok(()), Ok(()), Ok(())),
        });
        assert!(missing_root.contains("requires root"));

        let missing_procfs = unavailable_probe_reason(LinuxSocketDestroyProbe {
            capability: SocketDestroyCapabilityCheck::from_results(
                true,
                Err("procfs unavailable".to_string()),
                Ok(()),
                Ok(()),
            ),
        });
        assert!(missing_procfs.contains("requires procfs socket attribution"));

        let missing_netlink = unavailable_probe_reason(LinuxSocketDestroyProbe {
            capability: SocketDestroyCapabilityCheck::from_results(
                true,
                Ok(()),
                Err("netlink unavailable".to_string()),
                Ok(()),
            ),
        });
        assert!(missing_netlink.contains("requires NETLINK_SOCK_DIAG"));
        assert!(missing_netlink.contains("netlink unavailable"));

        let self_test_failed = unavailable_probe_reason(LinuxSocketDestroyProbe {
            capability: SocketDestroyCapabilityCheck::from_results(
                true,
                Ok(()),
                Ok(()),
                Err("self-test socket survived".to_string()),
            ),
        });
        assert!(self_test_failed.contains("active self-test failed"));
        assert!(self_test_failed.contains("self-test socket survived"));
    }

    fn unavailable_probe_reason(probe: LinuxSocketDestroyProbe) -> String {
        match probe.resolve() {
            LinuxSocketDestroyProbeResult::Available => {
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
