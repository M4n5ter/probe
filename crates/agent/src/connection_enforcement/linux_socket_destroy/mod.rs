mod backend;
mod owner;
mod probe;

use enforcement::linux_socket_destroy::NetlinkSocketDestroy;

use backend::LinuxSocketDestroyBackend;
use owner::ProcfsFlowOwnerVerifier;
use probe::{LinuxSocketDestroyProbe, LinuxSocketDestroyProbeResult};

use super::ConnectionEnforcementRuntime;

pub(super) fn resolve() -> ConnectionEnforcementRuntime {
    match LinuxSocketDestroyProbe::default().resolve() {
        LinuxSocketDestroyProbeResult::Available => {
            ConnectionEnforcementRuntime::available_with_note(
                LinuxSocketDestroyBackend::new(
                    NetlinkSocketDestroy::new(),
                    ProcfsFlowOwnerVerifier::default(),
                ),
                "linux socket destroy entrypoint reported a destroyed loopback TCP socket through NETLINK_SOCK_DIAG/SOCK_DESTROY and interrupted the probe connection; \
                 runtime enforcement uses procfs owner verification; \
                 each flow may still return unsupported if the event is not from live host capture, observation evidence \
                 is not destructive-safe, the target socket is gone, owner verification fails, or SOCK_DESTROY does not report \
                 a destroyed matching socket",
            )
        }
        LinuxSocketDestroyProbeResult::Unavailable(capability) => {
            ConnectionEnforcementRuntime::without_backend(capability)
        }
    }
}
