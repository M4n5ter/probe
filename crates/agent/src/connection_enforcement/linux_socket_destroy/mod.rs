mod backend;
mod owner;
mod probe;
mod ss;

use backend::LinuxSocketDestroyBackend;
use owner::ProcfsFlowOwnerVerifier;
use probe::{LinuxSocketDestroyProbe, LinuxSocketDestroyProbeResult};
use ss::SystemSsKill;

use super::ConnectionEnforcementRuntime;

pub(super) fn resolve() -> ConnectionEnforcementRuntime {
    match LinuxSocketDestroyProbe::default().resolve() {
        LinuxSocketDestroyProbeResult::Available { command } => {
            ConnectionEnforcementRuntime::available_with_note(
                LinuxSocketDestroyBackend::new(
                    SystemSsKill::new(command),
                    ProcfsFlowOwnerVerifier::default(),
                ),
                "linux socket destroy entrypoint is available with procfs owner verification; each flow may still return unsupported if the event is not from live host capture, the socket is gone, owner verification fails, or the kernel/namespace does not report a destroyed socket",
            )
        }
        LinuxSocketDestroyProbeResult::Unavailable(capability) => {
            ConnectionEnforcementRuntime::without_backend(capability)
        }
    }
}
