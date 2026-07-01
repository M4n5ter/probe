mod activity;
mod ebpf;
mod factory;
mod procfs_resolver;
mod runtime;

use capture::CaptureProvider;

pub(crate) use activity::{CaptureInputActivityRuntimeSnapshot, CaptureInputSignalRuntimeSnapshot};
#[cfg(test)]
pub(crate) use activity::{
    CaptureInputPollActivityRuntimeSnapshot, CaptureInputProviderActivityRuntimeSnapshot,
};
pub(super) use factory::{CaptureProviderPreflight, build_capture_provider};
pub(crate) use runtime::{
    CaptureProviderOpenFailureSnapshot, CaptureProviderRuntimeDetailsSnapshot,
    CaptureProviderRuntimeSnapshot, CaptureProviderRuntimeState,
};

pub(super) struct OpenedLiveCaptureBackend {
    pub(super) provider: Box<dyn CaptureProvider>,
    pub(super) provider_details: Option<runtime::CaptureProviderRuntimeDetailsSnapshot>,
}
