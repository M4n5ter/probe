mod attach_plan;
mod discovery;
mod keylog;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "libssl plaintext adapter is compiled before the Aya uprobe loader and runtime wiring use it"
    )
)]
pub(crate) mod plaintext;

pub use attach_plan::{
    LibsslUprobeAttachKind, LibsslUprobeAttachPlan, LibsslUprobeAttachProbe,
    LibsslUprobeAttachRecipe, LibsslUprobeAttachTarget,
};
pub use discovery::{
    LibsslExecutableMapping, LibsslLibraryKind, LibsslMappedFileIdentity, LibsslMappedLibrary,
    LibsslUprobeDegradationReason, LibsslUprobeDiscoveryError, LibsslUprobeSymbol,
    LibsslUprobeSymbolFailure, LibsslUprobeTarget, LibsslUprobeTargetDiscovery,
    LibsslUprobeTargetDiscoveryReport,
};
pub use keylog::{TlsKeyLogField, TlsKeyLogLabelCount, TlsKeyLogParseError, TlsKeyLogSummary};
