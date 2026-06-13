mod attach_inventory;
mod attach_plan;
mod attach_reconcile;
mod discovery;
mod keylog;
mod plaintext;

pub use attach_inventory::{
    LibsslUprobeAttachPlanningError, LibsslUprobeAttachPlanningReport,
    plan_libssl_uprobes_for_processes,
};
pub use attach_plan::{
    LibsslUprobeAttachKind, LibsslUprobeAttachPlan, LibsslUprobeAttachPoint,
    LibsslUprobeAttachProcess, LibsslUprobeAttachRecipe, LibsslUprobeAttachTarget,
    LibsslUprobeAttachTargetId,
};
pub use attach_reconcile::{LibsslUprobeAttachState, LibsslUprobeReconcileReport};
pub(in crate::tls) use discovery::LibsslUprobeProcessVerifier;
pub use discovery::{
    LibsslExecutableMapping, LibsslLibraryKind, LibsslMappedFileIdentity, LibsslMappedLibrary,
    LibsslUprobeDegradationReason, LibsslUprobeDiscoveryError,
    LibsslUprobeProcessGenerationFailure, LibsslUprobeSymbol, LibsslUprobeSymbolFailure,
    LibsslUprobeSymbolRole, LibsslUprobeTarget, LibsslUprobeTargetDiscovery,
    LibsslUprobeTargetDiscoveryReport,
};
pub use keylog::{TlsKeyLogField, TlsKeyLogLabelCount, TlsKeyLogParseError, TlsKeyLogSummary};
pub use plaintext::{
    LibsslResolvedFlow, LibsslUprobeFlowLookup, LibsslUprobeFlowResolver,
    LibsslUprobePlaintextOpen, LibsslUprobePlaintextProbeConfig, LibsslUprobePlaintextProvider,
};
