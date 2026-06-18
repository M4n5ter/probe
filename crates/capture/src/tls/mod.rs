mod attach_inventory;
mod attach_plan;
mod attach_reconcile;
mod discovery;
mod keylog;
mod plaintext;
mod secret;
mod session_secret;

pub use attach_inventory::{
    LibsslUprobeAttachPlanningError, LibsslUprobeAttachPlanningReport,
    plan_libssl_uprobes_for_processes,
};
pub use attach_plan::{
    LibsslUprobeAttachKind, LibsslUprobeAttachPlan, LibsslUprobeAttachPoint,
    LibsslUprobeAttachProcess, LibsslUprobeAttachRecipe, LibsslUprobeAttachTarget,
    LibsslUprobeAttachTargetId, LibsslUprobeAttachTargetSnapshot,
};
pub(in crate::tls) use attach_reconcile::{LibsslUprobeAttachState, LibsslUprobeReconcileReport};
pub(in crate::tls) use discovery::LibsslUprobeProcessVerifier;
pub use discovery::{
    LibsslExecutableMapping, LibsslLibraryKind, LibsslMappedFileIdentity, LibsslMappedLibrary,
    LibsslUprobeDegradationReason, LibsslUprobeDiscoveryError,
    LibsslUprobeProcessGenerationFailure, LibsslUprobeSymbol, LibsslUprobeSymbolFailure,
    LibsslUprobeSymbolRole, LibsslUprobeTarget, LibsslUprobeTargetDiscovery,
    LibsslUprobeTargetDiscoveryReport,
};
pub use keylog::{
    TlsKeyLog, TlsKeyLogEntry, TlsKeyLogField, TlsKeyLogLabel, TlsKeyLogLabelCount,
    TlsKeyLogParseError, TlsKeyLogSummary,
};
pub use plaintext::{
    LibsslResolvedFlow, LibsslUprobeFlowLookup, LibsslUprobeFlowResolver,
    LibsslUprobePlaintextOpen, LibsslUprobePlaintextProbeConfig, LibsslUprobePlaintextProvider,
    LibsslUprobePlaintextReconcile, LibsslUprobeReconcileTargetBucket,
    MAX_LIBSSL_RECONCILE_TARGET_SNAPSHOTS_PER_BUCKET,
};
pub(in crate::tls) use secret::{TLS_RANDOM_BYTES, decode_hex, hex_len, resolve_lookup};
pub use secret::{TlsMaterialLookup, TlsRandom, TlsSecret};
pub use session_secret::{
    Tls13ApplicationDataDecryptor, Tls13ApplicationTrafficSecretKind, Tls13DecryptError,
    Tls13DecryptedRecord, Tls13InnerContentType, Tls13SessionSecretDecryptingProvider,
    Tls13SessionSecretDecryptingProviderError, Tls13SessionSecretFlowBinding,
    Tls13SessionSecretFlowBindingPlanError, Tls13SessionSecretFlowBindingPlanner,
    Tls13SessionSecretFlowCandidate, Tls13SessionSecretFlowDecryptError,
    Tls13SessionSecretFlowDecryptor, Tls13SessionSecretPlaintextAdapter,
    Tls13SessionSecretPlaintextError, Tls13SessionSecretStreamAdapter,
    Tls13SessionSecretStreamCursor, Tls13SessionSecretStreamError, TlsCipherSuite,
    TlsSessionSecretKind, TlsSessionSecretLookupTime, TlsSessionSecretLookupTimeError,
    TlsSessionSecretParseError, TlsSessionSecretProtocol, TlsSessionSecretRecord,
    TlsSessionSecretStore, TlsSessionSecretSummary,
};
