pub(crate) const MITM_PLAINTEXT_COVERAGE: &str = "plain HTTP and TLS-decrypted HTTP";
pub(crate) const MITM_TLS_TRUST_ACTION: &str =
    "install the generated MITM CA into TLS client trust to see TLS-decrypted HTTP";
pub(crate) const MITM_QUICK_SETUP_APPLY: &str = "save prepares generated CA material, feed path, and policy manifest; install the CA into TLS client trust separately; the TUI managed agent restarts when this session owns it";
