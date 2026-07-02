pub(crate) const MITM_PLAINTEXT_COVERAGE: &str = "plain HTTP and TLS-decrypted HTTP";
pub(crate) const MITM_PROXY_FALLBACK_LABEL: &str = "reliable MITM proxy fallback";
pub(crate) const OUTBOUND_MITM_PROXY_FALLBACK_SETUP_LABEL: &str =
    "Setup outbound reliable MITM proxy fallback";
pub(crate) const INBOUND_MITM_PROXY_FALLBACK_SETUP_LABEL: &str =
    "Setup inbound reliable MITM proxy fallback";
pub(crate) const OUTBOUND_MITM_PROXY_FALLBACK_CONFIGURED_LABEL: &str =
    "Outbound reliable MITM proxy fallback configured for selected process";
pub(crate) const INBOUND_MITM_PROXY_FALLBACK_CONFIGURED_LABEL: &str =
    "Inbound reliable MITM proxy fallback configured for selected process";
pub(crate) const MITM_OUT_ACTION_LABEL: &str = "MITM Out";
pub(crate) const MITM_IN_ACTION_LABEL: &str = "MITM In";
pub(crate) const MITM_HTTP_PATH_LABEL: &str = "mitm-http";
pub(crate) const MITM_TLS_PATH_LABEL: &str = "mitm-tls";
pub(crate) const MITM_TLS_TRUST_ACTION: &str =
    "install the generated MITM CA into TLS client trust to see TLS-decrypted HTTP";
pub(crate) const MITM_QUICK_SETUP_APPLY: &str = "save prepares generated CA material, feed path, and policy manifest; install the CA into TLS client trust separately; the TUI managed agent restarts when this session owns it";
