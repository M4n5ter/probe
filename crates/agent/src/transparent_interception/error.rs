#[derive(Debug, thiserror::Error)]
pub(crate) enum TransparentInterceptionError {
    #[error("transparent interception nftables error: {0}")]
    Nftables(String),
    #[error("transparent interception proxy error: {0}")]
    Proxy(String),
}
