use std::time::Duration;

use http::{Method, Request, StatusCode, header::ACCEPT};
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use probe_http::{
    HttpConnectionOptions, ProbeHttpsConnector, https_connector, root_cert_store_with_native_roots,
};
use rustls::pki_types::CertificateDer;
use thiserror::Error;

type RemoteHttpClient = Client<ProbeHttpsConnector, Empty<Bytes>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RemoteTextFetchConfig {
    pub accept: &'static str,
    pub timeout: Duration,
    pub max_body_bytes: u64,
    pub connection: HttpConnectionOptions,
}

#[derive(Debug, Error)]
pub(crate) enum RemoteTextFetchError {
    #[error("failed to build remote HTTP client: {reason}")]
    Client { reason: String },
    #[error("failed to fetch remote source: {reason}")]
    Fetch { reason: String },
    #[error("remote source timed out after {timeout_ms} ms")]
    Timeout { timeout_ms: u128 },
    #[error("remote source returned HTTP status {status}")]
    Status { status: StatusCode },
    #[error("failed to read remote source: {reason}")]
    Read { reason: String },
    #[error("remote source is too large: body has at least {size} bytes, limit {limit}")]
    TooLarge { size: u64, limit: u64 },
    #[error("remote source is not UTF-8: {source}")]
    Utf8 {
        #[source]
        source: std::string::FromUtf8Error,
    },
}

pub(crate) async fn fetch_remote_text(
    endpoint: &str,
    config: RemoteTextFetchConfig,
) -> Result<String, RemoteTextFetchError> {
    let client = remote_http_client(config)?;
    let request = Request::builder()
        .method(Method::GET)
        .uri(endpoint)
        .header(ACCEPT, config.accept)
        .body(Empty::<Bytes>::new())
        .map_err(|source| RemoteTextFetchError::Fetch {
            reason: source.to_string(),
        })?;

    tokio::time::timeout(
        config.timeout,
        fetch_remote_text_content(client, request, config.max_body_bytes),
    )
    .await
    .map_err(|_| RemoteTextFetchError::Timeout {
        timeout_ms: config.timeout.as_millis(),
    })?
}

fn remote_http_client(
    config: RemoteTextFetchConfig,
) -> Result<RemoteHttpClient, RemoteTextFetchError> {
    let tls = remote_tls_config()?;
    let connector = https_connector(tls, config.connection);
    Ok(Client::builder(TokioExecutor::new()).build(connector))
}

fn remote_tls_config() -> Result<rustls::ClientConfig, RemoteTextFetchError> {
    remote_tls_config_with_native_roots(rustls_native_certs::load_native_certs().certs)
}

fn remote_tls_config_with_native_roots(
    native_roots: Vec<CertificateDer<'static>>,
) -> Result<rustls::ClientConfig, RemoteTextFetchError> {
    let roots = root_cert_store_with_native_roots(native_roots).map_err(|source| {
        RemoteTextFetchError::Client {
            reason: source.to_string(),
        }
    })?;
    Ok(rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

async fn fetch_remote_text_content(
    client: RemoteHttpClient,
    request: Request<Empty<Bytes>>,
    max_body_bytes: u64,
) -> Result<String, RemoteTextFetchError> {
    let response = client
        .request(request)
        .await
        .map_err(|source| RemoteTextFetchError::Fetch {
            reason: source.to_string(),
        })?;
    let status = response.status();
    if !status.is_success() {
        return Err(RemoteTextFetchError::Status { status });
    }

    let mut body = Vec::new();
    let mut incoming = response.into_body();
    while let Some(frame) =
        incoming
            .frame()
            .await
            .transpose()
            .map_err(|source| RemoteTextFetchError::Read {
                reason: source.to_string(),
            })?
    {
        if let Ok(chunk) = frame.into_data() {
            let new_size = body.len().saturating_add(chunk.len()) as u64;
            if new_size > max_body_bytes {
                return Err(RemoteTextFetchError::TooLarge {
                    size: new_size,
                    limit: max_body_bytes,
                });
            }
            body.extend_from_slice(&chunk);
        }
    }
    String::from_utf8(body).map_err(|source| RemoteTextFetchError::Utf8 { source })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_tls_config_allows_empty_native_roots() {
        let config = remote_tls_config_with_native_roots(Vec::new())
            .expect("empty native roots should still build a rustls client config");

        assert_eq!(config.alpn_protocols, Vec::<Vec<u8>>::new());
    }
}
