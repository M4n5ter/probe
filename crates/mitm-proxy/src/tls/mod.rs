use std::{
    fs::File,
    io::BufReader,
    net::TcpStream,
    path::{Path, PathBuf},
    sync::Arc,
};

use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
};

use crate::{MitmProxyError, error::io_error};

pub(crate) type TlsClientStream = StreamOwned<ClientConnection, TcpStream>;
pub(crate) type TlsServerStream = StreamOwned<ServerConnection, TcpStream>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsTerminationConfig {
    pub certificate_chain: PathBuf,
    pub private_key: PathBuf,
}

impl TlsTerminationConfig {
    pub fn new(certificate_chain: PathBuf, private_key: PathBuf) -> Self {
        Self {
            certificate_chain,
            private_key,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UpstreamTlsConfig {
    pub trust_anchors: Vec<PathBuf>,
    pub server_name: Option<String>,
}

impl UpstreamTlsConfig {
    pub fn new(trust_anchors: Vec<PathBuf>, server_name: Option<String>) -> Self {
        Self {
            trust_anchors,
            server_name,
        }
    }
}

pub(crate) struct TlsTerminator {
    config: Arc<ServerConfig>,
}

impl TlsTerminator {
    pub(crate) fn from_config(config: &TlsTerminationConfig) -> Result<Self, MitmProxyError> {
        let certificate_chain = load_certificate_chain(&config.certificate_chain)?;
        let private_key = load_private_key(&config.private_key)?;
        let crypto_provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let server_config = ServerConfig::builder_with_provider(crypto_provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(tls_error("configure MITM proxy TLS protocol versions"))?
            .with_no_client_auth()
            .with_single_cert(certificate_chain, private_key)
            .map_err(tls_error("configure MITM proxy TLS certificate"))?;
        Ok(Self {
            config: Arc::new(server_config),
        })
    }

    pub(crate) fn accept(&self, mut stream: TcpStream) -> Result<TlsServerStream, MitmProxyError> {
        let mut connection = ServerConnection::new(Arc::clone(&self.config))
            .map_err(tls_error("create MITM proxy TLS server connection"))?;
        while connection.is_handshaking() {
            let (read, written) = connection
                .complete_io(&mut stream)
                .map_err(io_error("complete MITM proxy TLS handshake"))?;
            if read == 0 && written == 0 && connection.is_handshaking() {
                return Err(MitmProxyError::Tls(
                    "TLS handshake ended without completing".to_string(),
                ));
            }
        }
        Ok(StreamOwned::new(connection, stream))
    }
}

pub(crate) struct TlsUpstreamConnector {
    config: Arc<ClientConfig>,
    server_name: Option<String>,
}

impl TlsUpstreamConnector {
    pub(crate) fn from_config(config: &UpstreamTlsConfig) -> Result<Self, MitmProxyError> {
        let roots = load_upstream_roots(&config.trust_anchors)?;
        let crypto_provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let client_config = ClientConfig::builder_with_provider(crypto_provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(tls_error(
                "configure MITM proxy upstream TLS protocol versions",
            ))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            config: Arc::new(client_config),
            server_name: config.server_name.clone(),
        })
    }

    pub(crate) fn connect(
        &self,
        mut stream: TcpStream,
        request_host: Option<&str>,
    ) -> Result<TlsClientStream, MitmProxyError> {
        let server_name = self.server_name(request_host)?;
        let mut connection = ClientConnection::new(Arc::clone(&self.config), server_name).map_err(
            tls_error("create MITM proxy upstream TLS client connection"),
        )?;
        while connection.is_handshaking() {
            let (read, written) = connection
                .complete_io(&mut stream)
                .map_err(io_error("complete MITM proxy upstream TLS handshake"))?;
            if read == 0 && written == 0 && connection.is_handshaking() {
                return Err(MitmProxyError::Tls(
                    "upstream TLS handshake ended without completing".to_string(),
                ));
            }
        }
        Ok(StreamOwned::new(connection, stream))
    }

    fn server_name(
        &self,
        request_authority: Option<&str>,
    ) -> Result<ServerName<'static>, MitmProxyError> {
        let Some(authority) = request_authority else {
            return Err(MitmProxyError::Tls(
                "upstream TLS requires a single valid HTTP Host header".to_string(),
            ));
        };
        let name = match self.server_name.as_deref() {
            Some(pinned) if !pinned.eq_ignore_ascii_case(authority) => {
                return Err(MitmProxyError::Tls(format!(
                    "upstream TLS server name {pinned:?} does not match HTTP Host {authority:?}"
                )));
            }
            Some(pinned) => pinned,
            None => authority,
        };
        ServerName::try_from(name.to_string()).map_err(|error| {
            MitmProxyError::Tls(format!(
                "invalid upstream TLS server name {name:?}: {error}"
            ))
        })
    }
}

fn load_upstream_roots(paths: &[PathBuf]) -> Result<RootCertStore, MitmProxyError> {
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    roots.add_parsable_certificates(native.certs);
    for path in paths {
        let (added, ignored) = roots.add_parsable_certificates(load_certificate_chain(path)?);
        if added == 0 || ignored > 0 {
            return Err(MitmProxyError::Tls(format!(
                "upstream TLS trust anchor {} contained {added} usable certificate(s) and {ignored} unusable certificate(s)",
                path.display()
            )));
        }
    }
    if roots.roots.is_empty() {
        return Err(MitmProxyError::Tls(
            "upstream TLS root store is empty; configure native roots or --upstream-trust-anchor"
                .to_string(),
        ));
    }
    Ok(roots)
}

fn load_certificate_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>, MitmProxyError> {
    let mut reader = pem_reader(path, "open MITM proxy TLS certificate chain")?;
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(io_error("parse MITM proxy TLS certificate chain"))?;
    if certificates.is_empty() {
        return Err(MitmProxyError::Tls(format!(
            "TLS certificate chain {} did not contain any certificates",
            path.display()
        )));
    }
    Ok(certificates)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, MitmProxyError> {
    let mut reader = pem_reader(path, "open MITM proxy TLS private key")?;
    rustls_pemfile::private_key(&mut reader)
        .map_err(io_error("parse MITM proxy TLS private key"))?
        .ok_or_else(|| {
            MitmProxyError::Tls(format!(
                "TLS private key {} did not contain a supported private key",
                path.display()
            ))
        })
}

fn pem_reader(path: &Path, action: &'static str) -> Result<BufReader<File>, MitmProxyError> {
    File::open(path)
        .map(BufReader::new)
        .map_err(io_error(action))
}

fn tls_error(action: &'static str) -> impl FnOnce(rustls::Error) -> MitmProxyError {
    move |error| MitmProxyError::Tls(format!("{action}: {error}"))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn upstream_tls_rejects_empty_operator_trust_anchor() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = tempdir()?;
        let empty_anchor = root.path().join("empty.pem");
        fs::write(&empty_anchor, "")?;
        let config = UpstreamTlsConfig::new(vec![empty_anchor], None);

        let error = match TlsUpstreamConnector::from_config(&config) {
            Ok(_) => return Err("empty upstream trust anchor should fail".into()),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("did not contain any certificates"),
            "{error}"
        );
        Ok(())
    }
}
