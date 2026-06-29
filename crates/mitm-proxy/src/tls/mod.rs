use std::{
    fs::File,
    io::BufReader,
    net::TcpStream,
    path::{Path, PathBuf},
    sync::Arc,
};

use rustls::{
    ServerConfig, ServerConnection, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer},
};

use crate::{MitmProxyError, error::io_error};

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
