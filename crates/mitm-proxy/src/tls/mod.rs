use std::{
    collections::{HashMap, VecDeque},
    fs::File,
    io::BufReader,
    net::TcpStream,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, Issuer, KeyPair};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    crypto::CryptoProvider,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};

use crate::{MitmProxyError, error::io_error};

pub(crate) type TlsClientStream = StreamOwned<ClientConnection, TcpStream>;
pub(crate) type TlsServerStream = StreamOwned<ServerConnection, TcpStream>;
const DYNAMIC_CERT_CACHE_CAPACITY: usize = 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TlsTerminationConfig {
    Static(TlsStaticTerminationConfig),
    DynamicCa(TlsDynamicCaTerminationConfig),
}

impl TlsTerminationConfig {
    pub fn new(certificate_chain: PathBuf, private_key: PathBuf) -> Self {
        Self::Static(TlsStaticTerminationConfig {
            certificate_chain,
            private_key,
        })
    }

    pub fn from_ca(certificate_chain: PathBuf, private_key: PathBuf) -> Self {
        Self::DynamicCa(TlsDynamicCaTerminationConfig {
            certificate_chain,
            private_key,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsStaticTerminationConfig {
    pub certificate_chain: PathBuf,
    pub private_key: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsDynamicCaTerminationConfig {
    pub certificate_chain: PathBuf,
    pub private_key: PathBuf,
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

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct UpstreamTlsNameCandidates<'a> {
    configured_server_name: Option<&'a str>,
    downstream_tls_server_name: Option<&'a str>,
    http_host: Option<&'a str>,
}

impl<'a> UpstreamTlsNameCandidates<'a> {
    pub(crate) fn observed(
        downstream_tls_server_name: Option<&'a str>,
        http_host: Option<&'a str>,
    ) -> Self {
        Self {
            downstream_tls_server_name,
            http_host,
            ..Self::default()
        }
    }

    fn with_configured_server_name(mut self, configured_server_name: Option<&'a str>) -> Self {
        self.configured_server_name = configured_server_name;
        self
    }

    fn resolve(self) -> Result<ServerName<'static>, MitmProxyError> {
        let candidate = self
            .ordered_candidates()
            .into_iter()
            .flatten()
            .try_fold(None, |selected, candidate| {
                selected_name_or_error(selected, candidate).map(Some)
            })?
            .ok_or_else(|| {
                MitmProxyError::Tls(
                    "upstream TLS requires a configured server name, downstream TLS SNI, or a single valid HTTP Host header".to_string(),
                )
            })?;
        ServerName::try_from(candidate.name.to_string()).map_err(|error| {
            MitmProxyError::Tls(format!(
                "invalid upstream TLS server name {:?}: {error}",
                candidate.name
            ))
        })
    }

    fn ordered_candidates(self) -> [Option<UpstreamTlsNameCandidate<'a>>; 3] {
        [
            self.configured_server_name
                .map(|name| UpstreamTlsNameCandidate {
                    label: "configured upstream TLS server name",
                    name,
                }),
            self.downstream_tls_server_name
                .map(|name| UpstreamTlsNameCandidate {
                    label: "downstream TLS SNI",
                    name,
                }),
            self.http_host.map(|name| UpstreamTlsNameCandidate {
                label: "HTTP Host",
                name,
            }),
        ]
    }
}

#[derive(Clone, Copy)]
struct UpstreamTlsNameCandidate<'a> {
    label: &'static str,
    name: &'a str,
}

fn selected_name_or_error<'a>(
    selected: Option<UpstreamTlsNameCandidate<'a>>,
    candidate: UpstreamTlsNameCandidate<'a>,
) -> Result<UpstreamTlsNameCandidate<'a>, MitmProxyError> {
    let Some(selected) = selected else {
        return Ok(candidate);
    };
    if selected.name.eq_ignore_ascii_case(candidate.name) {
        return Ok(selected);
    }
    Err(MitmProxyError::Tls(format!(
        "{} {:?} does not match {} {:?}",
        candidate.label, candidate.name, selected.label, selected.name
    )))
}

pub(crate) struct TlsTerminator {
    config: Arc<ServerConfig>,
}

impl TlsTerminator {
    pub(crate) fn from_config(config: &TlsTerminationConfig) -> Result<Self, MitmProxyError> {
        let crypto_provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let builder = ServerConfig::builder_with_provider(Arc::clone(&crypto_provider))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(tls_error("configure MITM proxy TLS protocol versions"))?
            .with_no_client_auth();
        let server_config = match config {
            TlsTerminationConfig::Static(config) => {
                let certificate_chain = load_certificate_chain(&config.certificate_chain)?;
                let private_key = load_private_key(&config.private_key)?;
                builder
                    .with_single_cert(certificate_chain, private_key)
                    .map_err(tls_error("configure MITM proxy TLS certificate"))?
            }
            TlsTerminationConfig::DynamicCa(config) => {
                let resolver =
                    DynamicCaCertResolver::from_config(config, Arc::clone(&crypto_provider))?;
                builder.with_cert_resolver(Arc::new(resolver))
            }
        };
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

struct DynamicCaCertResolver {
    issuer: Issuer<'static, KeyPair>,
    certificate_chain: Vec<CertificateDer<'static>>,
    crypto_provider: Arc<CryptoProvider>,
    cache: Mutex<DynamicCertCache>,
}

impl DynamicCaCertResolver {
    fn from_config(
        config: &TlsDynamicCaTerminationConfig,
        crypto_provider: Arc<CryptoProvider>,
    ) -> Result<Self, MitmProxyError> {
        let certificate_chain = load_certificate_chain(&config.certificate_chain)?;
        let issuer_certificate = certificate_chain
            .first()
            .ok_or_else(|| {
                MitmProxyError::Tls(format!(
                    "dynamic TLS CA certificate chain {} did not contain any certificates",
                    config.certificate_chain.display()
                ))
            })?
            .clone();
        validate_ca_certificate(&issuer_certificate, &config.certificate_chain)?;
        validate_ca_key_pair(&issuer_certificate, &config.private_key, &crypto_provider)?;
        let signing_key = load_rcgen_key_pair(&config.private_key)?;
        let issuer = Issuer::from_ca_cert_der(&issuer_certificate, signing_key)
            .map_err(rcgen_error("parse MITM proxy dynamic TLS CA certificate"))?;
        Ok(Self {
            issuer,
            certificate_chain,
            crypto_provider,
            cache: Mutex::new(DynamicCertCache::default()),
        })
    }

    fn certified_key_for_sni(&self, server_name: &str) -> Option<Arc<CertifiedKey>> {
        let server_name = server_name.to_ascii_lowercase();
        if let Some(certified_key) = self.cache.lock().ok()?.get(&server_name) {
            return Some(Arc::clone(certified_key));
        }
        let certified_key = Arc::new(self.generate_certified_key(&server_name).ok()?);
        let mut cache = self.cache.lock().ok()?;
        if let Some(existing) = cache.get(&server_name) {
            return Some(Arc::clone(existing));
        }
        cache.insert(server_name, Arc::clone(&certified_key));
        Some(certified_key)
    }

    fn generate_certified_key(&self, server_name: &str) -> Result<CertifiedKey, MitmProxyError> {
        let signing_key = KeyPair::generate().map_err(rcgen_error(
            "generate MITM proxy dynamic TLS leaf private key",
        ))?;
        let mut params = CertificateParams::new(vec![server_name.to_string()]).map_err(
            rcgen_error("build MITM proxy dynamic TLS leaf certificate params"),
        )?;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf_certificate = params
            .signed_by(&signing_key, &self.issuer)
            .map_err(rcgen_error("sign MITM proxy dynamic TLS leaf certificate"))?;
        let mut certificate_chain = vec![leaf_certificate.der().clone()];
        certificate_chain.extend(self.certificate_chain.iter().cloned());
        let private_key =
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
        CertifiedKey::from_der(certificate_chain, private_key, &self.crypto_provider).map_err(
            tls_error("configure MITM proxy dynamic TLS leaf certificate"),
        )
    }
}

#[derive(Default)]
struct DynamicCertCache {
    certificates: HashMap<String, Arc<CertifiedKey>>,
    insertion_order: VecDeque<String>,
}

impl DynamicCertCache {
    fn get(&self, server_name: &str) -> Option<&Arc<CertifiedKey>> {
        self.certificates.get(server_name)
    }

    fn insert(&mut self, server_name: String, certified_key: Arc<CertifiedKey>) {
        self.insertion_order.push_back(server_name.clone());
        self.certificates.insert(server_name, certified_key);
        while self.certificates.len() > DYNAMIC_CERT_CACHE_CAPACITY {
            if let Some(expired) = self.insertion_order.pop_front() {
                self.certificates.remove(&expired);
            }
        }
    }
}

impl std::fmt::Debug for DynamicCaCertResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DynamicCaCertResolver")
            .field("certificate_chain_len", &self.certificate_chain.len())
            .finish_non_exhaustive()
    }
}

impl ResolvesServerCert for DynamicCaCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let server_name = client_hello.server_name()?;
        self.certified_key_for_sni(server_name)
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
        name_candidates: UpstreamTlsNameCandidates<'_>,
    ) -> Result<TlsClientStream, MitmProxyError> {
        let server_name = name_candidates
            .with_configured_server_name(self.server_name.as_deref())
            .resolve()?;
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

fn validate_ca_certificate(
    certificate: &CertificateDer<'_>,
    path: &Path,
) -> Result<(), MitmProxyError> {
    let (remaining, certificate) = x509_parser::parse_x509_certificate(certificate.as_ref())
        .map_err(x509_error("parse MITM proxy dynamic TLS CA certificate"))?;
    if !remaining.is_empty() {
        return Err(MitmProxyError::Tls(format!(
            "dynamic TLS CA certificate {} contains trailing DER bytes",
            path.display()
        )));
    }
    let basic_constraints = certificate
        .basic_constraints()
        .map_err(x509_error(
            "parse MITM proxy dynamic TLS CA basic constraints",
        ))?
        .ok_or_else(|| {
            MitmProxyError::Tls(format!(
                "dynamic TLS CA certificate {} must include CA basic constraints",
                path.display()
            ))
        })?;
    if !basic_constraints.value.ca {
        return Err(MitmProxyError::Tls(format!(
            "dynamic TLS CA certificate {} must have CA:TRUE basic constraints",
            path.display()
        )));
    }
    let key_usage = certificate
        .key_usage()
        .map_err(x509_error("parse MITM proxy dynamic TLS CA key usage"))?
        .ok_or_else(|| {
            MitmProxyError::Tls(format!(
                "dynamic TLS CA certificate {} must include keyCertSign key usage",
                path.display()
            ))
        })?;
    if !key_usage.value.key_cert_sign() {
        return Err(MitmProxyError::Tls(format!(
            "dynamic TLS CA certificate {} must allow keyCertSign",
            path.display()
        )));
    }
    Ok(())
}

fn validate_ca_key_pair(
    certificate: &CertificateDer<'static>,
    private_key_path: &Path,
    crypto_provider: &CryptoProvider,
) -> Result<(), MitmProxyError> {
    let private_key = load_private_key(private_key_path)?;
    CertifiedKey::from_der(vec![certificate.clone()], private_key, crypto_provider)
        .map(|_| ())
        .map_err(tls_error("validate MITM proxy dynamic TLS CA key pair"))
}

fn load_rcgen_key_pair(path: &Path) -> Result<KeyPair, MitmProxyError> {
    let private_key = load_private_key(path)?;
    KeyPair::try_from(&private_key).map_err(rcgen_error("parse MITM proxy TLS private key"))
}

fn pem_reader(path: &Path, action: &'static str) -> Result<BufReader<File>, MitmProxyError> {
    File::open(path)
        .map(BufReader::new)
        .map_err(io_error(action))
}

fn tls_error(action: &'static str) -> impl FnOnce(rustls::Error) -> MitmProxyError {
    move |error| MitmProxyError::Tls(format!("{action}: {error}"))
}

fn rcgen_error(action: &'static str) -> impl FnOnce(rcgen::Error) -> MitmProxyError {
    move |error| MitmProxyError::Tls(format!("{action}: {error}"))
}

fn x509_error<E: std::fmt::Display>(action: &'static str) -> impl FnOnce(E) -> MitmProxyError {
    move |error| MitmProxyError::Tls(format!("{action}: {error}"))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
    };

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

    #[test]
    fn upstream_tls_server_name_uses_downstream_sni_without_http_host()
    -> Result<(), Box<dyn std::error::Error>> {
        let server_name =
            UpstreamTlsNameCandidates::observed(Some("sni.example"), None).resolve()?;

        assert_eq!(server_name.to_str().as_ref(), "sni.example");
        Ok(())
    }

    #[test]
    fn upstream_tls_server_name_uses_http_host_without_downstream_sni()
    -> Result<(), Box<dyn std::error::Error>> {
        let server_name =
            UpstreamTlsNameCandidates::observed(None, Some("host.example")).resolve()?;

        assert_eq!(server_name.to_str().as_ref(), "host.example");
        Ok(())
    }

    #[test]
    fn upstream_tls_server_name_rejects_downstream_sni_http_host_mismatch() {
        let error = UpstreamTlsNameCandidates::observed(Some("sni.example"), Some("host.example"))
            .resolve()
            .expect_err("SNI and HTTP Host mismatch must fail closed");

        assert!(
            error
                .to_string()
                .contains("does not match downstream TLS SNI"),
            "{error}"
        );
    }

    #[test]
    fn upstream_tls_server_name_rejects_configured_name_mismatch() {
        let error = UpstreamTlsNameCandidates::observed(Some("sni.example"), None)
            .with_configured_server_name(Some("pinned.example"))
            .resolve()
            .expect_err("configured upstream TLS name must pin observed SNI");

        assert!(
            error
                .to_string()
                .contains("does not match configured upstream TLS server name"),
            "{error}"
        );
    }

    #[test]
    fn dynamic_ca_rejects_non_ca_certificate() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempdir()?;
        let certified_key = rcgen::generate_simple_self_signed(["localhost".to_string()])?;
        let certificate_path = root.path().join("leaf.pem");
        let private_key_path = root.path().join("leaf.key");
        fs::write(&certificate_path, certified_key.cert.pem())?;
        fs::write(&private_key_path, certified_key.signing_key.serialize_pem())?;
        let config = TlsTerminationConfig::from_ca(certificate_path, private_key_path);

        let error = match TlsTerminator::from_config(&config) {
            Ok(_) => return Err("dynamic CA mode must reject non-CA certificates".into()),
            Err(error) => error,
        };

        assert!(
            error.to_string().contains("CA basic constraints")
                || error.to_string().contains("CA:TRUE"),
            "{error}"
        );
        Ok(())
    }

    #[test]
    fn dynamic_ca_rejects_mismatched_ca_private_key() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempdir()?;
        let (certificate_path, _first_key_path) = write_test_ca(root.path(), "first")?;
        let (_other_certificate_path, other_key_path) = write_test_ca(root.path(), "other")?;
        let config = TlsTerminationConfig::from_ca(certificate_path, other_key_path);

        let error = match TlsTerminator::from_config(&config) {
            Ok(_) => return Err("dynamic CA mode must reject mismatched CA private keys".into()),
            Err(error) => error,
        };

        assert!(
            error.to_string().contains("key pair")
                || error.to_string().contains("inconsistent keys"),
            "{error}"
        );
        Ok(())
    }

    fn write_test_ca(
        root: &Path,
        name: &str,
    ) -> Result<(PathBuf, PathBuf), Box<dyn std::error::Error>> {
        let signing_key = rcgen::KeyPair::generate()?;
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let certificate = params.self_signed(&signing_key)?;
        let certificate_path = root.join(format!("{name}-ca.pem"));
        let private_key_path = root.join(format!("{name}-ca.key"));
        fs::write(&certificate_path, certificate.pem())?;
        fs::write(&private_key_path, signing_key.serialize_pem())?;
        Ok((certificate_path, private_key_path))
    }
}
