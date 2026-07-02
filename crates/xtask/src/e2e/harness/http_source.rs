use std::{
    fs,
    io::{BufReader, ErrorKind, Read, Write},
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use rustls::{
    ServerConfig, ServerConnection, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer},
};

const REQUEST_IO_TIMEOUT: Duration = Duration::from_secs(3);

pub(crate) struct HttpSourceServer {
    endpoint: String,
    listen_port: u16,
    request_count: Arc<AtomicUsize>,
    body: Arc<Mutex<String>>,
    stop_requested: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<Result<(), String>>>,
}

impl HttpSourceServer {
    pub(crate) fn spawn(
        target: impl Into<String>,
        content_type: &'static str,
        body: String,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let target = target.into();
        if !target.starts_with('/') {
            return Err(super::e2e_error(format!(
                "HTTP source target must start with '/', got {target}"
            ))
            .into());
        }

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let listen_port = listener.local_addr()?.port();
        listener.set_nonblocking(true)?;
        let endpoint = format!("http://{}{}", listener.local_addr()?, target);
        let request_count = Arc::new(AtomicUsize::new(0));
        let request_count_for_thread = Arc::clone(&request_count);
        let body = Arc::new(Mutex::new(body));
        let body_for_thread = Arc::clone(&body);
        let stop_requested = Arc::new(AtomicBool::new(false));
        let stop_requested_for_thread = Arc::clone(&stop_requested);
        let handle = thread::spawn(move || {
            while !stop_requested_for_thread.load(Ordering::Relaxed) {
                let (mut stream, _) = match listener.accept() {
                    Ok(accepted) => accepted,
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => return Err(error.to_string()),
                };
                stream
                    .set_read_timeout(Some(REQUEST_IO_TIMEOUT))
                    .map_err(|error| error.to_string())?;
                stream
                    .set_write_timeout(Some(REQUEST_IO_TIMEOUT))
                    .map_err(|error| error.to_string())?;
                let (method, request_target) = read_http_request(&mut stream)?;
                if method != "GET" || request_target != target {
                    let response =
                        "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
                    stream
                        .write_all(response.as_bytes())
                        .map_err(|error| error.to_string())?;
                    return Err(format!(
                        "unexpected HTTP source request {method} {request_target}"
                    ));
                }
                let body = body_for_thread
                    .lock()
                    .map_err(|_| "HTTP source body lock was poisoned".to_string())?
                    .clone();
                let response = http_response(content_type, &body);
                stream
                    .write_all(response.as_bytes())
                    .map_err(|error| error.to_string())?;
                request_count_for_thread.fetch_add(1, Ordering::Relaxed);
            }
            Ok(())
        });

        Ok(Self {
            endpoint,
            listen_port,
            request_count,
            body,
            stop_requested,
            handle: Some(handle),
        })
    }

    pub(crate) fn endpoint(&self) -> String {
        self.endpoint.clone()
    }

    pub(crate) fn listen_port(&self) -> u16 {
        self.listen_port
    }

    pub(crate) fn request_count(&self) -> usize {
        self.request_count.load(Ordering::Relaxed)
    }

    pub(crate) fn replace_body(&self, body: String) -> Result<(), Box<dyn std::error::Error>> {
        *self
            .body
            .lock()
            .map_err(|_| super::e2e_error("HTTP source body lock was poisoned"))? = body;
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<usize, Box<dyn std::error::Error>> {
        self.stop_and_join()
            .map_err(|error| super::e2e_error(format!("HTTP source server failed: {error}")))?;
        Ok(self.request_count.load(Ordering::Relaxed))
    }

    fn stop_and_join(&mut self) -> Result<(), String> {
        self.stop_requested.store(true, Ordering::Relaxed);
        let Some(handle) = self.handle.take() else {
            return Ok(());
        };
        handle
            .join()
            .map_err(|_| "HTTP source server thread panicked".to_string())?
    }
}

impl Drop for HttpSourceServer {
    fn drop(&mut self) {
        if let Err(error) = self.stop_and_join() {
            eprintln!("HTTP source server cleanup failed: {error}");
        }
    }
}

pub(crate) struct TlsServerMaterial {
    pub(crate) certificate_path: PathBuf,
    private_key_path: PathBuf,
}

pub(crate) struct TlsHttpSourceServer {
    listen_port: u16,
    thread: Option<JoinHandle<Result<(), String>>>,
}

impl TlsHttpSourceServer {
    pub(crate) fn spawn(
        target: &'static str,
        content_type: &'static str,
        body: &'static str,
        material: &TlsServerMaterial,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let config = Arc::new(tls_http_source_config(material)?);
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let listen_port = listener.local_addr()?.port();
        let body = body.to_string();
        let thread = thread::spawn(move || {
            serve_tls_http_source(listener, config, target, content_type, &body)
        });
        Ok(Self {
            listen_port,
            thread: Some(thread),
        })
    }

    pub(crate) fn listen_port(&self) -> u16 {
        self.listen_port
    }

    pub(crate) fn finish(mut self) -> Result<(), Box<dyn std::error::Error>> {
        match self
            .thread
            .take()
            .ok_or_else(|| super::e2e_error("TLS HTTP source server already finished"))?
            .join()
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => {
                Err(super::e2e_error(format!("TLS HTTP source server failed: {error}")).into())
            }
            Err(_) => Err(super::e2e_error("TLS HTTP source server panicked").into()),
        }
    }
}

impl Drop for TlsHttpSourceServer {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take()
            && let Err(error) = thread.join()
        {
            eprintln!("TLS HTTP source server cleanup failed: {error:?}");
        }
    }
}

pub(crate) fn write_tls_server_material(
    root: &Path,
    server_name: &str,
) -> Result<TlsServerMaterial, Box<dyn std::error::Error>> {
    let certified_key = rcgen::generate_simple_self_signed([server_name.to_string()])?;
    let certificate_path = root.join("upstream-server.pem");
    let private_key_path = root.join("upstream-server.key");
    write_private_file(&certificate_path, certified_key.cert.pem())?;
    write_private_file(&private_key_path, certified_key.signing_key.serialize_pem())?;
    Ok(TlsServerMaterial {
        certificate_path,
        private_key_path,
    })
}

fn tls_http_source_config(
    material: &TlsServerMaterial,
) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let certificate_chain = load_certificate_chain(&material.certificate_path)?;
    let private_key = load_private_key(&material.private_key_path)?;
    let crypto_provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    Ok(ServerConfig::builder_with_provider(crypto_provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .with_no_client_auth()
        .with_single_cert(certificate_chain, private_key)?)
}

fn serve_tls_http_source(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    expected_target: &str,
    content_type: &str,
    body: &str,
) -> Result<(), String> {
    let stream = accept_tls_http_source_connection(listener)?;
    stream
        .set_read_timeout(Some(REQUEST_IO_TIMEOUT))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(REQUEST_IO_TIMEOUT))
        .map_err(|error| error.to_string())?;
    let connection = ServerConnection::new(config).map_err(|error| error.to_string())?;
    let mut stream = StreamOwned::new(connection, stream);
    let (method, target) = read_http_request(&mut stream)?;
    if method != "GET" || target != expected_target {
        return Err(format!(
            "unexpected TLS HTTP source request {method} {target}"
        ));
    }
    stream
        .write_all(http_response(content_type, body).as_bytes())
        .and_then(|()| stream.flush())
        .map_err(|error| error.to_string())
}

fn accept_tls_http_source_connection(listener: TcpListener) -> Result<TcpStream, String> {
    listener
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    let deadline = Instant::now() + REQUEST_IO_TIMEOUT;
    loop {
        match listener.accept() {
            Ok((stream, _)) => return Ok(stream),
            Err(error) if error.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                return Err("timed out waiting for TLS HTTP source connection".to_string());
            }
            Err(error) => return Err(error.to_string()),
        }
    }
}

fn read_http_request(stream: &mut impl Read) -> Result<(String, String), String> {
    let mut bytes = Vec::new();
    loop {
        let mut buffer = [0; 1024];
        let read = stream
            .read(&mut buffer)
            .map_err(|error| error.to_string())?;
        if read == 0 {
            return Err(
                "connection closed before HTTP source request headers completed".to_string(),
            );
        }
        bytes.extend_from_slice(&buffer[..read]);
        if header_end(&bytes).is_some() {
            break;
        }
    }
    let headers = String::from_utf8_lossy(&bytes);
    let line = headers
        .lines()
        .next()
        .ok_or_else(|| "HTTP source request is missing request line".to_string())?;
    let mut parts = line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| "HTTP source request line is missing method".to_string())?;
    let target = parts
        .next()
        .ok_or_else(|| "HTTP source request line is missing target".to_string())?;
    let version = parts
        .next()
        .ok_or_else(|| "HTTP source request line is missing version".to_string())?;
    if !version.starts_with("HTTP/") || parts.next().is_some() {
        return Err(format!("invalid HTTP source request line {line}"));
    }
    Ok((method.to_string(), target.to_string()))
}

fn http_response(content_type: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn load_certificate_chain(
    path: &Path,
) -> Result<Vec<CertificateDer<'static>>, Box<dyn std::error::Error>> {
    let mut reader = BufReader::new(fs::File::open(path)?);
    let certificates = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    if certificates.is_empty() {
        return Err(super::e2e_error(format!(
            "TLS HTTP source certificate chain {} was empty",
            path.display()
        ))
        .into());
    }
    Ok(certificates)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, Box<dyn std::error::Error>> {
    let mut reader = BufReader::new(fs::File::open(path)?);
    rustls_pemfile::private_key(&mut reader)?.ok_or_else(|| {
        super::e2e_error(format!(
            "TLS HTTP source private key {} was empty",
            path.display()
        ))
        .into()
    })
}

fn write_private_file(
    path: &Path,
    contents: impl AsRef<[u8]>,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(path, contents)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}
