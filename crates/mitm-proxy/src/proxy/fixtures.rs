use std::{
    error::Error,
    fs,
    io::{Read, Write},
    net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{Arc, mpsc},
    thread,
    time::{Duration, Instant},
};

use capture::CaptureEvent;
use probe_core::{
    Action, CaptureOrigin, CaptureSource, Direction, EventEnvelope, EventKind, FlowContext,
    HttpHeaders, Timestamp, Verdict, VerdictScope,
};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, StreamOwned,
    pki_types::{CertificateDer, ServerName},
};

use super::{
    MitmProxyConfig, MitmProxyGuard, ProxyListeners, TargetRecovery, UpstreamTargetRoutes,
};
use crate::{http::read_http_message, tls::TlsTerminationConfig};

pub(super) type ObservedSniReceiver = mpsc::Receiver<Option<String>>;

pub(super) fn test_config(
    listen: SocketAddr,
    feed_path: &Path,
    upstream: Option<SocketAddr>,
    tls: Option<TlsTerminationConfig>,
    policy_hook_listen: Option<SocketAddr>,
    action_timeout: Duration,
) -> MitmProxyConfig {
    MitmProxyConfig {
        listen,
        transparent_listen: false,
        feed_path: feed_path.to_path_buf(),
        pid_file: None,
        upstream,
        upstream_routes: UpstreamTargetRoutes::default(),
        upstream_tls: None,
        upstream_socket_mark: None,
        tls,
        target_recovery: TargetRecovery::AcceptedLocal,
        request_direction: Direction::Outbound,
        policy_hook_listen,
        policy_hook_path: "/mitm-policy-hook".to_string(),
        max_request_bytes: 65_536,
        io_timeout: Duration::from_secs(2),
        action_timeout,
    }
}

pub(super) fn start_test_proxy(
    config: MitmProxyConfig,
    data: TcpListener,
    policy_hook: Option<TcpListener>,
) -> Result<MitmProxyGuard, Box<dyn Error>> {
    Ok(MitmProxyGuard::start_with_listeners(
        config,
        ProxyListeners::from_bound(data, policy_hook)?,
    )?)
}

pub(super) fn bound_loopback_listener() -> Result<TcpListener, Box<dyn Error>> {
    Ok(TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?)
}

pub(super) fn write_test_certificate(
    root: &Path,
) -> Result<(PathBuf, PathBuf, CertificateDer<'static>), Box<dyn Error>> {
    write_test_certificate_for_name(root, "server", "localhost")
}

pub(super) fn write_test_certificate_for_name(
    root: &Path,
    prefix: &str,
    server_name: &str,
) -> Result<(PathBuf, PathBuf, CertificateDer<'static>), Box<dyn Error>> {
    let certified_key = rcgen::generate_simple_self_signed([server_name.to_string()])?;
    let certificate_path = root.join(format!("{prefix}.pem"));
    let private_key_path = root.join(format!("{prefix}.key"));
    fs::write(&certificate_path, certified_key.cert.pem())?;
    fs::write(&private_key_path, certified_key.signing_key.serialize_pem())?;
    Ok((
        certificate_path,
        private_key_path,
        certified_key.cert.der().clone(),
    ))
}

pub(super) fn write_test_ca(
    root: &Path,
) -> Result<(PathBuf, PathBuf, CertificateDer<'static>), Box<dyn Error>> {
    let signing_key = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let certificate = params.self_signed(&signing_key)?;
    let certificate_path = root.join("mitm-ca.pem");
    let private_key_path = root.join("mitm-ca.key");
    fs::write(&certificate_path, certificate.pem())?;
    fs::write(&private_key_path, signing_key.serialize_pem())?;
    Ok((
        certificate_path,
        private_key_path,
        certificate.der().clone(),
    ))
}

pub(super) fn tls_client_stream(
    target: SocketAddr,
    trusted_certificate: CertificateDer<'static>,
) -> Result<StreamOwned<ClientConnection, TcpStream>, Box<dyn Error>> {
    tls_client_stream_with_name(target, trusted_certificate, "localhost")
}

pub(super) fn tls_client_stream_with_name(
    target: SocketAddr,
    trusted_certificate: CertificateDer<'static>,
    server_name: &str,
) -> Result<StreamOwned<ClientConnection, TcpStream>, Box<dyn Error>> {
    tls_client_stream_with_sni(target, trusted_certificate, server_name, true)
}

pub(super) fn tls_client_stream_without_sni(
    target: SocketAddr,
    trusted_certificate: CertificateDer<'static>,
    server_name: &str,
) -> Result<StreamOwned<ClientConnection, TcpStream>, Box<dyn Error>> {
    tls_client_stream_with_sni(target, trusted_certificate, server_name, false)
}

fn tls_client_stream_with_sni(
    target: SocketAddr,
    trusted_certificate: CertificateDer<'static>,
    server_name: &str,
    enable_sni: bool,
) -> Result<StreamOwned<ClientConnection, TcpStream>, Box<dyn Error>> {
    let mut roots = RootCertStore::empty();
    roots.add(trusted_certificate)?;
    let crypto_provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = ClientConfig::builder_with_provider(crypto_provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.enable_sni = enable_sni;
    let server_name = ServerName::try_from(server_name.to_string())?;
    let connection = ClientConnection::new(Arc::new(config), server_name)?;
    let stream = TcpStream::connect(target)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    Ok(StreamOwned::new(connection, stream))
}

pub(super) fn wait_for_flow(feed_path: &PathBuf) -> Result<FlowContext, Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if let Ok(content) = fs::read_to_string(feed_path) {
            for line in complete_feed_lines(&content) {
                let event = serde_json::from_str::<CaptureEvent>(line)?;
                if let CaptureEvent::Bytes(bytes) = event {
                    return Ok(bytes.flow);
                }
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
    Err("timed out waiting for MITM proxy feed flow".into())
}

fn complete_feed_lines(content: &str) -> impl Iterator<Item = &str> {
    let complete = if content.ends_with('\n') {
        content
    } else {
        content
            .rsplit_once('\n')
            .map_or("", |(complete, _)| complete)
    };
    complete.lines()
}

pub(super) fn feed_has_bytes(
    feed_path: &PathBuf,
    direction: Direction,
    expected: &[u8],
) -> Result<bool, Box<dyn Error>> {
    for line in fs::read_to_string(feed_path)?.lines() {
        let event = serde_json::from_str::<CaptureEvent>(line)?;
        if let CaptureEvent::Bytes(bytes) = event
            && bytes.direction == direction
            && bytes.bytes.as_ref() == expected
        {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(super) fn feed_direction_bytes(
    feed_path: &PathBuf,
    direction: Direction,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    for line in fs::read_to_string(feed_path)?.lines() {
        let event = serde_json::from_str::<CaptureEvent>(line)?;
        if let CaptureEvent::Bytes(chunk) = event
            && chunk.direction == direction
        {
            bytes.extend_from_slice(chunk.bytes.as_ref());
        }
    }
    Ok(bytes)
}

pub(super) fn send_policy_hook_deny(
    target: SocketAddr,
    flow: FlowContext,
) -> Result<(), Box<dyn Error>> {
    let response = send_policy_hook_deny_response(target, flow)?;
    assert!(response.contains(r#""outcome":"delegated""#), "{response}");
    Ok(())
}

pub(super) fn send_policy_hook_deny_response(
    target: SocketAddr,
    flow: FlowContext,
) -> Result<String, Box<dyn Error>> {
    let trigger = EventEnvelope::from_flow(
        Timestamp {
            monotonic_ns: 1,
            wall_time_unix_ns: 1,
        },
        flow,
        CaptureOrigin::from_source(CaptureSource::L7MitmPlaintext),
        "test-config",
        EventKind::HttpRequestHeaders(HttpHeaders {
            direction: Direction::Outbound,
            stream_sequence: 1,
            method: Some("GET".to_string()),
            target: Some("/blocked".to_string()),
            status: None,
            reason: None,
            version: "HTTP/1.1".to_string(),
            headers: Vec::new(),
        }),
    );
    let body = serde_json::json!({
        "requested_action": Action::Deny,
        "verdict": Verdict {
            action: Action::Deny,
            scope: VerdictScope::Request,
            reason: "blocked by test".to_string(),
            confidence: 100,
            ttl_ms: None,
        },
        "trigger": trigger,
    })
    .to_string();
    let request = format!(
        "POST /mitm-policy-hook HTTP/1.1\r\nHost: {target}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut stream = TcpStream::connect(target)?;
    stream.write_all(request.as_bytes())?;
    stream.shutdown(Shutdown::Write)?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

pub(super) fn upstream_server(response: &'static [u8]) -> Result<SocketAddr, Box<dyn Error>> {
    delayed_upstream_server(response, Duration::ZERO)
}

pub(super) fn tls_upstream_server(
    response: &'static [u8],
    certificate_chain: PathBuf,
    private_key: PathBuf,
) -> Result<SocketAddr, Box<dyn Error>> {
    tls_upstream_server_with_shutdown(
        response,
        certificate_chain,
        private_key,
        TlsUpstreamShutdown::CloseNotify,
    )
}

pub(super) fn tls_upstream_server_record_sni(
    response: &'static [u8],
    certificate_chain: PathBuf,
    private_key: PathBuf,
) -> Result<(SocketAddr, ObservedSniReceiver), Box<dyn Error>> {
    let (sender, receiver) = mpsc::channel();
    let target = tls_upstream_server_with_shutdown_and_sni(
        response,
        certificate_chain,
        private_key,
        TlsUpstreamShutdown::CloseNotify,
        Some(sender),
    )?;
    Ok((target, receiver))
}

pub(super) fn tls_upstream_keep_alive_server(
    response: &'static [u8],
    certificate_chain: PathBuf,
    private_key: PathBuf,
    hold_open: Duration,
) -> Result<SocketAddr, Box<dyn Error>> {
    tls_upstream_server_with_shutdown(
        response,
        certificate_chain,
        private_key,
        TlsUpstreamShutdown::HoldOpen(hold_open),
    )
}

enum TlsUpstreamShutdown {
    CloseNotify,
    HoldOpen(Duration),
}

fn tls_upstream_server_with_shutdown(
    response: &'static [u8],
    certificate_chain: PathBuf,
    private_key: PathBuf,
    shutdown: TlsUpstreamShutdown,
) -> Result<SocketAddr, Box<dyn Error>> {
    tls_upstream_server_with_shutdown_and_sni(
        response,
        certificate_chain,
        private_key,
        shutdown,
        None,
    )
}

fn tls_upstream_server_with_shutdown_and_sni(
    response: &'static [u8],
    certificate_chain: PathBuf,
    private_key: PathBuf,
    shutdown: TlsUpstreamShutdown,
    observed_sni: Option<mpsc::Sender<Option<String>>>,
) -> Result<SocketAddr, Box<dyn Error>> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let target = listener.local_addr()?;
    thread::spawn(move || {
        let Ok((stream, _peer)) = listener.accept() else {
            return;
        };
        let config = TlsTerminationConfig::new(certificate_chain, private_key);
        let Ok(terminator) = crate::tls::TlsTerminator::from_config(&config) else {
            return;
        };
        let Ok(mut stream) = terminator.accept(stream) else {
            return;
        };
        if let Some(observed_sni) = observed_sni {
            let _ = observed_sni.send(stream.conn.server_name().map(str::to_string));
        }
        if read_http_message(&mut stream, 65_536)
            .ok()
            .flatten()
            .is_some()
        {
            let _ = stream.write_all(response);
            match shutdown {
                TlsUpstreamShutdown::CloseNotify => {
                    stream.conn.send_close_notify();
                    let _ = stream.flush();
                }
                TlsUpstreamShutdown::HoldOpen(duration) => {
                    let _ = stream.flush();
                    thread::sleep(duration);
                }
            }
        }
    });
    Ok(target)
}

pub(super) fn delayed_upstream_server(
    response: &'static [u8],
    delay: Duration,
) -> Result<SocketAddr, Box<dyn Error>> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let target = listener.local_addr()?;
    thread::spawn(move || {
        if let Ok((mut stream, _peer)) = listener.accept() {
            let mut request = Vec::new();
            let _ = stream.read_to_end(&mut request);
            thread::sleep(delay);
            let _ = stream.write_all(response);
            let _ = stream.flush();
        }
    });
    Ok(target)
}
