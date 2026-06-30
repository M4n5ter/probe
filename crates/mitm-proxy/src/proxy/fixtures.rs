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
    Action, ApplicationProtocolPolicy, CaptureOrigin, CaptureSource, Direction, EventEnvelope,
    EventKind, FlowContext, HttpHeaders, Timestamp, Verdict, VerdictScope,
};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, StreamOwned,
    pki_types::{CertificateDer, ServerName},
};

use super::{
    MitmProxyConfig, MitmProxyGuard, ProxyListeners, TargetRecovery, UpstreamTargetRoutes,
};
use crate::{http::read_http_message, tls::TlsTerminationConfig};

pub(super) type ObservedTlsHandshakeReceiver = mpsc::Receiver<ObservedTlsHandshake>;
pub(super) type ObservedClientFrameReceiver = mpsc::Receiver<Vec<u8>>;

#[derive(Debug, PartialEq, Eq)]
pub(super) struct ObservedTlsHandshake {
    pub(super) server_name: Option<String>,
    pub(super) alpn_protocol: Option<Vec<u8>>,
}

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
        application_protocols: ApplicationProtocolPolicy::default(),
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
    tls_client_stream_with_sni_and_alpn(
        target,
        trusted_certificate,
        server_name,
        enable_sni,
        Vec::new(),
    )
}

pub(super) fn tls_client_stream_with_alpn(
    target: SocketAddr,
    trusted_certificate: CertificateDer<'static>,
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<StreamOwned<ClientConnection, TcpStream>, Box<dyn Error>> {
    tls_client_stream_with_sni_and_alpn(
        target,
        trusted_certificate,
        "localhost",
        true,
        alpn_protocols,
    )
}

fn tls_client_stream_with_sni_and_alpn(
    target: SocketAddr,
    trusted_certificate: CertificateDer<'static>,
    server_name: &str,
    enable_sni: bool,
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<StreamOwned<ClientConnection, TcpStream>, Box<dyn Error>> {
    let mut roots = RootCertStore::empty();
    roots.add(trusted_certificate)?;
    let crypto_provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = ClientConfig::builder_with_provider(crypto_provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.enable_sni = enable_sni;
    config.alpn_protocols = alpn_protocols;
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
    let content = fs::read_to_string(feed_path)?;
    for line in complete_feed_lines(&content) {
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

pub(super) fn wait_for_bytes(
    feed_path: &PathBuf,
    direction: Direction,
    expected: &[u8],
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if feed_path.try_exists()? && feed_has_bytes(feed_path, direction, expected)? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(20));
    }
    Err("timed out waiting for MITM proxy feed bytes".into())
}

pub(super) fn feed_has_connection_closed(
    feed_path: &PathBuf,
    flow_id: &str,
) -> Result<bool, Box<dyn Error>> {
    for line in fs::read_to_string(feed_path)?.lines() {
        let event = serde_json::from_str::<CaptureEvent>(line)?;
        if let CaptureEvent::ConnectionClosed { flow, .. } = event
            && flow.id.0 == flow_id
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
    send_policy_hook_deny_response_for_sequence(target, flow, 1)
}

pub(super) fn send_policy_hook_deny_response_for_sequence(
    target: SocketAddr,
    flow: FlowContext,
    stream_sequence: u64,
) -> Result<String, Box<dyn Error>> {
    let body = policy_hook_deny_body(flow, stream_sequence)?.to_string();
    let request = format!(
        "POST /mitm-policy-hook HTTP/1.1\r\nHost: {target}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    send_policy_hook_request(target, request.as_bytes())
}

pub(super) fn send_chunked_policy_hook_deny_response(
    target: SocketAddr,
    flow: FlowContext,
) -> Result<String, Box<dyn Error>> {
    let body = policy_hook_deny_body(flow, 1)?.to_string();
    let split = body.len() / 2;
    let (first, second) = body.split_at(split);
    let request = format!(
        "POST /mitm-policy-hook HTTP/1.1\r\nHost: {target}\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{}\r\n{:x}\r\n{}\r\n0\r\n\r\n",
        first.len(),
        first,
        second.len(),
        second
    );
    send_policy_hook_request(target, request.as_bytes())
}

fn policy_hook_deny_body(
    flow: FlowContext,
    stream_sequence: u64,
) -> Result<serde_json::Value, Box<dyn Error>> {
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
            stream_sequence,
            method: Some("GET".to_string()),
            target: Some("/blocked".to_string()),
            status: None,
            reason: None,
            version: "HTTP/1.1".to_string(),
            headers: Vec::new(),
        }),
    );
    Ok(serde_json::json!({
        "requested_action": Action::Deny,
        "verdict": Verdict {
            action: Action::Deny,
            scope: VerdictScope::Request,
            reason: "blocked by test".to_string(),
            confidence: 100,
            ttl_ms: None,
        },
        "trigger": trigger,
    }))
}

fn send_policy_hook_request(target: SocketAddr, request: &[u8]) -> Result<String, Box<dyn Error>> {
    let mut stream = TcpStream::connect(target)?;
    stream.write_all(request)?;
    stream.shutdown(Shutdown::Write)?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

pub(super) fn upstream_server(response: &'static [u8]) -> Result<SocketAddr, Box<dyn Error>> {
    delayed_upstream_server(response, Duration::ZERO)
}

pub(super) fn websocket_upstream_server(
    frame: &'static [u8],
) -> Result<SocketAddr, Box<dyn Error>> {
    let (target, _receiver) = websocket_upstream_server_with_client_frame(frame, 0)?;
    Ok(target)
}

pub(super) fn websocket_upstream_server_with_client_frame(
    frame: &'static [u8],
    client_frame_len: usize,
) -> Result<(SocketAddr, ObservedClientFrameReceiver), Box<dyn Error>> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let target = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        if let Ok((mut stream, _peer)) = listener.accept()
            && read_http_message(&mut stream, 65_536)
                .ok()
                .flatten()
                .is_some()
        {
            let _ = stream.write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            );
            let _ = stream.write_all(frame);
            let _ = stream.flush();
            if client_frame_len > 0 {
                let mut client_frame = vec![0_u8; client_frame_len];
                if stream.read_exact(&mut client_frame).is_ok() {
                    let _ = sender.send(client_frame);
                }
            }
        }
    });
    Ok((target, receiver))
}

pub(super) fn websocket_upstream_server_after_client_half_close(
    frame: &'static [u8],
    client_frame_len: usize,
) -> Result<(SocketAddr, ObservedClientFrameReceiver), Box<dyn Error>> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let target = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        if let Ok((mut stream, _peer)) = listener.accept() {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            if read_http_message(&mut stream, 65_536)
                .ok()
                .flatten()
                .is_none()
            {
                return;
            }
            let _ = stream.write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            );
            let _ = stream.flush();
            let mut client_frame = vec![0_u8; client_frame_len];
            if stream.read_exact(&mut client_frame).is_err() {
                return;
            }
            let mut eof = [0_u8; 1];
            if stream.read(&mut eof).ok() != Some(0) {
                return;
            }
            let _ = sender.send(client_frame);
            let _ = stream.write_all(frame);
            let _ = stream.flush();
        }
    });
    Ok((target, receiver))
}

pub(super) fn upgrade_observer_upstream_server(
    response: &'static [u8],
    max_extra_bytes: usize,
) -> Result<(SocketAddr, ObservedClientFrameReceiver), Box<dyn Error>> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let target = listener.local_addr()?;
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        if let Ok((mut stream, _peer)) = listener.accept() {
            let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
            let Some(request) = read_http_message(&mut stream, 65_536).ok().flatten() else {
                return;
            };
            let _ = stream.write_all(response);
            let _ = stream.flush();
            let mut observed = request.prefetched_tunnel_bytes;
            if observed.is_empty() && max_extra_bytes > 0 {
                let mut buffer = vec![0_u8; max_extra_bytes];
                if let Ok(read) = stream.read(&mut buffer) {
                    observed.extend_from_slice(&buffer[..read]);
                }
            }
            let _ = sender.send(observed);
        }
    });
    Ok((target, receiver))
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

pub(super) fn tls_upstream_server_record_handshake(
    response: &'static [u8],
    certificate_chain: PathBuf,
    private_key: PathBuf,
) -> Result<(SocketAddr, ObservedTlsHandshakeReceiver), Box<dyn Error>> {
    let (sender, receiver) = mpsc::channel();
    let target = tls_upstream_server_with_shutdown_and_observer(
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
    tls_upstream_server_with_shutdown_and_observer(
        response,
        certificate_chain,
        private_key,
        shutdown,
        None,
    )
}

fn tls_upstream_server_with_shutdown_and_observer(
    response: &'static [u8],
    certificate_chain: PathBuf,
    private_key: PathBuf,
    shutdown: TlsUpstreamShutdown,
    observed_handshake: Option<mpsc::Sender<ObservedTlsHandshake>>,
) -> Result<SocketAddr, Box<dyn Error>> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let target = listener.local_addr()?;
    thread::spawn(move || {
        let Ok((stream, _peer)) = listener.accept() else {
            return;
        };
        let config = TlsTerminationConfig::new(certificate_chain, private_key);
        let Ok(terminator) =
            crate::tls::TlsTerminator::from_config(&config, &ApplicationProtocolPolicy::default())
        else {
            return;
        };
        let Ok(mut stream) = terminator.accept(stream) else {
            return;
        };
        if let Some(observed_handshake) = observed_handshake {
            let _ = observed_handshake.send(ObservedTlsHandshake {
                server_name: stream.conn.server_name().map(str::to_string),
                alpn_protocol: stream.conn.alpn_protocol().map(<[u8]>::to_vec),
            });
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
