mod downstream;
mod policy_hook;
mod upstream;

use std::{
    fs::OpenOptions,
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    num::NonZeroU32,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use clap::ValueEnum;
use probe_core::Direction;
use socket2::Socket;

use crate::{
    MitmProxyError,
    error::io_error,
    feed::{CaptureEventFeedWriter, FlowOffsets},
    flow::{FlowFactory, FlowRegistry, ProxyAction},
    http::{HttpMessage, read_http_message, relay_http_response, write_empty_response},
    tls::{TlsTerminationConfig, UpstreamTlsConfig},
};

use self::downstream::{DownstreamAcceptor, DownstreamIo};
use self::policy_hook::spawn_policy_hook_listener;
use self::upstream::UpstreamConnector;

const ACCEPT_IDLE_SLEEP: Duration = Duration::from_millis(20);

#[derive(Clone, Debug)]
pub struct MitmProxyConfig {
    pub listen: SocketAddr,
    pub feed_path: PathBuf,
    pub pid_file: Option<PathBuf>,
    pub upstream: Option<SocketAddr>,
    pub upstream_tls: Option<UpstreamTlsConfig>,
    pub upstream_socket_mark: Option<NonZeroU32>,
    pub tls: Option<TlsTerminationConfig>,
    pub target_recovery: TargetRecovery,
    pub request_direction: Direction,
    pub policy_hook_listen: Option<SocketAddr>,
    pub policy_hook_path: String,
    pub max_request_bytes: usize,
    pub io_timeout: Duration,
    pub action_timeout: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum TargetRecovery {
    AcceptedLocal,
    LinuxOriginalDestination,
}

impl std::fmt::Display for TargetRecovery {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AcceptedLocal => formatter.write_str("accepted-local"),
            Self::LinuxOriginalDestination => formatter.write_str("linux-original-destination"),
        }
    }
}

pub struct MitmProxyGuard {
    shutdown: Arc<AtomicBool>,
    threads: Vec<JoinHandle<Result<(), MitmProxyError>>>,
}

impl MitmProxyGuard {
    pub fn start(config: MitmProxyConfig) -> Result<Self, MitmProxyError> {
        validate_config(&config)?;
        let listeners = ProxyListeners::bind(&config)?;
        Self::start_with_listeners(config, listeners)
    }

    fn start_with_listeners(
        config: MitmProxyConfig,
        listeners: ProxyListeners,
    ) -> Result<Self, MitmProxyError> {
        validate_config(&config)?;
        let downstream = DownstreamAcceptor::from_tls_config(config.tls.as_ref())?;
        let upstream = UpstreamConnector::from_config(
            config.upstream_tls.as_ref(),
            config.upstream_socket_mark,
        )?;
        write_pid_file(config.pid_file.as_ref())?;
        let feed = Arc::new(CaptureEventFeedWriter::create(&config.feed_path)?);
        let state = Arc::new(ProxyState {
            config: Arc::new(config),
            downstream,
            upstream,
            feed,
            registry: Arc::new(FlowRegistry::default()),
            flow_factory: Arc::new(FlowFactory::new()),
        });
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut threads = vec![spawn_data_listener(
            listeners.data,
            Arc::clone(&state),
            Arc::clone(&shutdown),
        )];
        if let Some(listener) = listeners.policy_hook {
            threads.push(spawn_policy_hook_listener(
                listener,
                state,
                Arc::clone(&shutdown),
            ));
        }
        Ok(Self { shutdown, threads })
    }

    pub fn stop(mut self) -> Result<(), MitmProxyError> {
        self.shutdown.store(true, Ordering::SeqCst);
        let mut first_error = None;
        for thread in self.threads.drain(..) {
            match thread.join().map_err(|_| MitmProxyError::ThreadPanic)? {
                Ok(()) => {}
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(_) => {}
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    pub fn wait(mut self) -> Result<(), MitmProxyError> {
        for thread in self.threads.drain(..) {
            thread.join().map_err(|_| MitmProxyError::ThreadPanic)??;
        }
        Ok(())
    }
}

pub fn run_forever(config: MitmProxyConfig) -> Result<(), MitmProxyError> {
    MitmProxyGuard::start(config)?.wait()
}

struct ProxyState {
    config: Arc<MitmProxyConfig>,
    downstream: DownstreamAcceptor,
    upstream: UpstreamConnector,
    feed: Arc<CaptureEventFeedWriter>,
    registry: Arc<FlowRegistry>,
    flow_factory: Arc<FlowFactory>,
}

struct ProxyListeners {
    data: TcpListener,
    policy_hook: Option<TcpListener>,
}

fn validate_config(config: &MitmProxyConfig) -> Result<(), MitmProxyError> {
    if !config.listen.ip().is_loopback() {
        return Err(MitmProxyError::InvalidConfig(format!(
            "MITM proxy listen address must be loopback, got {}",
            config.listen
        )));
    }
    if let Some(policy_hook_listen) = config.policy_hook_listen
        && !policy_hook_listen.ip().is_loopback()
    {
        return Err(MitmProxyError::InvalidConfig(format!(
            "MITM proxy policy hook listen address must be loopback, got {policy_hook_listen}"
        )));
    }
    if config.max_request_bytes == 0 {
        return Err(MitmProxyError::InvalidConfig(
            "max_request_bytes must be greater than zero".to_string(),
        ));
    }
    Ok(())
}

impl ProxyListeners {
    fn bind(config: &MitmProxyConfig) -> Result<Self, MitmProxyError> {
        Ok(Self {
            data: bind_listener(config.listen)
                .map_err(io_error("bind MITM proxy data listener"))?,
            policy_hook: config
                .policy_hook_listen
                .map(bind_listener)
                .transpose()
                .map_err(io_error("bind MITM proxy policy hook listener"))?,
        })
    }

    #[cfg(test)]
    fn from_bound(data: TcpListener, policy_hook: Option<TcpListener>) -> Result<Self, io::Error> {
        Ok(Self {
            data: prepare_listener(data)?,
            policy_hook: policy_hook.map(prepare_listener).transpose()?,
        })
    }
}

fn bind_listener(listen: SocketAddr) -> io::Result<TcpListener> {
    prepare_listener(TcpListener::bind(listen)?)
}

fn prepare_listener(listener: TcpListener) -> io::Result<TcpListener> {
    listener.set_nonblocking(true)?;
    Ok(listener)
}

fn write_pid_file(path: Option<&PathBuf>) -> Result<(), MitmProxyError> {
    let Some(path) = path else {
        return Ok(());
    };
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(io_error("create MITM proxy pid file"))?;
    file.write_all(std::process::id().to_string().as_bytes())
        .map_err(io_error("write MITM proxy pid file"))
}

fn spawn_data_listener(
    listener: TcpListener,
    state: Arc<ProxyState>,
    shutdown: Arc<AtomicBool>,
) -> JoinHandle<Result<(), MitmProxyError>> {
    thread::spawn(move || accept_data_connections(listener, state, shutdown))
}

fn accept_data_connections(
    listener: TcpListener,
    state: Arc<ProxyState>,
    shutdown: Arc<AtomicBool>,
) -> Result<(), MitmProxyError> {
    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _peer)) => {
                let state = Arc::clone(&state);
                thread::spawn(move || {
                    if let Err(error) = handle_data_connection(stream, state) {
                        eprintln!("MITM proxy data connection failed: {error}");
                    }
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_IDLE_SLEEP);
            }
            Err(source) => return Err(io_error("accept MITM proxy data connection")(source)),
        }
    }
    Ok(())
}

fn handle_data_connection(
    downstream: TcpStream,
    state: Arc<ProxyState>,
) -> Result<(), MitmProxyError> {
    configure_stream(&downstream, state.config.io_timeout)?;
    let peer = downstream
        .peer_addr()
        .map_err(io_error("read MITM proxy downstream peer address"))?;
    let target = recover_target(&downstream, &state.config)?;
    let mut downstream = state.downstream.accept(downstream)?;
    handle_http_connection(&mut downstream, peer, target, state)
}

fn handle_http_connection(
    mut downstream: &mut impl DownstreamIo,
    peer: SocketAddr,
    target: SocketAddr,
    state: Arc<ProxyState>,
) -> Result<(), MitmProxyError> {
    let Some(request) = read_http_message(downstream, state.config.max_request_bytes)? else {
        return Ok(());
    };
    let flow = state
        .flow_factory
        .flow(peer, target, state.config.request_direction);
    let registration = state
        .config
        .policy_hook_listen
        .map(|_| state.registry.register(flow.id.clone()));
    let mut offsets = FlowOffsets::default();
    state.feed.connection_opened(&flow)?;
    let request_offset = offsets.record(state.config.request_direction, request.raw.len());
    state.feed.bytes(
        &flow,
        state.config.request_direction,
        request_offset,
        &request.raw,
    )?;

    let action = match registration {
        Some(registration) => registration.recv_timeout(state.config.action_timeout),
        None => None,
    };
    match action {
        Some(ProxyAction::Deny { reason }) => {
            write_deny_response(&mut downstream, &state, &flow, &mut offsets, reason)?
        }
        None => forward_or_gateway_response(
            &mut downstream,
            target,
            request,
            &state,
            &flow,
            &mut offsets,
        )?,
    }
    let finish_result = downstream.finish();
    let close_result = state.feed.connection_closed(flow);
    finish_result.and(close_result)
}

fn configure_stream(stream: &TcpStream, timeout: Duration) -> Result<(), MitmProxyError> {
    stream
        .set_read_timeout(Some(timeout))
        .map_err(io_error("set MITM proxy read timeout"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(io_error("set MITM proxy write timeout"))
}

fn recover_target(
    downstream: &TcpStream,
    config: &MitmProxyConfig,
) -> Result<SocketAddr, MitmProxyError> {
    if let Some(upstream) = config.upstream {
        return Ok(upstream);
    }
    match config.target_recovery {
        TargetRecovery::AcceptedLocal => downstream
            .local_addr()
            .map_err(io_error("read MITM proxy accepted local address")),
        TargetRecovery::LinuxOriginalDestination => linux_original_destination(downstream),
    }
}

fn linux_original_destination(downstream: &TcpStream) -> Result<SocketAddr, MitmProxyError> {
    let local = downstream
        .local_addr()
        .map_err(io_error("read MITM proxy downstream local address"))?;
    let socket = Socket::from(
        downstream
            .try_clone()
            .map_err(io_error("clone MITM proxy downstream socket"))?,
    );
    let original_destination = match local {
        SocketAddr::V4(_) => socket
            .original_dst_v4()
            .map_err(io_error("read IPv4 Linux original destination"))?,
        SocketAddr::V6(_) => socket
            .original_dst_v6()
            .map_err(io_error("read IPv6 Linux original destination"))?,
    };
    original_destination
        .as_socket()
        .ok_or_else(|| MitmProxyError::Http("Linux original destination is not IP".to_string()))
}

fn write_deny_response(
    downstream: &mut impl Write,
    state: &ProxyState,
    flow: &probe_core::FlowContext,
    offsets: &mut FlowOffsets,
    reason: Option<String>,
) -> Result<(), MitmProxyError> {
    let body = reason.unwrap_or_else(|| "request denied by local policy".to_string());
    let response = deny_response_bytes(&body);
    downstream
        .write_all(&response)
        .map_err(io_error("write MITM proxy deny response"))?;
    downstream
        .flush()
        .map_err(io_error("flush MITM proxy deny response"))?;
    let direction = response_direction(state.config.request_direction);
    let offset = offsets.record(direction, response.len());
    state.feed.bytes(flow, direction, offset, &response)
}

fn forward_or_gateway_response(
    downstream: &mut impl Write,
    target: SocketAddr,
    request: HttpMessage,
    state: &ProxyState,
    flow: &probe_core::FlowContext,
    offsets: &mut FlowOffsets,
) -> Result<(), MitmProxyError> {
    let config = &state.config;
    if is_self_target(target, config.listen) {
        return write_empty_response(downstream, 200);
    }
    match state.upstream.connect(target, &request, config.io_timeout) {
        Ok(mut upstream) => {
            upstream
                .write_all(&request.raw)
                .map_err(io_error("write MITM proxy upstream request"))?;
            upstream
                .flush()
                .map_err(io_error("flush MITM proxy upstream request"))?;
            upstream.finish_request()?;
            relay_response(
                &mut upstream,
                &request,
                downstream,
                &state.feed,
                flow,
                offsets,
                response_direction(config.request_direction),
            )
        }
        Err(_) => write_empty_response(downstream, 502),
    }
}

fn relay_response(
    upstream: &mut impl Read,
    request: &HttpMessage,
    downstream: &mut impl Write,
    feed: &CaptureEventFeedWriter,
    flow: &probe_core::FlowContext,
    offsets: &mut FlowOffsets,
    direction: Direction,
) -> Result<(), MitmProxyError> {
    relay_http_response(upstream, request, |bytes| {
        let offset = offsets.record(direction, bytes.len());
        feed.bytes(flow, direction, offset, bytes)?;
        downstream
            .write_all(bytes)
            .map_err(io_error("write MITM proxy downstream response"))
    })
}

fn deny_response_bytes(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn response_direction(request_direction: Direction) -> Direction {
    match request_direction {
        Direction::Inbound => Direction::Outbound,
        Direction::Outbound => Direction::Inbound,
    }
}

fn is_self_target(target: SocketAddr, listen: SocketAddr) -> bool {
    target.port() == listen.port()
        && (target.ip() == listen.ip()
            || target.ip().is_loopback() && listen.ip().is_loopback()
            || target.ip() == Ipv4Addr::UNSPECIFIED)
}

#[cfg(test)]
mod tests {
    use std::{
        error::Error,
        fs,
        io::{Read, Write},
        net::{Ipv4Addr, Shutdown, TcpListener},
        path::{Path, PathBuf},
        sync::Arc,
        thread,
    };

    use capture::CaptureEvent;
    use probe_core::{
        Action, CaptureOrigin, CaptureSource, EventEnvelope, EventKind, FlowContext, HttpHeaders,
        Timestamp, Verdict, VerdictScope,
    };
    use rustls::{
        ClientConfig, ClientConnection, RootCertStore, StreamOwned,
        pki_types::{CertificateDer, ServerName},
    };
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn policy_hook_can_deny_pending_http_flow() -> Result<(), Box<dyn Error>> {
        let root = tempdir()?;
        let feed_path = root.path().join("mitm-feed.jsonl");
        let data_listener = bound_loopback_listener()?;
        let listen = data_listener.local_addr()?;
        let policy_hook_listener = bound_loopback_listener()?;
        let policy_hook_listen = policy_hook_listener.local_addr()?;
        let guard = start_test_proxy(
            test_config(
                listen,
                &feed_path,
                None,
                None,
                Some(policy_hook_listen),
                Duration::from_secs(2),
            ),
            data_listener,
            Some(policy_hook_listener),
        )?;

        let client = thread::spawn(move || -> Result<Vec<u8>, String> {
            let mut stream = TcpStream::connect(listen).map_err(|error| error.to_string())?;
            stream
                .write_all(b"GET /blocked HTTP/1.1\r\nHost: example.test\r\n\r\n")
                .map_err(|error| error.to_string())?;
            stream
                .shutdown(Shutdown::Write)
                .map_err(|error| error.to_string())?;
            let mut response = Vec::new();
            stream
                .read_to_end(&mut response)
                .map_err(|error| error.to_string())?;
            Ok(response)
        });
        let flow = wait_for_flow(&feed_path)?;
        send_policy_hook_deny(policy_hook_listen, flow)?;

        let response = client
            .join()
            .map_err(|_| "client thread panicked")?
            .map_err(std::io::Error::other)?;
        guard.stop()?;

        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 403 Forbidden"));
        assert!(feed_has_bytes(
            &feed_path,
            Direction::Inbound,
            deny_response_bytes("blocked by test").as_slice()
        )?);
        Ok(())
    }

    #[test]
    fn policy_hook_rejects_deny_after_action_timeout() -> Result<(), Box<dyn Error>> {
        let root = tempdir()?;
        let feed_path = root.path().join("mitm-feed.jsonl");
        let upstream = delayed_upstream_server(
            b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nallowed",
            Duration::from_millis(500),
        )?;
        let data_listener = bound_loopback_listener()?;
        let listen = data_listener.local_addr()?;
        let policy_hook_listener = bound_loopback_listener()?;
        let policy_hook_listen = policy_hook_listener.local_addr()?;
        let guard = start_test_proxy(
            test_config(
                listen,
                &feed_path,
                Some(upstream),
                None,
                Some(policy_hook_listen),
                Duration::from_millis(50),
            ),
            data_listener,
            Some(policy_hook_listener),
        )?;

        let client = thread::spawn(move || -> Result<Vec<u8>, String> {
            let mut stream = TcpStream::connect(listen).map_err(|error| error.to_string())?;
            stream
                .write_all(b"GET /allowed HTTP/1.1\r\nHost: example.test\r\n\r\n")
                .map_err(|error| error.to_string())?;
            stream
                .shutdown(Shutdown::Write)
                .map_err(|error| error.to_string())?;
            let mut response = Vec::new();
            stream
                .read_to_end(&mut response)
                .map_err(|error| error.to_string())?;
            Ok(response)
        });
        let flow = wait_for_flow(&feed_path)?;
        thread::sleep(Duration::from_millis(150));
        let hook_response = send_policy_hook_deny_response(policy_hook_listen, flow)?;

        let response = client
            .join()
            .map_err(|_| "client thread panicked")?
            .map_err(std::io::Error::other)?;
        guard.stop()?;

        assert!(
            hook_response.contains(r#""outcome":"unsupported""#)
                && hook_response.contains("is not pending in MITM proxy"),
            "{hook_response}"
        );
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200 OK"));
        Ok(())
    }

    #[test]
    fn http_flow_without_policy_hook_is_forwarded_to_upstream() -> Result<(), Box<dyn Error>> {
        let root = tempdir()?;
        let feed_path = root.path().join("mitm-feed.jsonl");
        let upstream = upstream_server(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")?;
        let data_listener = bound_loopback_listener()?;
        let listen = data_listener.local_addr()?;
        let guard = start_test_proxy(
            test_config(
                listen,
                &feed_path,
                Some(upstream),
                None,
                None,
                Duration::from_secs(2),
            ),
            data_listener,
            None,
        )?;

        let mut stream = TcpStream::connect(listen)?;
        stream.write_all(b"GET /ok HTTP/1.1\r\nHost: example.test\r\n\r\n")?;
        stream.shutdown(Shutdown::Write)?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        guard.stop()?;

        assert_eq!(
            String::from_utf8_lossy(&response),
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
        );
        assert_eq!(
            feed_direction_bytes(&feed_path, Direction::Inbound)?,
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
        );
        Ok(())
    }

    #[test]
    fn tls_listener_terminates_client_tls_and_feeds_plaintext_http() -> Result<(), Box<dyn Error>> {
        let root = tempdir()?;
        let feed_path = root.path().join("mitm-feed.jsonl");
        let (certificate_chain, private_key, trusted_certificate) =
            write_test_certificate(root.path())?;
        let upstream = upstream_server(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nfrom-tls")?;
        let data_listener = bound_loopback_listener()?;
        let listen = data_listener.local_addr()?;
        let guard = start_test_proxy(
            test_config(
                listen,
                &feed_path,
                Some(upstream),
                Some(TlsTerminationConfig::new(certificate_chain, private_key)),
                None,
                Duration::from_secs(2),
            ),
            data_listener,
            None,
        )?;

        let mut stream = tls_client_stream(listen, trusted_certificate)?;
        let request = b"GET /tls HTTP/1.1\r\nHost: localhost\r\n\r\n";
        stream.write_all(request)?;
        stream.flush()?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        guard.stop()?;

        assert_eq!(
            String::from_utf8_lossy(&response),
            "HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nfrom-tls"
        );
        assert!(feed_has_bytes(&feed_path, Direction::Outbound, request)?);
        assert_eq!(
            feed_direction_bytes(&feed_path, Direction::Inbound)?,
            b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nfrom-tls"
        );
        Ok(())
    }

    #[test]
    fn dynamic_ca_tls_listener_signs_sni_leaf_and_feeds_plaintext_http()
    -> Result<(), Box<dyn Error>> {
        let root = tempdir()?;
        let feed_path = root.path().join("mitm-feed.jsonl");
        let (ca_certificate_chain, ca_private_key, trusted_ca_certificate) =
            write_test_ca(root.path())?;
        let upstream =
            upstream_server(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\ndynamic-tls")?;
        let data_listener = bound_loopback_listener()?;
        let listen = data_listener.local_addr()?;
        let guard = start_test_proxy(
            test_config(
                listen,
                &feed_path,
                Some(upstream),
                Some(TlsTerminationConfig::from_ca(
                    ca_certificate_chain,
                    ca_private_key,
                )),
                None,
                Duration::from_secs(2),
            ),
            data_listener,
            None,
        )?;

        let mut stream =
            tls_client_stream_with_name(listen, trusted_ca_certificate, "dynamic.example")?;
        let request = b"GET /dynamic HTTP/1.1\r\nHost: dynamic.example\r\n\r\n";
        stream.write_all(request)?;
        stream.flush()?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        guard.stop()?;

        assert_eq!(
            String::from_utf8_lossy(&response),
            "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\ndynamic-tls"
        );
        assert!(feed_has_bytes(&feed_path, Direction::Outbound, request)?);
        Ok(())
    }

    #[test]
    fn dynamic_ca_tls_listener_rejects_clients_without_sni() -> Result<(), Box<dyn Error>> {
        let root = tempdir()?;
        let feed_path = root.path().join("mitm-feed.jsonl");
        let (ca_certificate_chain, ca_private_key, trusted_ca_certificate) =
            write_test_ca(root.path())?;
        let upstream = upstream_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")?;
        let data_listener = bound_loopback_listener()?;
        let listen = data_listener.local_addr()?;
        let guard = start_test_proxy(
            test_config(
                listen,
                &feed_path,
                Some(upstream),
                Some(TlsTerminationConfig::from_ca(
                    ca_certificate_chain,
                    ca_private_key,
                )),
                None,
                Duration::from_secs(2),
            ),
            data_listener,
            None,
        )?;

        let mut stream =
            tls_client_stream_without_sni(listen, trusted_ca_certificate, "dynamic.example")?;
        let result = stream
            .write_all(b"GET / HTTP/1.1\r\nHost: dynamic.example\r\n\r\n")
            .and_then(|_| stream.flush())
            .and_then(|_| {
                let mut response = Vec::new();
                stream.read_to_end(&mut response)
            });
        guard.stop()?;

        assert!(result.is_err(), "dynamic CA mode must require SNI");
        assert!(!feed_path.exists() || fs::read_to_string(&feed_path)?.is_empty());
        Ok(())
    }

    #[test]
    fn tls_listener_relays_plaintext_http_to_tls_upstream() -> Result<(), Box<dyn Error>> {
        let root = tempdir()?;
        let feed_path = root.path().join("mitm-feed.jsonl");
        let (certificate_chain, private_key, trusted_certificate) =
            write_test_certificate(root.path())?;
        let upstream = tls_upstream_server(
            b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nfrom-upstream",
            certificate_chain.clone(),
            private_key.clone(),
        )?;
        let data_listener = bound_loopback_listener()?;
        let listen = data_listener.local_addr()?;
        let mut config = test_config(
            listen,
            &feed_path,
            Some(upstream),
            Some(TlsTerminationConfig::new(
                certificate_chain.clone(),
                private_key,
            )),
            None,
            Duration::from_secs(2),
        );
        config.upstream_tls = Some(UpstreamTlsConfig::new(vec![certificate_chain], None));
        let guard = start_test_proxy(config, data_listener, None)?;

        let mut stream = tls_client_stream(listen, trusted_certificate)?;
        let request = format!(
            "GET /tls-upstream HTTP/1.1\r\nHost: localhost:{}\r\n\r\n",
            upstream.port()
        );
        stream.write_all(request.as_bytes())?;
        stream.flush()?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        guard.stop()?;

        assert_eq!(
            String::from_utf8_lossy(&response),
            "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nfrom-upstream"
        );
        assert!(feed_has_bytes(
            &feed_path,
            Direction::Outbound,
            request.as_bytes()
        )?);
        assert_eq!(
            feed_direction_bytes(&feed_path, Direction::Inbound)?,
            b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nfrom-upstream"
        );
        Ok(())
    }

    #[test]
    fn tls_upstream_keep_alive_response_completes_by_http_framing() -> Result<(), Box<dyn Error>> {
        let root = tempdir()?;
        let feed_path = root.path().join("mitm-feed.jsonl");
        let (certificate_chain, private_key, trusted_certificate) =
            write_test_certificate(root.path())?;
        let upstream = tls_upstream_keep_alive_server(
            b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nkeepalive",
            certificate_chain.clone(),
            private_key.clone(),
            Duration::from_secs(4),
        )?;
        let data_listener = bound_loopback_listener()?;
        let listen = data_listener.local_addr()?;
        let mut config = test_config(
            listen,
            &feed_path,
            Some(upstream),
            Some(TlsTerminationConfig::new(
                certificate_chain.clone(),
                private_key,
            )),
            None,
            Duration::from_secs(2),
        );
        config.io_timeout = Duration::from_secs(5);
        config.upstream_tls = Some(UpstreamTlsConfig::new(vec![certificate_chain], None));
        let guard = start_test_proxy(config, data_listener, None)?;

        let started = std::time::Instant::now();
        let mut stream = tls_client_stream(listen, trusted_certificate)?;
        stream.write_all(
            format!(
                "GET /tls-keep-alive HTTP/1.1\r\nHost: localhost:{}\r\n\r\n",
                upstream.port()
            )
            .as_bytes(),
        )?;
        stream.flush()?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        guard.stop()?;

        assert!(
            started.elapsed() < Duration::from_secs(2),
            "response relay should complete before upstream keep-alive closes"
        );
        assert_eq!(
            String::from_utf8_lossy(&response),
            "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nkeepalive"
        );
        Ok(())
    }

    fn test_config(
        listen: SocketAddr,
        feed_path: &Path,
        upstream: Option<SocketAddr>,
        tls: Option<TlsTerminationConfig>,
        policy_hook_listen: Option<SocketAddr>,
        action_timeout: Duration,
    ) -> MitmProxyConfig {
        MitmProxyConfig {
            listen,
            feed_path: feed_path.to_path_buf(),
            pid_file: None,
            upstream,
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

    fn start_test_proxy(
        config: MitmProxyConfig,
        data: TcpListener,
        policy_hook: Option<TcpListener>,
    ) -> Result<MitmProxyGuard, Box<dyn Error>> {
        Ok(MitmProxyGuard::start_with_listeners(
            config,
            ProxyListeners::from_bound(data, policy_hook)?,
        )?)
    }

    fn bound_loopback_listener() -> Result<TcpListener, Box<dyn Error>> {
        Ok(TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?)
    }

    fn write_test_certificate(
        root: &std::path::Path,
    ) -> Result<(PathBuf, PathBuf, CertificateDer<'static>), Box<dyn Error>> {
        let certified_key = rcgen::generate_simple_self_signed(["localhost".to_string()])?;
        let certificate_path = root.join("server.pem");
        let private_key_path = root.join("server.key");
        fs::write(&certificate_path, certified_key.cert.pem())?;
        fs::write(&private_key_path, certified_key.signing_key.serialize_pem())?;
        Ok((
            certificate_path,
            private_key_path,
            certified_key.cert.der().clone(),
        ))
    }

    fn write_test_ca(
        root: &std::path::Path,
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

    fn tls_client_stream(
        target: SocketAddr,
        trusted_certificate: CertificateDer<'static>,
    ) -> Result<StreamOwned<ClientConnection, TcpStream>, Box<dyn Error>> {
        tls_client_stream_with_name(target, trusted_certificate, "localhost")
    }

    fn tls_client_stream_with_name(
        target: SocketAddr,
        trusted_certificate: CertificateDer<'static>,
        server_name: &str,
    ) -> Result<StreamOwned<ClientConnection, TcpStream>, Box<dyn Error>> {
        tls_client_stream_with_sni(target, trusted_certificate, server_name, true)
    }

    fn tls_client_stream_without_sni(
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

    fn wait_for_flow(feed_path: &PathBuf) -> Result<FlowContext, Box<dyn Error>> {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
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

    fn feed_has_bytes(
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

    fn feed_direction_bytes(
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

    fn send_policy_hook_deny(target: SocketAddr, flow: FlowContext) -> Result<(), Box<dyn Error>> {
        let response = send_policy_hook_deny_response(target, flow)?;
        assert!(response.contains(r#""outcome":"delegated""#), "{response}");
        Ok(())
    }

    fn send_policy_hook_deny_response(
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

    fn upstream_server(response: &'static [u8]) -> Result<SocketAddr, Box<dyn Error>> {
        delayed_upstream_server(response, Duration::ZERO)
    }

    fn tls_upstream_server(
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

    fn tls_upstream_keep_alive_server(
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

    fn delayed_upstream_server(
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
}
