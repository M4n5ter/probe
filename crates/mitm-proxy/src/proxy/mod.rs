mod downstream;
#[cfg(test)]
mod fixtures;
mod listener;
mod policy_hook;
mod upstream;

use std::{
    fs::OpenOptions,
    io::{Read, Write},
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
use self::listener::ProxyListeners;
use self::policy_hook::spawn_policy_hook_listener;
use self::upstream::UpstreamConnector;

const ACCEPT_IDLE_SLEEP: Duration = Duration::from_millis(20);

#[derive(Clone, Debug)]
pub struct MitmProxyConfig {
    pub listen: SocketAddr,
    pub transparent_listen: bool,
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
    let downstream_tls_server_name = downstream.tls_server_name().map(str::to_string);
    handle_http_connection(
        &mut downstream,
        peer,
        target,
        downstream_tls_server_name.as_deref(),
        state,
    )
}

fn handle_http_connection(
    mut downstream: &mut impl DownstreamIo,
    peer: SocketAddr,
    target: SocketAddr,
    downstream_tls_server_name: Option<&str>,
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
            downstream_tls_server_name,
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
    downstream_tls_server_name: Option<&str>,
    request: HttpMessage,
    state: &ProxyState,
    flow: &probe_core::FlowContext,
    offsets: &mut FlowOffsets,
) -> Result<(), MitmProxyError> {
    let config = &state.config;
    if is_self_target(target, config.listen) {
        return write_empty_response(downstream, 200);
    }
    match state.upstream.connect(
        target,
        &request,
        downstream_tls_server_name,
        config.io_timeout,
    ) {
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
        net::{Shutdown, TcpStream},
        thread,
        time::Duration,
    };

    use probe_core::Direction;
    use tempfile::tempdir;

    use super::fixtures::*;
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
    fn plaintext_listener_uses_http_host_for_upstream_tls_without_downstream_sni()
    -> Result<(), Box<dyn Error>> {
        let root = tempdir()?;
        let feed_path = root.path().join("mitm-feed.jsonl");
        let (upstream_certificate_chain, upstream_private_key, _trusted_upstream_certificate) =
            write_test_certificate_for_name(root.path(), "upstream", "host-upstream.example")?;
        let (upstream, observed_upstream_sni) = tls_upstream_server_record_sni(
            b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nhost-upstream",
            upstream_certificate_chain.clone(),
            upstream_private_key,
        )?;
        let data_listener = bound_loopback_listener()?;
        let listen = data_listener.local_addr()?;
        let mut config = test_config(
            listen,
            &feed_path,
            Some(upstream),
            None,
            None,
            Duration::from_secs(2),
        );
        config.upstream_tls = Some(UpstreamTlsConfig::new(
            vec![upstream_certificate_chain],
            None,
        ));
        let guard = start_test_proxy(config, data_listener, None)?;

        let mut stream = TcpStream::connect(listen)?;
        let request = format!(
            "GET /host-upstream HTTP/1.1\r\nHost: host-upstream.example:{}\r\n\r\n",
            upstream.port()
        );
        stream.write_all(request.as_bytes())?;
        stream.shutdown(Shutdown::Write)?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        guard.stop()?;

        assert_eq!(
            String::from_utf8_lossy(&response),
            "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nhost-upstream"
        );
        assert_eq!(
            observed_upstream_sni.recv_timeout(Duration::from_secs(2))?,
            Some("host-upstream.example".to_string())
        );
        assert!(feed_has_bytes(
            &feed_path,
            Direction::Outbound,
            request.as_bytes()
        )?);
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
    fn dynamic_ca_tls_listener_uses_downstream_sni_for_upstream_tls_without_http_host()
    -> Result<(), Box<dyn Error>> {
        let root = tempdir()?;
        let feed_path = root.path().join("mitm-feed.jsonl");
        let (ca_certificate_chain, ca_private_key, trusted_ca_certificate) =
            write_test_ca(root.path())?;
        let (upstream_certificate_chain, upstream_private_key, _trusted_upstream_certificate) =
            write_test_certificate_for_name(root.path(), "upstream", "sni-upstream.example")?;
        let (upstream, observed_upstream_sni) = tls_upstream_server_record_sni(
            b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nsni-upstream",
            upstream_certificate_chain.clone(),
            upstream_private_key,
        )?;
        let data_listener = bound_loopback_listener()?;
        let listen = data_listener.local_addr()?;
        let mut config = test_config(
            listen,
            &feed_path,
            Some(upstream),
            Some(TlsTerminationConfig::from_ca(
                ca_certificate_chain,
                ca_private_key,
            )),
            None,
            Duration::from_secs(2),
        );
        config.upstream_tls = Some(UpstreamTlsConfig::new(
            vec![upstream_certificate_chain],
            None,
        ));
        let guard = start_test_proxy(config, data_listener, None)?;

        let mut stream =
            tls_client_stream_with_name(listen, trusted_ca_certificate, "sni-upstream.example")?;
        let request = b"GET /sni-upstream HTTP/1.0\r\n\r\n";
        stream.write_all(request)?;
        stream.flush()?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        guard.stop()?;

        assert_eq!(
            String::from_utf8_lossy(&response),
            "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nsni-upstream"
        );
        assert_eq!(
            observed_upstream_sni.recv_timeout(Duration::from_secs(2))?,
            Some("sni-upstream.example".to_string())
        );
        assert!(feed_has_bytes(&feed_path, Direction::Outbound, request)?);
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
}
