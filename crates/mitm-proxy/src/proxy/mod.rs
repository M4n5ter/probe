mod downstream;
#[cfg(test)]
mod fixtures;
mod listener;
mod policy_hook;
mod route;
mod tunnel;
mod upstream;

use std::{
    fs::OpenOptions,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
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
use probe_core::{Direction, socket_addr_points_to_listener};
use socket2::Socket;

use crate::{
    MitmProxyError,
    authority::ObservedAuthority,
    error::io_error,
    feed::{CaptureEventFeedWriter, FlowOffsets},
    flow::{FlowFactory, FlowRegistry, PendingActionKey, ProxyAction},
    http::{
        HttpMessage, HttpResponseRelay, empty_response_bytes, read_http_message,
        relay_http_response, simple_response_bytes,
    },
    tls::{TlsTerminationConfig, UpstreamTlsConfig},
};

use self::downstream::{DownstreamAcceptor, DownstreamStream};
use self::listener::ProxyListeners;
use self::policy_hook::spawn_policy_hook_listener;
use self::tunnel::relay_upgraded_tunnel;
use self::upstream::UpstreamConnector;

const ACCEPT_IDLE_SLEEP: Duration = Duration::from_millis(20);

#[derive(Clone, Debug)]
pub struct MitmProxyConfig {
    pub listen: SocketAddr,
    pub transparent_listen: bool,
    pub feed_path: PathBuf,
    pub pid_file: Option<PathBuf>,
    pub upstream: Option<SocketAddr>,
    pub upstream_routes: UpstreamTargetRoutes,
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

pub use self::route::{UpstreamTargetRoute, UpstreamTargetRoutes};

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
        let request_direction = config.request_direction;
        let state = Arc::new(ProxyState {
            config: Arc::new(config),
            downstream,
            upstream,
            feed,
            registry: Arc::new(FlowRegistry::default()),
            flow_factory: Arc::new(FlowFactory::new(request_direction)),
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DownstreamDisposition {
    Continue,
    Close,
}

struct SequencedHttpRequest {
    message: HttpMessage,
    sequence: u64,
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
    for (host, target) in config.upstream_routes.iter() {
        if socket_addr_points_to_listener(target, config.listen) {
            return Err(MitmProxyError::InvalidConfig(format!(
                "upstream route {host} target must not point back to the MITM proxy listener"
            )));
        }
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
    let downstream = state.downstream.accept(downstream)?;
    let downstream_tls_server_name = downstream.tls_server_name().map(str::to_string);
    handle_http_connection(
        downstream,
        peer,
        target,
        downstream_tls_server_name.as_deref(),
        state,
    )
}

fn handle_http_connection(
    mut downstream: DownstreamStream,
    peer: SocketAddr,
    target: SocketAddr,
    downstream_tls_server_name: Option<&str>,
    state: Arc<ProxyState>,
) -> Result<(), MitmProxyError> {
    let Some(first_request) = read_http_message(&mut downstream, state.config.max_request_bytes)?
    else {
        return Ok(());
    };
    let flow = state.flow_factory.flow(peer, target);
    let mut offsets = FlowOffsets::default();
    state.feed.connection_opened(&flow)?;

    let mut request_sequence = 0_u64;
    let mut next_request = Some(first_request);
    let result = loop {
        let request = match next_request.take() {
            Some(request) => request,
            None => match read_http_message(&mut downstream, state.config.max_request_bytes) {
                Ok(Some(request)) => request,
                Ok(None) => break Ok(()),
                Err(error) => break Err(error),
            },
        };
        request_sequence = request_sequence.saturating_add(1);
        let disposition = match handle_http_request(
            &mut downstream,
            target,
            downstream_tls_server_name,
            SequencedHttpRequest {
                message: request,
                sequence: request_sequence,
            },
            &state,
            &flow,
            &mut offsets,
        ) {
            Ok(disposition) => disposition,
            Err(error) => break Err(error),
        };
        if disposition == DownstreamDisposition::Close {
            break Ok(());
        }
    };

    let finish_result = downstream.finish();
    let close_result = state.feed.connection_closed(flow);
    result.and(finish_result).and(close_result)
}

fn handle_http_request(
    downstream: &mut DownstreamStream,
    target: SocketAddr,
    downstream_tls_server_name: Option<&str>,
    request: SequencedHttpRequest,
    state: &ProxyState,
    flow: &probe_core::FlowContext,
    offsets: &mut FlowOffsets,
) -> Result<DownstreamDisposition, MitmProxyError> {
    let registration = state.config.policy_hook_listen.map(|_| {
        state.registry.register(PendingActionKey::request(
            flow.id.clone(),
            state.config.request_direction,
            request.sequence,
        ))
    });
    let request_offset = offsets.record(state.config.request_direction, request.message.raw.len());
    state.feed.bytes(
        flow,
        state.config.request_direction,
        request_offset,
        &request.message.raw,
    )?;

    let action = match registration {
        Some(registration) => registration.recv_timeout(state.config.action_timeout),
        None => None,
    };
    match action {
        Some(ProxyAction::Deny { reason }) => {
            write_deny_response(downstream, state, flow, offsets, reason)?;
            Ok(DownstreamDisposition::Close)
        }
        None => forward_or_gateway_response(
            downstream,
            target,
            downstream_tls_server_name,
            request.message,
            state,
            flow,
            offsets,
        ),
    }
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
    let response = simple_response_bytes(403, body.as_bytes(), "text/plain");
    write_generated_response(downstream, state, flow, offsets, &response)
}

fn write_generated_empty_response(
    downstream: &mut impl Write,
    state: &ProxyState,
    flow: &probe_core::FlowContext,
    offsets: &mut FlowOffsets,
    status: u16,
) -> Result<(), MitmProxyError> {
    let response = empty_response_bytes(status);
    write_generated_response(downstream, state, flow, offsets, &response)
}

fn write_generated_response(
    downstream: &mut impl Write,
    state: &ProxyState,
    flow: &probe_core::FlowContext,
    offsets: &mut FlowOffsets,
    response: &[u8],
) -> Result<(), MitmProxyError> {
    let direction = response_direction(state.config.request_direction);
    let mut emitter =
        DownstreamResponseEmitter::new(downstream, &state.feed, flow, offsets, direction);
    emitter.emit(response)?;
    emitter.flush("flush MITM proxy generated response")
}

fn forward_or_gateway_response(
    downstream: &mut DownstreamStream,
    target: SocketAddr,
    downstream_tls_server_name: Option<&str>,
    request: HttpMessage,
    state: &ProxyState,
    flow: &probe_core::FlowContext,
    offsets: &mut FlowOffsets,
) -> Result<DownstreamDisposition, MitmProxyError> {
    let config = &state.config;
    let request_keep_alive = request.explicit_keep_alive();
    let has_prefetched_tunnel_bytes = !request.prefetched_tunnel_bytes.is_empty();
    let authority = match observed_authority_for_request(
        config,
        &state.upstream,
        downstream_tls_server_name,
        &request,
    ) {
        Ok(authority) => authority,
        Err(_) => {
            return write_generated_empty_response(downstream, state, flow, offsets, 502)
                .map(|()| DownstreamDisposition::Close);
        }
    };
    let target = match upstream_target_for_request(config, target, authority) {
        Ok(target) => target,
        Err(_) => {
            return write_generated_empty_response(downstream, state, flow, offsets, 502)
                .map(|()| DownstreamDisposition::Close);
        }
    };
    if socket_addr_points_to_listener(target, config.listen) {
        return write_generated_empty_response(downstream, state, flow, offsets, 200)
            .map(|()| DownstreamDisposition::Close);
    }
    match state.upstream.connect(target, authority, config.io_timeout) {
        Ok(mut upstream) => {
            upstream
                .write_all(&request.raw)
                .map_err(io_error("write MITM proxy upstream request"))?;
            upstream
                .flush()
                .map_err(io_error("flush MITM proxy upstream request"))?;
            if !request.requests_protocol_upgrade() {
                upstream.finish_request()?;
            }
            let relay = relay_response(
                &mut upstream,
                &request,
                downstream,
                &state.feed,
                flow,
                offsets,
                response_direction(config.request_direction),
            )?;
            downstream
                .flush()
                .map_err(io_error("flush MITM proxy downstream response"))?;
            match relay {
                HttpResponseRelay::UpgradeTunnel => {
                    relay_upgraded_tunnel(
                        downstream,
                        &mut upstream,
                        &state.feed,
                        flow,
                        offsets,
                        config.request_direction,
                        &request.prefetched_tunnel_bytes,
                    )?;
                    Ok(DownstreamDisposition::Close)
                }
                HttpResponseRelay::Http { close_downstream } => Ok(
                    if request_keep_alive && !close_downstream && !has_prefetched_tunnel_bytes {
                        DownstreamDisposition::Continue
                    } else {
                        DownstreamDisposition::Close
                    },
                ),
            }
        }
        Err(_) => write_generated_empty_response(downstream, state, flow, offsets, 502)
            .map(|()| DownstreamDisposition::Close),
    }
}

fn upstream_target_for_request(
    config: &MitmProxyConfig,
    recovered_target: SocketAddr,
    authority: ObservedAuthority<'_>,
) -> Result<SocketAddr, MitmProxyError> {
    if config.upstream_routes.is_empty() {
        return Ok(recovered_target);
    }
    Ok(config
        .upstream_routes
        .target_for_observed_authority(authority)?
        .unwrap_or(recovered_target))
}

fn observed_authority_for_request<'a>(
    config: &MitmProxyConfig,
    upstream: &UpstreamConnector,
    downstream_tls_server_name: Option<&'a str>,
    request: &'a HttpMessage,
) -> Result<ObservedAuthority<'a>, MitmProxyError> {
    ObservedAuthority::from_request(
        downstream_tls_server_name,
        request,
        !config.upstream_routes.is_empty() || upstream.uses_tls(),
    )
}

fn relay_response(
    upstream: &mut impl Read,
    request: &HttpMessage,
    downstream: &mut impl Write,
    feed: &CaptureEventFeedWriter,
    flow: &probe_core::FlowContext,
    offsets: &mut FlowOffsets,
    direction: Direction,
) -> Result<HttpResponseRelay, MitmProxyError> {
    let mut emitter = DownstreamResponseEmitter::new(downstream, feed, flow, offsets, direction);
    relay_http_response(upstream, request, |bytes| emitter.emit(bytes))
}

struct DownstreamResponseEmitter<'a, W: Write + ?Sized> {
    downstream: &'a mut W,
    feed: &'a CaptureEventFeedWriter,
    flow: &'a probe_core::FlowContext,
    offsets: &'a mut FlowOffsets,
    direction: Direction,
}

impl<'a, W: Write + ?Sized> DownstreamResponseEmitter<'a, W> {
    fn new(
        downstream: &'a mut W,
        feed: &'a CaptureEventFeedWriter,
        flow: &'a probe_core::FlowContext,
        offsets: &'a mut FlowOffsets,
        direction: Direction,
    ) -> Self {
        Self {
            downstream,
            feed,
            flow,
            offsets,
            direction,
        }
    }

    fn emit(&mut self, bytes: &[u8]) -> Result<(), MitmProxyError> {
        let offset = self.offsets.record(self.direction, bytes.len());
        self.feed.bytes(self.flow, self.direction, offset, bytes)?;
        self.downstream
            .write_all(bytes)
            .map_err(io_error("write MITM proxy downstream response"))
    }

    fn flush(&mut self, context: &'static str) -> Result<(), MitmProxyError> {
        self.downstream.flush().map_err(io_error(context))
    }
}

fn response_direction(request_direction: Direction) -> Direction {
    match request_direction {
        Direction::Inbound => Direction::Outbound,
        Direction::Outbound => Direction::Inbound,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        error::Error,
        fs,
        io::{Read, Write},
        net::{Shutdown, SocketAddr, TcpListener, TcpStream},
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
        assert_eq!(
            feed_direction_bytes(&feed_path, Direction::Inbound)?,
            response
        );
        Ok(())
    }

    #[test]
    fn policy_hook_accepts_chunked_json_deny_request() -> Result<(), Box<dyn Error>> {
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
        let hook_response = send_chunked_policy_hook_deny_response(policy_hook_listen, flow)?;

        let response = client
            .join()
            .map_err(|_| "client thread panicked")?
            .map_err(std::io::Error::other)?;
        guard.stop()?;

        assert!(hook_response.contains(r#""outcome":"delegated""#));
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 403 Forbidden"));
        assert_eq!(
            feed_direction_bytes(&feed_path, Direction::Inbound)?,
            response
        );
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
    fn upstream_connect_failure_response_is_written_to_feed() -> Result<(), Box<dyn Error>> {
        let root = tempdir()?;
        let feed_path = root.path().join("mitm-feed.jsonl");
        let data_listener = bound_loopback_listener()?;
        let listen = data_listener.local_addr()?;
        let upstream = "127.0.0.1:0".parse()?;
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
        stream.write_all(b"GET /gateway HTTP/1.1\r\nHost: example.test\r\n\r\n")?;
        stream.shutdown(Shutdown::Write)?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        guard.stop()?;

        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 502 Bad Gateway"));
        assert_eq!(
            feed_direction_bytes(&feed_path, Direction::Inbound)?,
            response
        );
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
    fn chunked_http_request_is_forwarded_to_upstream() -> Result<(), Box<dyn Error>> {
        let root = tempdir()?;
        let feed_path = root.path().join("mitm-feed.jsonl");
        let upstream = upstream_server(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nchunked")?;
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

        let request = b"POST /chunked HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let mut stream = TcpStream::connect(listen)?;
        stream.write_all(request)?;
        stream.shutdown(Shutdown::Write)?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        guard.stop()?;

        assert_eq!(
            String::from_utf8_lossy(&response),
            "HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nchunked"
        );
        assert!(feed_has_bytes(&feed_path, Direction::Outbound, request)?);
        Ok(())
    }

    #[test]
    fn websocket_upgrade_tunnels_server_frame_and_feeds_plaintext() -> Result<(), Box<dyn Error>> {
        let root = tempdir()?;
        let feed_path = root.path().join("mitm-feed.jsonl");
        let upstream = websocket_upstream_server(b"\x81\x02hi")?;
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

        let request = b"GET /chat HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
        let expected_response = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n\x81\x02hi";
        let mut stream = TcpStream::connect(listen)?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.write_all(request)?;
        stream.flush()?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        guard.stop()?;

        assert_eq!(response, expected_response);
        assert!(feed_has_bytes(&feed_path, Direction::Outbound, request)?);
        assert_eq!(
            feed_direction_bytes(&feed_path, Direction::Inbound)?,
            expected_response
        );
        Ok(())
    }

    #[test]
    fn websocket_upgrade_forwards_prefetched_client_frame() -> Result<(), Box<dyn Error>> {
        let root = tempdir()?;
        let feed_path = root.path().join("mitm-feed.jsonl");
        let client_frame = b"\x81\x82\x01\x02\x03\x04ik";
        let (upstream, received_client_frame) =
            websocket_upstream_server_with_client_frame(b"\x81\x02ok", client_frame.len())?;
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

        let request =
            b"GET /chat HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
        let mut stream = TcpStream::connect(listen)?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.write_all(request)?;
        stream.write_all(client_frame)?;
        stream.flush()?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        guard.stop()?;

        assert_eq!(
            received_client_frame.recv_timeout(Duration::from_secs(2))?,
            client_frame
        );
        assert!(feed_has_bytes(&feed_path, Direction::Outbound, request)?);
        assert!(feed_has_bytes(
            &feed_path,
            Direction::Outbound,
            client_frame
        )?);
        assert_eq!(
            response,
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n\x81\x02ok"
        );
        Ok(())
    }

    #[test]
    fn websocket_upgrade_relay_survives_client_write_half_close() -> Result<(), Box<dyn Error>> {
        let root = tempdir()?;
        let feed_path = root.path().join("mitm-feed.jsonl");
        let client_frame = b"\x81\x82\x01\x02\x03\x04ik";
        let server_frame = b"\x81\x02ok";
        let (upstream, received_client_frame) =
            websocket_upstream_server_after_client_half_close(server_frame, client_frame.len())?;
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

        let request =
            b"GET /chat HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
        let mut stream = TcpStream::connect(listen)?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.write_all(request)?;
        stream.write_all(client_frame)?;
        stream.shutdown(Shutdown::Write)?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        guard.stop()?;

        assert_eq!(
            received_client_frame.recv_timeout(Duration::from_secs(2))?,
            client_frame
        );
        assert_eq!(
            response,
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n\x81\x02ok"
        );
        assert!(feed_has_bytes(&feed_path, Direction::Outbound, request)?);
        assert!(feed_has_bytes(
            &feed_path,
            Direction::Outbound,
            client_frame
        )?);
        assert_eq!(
            feed_direction_bytes(&feed_path, Direction::Inbound)?,
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n\x81\x02ok"
        );
        Ok(())
    }

    #[test]
    fn websocket_prefetched_client_frame_is_withheld_without_101() -> Result<(), Box<dyn Error>> {
        let root = tempdir()?;
        let feed_path = root.path().join("mitm-feed.jsonl");
        let client_frame = b"\x81\x82\x01\x02\x03\x04ik";
        let (upstream, observed_extra_bytes) = upgrade_observer_upstream_server(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok",
            client_frame.len(),
        )?;
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

        let request =
            b"GET /chat HTTP/1.1\r\nHost: example.test\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\n";
        let expected_response =
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok";
        let mut stream = TcpStream::connect(listen)?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.write_all(request)?;
        stream.write_all(client_frame)?;
        stream.flush()?;
        let mut response = vec![0_u8; expected_response.len()];
        stream.read_exact(&mut response)?;
        let mut remaining = Vec::new();
        let close_result = stream.read_to_end(&mut remaining);
        guard.stop()?;

        close_result?;
        assert_eq!(response, expected_response);
        assert!(remaining.is_empty());
        assert_eq!(
            observed_extra_bytes.recv_timeout(Duration::from_secs(2))?,
            Vec::<u8>::new()
        );
        assert!(feed_has_bytes(&feed_path, Direction::Outbound, request)?);
        assert!(!feed_has_bytes(
            &feed_path,
            Direction::Outbound,
            client_frame
        )?);
        Ok(())
    }

    #[test]
    fn explicit_keep_alive_allows_sequential_requests_on_one_downstream_connection()
    -> Result<(), Box<dyn Error>> {
        let root = tempdir()?;
        let feed_path = root.path().join("mitm-feed.jsonl");
        let upstream = sequential_upstream_server([
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ntwo".as_slice(),
        ])?;
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

        let first_request =
            b"GET /one HTTP/1.1\r\nHost: example.test\r\nConnection: keep-alive\r\n\r\n";
        let first_response = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none";
        let second_request = b"GET /two HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let second_response = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ntwo";
        let mut stream = TcpStream::connect(listen)?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.write_all(first_request)?;
        stream.flush()?;
        let mut response = vec![0_u8; first_response.len()];
        stream.read_exact(&mut response)?;
        assert_eq!(response, first_response);

        stream.write_all(second_request)?;
        stream.flush()?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        guard.stop()?;

        assert_eq!(response, second_response);
        assert!(feed_has_bytes(
            &feed_path,
            Direction::Outbound,
            first_request
        )?);
        assert!(feed_has_bytes(
            &feed_path,
            Direction::Outbound,
            second_request
        )?);
        let response_bytes = feed_direction_bytes(&feed_path, Direction::Inbound)?;
        assert!(
            response_bytes
                .windows(first_response.len())
                .any(|window| window == first_response)
        );
        assert!(
            response_bytes
                .windows(second_response.len())
                .any(|window| window == second_response)
        );
        Ok(())
    }

    #[test]
    fn idle_keep_alive_connection_closes_with_lifecycle_event() -> Result<(), Box<dyn Error>> {
        let root = tempdir()?;
        let feed_path = root.path().join("mitm-feed.jsonl");
        let upstream = upstream_server(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none")?;
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
        config.io_timeout = Duration::from_millis(150);
        let guard = start_test_proxy(config, data_listener, None)?;

        let request = b"GET /one HTTP/1.1\r\nHost: example.test\r\nConnection: keep-alive\r\n\r\n";
        let expected_response = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none";
        let mut stream = TcpStream::connect(listen)?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.write_all(request)?;
        stream.flush()?;
        let flow = wait_for_flow(&feed_path)?;
        let mut response = vec![0_u8; expected_response.len()];
        stream.read_exact(&mut response)?;
        assert_eq!(response, expected_response);

        let mut remaining = Vec::new();
        stream.read_to_end(&mut remaining)?;
        guard.stop()?;

        assert!(remaining.is_empty());
        assert!(feed_has_connection_closed(&feed_path, flow.id.0.as_str())?);
        Ok(())
    }

    #[test]
    fn upstream_connection_close_response_closes_downstream() -> Result<(), Box<dyn Error>> {
        let root = tempdir()?;
        let feed_path = root.path().join("mitm-feed.jsonl");
        let upstream = sequential_upstream_server([
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\none".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ntwo".as_slice(),
        ])?;
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

        let first_request =
            b"GET /one HTTP/1.1\r\nHost: example.test\r\nConnection: keep-alive\r\n\r\n";
        let first_response =
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\none";
        let second_request = b"GET /two HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let mut stream = TcpStream::connect(listen)?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.write_all(first_request)?;
        stream.flush()?;
        let mut response = vec![0_u8; first_response.len()];
        stream.read_exact(&mut response)?;
        assert_eq!(response, first_response);

        let _ = stream.write_all(second_request);
        let _ = stream.flush();
        let response = read_to_end_or_connection_reset(&mut stream)?;
        guard.stop()?;

        assert!(response.is_empty());
        assert!(!feed_has_bytes(
            &feed_path,
            Direction::Outbound,
            second_request
        )?);
        Ok(())
    }

    #[test]
    fn http10_response_without_keep_alive_closes_downstream() -> Result<(), Box<dyn Error>> {
        let root = tempdir()?;
        let feed_path = root.path().join("mitm-feed.jsonl");
        let upstream = sequential_upstream_server([
            b"HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\none".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ntwo".as_slice(),
        ])?;
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

        let first_request =
            b"GET /one HTTP/1.1\r\nHost: example.test\r\nConnection: keep-alive\r\n\r\n";
        let first_response = b"HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\none";
        let second_request = b"GET /two HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let mut stream = TcpStream::connect(listen)?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.write_all(first_request)?;
        stream.flush()?;
        let mut response = vec![0_u8; first_response.len()];
        stream.read_exact(&mut response)?;
        assert_eq!(response, first_response);

        let _ = stream.write_all(second_request);
        let _ = stream.flush();
        let response = read_to_end_or_connection_reset(&mut stream)?;
        guard.stop()?;

        assert!(response.is_empty());
        assert!(!feed_has_bytes(
            &feed_path,
            Direction::Outbound,
            second_request
        )?);
        Ok(())
    }

    #[test]
    fn late_policy_hook_deny_does_not_apply_to_later_keep_alive_request()
    -> Result<(), Box<dyn Error>> {
        let root = tempdir()?;
        let feed_path = root.path().join("mitm-feed.jsonl");
        let upstream = sequential_upstream_server([
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ntwo".as_slice(),
        ])?;
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
                Duration::from_secs(1),
            ),
            data_listener,
            Some(policy_hook_listener),
        )?;

        let first_request =
            b"GET /one HTTP/1.1\r\nHost: example.test\r\nConnection: keep-alive\r\n\r\n";
        let first_response = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\none";
        let second_request = b"GET /two HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let second_response = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ntwo";
        let mut stream = TcpStream::connect(listen)?;
        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
        stream.write_all(first_request)?;
        stream.flush()?;
        let flow = wait_for_flow(&feed_path)?;
        let mut response = vec![0_u8; first_response.len()];
        stream.read_exact(&mut response)?;
        assert_eq!(response, first_response);

        stream.write_all(second_request)?;
        stream.flush()?;
        wait_for_bytes(&feed_path, Direction::Outbound, second_request)?;
        let hook_response =
            send_policy_hook_deny_response_for_sequence(policy_hook_listen, flow, 1)?;
        assert!(
            hook_response.contains(r#""outcome":"unsupported""#)
                && hook_response.contains("is not pending in MITM proxy"),
            "{hook_response}"
        );
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        guard.stop()?;

        assert_eq!(response, second_response);
        Ok(())
    }

    #[test]
    fn upstream_route_uses_http_host_to_select_target() -> Result<(), Box<dyn Error>> {
        let root = tempdir()?;
        let feed_path = root.path().join("mitm-feed.jsonl");
        let route_target = upstream_server(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nrouted")?;
        let data_listener = bound_loopback_listener()?;
        let listen = data_listener.local_addr()?;
        let mut config = test_config(listen, &feed_path, None, None, None, Duration::from_secs(2));
        config.upstream_routes = UpstreamTargetRoutes::from_routes([UpstreamTargetRoute::new(
            "Route.Example",
            route_target,
        )?])?;
        let guard = start_test_proxy(config, data_listener, None)?;

        let mut stream = TcpStream::connect(listen)?;
        stream.write_all(b"GET /route HTTP/1.1\r\nHost: route.example\r\n\r\n")?;
        stream.shutdown(Shutdown::Write)?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        guard.stop()?;

        assert_eq!(
            String::from_utf8_lossy(&response),
            "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nrouted"
        );
        assert!(feed_has_bytes(
            &feed_path,
            Direction::Outbound,
            b"GET /route HTTP/1.1\r\nHost: route.example\r\n\r\n"
        )?);
        Ok(())
    }

    #[test]
    fn wildcard_upstream_route_uses_http_host_to_select_target() -> Result<(), Box<dyn Error>> {
        let root = tempdir()?;
        let feed_path = root.path().join("mitm-feed.jsonl");
        let route_target =
            upstream_server(b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\nwildcard-routed")?;
        let data_listener = bound_loopback_listener()?;
        let listen = data_listener.local_addr()?;
        let mut config = test_config(listen, &feed_path, None, None, None, Duration::from_secs(2));
        config.upstream_routes = UpstreamTargetRoutes::from_routes([UpstreamTargetRoute::new(
            "*.Route.Example",
            route_target,
        )?])?;
        let guard = start_test_proxy(config, data_listener, None)?;

        let mut stream = TcpStream::connect(listen)?;
        stream.write_all(b"GET /route HTTP/1.1\r\nHost: api.route.example\r\n\r\n")?;
        stream.shutdown(Shutdown::Write)?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        guard.stop()?;

        assert_eq!(
            String::from_utf8_lossy(&response),
            "HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\nwildcard-routed"
        );
        assert!(feed_has_bytes(
            &feed_path,
            Direction::Outbound,
            b"GET /route HTTP/1.1\r\nHost: api.route.example\r\n\r\n"
        )?);
        Ok(())
    }

    #[test]
    fn upstream_route_miss_falls_back_for_unsupported_http_authority() -> Result<(), Box<dyn Error>>
    {
        let root = tempdir()?;
        let feed_path = root.path().join("mitm-feed.jsonl");
        let fallback_target =
            upstream_server(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nfallback")?;
        let data_listener = bound_loopback_listener()?;
        let listen = data_listener.local_addr()?;
        let mut config = test_config(
            listen,
            &feed_path,
            Some(fallback_target),
            None,
            None,
            Duration::from_secs(2),
        );
        config.upstream_routes = UpstreamTargetRoutes::from_routes([UpstreamTargetRoute::new(
            "Route.Example",
            "127.0.0.1:8443".parse()?,
        )?])?;
        let guard = start_test_proxy(config, data_listener, None)?;

        let mut stream = TcpStream::connect(listen)?;
        stream.write_all(b"GET /fallback HTTP/1.1\r\nHost: [::1]:8443\r\n\r\n")?;
        stream.shutdown(Shutdown::Write)?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        guard.stop()?;

        assert_eq!(
            String::from_utf8_lossy(&response),
            "HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nfallback"
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
    fn tls_listener_negotiates_http1_alpn() -> Result<(), Box<dyn Error>> {
        let root = tempdir()?;
        let feed_path = root.path().join("mitm-feed.jsonl");
        let (certificate_chain, private_key, trusted_certificate) =
            write_test_certificate(root.path())?;
        let upstream = upstream_server(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nwith-alpn")?;
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

        let mut stream =
            tls_client_stream_with_alpn(listen, trusted_certificate, vec![b"http/1.1".to_vec()])?;
        let request = b"GET /alpn HTTP/1.1\r\nHost: localhost\r\n\r\n";
        stream.write_all(request)?;
        stream.flush()?;
        assert_eq!(stream.conn.alpn_protocol(), Some(b"http/1.1".as_slice()));
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        guard.stop()?;

        assert_eq!(
            String::from_utf8_lossy(&response),
            "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nwith-alpn"
        );
        Ok(())
    }

    #[test]
    fn tls_listener_rejects_h2_only_clients() -> Result<(), Box<dyn Error>> {
        let root = tempdir()?;
        let feed_path = root.path().join("mitm-feed.jsonl");
        let (certificate_chain, private_key, trusted_certificate) =
            write_test_certificate(root.path())?;
        let upstream = upstream_server(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")?;
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

        let mut stream =
            tls_client_stream_with_alpn(listen, trusted_certificate, vec![b"h2".to_vec()])?;
        let result = stream
            .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            .and_then(|_| stream.flush());
        guard.stop()?;

        assert!(result.is_err(), "h2-only client must fail closed");
        assert!(!feed_path.exists() || fs::read_to_string(&feed_path)?.is_empty());
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
        let (upstream, observed_upstream_handshake) = tls_upstream_server_record_handshake(
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
            observed_upstream_handshake
                .recv_timeout(Duration::from_secs(2))?
                .server_name,
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
    fn tls_listener_negotiates_http1_alpn_with_tls_upstream() -> Result<(), Box<dyn Error>> {
        let root = tempdir()?;
        let feed_path = root.path().join("mitm-feed.jsonl");
        let (certificate_chain, private_key, trusted_certificate) =
            write_test_certificate(root.path())?;
        let (upstream, observed_upstream_handshake) = tls_upstream_server_record_handshake(
            b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nupstream-alpn",
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
            "GET /tls-upstream-alpn HTTP/1.1\r\nHost: localhost:{}\r\n\r\n",
            upstream.port()
        );
        stream.write_all(request.as_bytes())?;
        stream.flush()?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response)?;
        guard.stop()?;

        assert_eq!(
            String::from_utf8_lossy(&response),
            "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nupstream-alpn"
        );
        assert_eq!(
            observed_upstream_handshake
                .recv_timeout(Duration::from_secs(2))?
                .alpn_protocol,
            Some(b"http/1.1".to_vec())
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
        let (upstream, observed_upstream_handshake) = tls_upstream_server_record_handshake(
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
            observed_upstream_handshake
                .recv_timeout(Duration::from_secs(2))?
                .server_name,
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

    fn sequential_upstream_server<const N: usize>(
        responses: [&'static [u8]; N],
    ) -> Result<SocketAddr, Box<dyn Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let target = listener.local_addr()?;
        thread::spawn(move || {
            for response in responses {
                let Ok((mut stream, _peer)) = listener.accept() else {
                    return;
                };
                if read_http_message(&mut stream, 65_536)
                    .ok()
                    .flatten()
                    .is_some()
                {
                    let _ = stream.write_all(response);
                    let _ = stream.flush();
                }
            }
        });
        Ok(target)
    }

    fn read_to_end_or_connection_reset(stream: &mut TcpStream) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut response = Vec::new();
        match stream.read_to_end(&mut response) {
            Ok(_) => Ok(response),
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => Ok(response),
            Err(error) => Err(error.into()),
        }
    }
}
