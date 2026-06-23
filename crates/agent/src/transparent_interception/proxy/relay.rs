use std::{
    fmt, io,
    net::{Shutdown, SocketAddr, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use socket2::{SockAddr, Socket};

use super::{
    connect::tcp_connect_failure_reason,
    proxy_error, proxy_io_error,
    registry::{RelayRegistry, RelaySlot, shutdown_streams},
    state::TransparentProxyRuntime,
    target::TransparentProxyTargetRecovery,
};
use crate::transparent_interception::TransparentInterceptionError;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) fn spawn_relay(
    accepted: Socket,
    peer: SockAddr,
    context: TransparentProxyRelayContext,
    shutdown_requested: Arc<AtomicBool>,
    relays: RelayRegistry,
    slot: RelaySlot,
    runtime: TransparentProxyRuntime,
) -> JoinHandle<()> {
    thread::spawn(move || {
        if let Err(error) = relay_connection(
            accepted,
            peer,
            context,
            shutdown_requested,
            relays,
            slot,
            runtime.clone(),
        ) {
            if error.counts_as_relay_failure() {
                runtime.record_relay_failure();
                eprintln!("managed transparent proxy relay failed: {error}");
            } else {
                eprintln!("managed transparent proxy upstream connect failed: {error}");
            }
        }
    })
}

fn relay_connection(
    accepted: Socket,
    peer: SockAddr,
    context: TransparentProxyRelayContext,
    shutdown_requested: Arc<AtomicBool>,
    relays: RelayRegistry,
    _slot: RelaySlot,
    runtime: TransparentProxyRuntime,
) -> Result<(), RelayConnectionError> {
    let peer = peer
        .as_socket()
        .ok_or_else(|| proxy_error("transparent proxy accepted non-IP peer address"))
        .map_err(RelayConnectionError::relay)?;
    let target = context
        .target_recovery
        .recover(&accepted)
        .map_err(RelayConnectionError::relay)?;
    if context.self_relay_guard.is_self_relay(target) {
        return Err(RelayConnectionError::relay(proxy_error(format!(
            "refusing transparent proxy self-relay for peer {peer} target {target}"
        ))));
    }
    let downstream = TcpStream::from(accepted);
    downstream
        .set_nodelay(true)
        .map_err(proxy_io_error("set downstream TCP_NODELAY"))
        .map_err(RelayConnectionError::relay)?;
    let upstream = connect_upstream_for_relay(target, peer, &runtime)
        .map_err(RelayConnectionError::upstream_connect)?;
    upstream
        .set_nodelay(true)
        .map_err(proxy_io_error("set upstream TCP_NODELAY"))
        .map_err(RelayConnectionError::relay)?;
    let _registration = relays
        .register(&downstream, &upstream)
        .map_err(proxy_io_error("register active transparent relay"))
        .map_err(RelayConnectionError::relay)?;
    if shutdown_requested.load(Ordering::SeqCst) {
        shutdown_streams(&downstream, &upstream);
    }
    relay_bidirectional(downstream, upstream).map_err(RelayConnectionError::relay)
}

#[derive(Clone, Copy)]
pub(super) struct TransparentProxyRelayContext {
    target_recovery: TransparentProxyTargetRecovery,
    self_relay_guard: TransparentProxySelfRelayGuard,
}

impl TransparentProxyRelayContext {
    pub(super) fn inbound_tproxy(listen_port: u16) -> Self {
        Self {
            target_recovery: TransparentProxyTargetRecovery::TproxyLocalAddress,
            self_relay_guard: TransparentProxySelfRelayGuard::RejectSamePort { listen_port },
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum TransparentProxySelfRelayGuard {
    RejectSamePort { listen_port: u16 },
}

impl TransparentProxySelfRelayGuard {
    fn is_self_relay(self, target: SocketAddr) -> bool {
        match self {
            Self::RejectSamePort { listen_port } => target.port() == listen_port,
        }
    }
}

#[derive(Debug)]
enum RelayConnectionError {
    UpstreamConnect(TransparentInterceptionError),
    Relay(TransparentInterceptionError),
}

impl RelayConnectionError {
    fn upstream_connect(error: TransparentInterceptionError) -> Self {
        Self::UpstreamConnect(error)
    }

    fn relay(error: TransparentInterceptionError) -> Self {
        Self::Relay(error)
    }

    fn counts_as_relay_failure(&self) -> bool {
        match self {
            Self::UpstreamConnect(_) => false,
            Self::Relay(_) => true,
        }
    }
}

impl fmt::Display for RelayConnectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UpstreamConnect(error) | Self::Relay(error) => {
                fmt::Display::fmt(error, formatter)
            }
        }
    }
}

fn connect_upstream_for_relay(
    target: SocketAddr,
    peer: SocketAddr,
    runtime: &TransparentProxyRuntime,
) -> Result<TcpStream, TransparentInterceptionError> {
    match TcpStream::connect_timeout(&target, CONNECT_TIMEOUT) {
        Ok(upstream) => {
            runtime.record_upstream_connect_success();
            Ok(upstream)
        }
        Err(error) => {
            runtime.record_upstream_connect_failure(tcp_connect_failure_reason(&error));
            Err(proxy_io_error(format!(
                "connect transparent upstream target {target} for peer {peer}"
            ))(error))
        }
    }
}

fn relay_bidirectional(
    downstream: TcpStream,
    upstream: TcpStream,
) -> Result<(), TransparentInterceptionError> {
    let upload_source = downstream
        .try_clone()
        .map_err(proxy_io_error("clone downstream upload source"))?;
    let upload_destination = upstream
        .try_clone()
        .map_err(proxy_io_error("clone upstream upload destination"))?;
    let download_source = upstream
        .try_clone()
        .map_err(proxy_io_error("clone upstream download source"))?;
    let download_destination = downstream
        .try_clone()
        .map_err(proxy_io_error("clone downstream download destination"))?;

    let upload = thread::spawn(move || relay_direction(upload_source, upload_destination));
    let download = thread::spawn(move || relay_direction(download_source, download_destination));

    let upload = upload
        .join()
        .map_err(|_| proxy_error("transparent proxy upload relay panicked"))?;
    let download = download
        .join()
        .map_err(|_| proxy_error("transparent proxy download relay panicked"))?;
    shutdown_streams(&downstream, &upstream);

    ignore_expected_relay_close(upload).map_err(proxy_io_error("relay downstream to upstream"))?;
    ignore_expected_relay_close(download)
        .map_err(proxy_io_error("relay upstream to downstream"))?;
    Ok(())
}

fn relay_direction(mut source: TcpStream, mut destination: TcpStream) -> io::Result<u64> {
    let result = io::copy(&mut source, &mut destination);
    let _ = destination.shutdown(Shutdown::Write);
    result
}

fn ignore_expected_relay_close(result: io::Result<u64>) -> io::Result<()> {
    match result {
        Ok(_) => Ok(()),
        Err(error) if is_expected_relay_close(&error) => Ok(()),
        Err(error) => Err(error),
    }
}

fn is_expected_relay_close(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::NotConnected
    )
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::{Ipv4Addr, SocketAddr, TcpListener},
    };

    use probe_config::{
        EnforcementInterceptionConfig, TransparentInterceptionProxyConfig,
        TransparentInterceptionProxyModeConfig, TransparentInterceptionStrategyConfig,
    };

    use super::*;

    #[test]
    fn relay_propagates_downstream_half_close_to_upstream() -> Result<(), Box<dyn std::error::Error>>
    {
        let downstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let downstream_client = TcpStream::connect(downstream_listener.local_addr()?)?;
        let upstream = TcpStream::connect(upstream_listener.local_addr()?)?;
        let (downstream, _) = downstream_listener.accept()?;
        let (upstream_server, _) = upstream_listener.accept()?;
        downstream_client.set_read_timeout(Some(Duration::from_secs(2)))?;
        upstream_server.set_read_timeout(Some(Duration::from_secs(2)))?;

        let relay = thread::spawn(move || relay_bidirectional(downstream, upstream));
        let client = thread::spawn(move || -> io::Result<Vec<u8>> {
            let mut client = downstream_client;
            client.write_all(b"request")?;
            client.shutdown(Shutdown::Write)?;
            let mut response = Vec::new();
            client.read_to_end(&mut response)?;
            Ok(response)
        });
        let server = thread::spawn(move || -> io::Result<Vec<u8>> {
            let mut server = upstream_server;
            let mut request = Vec::new();
            server.read_to_end(&mut request)?;
            server.write_all(b"response")?;
            server.shutdown(Shutdown::Write)?;
            Ok(request)
        });

        let response = client.join().expect("client thread should not panic")?;
        let request = server.join().expect("server thread should not panic")?;
        relay
            .join()
            .expect("relay thread should not panic")
            .expect("relay should complete");

        assert_eq!(request, b"request");
        assert_eq!(response, b"response");
        Ok(())
    }

    #[test]
    fn relay_keeps_upload_open_after_upstream_half_close() -> Result<(), Box<dyn std::error::Error>>
    {
        let downstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let downstream_client = TcpStream::connect(downstream_listener.local_addr()?)?;
        let upstream = TcpStream::connect(upstream_listener.local_addr()?)?;
        let (downstream, _) = downstream_listener.accept()?;
        let (upstream_server, _) = upstream_listener.accept()?;
        downstream_client.set_read_timeout(Some(Duration::from_secs(2)))?;
        upstream_server.set_read_timeout(Some(Duration::from_secs(2)))?;

        let relay = thread::spawn(move || relay_bidirectional(downstream, upstream));
        let client = thread::spawn(move || -> io::Result<Vec<u8>> {
            let mut client = downstream_client;
            client.write_all(b"part-1")?;
            let mut response = Vec::new();
            client.read_to_end(&mut response)?;
            client.write_all(b"part-2")?;
            client.shutdown(Shutdown::Write)?;
            Ok(response)
        });
        let server = thread::spawn(move || -> io::Result<Vec<u8>> {
            let mut server = upstream_server;
            server.write_all(b"response")?;
            server.shutdown(Shutdown::Write)?;
            let mut request = Vec::new();
            server.read_to_end(&mut request)?;
            Ok(request)
        });

        let response = client.join().expect("client thread should not panic")?;
        let request = server.join().expect("server thread should not panic")?;
        relay
            .join()
            .expect("relay thread should not panic")
            .expect("relay should complete");

        assert_eq!(request, b"part-1part-2");
        assert_eq!(response, b"response");
        Ok(())
    }

    #[test]
    fn expected_peer_close_errors_are_not_relay_failures() {
        for kind in [
            io::ErrorKind::UnexpectedEof,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::NotConnected,
        ] {
            assert!(is_expected_relay_close(&io::Error::from(kind)));
        }
    }

    #[test]
    fn upstream_connect_success_records_connect_metrics() -> Result<(), Box<dyn std::error::Error>>
    {
        let runtime = TransparentProxyRuntime::for_test_config(&managed_interception_config());
        let handle = runtime.handle();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 42000));

        let upstream = connect_upstream_for_relay(listener.local_addr()?, peer, &runtime)?;
        let (_accepted, _) = listener.accept()?;
        drop(upstream);

        let snapshot = handle.snapshot();
        assert_eq!(snapshot.upstream_connects.connect_successes, 1);
        assert_eq!(snapshot.upstream_connects.connect_failures, 0);
        assert_eq!(snapshot.upstream_connects.last_failure_reason, None);
        Ok(())
    }

    #[test]
    fn upstream_connect_failure_records_connect_metrics() -> Result<(), Box<dyn std::error::Error>>
    {
        let runtime = TransparentProxyRuntime::for_test_config(&managed_interception_config());
        let handle = runtime.handle();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let target = listener.local_addr()?;
        drop(listener);
        let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 42000));

        let error = connect_upstream_for_relay(target, peer, &runtime)
            .expect_err("closed listener should refuse upstream connect");

        assert!(error.to_string().contains("connect transparent upstream"));
        let snapshot = handle.snapshot();
        assert_eq!(snapshot.upstream_connects.connect_successes, 0);
        assert_eq!(snapshot.upstream_connects.connect_failures, 1);
        assert_eq!(
            snapshot.upstream_connects.last_failure_reason.as_deref(),
            Some("connection refused")
        );
        Ok(())
    }

    #[test]
    fn upstream_connect_failure_is_not_a_relay_failure() -> Result<(), Box<dyn std::error::Error>> {
        let runtime = TransparentProxyRuntime::for_test_config(&managed_interception_config());
        let handle = runtime.handle();
        let registry = RelayRegistry::new(runtime.clone());
        let slot = registry
            .try_acquire_slot()
            .expect("relay slot should be available");
        let shutdown_requested = Arc::new(AtomicBool::new(false));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let client = TcpStream::connect(listener.local_addr()?)?;
        let (downstream, peer) = listener.accept()?;
        drop(listener);

        let relay = spawn_relay(
            Socket::from(downstream),
            SockAddr::from(peer),
            TransparentProxyRelayContext::inbound_tproxy(0),
            shutdown_requested,
            registry,
            slot,
            runtime,
        );

        relay.join().expect("relay thread should not panic");
        drop(client);

        let snapshot = handle.snapshot();
        assert_eq!(snapshot.active_relays, 0);
        assert_eq!(snapshot.relay_failures, 0);
        assert_eq!(snapshot.upstream_connects.connect_successes, 0);
        assert_eq!(snapshot.upstream_connects.connect_failures, 1);
        assert_eq!(
            snapshot.upstream_connects.last_failure_reason.as_deref(),
            Some("connection refused")
        );
        Ok(())
    }

    fn managed_interception_config() -> EnforcementInterceptionConfig {
        EnforcementInterceptionConfig {
            strategy: TransparentInterceptionStrategyConfig::InboundTproxy,
            proxy: TransparentInterceptionProxyConfig {
                mode: TransparentInterceptionProxyModeConfig::ManagedTcpRelay,
                listen_port: Some(15001),
                ..TransparentInterceptionProxyConfig::default()
            },
            ..EnforcementInterceptionConfig::default()
        }
    }
}
