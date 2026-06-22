use std::{
    io,
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
    proxy_error, proxy_io_error,
    registry::{RelayRegistry, RelaySlot, shutdown_streams},
    state::TransparentProxyRuntime,
};
use crate::transparent_interception::TransparentInterceptionError;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) fn spawn_relay(
    accepted: Socket,
    peer: SockAddr,
    listen_port: u16,
    shutdown_requested: Arc<AtomicBool>,
    relays: RelayRegistry,
    slot: RelaySlot,
    runtime: TransparentProxyRuntime,
) -> JoinHandle<()> {
    thread::spawn(move || {
        if let Err(error) = relay_connection(
            accepted,
            peer,
            listen_port,
            shutdown_requested,
            relays,
            slot,
        ) {
            runtime.record_relay_failure();
            eprintln!("managed transparent proxy relay failed: {error}");
        }
    })
}

fn relay_connection(
    accepted: Socket,
    peer: SockAddr,
    listen_port: u16,
    shutdown_requested: Arc<AtomicBool>,
    relays: RelayRegistry,
    _slot: RelaySlot,
) -> Result<(), TransparentInterceptionError> {
    let peer = peer
        .as_socket()
        .ok_or_else(|| proxy_error("transparent proxy accepted non-IP peer address"))?;
    let target = tproxy_target(&accepted)?;
    if target.port() == listen_port {
        return Err(proxy_error(format!(
            "refusing transparent proxy self-relay for peer {peer} target {target}"
        )));
    }
    let downstream = TcpStream::from(accepted);
    downstream
        .set_nodelay(true)
        .map_err(proxy_io_error("set downstream TCP_NODELAY"))?;
    let upstream = TcpStream::connect_timeout(&target, CONNECT_TIMEOUT).map_err(proxy_io_error(
        format!("connect transparent upstream target {target} for peer {peer}"),
    ))?;
    upstream
        .set_nodelay(true)
        .map_err(proxy_io_error("set upstream TCP_NODELAY"))?;
    let _registration = relays
        .register(&downstream, &upstream)
        .map_err(proxy_io_error("register active transparent relay"))?;
    if shutdown_requested.load(Ordering::SeqCst) {
        shutdown_streams(&downstream, &upstream);
    }
    relay_bidirectional(downstream, upstream)
}

fn tproxy_target(socket: &Socket) -> Result<SocketAddr, TransparentInterceptionError> {
    socket
        .local_addr()
        .map_err(proxy_io_error("read transparent socket local address"))?
        .as_socket()
        .ok_or_else(|| proxy_error("transparent socket local address is not an IP socket"))
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
        net::{Ipv4Addr, TcpListener},
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
}
