use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use super::super::harness::e2e_error;
use super::commands::nc_command;
use super::{
    CLIENT_PAYLOAD, CLIENT_TIMEOUT, LOOPBACK_ADDR, OUTBOUND_BYPASS_MARK, OutboundProxyE2eMode,
    PROXY_PORT, SERVER_ACCEPT_TIMEOUT, SERVER_RESPONSE, UPSTREAM_PORT,
};

pub(super) struct UpstreamServer {
    report: mpsc::Receiver<Result<UpstreamReport, String>>,
    thread: thread::JoinHandle<()>,
}

impl UpstreamServer {
    pub(super) fn spawn() -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind((LOOPBACK_ADDR, UPSTREAM_PORT))?;
        listener.set_nonblocking(true)?;
        let (sender, report) = mpsc::channel();
        let thread = thread::spawn(move || {
            let result = run_upstream_server(listener).map_err(|error| error.to_string());
            let _ = sender.send(result);
        });
        Ok(Self { report, thread })
    }

    pub(super) fn join(self) -> Result<UpstreamReport, Box<dyn std::error::Error>> {
        let result = self
            .report
            .recv_timeout(SERVER_ACCEPT_TIMEOUT + Duration::from_secs(1))
            .map_err(|error| e2e_error(format!("upstream server did not report: {error}")))?;
        self.thread
            .join()
            .map_err(|_| e2e_error("upstream server thread panicked"))?;
        result.map_err(|error| e2e_error(error).into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct UpstreamReport {
    pub(super) peer_addr: SocketAddr,
    pub(super) request: Vec<u8>,
}

pub(super) enum ProxyFixture {
    ManagedRelay,
    ExternalProxy(ExternalProxyServer),
}

impl ProxyFixture {
    pub(super) fn spawn(mode: OutboundProxyE2eMode) -> Result<Self, Box<dyn std::error::Error>> {
        match mode {
            OutboundProxyE2eMode::ManagedRelay => Ok(Self::ManagedRelay),
            OutboundProxyE2eMode::ExternalProxy => {
                ExternalProxyServer::spawn().map(Self::ExternalProxy)
            }
        }
    }

    pub(super) fn join(self) -> Result<ProxyFixtureReport, Box<dyn std::error::Error>> {
        match self {
            Self::ManagedRelay => Ok(ProxyFixtureReport::ManagedRelay),
            Self::ExternalProxy(proxy) => proxy.join().map(ProxyFixtureReport::ExternalProxy),
        }
    }
}

pub(super) enum ProxyFixtureReport {
    ManagedRelay,
    ExternalProxy(ExternalProxyReport),
}

pub(super) struct ExternalProxyServer {
    report: mpsc::Receiver<Result<ExternalProxyReport, String>>,
    thread: thread::JoinHandle<()>,
}

impl ExternalProxyServer {
    fn spawn() -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind((LOOPBACK_ADDR, PROXY_PORT))?;
        listener.set_nonblocking(true)?;
        let (sender, report) = mpsc::channel();
        let thread = thread::spawn(move || {
            let result = run_external_proxy(listener).map_err(|error| error.to_string());
            let _ = sender.send(result);
        });
        Ok(Self { report, thread })
    }

    fn join(self) -> Result<ExternalProxyReport, Box<dyn std::error::Error>> {
        let result = self
            .report
            .recv_timeout(SERVER_ACCEPT_TIMEOUT + Duration::from_secs(1))
            .map_err(|error| e2e_error(format!("external proxy did not report: {error}")))?;
        self.thread
            .join()
            .map_err(|_| e2e_error("external proxy thread panicked"))?;
        result.map_err(|error| e2e_error(error).into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExternalProxyReport {
    pub(super) client_peer_addr: SocketAddr,
    pub(super) request: Vec<u8>,
    pub(super) upstream_response: Vec<u8>,
}

fn run_upstream_server(
    listener: TcpListener,
) -> Result<UpstreamReport, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + SERVER_ACCEPT_TIMEOUT;
    let (mut stream, peer_addr) = accept_until_deadline(
        &listener,
        deadline,
        "upstream server timed out waiting for relayed client",
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let request =
        read_exact_fixture_bytes(&mut stream, CLIENT_PAYLOAD.len(), "upstream server request")?;
    stream.write_all(SERVER_RESPONSE)?;
    Ok(UpstreamReport { peer_addr, request })
}

fn run_external_proxy(
    listener: TcpListener,
) -> Result<ExternalProxyReport, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + SERVER_ACCEPT_TIMEOUT;
    let (mut client, client_peer_addr) = accept_until_deadline(
        &listener,
        deadline,
        "external proxy timed out waiting for redirected client",
    )?;
    client.set_read_timeout(Some(Duration::from_secs(2)))?;
    client.set_write_timeout(Some(Duration::from_secs(2)))?;

    let request =
        read_exact_fixture_bytes(&mut client, CLIENT_PAYLOAD.len(), "external proxy request")?;

    let mut upstream = connect_marked_upstream()?;
    upstream.set_read_timeout(Some(Duration::from_secs(2)))?;
    upstream.set_write_timeout(Some(Duration::from_secs(2)))?;
    upstream.write_all(&request)?;

    let upstream_response = read_exact_fixture_bytes(
        &mut upstream,
        SERVER_RESPONSE.len(),
        "external proxy upstream response",
    )?;
    client.write_all(&upstream_response)?;

    Ok(ExternalProxyReport {
        client_peer_addr,
        request,
        upstream_response,
    })
}

fn accept_until_deadline(
    listener: &TcpListener,
    deadline: Instant,
    timeout_message: &'static str,
) -> Result<(TcpStream, SocketAddr), Box<dyn std::error::Error>> {
    loop {
        match listener.accept() {
            Ok(accepted) => return Ok(accepted),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
        if Instant::now() >= deadline {
            return Err(e2e_error(timeout_message).into());
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn read_exact_fixture_bytes(
    stream: &mut impl Read,
    len: usize,
    label: &'static str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = vec![0_u8; len];
    stream.read_exact(&mut bytes).map_err(|error| {
        e2e_error(format!(
            "{label} read failed after expecting {len} bytes: {error}"
        ))
    })?;
    Ok(bytes)
}

fn connect_marked_upstream() -> Result<TcpStream, Box<dyn std::error::Error>> {
    let target = SocketAddr::from((LOOPBACK_ADDR, UPSTREAM_PORT));
    let socket = Socket::new(
        Domain::for_address(target),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    socket.set_mark(OUTBOUND_BYPASS_MARK)?;
    socket.connect_timeout(&SockAddr::from(target), CLIENT_TIMEOUT)?;
    Ok(TcpStream::from(socket))
}

pub(super) fn run_client() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let host = LOOPBACK_ADDR.to_string();
    let port = UPSTREAM_PORT.to_string();
    let mut child = Command::new(nc_command()?)
        .args(["-w", "2", &host, &port])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or_else(|| e2e_error("failed to open nc stdin"))?
        .write_all(CLIENT_PAYLOAD)?;
    let output = wait_with_timeout(child, CLIENT_TIMEOUT)?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(e2e_error(format!(
            "client nc failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ))
        .into())
    }
}

fn wait_with_timeout(
    mut child: Child,
    timeout: Duration,
) -> Result<std::process::Output, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait()?.is_some() {
            return Ok(child.wait_with_output()?);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e2e_error(format!(
                "client command timed out after {}ms",
                timeout.as_millis()
            ))
            .into());
        }
        thread::sleep(Duration::from_millis(20));
    }
}
