use std::{
    error::Error,
    ffi::OsString,
    fmt, fs,
    fs::OpenOptions,
    io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

pub(crate) const IO_TIMEOUT: Duration = Duration::from_secs(5);

const COORDINATION_TIMEOUT: Duration = Duration::from_secs(30);
const LOOPBACK_LISTENER_BACKLOG: i32 = 128;
const READY_FILE_TEMP_ATTEMPTS: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LoopbackRunOptions {
    pub listen_port: u16,
    pub connect_write_delay_ms: u64,
    pub post_exchange_delay_ms: u64,
    pub coordination: LoopbackCoordination,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LoopbackCoordination {
    Immediate,
    TwoPhase {
        ready_file: PathBuf,
        start_file: PathBuf,
    },
}

impl Default for LoopbackRunOptions {
    fn default() -> Self {
        Self {
            listen_port: 0,
            connect_write_delay_ms: 0,
            post_exchange_delay_ms: 0,
            coordination: LoopbackCoordination::Immediate,
        }
    }
}

#[derive(Debug)]
pub(crate) enum LoopbackError {
    Invalid(String),
    Io {
        action: &'static str,
        source: io::Error,
    },
}

impl fmt::Display for LoopbackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => write!(formatter, "{reason}"),
            Self::Io { action, source } => write!(formatter, "failed to {action}: {source}"),
        }
    }
}

impl Error for LoopbackError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Invalid(_) => None,
            Self::Io { source, .. } => Some(source),
        }
    }
}

pub(crate) fn bind_loopback_listener(listen_port: u16) -> Result<TcpListener, LoopbackError> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
        .map_err(|source| io_error("create loopback TCP listener socket", source))?;
    socket
        .set_reuse_address(true)
        .map_err(|source| io_error("set listener SO_REUSEADDR", source))?;
    socket
        .bind(&SockAddr::from(SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            listen_port,
        )))
        .map_err(|source| io_error("bind loopback TCP listener", source))?;
    socket
        .listen(LOOPBACK_LISTENER_BACKLOG)
        .map_err(|source| io_error("listen on loopback TCP listener", source))?;
    let listener = TcpListener::from(socket);
    listener
        .set_nonblocking(true)
        .map_err(|source| io_error("set listener nonblocking", source))?;
    Ok(listener)
}

pub(crate) fn coordinate_start(
    coordination: &LoopbackCoordination,
    listen_addr: SocketAddr,
) -> Result<(), LoopbackError> {
    coordinate_with_ready_file(coordination, |start_nonce| {
        format!(
            "pid={}\nlisten_addr={listen_addr}\nstart_nonce={start_nonce}\n",
            std::process::id()
        )
    })
}

pub(crate) fn coordinate_process_start(
    coordination: &LoopbackCoordination,
    scenario: &str,
) -> Result<(), LoopbackError> {
    coordinate_with_ready_file(coordination, |start_nonce| {
        format!(
            "pid={}\nscenario={scenario}\nstart_nonce={start_nonce}\n",
            std::process::id()
        )
    })
}

fn coordinate_with_ready_file(
    coordination: &LoopbackCoordination,
    ready_content: impl FnOnce(&str) -> String,
) -> Result<(), LoopbackError> {
    match coordination {
        LoopbackCoordination::Immediate => {}
        LoopbackCoordination::TwoPhase {
            ready_file,
            start_file,
        } => {
            let start_nonce = coordination_nonce();
            publish_ready_file(ready_file, ready_content(&start_nonce).as_bytes())
                .map_err(|source| io_error("publish ready file", source))?;
            wait_for_start_file(start_file, &start_nonce)?;
        }
    }
    Ok(())
}

pub(crate) fn accept_with_timeout(
    listener: &TcpListener,
) -> Result<(TcpStream, SocketAddr), LoopbackError> {
    let deadline = Instant::now() + IO_TIMEOUT;
    loop {
        match listener.accept() {
            Ok(accepted) => return Ok(accepted),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(LoopbackError::Invalid(
                        "timed out waiting for fixture client connection".to_string(),
                    ));
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(source) => return Err(io_error("accept fixture client connection", source)),
        }
    }
}

pub(crate) fn configure_stream(stream: &TcpStream) -> Result<(), LoopbackError> {
    stream
        .set_nodelay(true)
        .map_err(|source| io_error("set TCP_NODELAY", source))?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|source| io_error("set read timeout", source))?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|source| io_error("set write timeout", source))
}

pub(crate) fn delay_after_exchange(delay_ms: u64) {
    if delay_ms > 0 {
        thread::sleep(Duration::from_millis(delay_ms));
    }
}

pub(crate) fn delay_before_accept_read(delay_ms: u64) {
    if delay_ms > 0 {
        thread::sleep(Duration::from_millis(delay_ms));
    }
}

pub(crate) fn start_nonce(content: &str) -> Option<String> {
    content
        .lines()
        .find_map(|line| line.strip_prefix("start_nonce="))
        .map(ToOwned::to_owned)
}

fn wait_for_start_file(path: &Path, expected_nonce: &str) -> Result<(), LoopbackError> {
    let deadline = Instant::now() + COORDINATION_TIMEOUT;
    loop {
        match fs::read_to_string(path) {
            Ok(content) if start_nonce(&content).as_deref() == Some(expected_nonce) => {
                return Ok(());
            }
            Ok(content) => {
                return Err(LoopbackError::Invalid(format!(
                    "start file {} did not contain expected nonce {expected_nonce}: {content:?}",
                    path.display()
                )));
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(io_error("check start file", source)),
        }
        if Instant::now() >= deadline {
            return Err(LoopbackError::Invalid(format!(
                "timed out waiting for start file {}",
                path.display()
            )));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn publish_ready_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    for attempt in 0..READY_FILE_TEMP_ATTEMPTS {
        let temp_path = sibling_ready_temp_path(path, attempt);
        match write_new_file(&temp_path, bytes) {
            Ok(()) => {
                if let Err(error) = fs::rename(&temp_path, path) {
                    let _ = fs::remove_file(&temp_path);
                    return Err(error);
                }
                return Ok(());
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!(
            "failed to allocate ready file temp path beside {}",
            path.display()
        ),
    ))
}

fn write_new_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    std::io::Write::write_all(&mut file, bytes)
}

fn sibling_ready_temp_path(path: &Path, attempt: usize) -> PathBuf {
    let mut file_name = path
        .file_name()
        .map(OsString::from)
        .unwrap_or_else(|| OsString::from("ready"));
    file_name.push(format!(
        ".tmp.{}.{}.{}",
        std::process::id(),
        wall_time_unix_ns(),
        attempt
    ));
    path.with_file_name(file_name)
}

fn coordination_nonce() -> String {
    format!("{}-{}", std::process::id(), wall_time_unix_ns())
}

fn wall_time_unix_ns() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}

fn io_error(action: &'static str, source: io::Error) -> LoopbackError {
    LoopbackError::Io { action, source }
}
