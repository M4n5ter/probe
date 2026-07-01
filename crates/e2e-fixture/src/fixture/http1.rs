use std::{
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io,
    io::{IoSlice, IoSliceMut, Seek, SeekFrom, Write},
    mem::MaybeUninit,
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use super::{
    http::{self, ExchangeReport, HttpMessageError, HttpTrafficConfig},
    loopback::{
        LoopbackError, LoopbackRunOptions, accept_with_timeout, bind_loopback_listener,
        configure_stream, coordinate_start, delay_after_exchange, delay_before_accept_read,
    },
};

const SCENARIO: &str = "http1-loopback";
const VECTOR_FIRST_PAYLOAD_SLICE_BYTES: usize = 192;
static SENDFILE_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Http1LoopbackConfig {
    pub traffic: HttpTrafficConfig,
    pub run: LoopbackRunOptions,
    pub io_mode: Http1IoMode,
    pub accept_read_delay_ms: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Http1IoMode {
    #[default]
    ReadWrite,
    SendRecv,
    ReadvWritev,
    SendmsgRecvmsg,
    Sendfile,
}

impl Http1IoMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ReadWrite => "read-write",
            Self::SendRecv => "send-recv",
            Self::ReadvWritev => "readv-writev",
            Self::SendmsgRecvmsg => "sendmsg-recvmsg",
            Self::Sendfile => "sendfile",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "read-write" => Some(Self::ReadWrite),
            "send-recv" => Some(Self::SendRecv),
            "readv-writev" => Some(Self::ReadvWritev),
            "sendmsg-recvmsg" => Some(Self::SendmsgRecvmsg),
            "sendfile" => Some(Self::Sendfile),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Http1LoopbackReport {
    pub pid: u32,
    pub listen_addr: SocketAddr,
    pub requests: usize,
    pub write_chunks: usize,
    pub io_mode: Http1IoMode,
    pub client_bytes_written: usize,
    pub client_bytes_read: usize,
    pub server_bytes_read: usize,
    pub server_bytes_written: usize,
}

impl fmt::Display for Http1LoopbackReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "scenario={SCENARIO}")?;
        writeln!(formatter, "pid={}", self.pid)?;
        writeln!(formatter, "listen_addr={}", self.listen_addr)?;
        writeln!(formatter, "requests={}", self.requests)?;
        writeln!(formatter, "write_chunks={}", self.write_chunks)?;
        writeln!(formatter, "io_mode={}", self.io_mode.as_str())?;
        writeln!(
            formatter,
            "client_bytes_written={}",
            self.client_bytes_written
        )?;
        writeln!(formatter, "client_bytes_read={}", self.client_bytes_read)?;
        writeln!(formatter, "server_bytes_read={}", self.server_bytes_read)?;
        writeln!(
            formatter,
            "server_bytes_written={}",
            self.server_bytes_written
        )?;
        writeln!(formatter, "result=ok")
    }
}

#[derive(Debug)]
pub(crate) enum Http1LoopbackError {
    Loopback(LoopbackError),
    Http(HttpMessageError),
    Io {
        action: &'static str,
        source: io::Error,
    },
    ServerThreadPanicked,
}

impl fmt::Display for Http1LoopbackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Loopback(error) => write!(formatter, "{error}"),
            Self::Http(error) => write!(formatter, "{error}"),
            Self::Io { action, source } => write!(formatter, "failed to {action}: {source}"),
            Self::ServerThreadPanicked => {
                write!(formatter, "http1-loopback server thread panicked")
            }
        }
    }
}

impl Error for Http1LoopbackError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Loopback(error) => Some(error),
            Self::Http(error) => Some(error),
            Self::Io { source, .. } => Some(source),
            Self::ServerThreadPanicked => None,
        }
    }
}

impl From<LoopbackError> for Http1LoopbackError {
    fn from(error: LoopbackError) -> Self {
        Self::Loopback(error)
    }
}

impl From<HttpMessageError> for Http1LoopbackError {
    fn from(error: HttpMessageError) -> Self {
        Self::Http(error)
    }
}

pub(crate) fn run_http1_loopback(
    config: Http1LoopbackConfig,
) -> Result<Http1LoopbackReport, Http1LoopbackError> {
    http::validate_traffic_config(&config.traffic)?;
    let listener = bind_loopback_listener(config.run.listen_port)?;
    let listen_addr = listener
        .local_addr()
        .map_err(|source| io_error("read listener address", source))?;
    coordinate_start(&config.run.coordination, listen_addr)?;
    let traffic = config.traffic;
    let io_mode = config.io_mode;
    let accept_read_delay_ms = config.accept_read_delay_ms;
    let post_exchange_delay_ms = config.run.post_exchange_delay_ms;
    let server = thread::spawn(move || {
        serve_http1(
            listener,
            traffic,
            io_mode,
            accept_read_delay_ms,
            post_exchange_delay_ms,
        )
    });

    let mut client_bytes_written = 0usize;
    let mut client_bytes_read = 0usize;
    for request_index in 0..traffic.requests {
        let exchange = run_client_exchange(
            listen_addr,
            request_index,
            &traffic,
            io_mode,
            config.run.connect_write_delay_ms,
            config.run.post_exchange_delay_ms,
        )?;
        client_bytes_written = client_bytes_written.saturating_add(exchange.bytes_written);
        client_bytes_read = client_bytes_read.saturating_add(exchange.bytes_read);
    }

    let server_report = server
        .join()
        .map_err(|_| Http1LoopbackError::ServerThreadPanicked)??;
    Ok(Http1LoopbackReport {
        pid: std::process::id(),
        listen_addr,
        requests: traffic.requests,
        write_chunks: traffic.write_chunks,
        io_mode,
        client_bytes_written,
        client_bytes_read,
        server_bytes_read: server_report.bytes_read,
        server_bytes_written: server_report.bytes_written,
    })
}

fn run_client_exchange(
    listen_addr: SocketAddr,
    request_index: usize,
    config: &HttpTrafficConfig,
    io_mode: Http1IoMode,
    connect_write_delay_ms: u64,
    post_exchange_delay_ms: u64,
) -> Result<ExchangeReport, Http1LoopbackError> {
    let stream = TcpStream::connect(listen_addr)
        .map_err(|source| io_error("connect to loopback fixture server", source))?;
    configure_stream(&stream)?;
    if connect_write_delay_ms > 0 {
        thread::sleep(Duration::from_millis(connect_write_delay_ms));
    }
    let request = http::request(request_index, config.request_body_bytes);
    write_in_chunks(
        &stream,
        &request,
        config.write_chunks,
        io_mode,
        "write HTTP fixture request chunk",
    )?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(|source| io_error("half-close client write side", source))?;
    let response = read_to_end(&stream, io_mode)
        .map_err(|source| io_error("read HTTP fixture response", source))?;
    http::validate_response(&response, request_index, config.response_body_bytes)?;
    delay_after_exchange(post_exchange_delay_ms);
    Ok(ExchangeReport {
        bytes_written: request.len(),
        bytes_read: response.len(),
    })
}

fn serve_http1(
    listener: TcpListener,
    config: HttpTrafficConfig,
    io_mode: Http1IoMode,
    accept_read_delay_ms: u64,
    post_exchange_delay_ms: u64,
) -> Result<ExchangeReport, Http1LoopbackError> {
    let mut bytes_read = 0usize;
    let mut bytes_written = 0usize;
    for request_index in 0..config.requests {
        let (stream, _) = accept_with_timeout(&listener)?;
        configure_stream(&stream)?;
        delay_before_accept_read(accept_read_delay_ms);
        let request = read_to_end(&stream, io_mode)
            .map_err(|source| io_error("read HTTP fixture request", source))?;
        http::validate_request(&request, request_index, config.request_body_bytes)?;
        let response = http::response(request_index, config.response_body_bytes);
        write_in_chunks(
            &stream,
            &response,
            1,
            io_mode,
            "write HTTP fixture response chunk",
        )?;
        delay_after_exchange(post_exchange_delay_ms);
        bytes_read = bytes_read.saturating_add(request.len());
        bytes_written = bytes_written.saturating_add(response.len());
    }
    Ok(ExchangeReport {
        bytes_read,
        bytes_written,
    })
}

fn write_in_chunks(
    stream: &TcpStream,
    bytes: &[u8],
    chunks: usize,
    io_mode: Http1IoMode,
    action: &'static str,
) -> Result<(), Http1LoopbackError> {
    let chunk_size = http::chunk_size(bytes.len(), chunks);
    for chunk in bytes.chunks(chunk_size) {
        let written =
            write_chunk(stream, chunk, io_mode).map_err(|source| io_error(action, source))?;
        if written != chunk.len() {
            return Err(HttpMessageError::InvalidMessage(format!(
                "partial fixture request chunk write: wrote {written} of {} bytes",
                chunk.len()
            ))
            .into());
        }
    }
    Ok(())
}

fn write_chunk(stream: &TcpStream, chunk: &[u8], io_mode: Http1IoMode) -> io::Result<usize> {
    match io_mode {
        Http1IoMode::ReadWrite => rustix::io::write(stream, chunk).map_err(Into::into),
        Http1IoMode::ReadvWritev => {
            let slices = vector_write_slices(chunk);
            rustix::io::writev(stream, &slices).map_err(Into::into)
        }
        Http1IoMode::SendRecv => {
            rustix::net::send(stream, chunk, rustix::net::SendFlags::empty()).map_err(Into::into)
        }
        Http1IoMode::SendmsgRecvmsg => {
            let mut control = rustix::net::SendAncillaryBuffer::default();
            let slices = vector_write_slices(chunk);
            rustix::net::sendmsg(
                stream,
                &slices,
                &mut control,
                rustix::net::SendFlags::empty(),
            )
            .map_err(Into::into)
        }
        Http1IoMode::Sendfile => write_chunk_with_sendfile(stream, chunk),
    }
}

fn read_to_end(stream: &TcpStream, io_mode: Http1IoMode) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let read = read_chunk(stream, &mut buffer, io_mode)?;
        if read == 0 {
            return Ok(bytes);
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
}

fn read_chunk(stream: &TcpStream, buffer: &mut [u8], io_mode: Http1IoMode) -> io::Result<usize> {
    match io_mode {
        Http1IoMode::ReadWrite => rustix::io::read(stream, buffer).map_err(io::Error::from),
        Http1IoMode::Sendfile => rustix::io::read(stream, buffer).map_err(io::Error::from),
        Http1IoMode::ReadvWritev => {
            let mut empty = [];
            let mut slices = vector_read_slices(&mut empty, buffer);
            rustix::io::readv(stream, &mut slices).map_err(io::Error::from)
        }
        Http1IoMode::SendRecv => {
            let (read, _) = rustix::net::recv(stream, buffer, rustix::net::RecvFlags::empty())
                .map_err(io::Error::from)?;
            Ok(read)
        }
        Http1IoMode::SendmsgRecvmsg => {
            let mut control_space: [MaybeUninit<u8>; 0] = [];
            let mut control = rustix::net::RecvAncillaryBuffer::new(&mut control_space);
            let mut empty = [];
            let mut slices = vector_read_slices(&mut empty, buffer);
            let received = rustix::net::recvmsg(
                stream,
                &mut slices,
                &mut control,
                rustix::net::RecvFlags::empty(),
            )
            .map_err(io::Error::from)?;
            Ok(received.bytes)
        }
    }
}

fn write_chunk_with_sendfile(stream: &TcpStream, chunk: &[u8]) -> io::Result<usize> {
    let (path, mut file) = create_sendfile_temp_file()?;
    let result = (|| {
        file.write_all(chunk)?;
        file.flush()?;
        file.seek(SeekFrom::Start(0))?;
        let mut offset = 0;
        rustix::fs::sendfile(stream, &file, Some(&mut offset), chunk.len()).map_err(io::Error::from)
    })();
    let remove_result = fs::remove_file(&path);
    match (result, remove_result) {
        (Ok(written), Ok(())) => Ok(written),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

fn create_sendfile_temp_file() -> io::Result<(PathBuf, File)> {
    for _ in 0..16 {
        let path = sendfile_temp_path();
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "failed to allocate unique sendfile fixture temp path",
    ))
}

fn sendfile_temp_path() -> PathBuf {
    let sequence = SENDFILE_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    std::env::temp_dir().join(format!(
        "traffic-probe-e2e-sendfile-{}-{timestamp}-{sequence}",
        std::process::id(),
    ))
}

fn vector_write_slices(chunk: &[u8]) -> [IoSlice<'_>; 3] {
    let first_len = vector_first_payload_slice_len(chunk.len());
    [
        IoSlice::new(&chunk[..0]),
        IoSlice::new(&chunk[..first_len]),
        IoSlice::new(&chunk[first_len..]),
    ]
}

fn vector_read_slices<'a>(
    leading_empty: &'a mut [u8; 0],
    buffer: &'a mut [u8],
) -> [IoSliceMut<'a>; 3] {
    let first_len = vector_first_payload_slice_len(buffer.len());
    let (first, second) = buffer.split_at_mut(first_len);
    [
        IoSliceMut::new(leading_empty),
        IoSliceMut::new(first),
        IoSliceMut::new(second),
    ]
}

fn vector_first_payload_slice_len(len: usize) -> usize {
    core::cmp::min(len, VECTOR_FIRST_PAYLOAD_SLICE_BYTES)
}

fn io_error(action: &'static str, source: io::Error) -> Http1LoopbackError {
    Http1LoopbackError::Io { action, source }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{Instant, SystemTime, UNIX_EPOCH},
    };

    use super::super::loopback::{LoopbackCoordination, start_nonce};

    use super::*;

    #[test]
    fn http1_loopback_fixture_runs_multiple_chunked_requests() -> Result<(), Box<dyn Error>> {
        let report = run_http1_loopback(Http1LoopbackConfig {
            traffic: HttpTrafficConfig {
                requests: 2,
                request_body_bytes: 96,
                response_body_bytes: 48,
                write_chunks: 3,
            },
            run: LoopbackRunOptions::default(),
            io_mode: Http1IoMode::ReadWrite,
            accept_read_delay_ms: 0,
        })?;

        assert_eq!(report.requests, 2);
        assert_eq!(report.write_chunks, 3);
        assert_eq!(report.io_mode, Http1IoMode::ReadWrite);
        assert_eq!(report.client_bytes_written, report.server_bytes_read);
        assert_eq!(report.client_bytes_read, report.server_bytes_written);
        assert!(report.client_bytes_written > 0);
        assert!(report.client_bytes_read > 0);
        Ok(())
    }

    #[test]
    fn http1_loopback_two_phase_waits_for_start_file() -> Result<(), Box<dyn Error>> {
        let temp = test_dir("http1-two-phase")?;
        let ready_path = temp.join("fixture.ready");
        let start_path = temp.join("fixture.start");
        let (done_sender, done_receiver) = std::sync::mpsc::channel();
        let config = Http1LoopbackConfig {
            traffic: HttpTrafficConfig {
                requests: 1,
                request_body_bytes: 32,
                response_body_bytes: 16,
                write_chunks: 2,
            },
            run: LoopbackRunOptions {
                listen_port: 0,
                connect_write_delay_ms: 0,
                post_exchange_delay_ms: 0,
                coordination: LoopbackCoordination::TwoPhase {
                    ready_file: ready_path.clone(),
                    start_file: start_path.clone(),
                },
            },
            io_mode: Http1IoMode::ReadWrite,
            accept_read_delay_ms: 0,
        };
        let handle = thread::spawn(move || {
            let report = run_http1_loopback(config);
            let _ = done_sender.send(());
            report
        });

        let ready = wait_for_ready_file(&ready_path)?;
        assert!(ready.contains("pid="));
        assert!(ready.contains("listen_addr=127.0.0.1:"));
        let start_nonce = start_nonce(&ready).ok_or("ready file omitted start nonce")?;
        assert!(matches!(
            done_receiver.recv_timeout(Duration::from_millis(200)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));

        fs::write(&start_path, format!("start_nonce={start_nonce}\n"))?;
        let report = handle
            .join()
            .map_err(|_| "two-phase fixture thread panicked")??;

        assert_eq!(report.requests, 1);
        assert_eq!(report.write_chunks, 2);
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn http1_loopback_two_phase_rejects_stale_start_file() -> Result<(), Box<dyn Error>> {
        let temp = test_dir("http1-stale-start")?;
        let ready_path = temp.join("fixture.ready");
        let start_path = temp.join("fixture.start");
        fs::write(&start_path, b"start_nonce=stale\n")?;
        let config = Http1LoopbackConfig {
            traffic: HttpTrafficConfig::default(),
            run: LoopbackRunOptions {
                listen_port: 0,
                connect_write_delay_ms: 0,
                post_exchange_delay_ms: 0,
                coordination: LoopbackCoordination::TwoPhase {
                    ready_file: ready_path,
                    start_file: start_path,
                },
            },
            io_mode: Http1IoMode::ReadWrite,
            accept_read_delay_ms: 0,
        };

        let error = run_http1_loopback(config).expect_err("stale start file must fail");

        assert!(error.to_string().contains("did not contain expected nonce"));
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn http1_loopback_runs_with_send_recv_syscalls() -> Result<(), Box<dyn Error>> {
        let report = run_http1_loopback(Http1LoopbackConfig {
            traffic: HttpTrafficConfig {
                requests: 1,
                request_body_bytes: 64,
                response_body_bytes: 32,
                write_chunks: 2,
            },
            run: LoopbackRunOptions::default(),
            io_mode: Http1IoMode::SendRecv,
            accept_read_delay_ms: 0,
        })?;

        assert_eq!(report.io_mode, Http1IoMode::SendRecv);
        assert_eq!(report.client_bytes_written, report.server_bytes_read);
        assert_eq!(report.client_bytes_read, report.server_bytes_written);
        Ok(())
    }

    #[test]
    fn http1_loopback_runs_with_sendfile_syscall() -> Result<(), Box<dyn Error>> {
        let report = run_http1_loopback(Http1LoopbackConfig {
            traffic: HttpTrafficConfig {
                requests: 1,
                request_body_bytes: 64,
                response_body_bytes: 32,
                write_chunks: 2,
            },
            run: LoopbackRunOptions::default(),
            io_mode: Http1IoMode::Sendfile,
            accept_read_delay_ms: 0,
        })?;

        assert_eq!(report.io_mode, Http1IoMode::Sendfile);
        assert_eq!(report.client_bytes_written, report.server_bytes_read);
        assert_eq!(report.client_bytes_read, report.server_bytes_written);
        Ok(())
    }

    #[test]
    fn http1_loopback_runs_with_vector_syscalls() -> Result<(), Box<dyn Error>> {
        for io_mode in [Http1IoMode::ReadvWritev, Http1IoMode::SendmsgRecvmsg] {
            let report = run_http1_loopback(Http1LoopbackConfig {
                traffic: HttpTrafficConfig {
                    requests: 1,
                    request_body_bytes: VECTOR_FIRST_PAYLOAD_SLICE_BYTES + 64,
                    response_body_bytes: VECTOR_FIRST_PAYLOAD_SLICE_BYTES + 32,
                    write_chunks: 1,
                },
                run: LoopbackRunOptions::default(),
                io_mode,
                accept_read_delay_ms: 0,
            })?;

            assert_eq!(report.io_mode, io_mode);
            assert_eq!(report.client_bytes_written, report.server_bytes_read);
            assert_eq!(report.client_bytes_read, report.server_bytes_written);
        }
        Ok(())
    }

    fn wait_for_ready_file(path: &std::path::Path) -> Result<String, Box<dyn Error>> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match fs::read_to_string(path) {
                Ok(content) => return Ok(content),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            if Instant::now() >= deadline {
                return Err(format!("timed out waiting for ready file {}", path.display()).into());
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn test_dir(name: &str) -> Result<PathBuf, io::Error> {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "traffic-probe-e2e-fixture-{name}-{}-{}",
            std::process::id(),
            unique
        ));
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
        fs::create_dir_all(&path)?;
        Ok(path)
    }
}
