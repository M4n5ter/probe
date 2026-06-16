use std::{
    error::Error,
    fmt,
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    thread,
    time::Duration,
};

use super::{
    http::{self, ExchangeReport, HttpMessageError, HttpTrafficConfig},
    loopback::{
        LoopbackError, LoopbackRunOptions, accept_with_timeout, bind_loopback_listener,
        configure_stream, coordinate_start, delay_after_exchange,
    },
};

const SCENARIO: &str = "http1-loopback";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Http1LoopbackConfig {
    pub traffic: HttpTrafficConfig,
    pub run: LoopbackRunOptions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Http1LoopbackReport {
    pub pid: u32,
    pub listen_addr: SocketAddr,
    pub requests: usize,
    pub write_chunks: usize,
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
    let post_exchange_delay_ms = config.run.post_exchange_delay_ms;
    let server = thread::spawn(move || serve_http1(listener, traffic, post_exchange_delay_ms));

    let mut client_bytes_written = 0usize;
    let mut client_bytes_read = 0usize;
    for request_index in 0..traffic.requests {
        let exchange = run_client_exchange(
            listen_addr,
            request_index,
            &traffic,
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
    connect_write_delay_ms: u64,
    post_exchange_delay_ms: u64,
) -> Result<ExchangeReport, Http1LoopbackError> {
    let mut stream = TcpStream::connect(listen_addr)
        .map_err(|source| io_error("connect to loopback fixture server", source))?;
    configure_stream(&stream)?;
    if connect_write_delay_ms > 0 {
        thread::sleep(Duration::from_millis(connect_write_delay_ms));
    }
    let request = http::request(request_index, config.request_body_bytes);
    write_in_chunks(&stream, &request, config.write_chunks)?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(|source| io_error("half-close client write side", source))?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
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
    post_exchange_delay_ms: u64,
) -> Result<ExchangeReport, Http1LoopbackError> {
    let mut bytes_read = 0usize;
    let mut bytes_written = 0usize;
    for request_index in 0..config.requests {
        let (mut stream, _) = accept_with_timeout(&listener)?;
        configure_stream(&stream)?;
        let mut request = Vec::new();
        stream
            .read_to_end(&mut request)
            .map_err(|source| io_error("read HTTP fixture request", source))?;
        http::validate_request(&request, request_index, config.request_body_bytes)?;
        let response = http::response(request_index, config.response_body_bytes);
        stream
            .write_all(&response)
            .map_err(|source| io_error("write HTTP fixture response", source))?;
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
) -> Result<(), Http1LoopbackError> {
    let chunk_size = http::chunk_size(bytes.len(), chunks);
    for chunk in bytes.chunks(chunk_size) {
        let written = write_chunk_with_write_syscall(stream, chunk)
            .map_err(|source| io_error("write HTTP fixture request chunk", source))?;
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

fn write_chunk_with_write_syscall(stream: &TcpStream, chunk: &[u8]) -> io::Result<usize> {
    rustix::io::write(stream, chunk).map_err(Into::into)
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
        })?;

        assert_eq!(report.requests, 2);
        assert_eq!(report.write_chunks, 3);
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
        };

        let error = run_http1_loopback(config).expect_err("stale start file must fail");

        assert!(error.to_string().contains("did not contain expected nonce"));
        fs::remove_dir_all(temp)?;
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
            "sssa-e2e-fixture-{name}-{}-{}",
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
