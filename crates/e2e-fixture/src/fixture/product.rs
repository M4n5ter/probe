use std::{error::Error, fmt};

use super::{
    http::{HttpMessageError, HttpTrafficConfig},
    http1::{Http1IoMode, Http1LoopbackConfig, Http1LoopbackError, Http1LoopbackReport},
    loopback::{LoopbackCoordination, LoopbackError, LoopbackRunOptions, coordinate_process_start},
    tls::{TlsHttp1LoopbackConfig, TlsHttp1LoopbackError, TlsHttp1LoopbackReport},
    websocket::{
        WebSocketLoopbackConfig, WebSocketLoopbackError, WebSocketLoopbackReport,
        WebSocketTrafficConfig,
    },
};

pub(crate) const SCENARIO: &str = "product-loopback";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ProductLoopbackConfig {
    pub http: HttpTrafficConfig,
    pub websocket: WebSocketTrafficConfig,
    pub run: LoopbackRunOptions,
    pub http_io_mode: Http1IoMode,
    pub accept_read_delay_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProductLoopbackReport {
    pub pid: u32,
    pub http1: Http1LoopbackReport,
    pub websocket: WebSocketLoopbackReport,
    pub tls_http1: TlsHttp1LoopbackReport,
}

impl fmt::Display for ProductLoopbackReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "scenario={SCENARIO}")?;
        writeln!(formatter, "pid={}", self.pid)?;
        write_http1_report(formatter, &self.http1)?;
        write_websocket_report(formatter, &self.websocket)?;
        write_tls_http1_report(formatter, &self.tls_http1)?;
        writeln!(
            formatter,
            "total_client_bytes_written={}",
            self.http1.client_bytes_written
                + self.websocket.client_bytes_written
                + self.tls_http1.client_bytes_written
        )?;
        writeln!(
            formatter,
            "total_client_bytes_read={}",
            self.http1.client_bytes_read
                + self.websocket.client_bytes_read
                + self.tls_http1.client_bytes_read
        )?;
        writeln!(formatter, "result=ok")
    }
}

#[derive(Debug)]
pub(crate) enum ProductLoopbackError {
    InvalidConfig(String),
    Loopback(LoopbackError),
    Http(HttpMessageError),
    Http1Scenario(Http1LoopbackError),
    TlsScenario(TlsHttp1LoopbackError),
    WebSocketScenario(WebSocketLoopbackError),
}

impl fmt::Display for ProductLoopbackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(reason) => {
                write!(formatter, "invalid product-loopback config: {reason}")
            }
            Self::Loopback(error) => write!(formatter, "{error}"),
            Self::Http(error) => write!(formatter, "{error}"),
            Self::Http1Scenario(error) => write!(formatter, "{error}"),
            Self::TlsScenario(error) => write!(formatter, "{error}"),
            Self::WebSocketScenario(error) => write!(formatter, "{error}"),
        }
    }
}

impl Error for ProductLoopbackError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidConfig(_) => None,
            Self::Loopback(error) => Some(error),
            Self::Http(error) => Some(error),
            Self::Http1Scenario(error) => Some(error),
            Self::TlsScenario(error) => Some(error),
            Self::WebSocketScenario(error) => Some(error),
        }
    }
}

impl From<LoopbackError> for ProductLoopbackError {
    fn from(error: LoopbackError) -> Self {
        Self::Loopback(error)
    }
}

impl From<HttpMessageError> for ProductLoopbackError {
    fn from(error: HttpMessageError) -> Self {
        Self::Http(error)
    }
}

impl From<Http1LoopbackError> for ProductLoopbackError {
    fn from(error: Http1LoopbackError) -> Self {
        Self::Http1Scenario(error)
    }
}

impl From<TlsHttp1LoopbackError> for ProductLoopbackError {
    fn from(error: TlsHttp1LoopbackError) -> Self {
        Self::TlsScenario(error)
    }
}

impl From<WebSocketLoopbackError> for ProductLoopbackError {
    fn from(error: WebSocketLoopbackError) -> Self {
        Self::WebSocketScenario(error)
    }
}

pub(crate) fn run_product_loopback(
    config: ProductLoopbackConfig,
) -> Result<ProductLoopbackReport, ProductLoopbackError> {
    validate_config(&config)?;
    coordinate_process_start(&config.run.coordination, SCENARIO)?;
    let http1 = super::http1::run_http1_loopback(Http1LoopbackConfig {
        traffic: config.http,
        run: inner_run_options(&config.run),
        io_mode: config.http_io_mode,
        accept_read_delay_ms: config.accept_read_delay_ms,
        vector_first_payload_slice_bytes: None,
    })?;
    let websocket = super::websocket::run_websocket_loopback(WebSocketLoopbackConfig {
        traffic: config.websocket,
        run: inner_run_options(&config.run),
    })?;
    let tls_http1 = super::tls::run_tls_http1_loopback(TlsHttp1LoopbackConfig {
        traffic: config.http,
        run: inner_run_options(&config.run),
    })?;
    Ok(ProductLoopbackReport {
        pid: std::process::id(),
        http1,
        websocket,
        tls_http1,
    })
}

fn validate_config(config: &ProductLoopbackConfig) -> Result<(), ProductLoopbackError> {
    if config.run.listen_port != 0 {
        return Err(ProductLoopbackError::InvalidConfig(
            "product-loopback starts multiple child listeners and requires listen_port 0"
                .to_string(),
        ));
    }
    super::http::validate_traffic_config(&config.http)?;
    super::websocket::validate_traffic_config(&config.websocket)?;
    Ok(())
}

fn inner_run_options(run: &LoopbackRunOptions) -> LoopbackRunOptions {
    LoopbackRunOptions {
        listen_port: 0,
        connect_write_delay_ms: run.connect_write_delay_ms,
        post_exchange_delay_ms: run.post_exchange_delay_ms,
        coordination: LoopbackCoordination::Immediate,
    }
}

fn write_http1_report(
    formatter: &mut fmt::Formatter<'_>,
    report: &Http1LoopbackReport,
) -> fmt::Result {
    writeln!(formatter, "http1.listen_addr={}", report.listen_addr)?;
    writeln!(formatter, "http1.requests={}", report.requests)?;
    writeln!(formatter, "http1.write_chunks={}", report.write_chunks)?;
    writeln!(formatter, "http1.io_mode={}", report.io_mode.as_str())?;
    writeln!(
        formatter,
        "http1.client_bytes_written={}",
        report.client_bytes_written
    )?;
    writeln!(
        formatter,
        "http1.client_bytes_read={}",
        report.client_bytes_read
    )?;
    write_server_bytes(
        formatter,
        "http1",
        report.server_bytes_read,
        report.server_bytes_written,
    )
}

fn write_server_bytes(
    formatter: &mut fmt::Formatter<'_>,
    prefix: &str,
    server_bytes_read: usize,
    server_bytes_written: usize,
) -> fmt::Result {
    writeln!(formatter, "{prefix}.server_bytes_read={server_bytes_read}")?;
    writeln!(
        formatter,
        "{prefix}.server_bytes_written={server_bytes_written}"
    )
}

fn write_websocket_report(
    formatter: &mut fmt::Formatter<'_>,
    report: &WebSocketLoopbackReport,
) -> fmt::Result {
    writeln!(formatter, "websocket.listen_addr={}", report.listen_addr)?;
    writeln!(formatter, "websocket.connections={}", report.connections)?;
    writeln!(formatter, "websocket.write_chunks={}", report.write_chunks)?;
    writeln!(
        formatter,
        "websocket.frame_payload_bytes={}",
        report.frame_payload_bytes
    )?;
    writeln!(
        formatter,
        "websocket.client_bytes_written={}",
        report.client_bytes_written
    )?;
    writeln!(
        formatter,
        "websocket.client_bytes_read={}",
        report.client_bytes_read
    )?;
    write_server_bytes(
        formatter,
        "websocket",
        report.server_bytes_read,
        report.server_bytes_written,
    )
}

fn write_tls_http1_report(
    formatter: &mut fmt::Formatter<'_>,
    report: &TlsHttp1LoopbackReport,
) -> fmt::Result {
    writeln!(formatter, "tls_http1.listen_addr={}", report.listen_addr)?;
    writeln!(formatter, "tls_http1.requests={}", report.requests)?;
    writeln!(formatter, "tls_http1.write_chunks={}", report.write_chunks)?;
    writeln!(
        formatter,
        "tls_http1.client_bytes_written={}",
        report.client_bytes_written
    )?;
    writeln!(
        formatter,
        "tls_http1.client_bytes_read={}",
        report.client_bytes_read
    )?;
    write_server_bytes(
        formatter,
        "tls_http1",
        report.server_bytes_read,
        report.server_bytes_written,
    )
}

#[cfg(test)]
mod tests {
    use std::{
        fs, io, thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    use super::*;
    use crate::fixture::loopback::start_nonce;

    #[test]
    fn product_loopback_runs_plain_websocket_and_tls_traffic() -> Result<(), Box<dyn Error>> {
        let report = run_product_loopback(ProductLoopbackConfig {
            http: HttpTrafficConfig {
                requests: 1,
                request_body_bytes: 8,
                response_body_bytes: 8,
                write_chunks: 2,
            },
            websocket: WebSocketTrafficConfig {
                connections: 1,
                frame_payload_bytes: 2,
                write_chunks: 2,
            },
            ..ProductLoopbackConfig::default()
        })?;

        assert_eq!(report.http1.requests, 1);
        assert_eq!(report.websocket.connections, 1);
        assert_eq!(report.tls_http1.requests, 1);
        assert!(report.http1.client_bytes_written > 0);
        assert!(report.websocket.client_bytes_written > 0);
        assert!(report.tls_http1.client_bytes_written > 0);
        Ok(())
    }

    #[test]
    fn product_loopback_two_phase_waits_for_start_file() -> Result<(), Box<dyn Error>> {
        let temp = test_dir("product-two-phase")?;
        let ready_path = temp.join("fixture.ready");
        let start_path = temp.join("fixture.start");
        let (done_sender, done_receiver) = std::sync::mpsc::channel();
        let config = ProductLoopbackConfig {
            http: HttpTrafficConfig {
                requests: 1,
                request_body_bytes: 8,
                response_body_bytes: 8,
                write_chunks: 2,
            },
            websocket: WebSocketTrafficConfig {
                connections: 1,
                frame_payload_bytes: 2,
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
            ..ProductLoopbackConfig::default()
        };
        let handle = thread::spawn(move || {
            let report = run_product_loopback(config);
            let _ = done_sender.send(());
            report
        });

        let ready = wait_for_ready_file(&ready_path)?;
        assert!(ready.contains("pid="));
        assert!(ready.contains("scenario=product-loopback"));
        let start_nonce = start_nonce(&ready).ok_or("ready file omitted start nonce")?;
        assert!(matches!(
            done_receiver.recv_timeout(Duration::from_millis(200)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));

        fs::write(&start_path, format!("start_nonce={start_nonce}\n"))?;
        let report = handle
            .join()
            .map_err(|_| "two-phase product fixture thread panicked")??;

        assert_eq!(report.http1.requests, 1);
        assert_eq!(report.websocket.connections, 1);
        assert_eq!(report.tls_http1.requests, 1);
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn product_loopback_invalid_config_fails_before_ready() -> Result<(), Box<dyn Error>> {
        let temp = test_dir("product-invalid-before-ready")?;
        let ready_path = temp.join("fixture.ready");
        let start_path = temp.join("fixture.start");
        let config = ProductLoopbackConfig {
            http: HttpTrafficConfig {
                requests: 0,
                ..HttpTrafficConfig::default()
            },
            run: LoopbackRunOptions {
                listen_port: 0,
                connect_write_delay_ms: 0,
                post_exchange_delay_ms: 0,
                coordination: LoopbackCoordination::TwoPhase {
                    ready_file: ready_path.clone(),
                    start_file: start_path,
                },
            },
            ..ProductLoopbackConfig::default()
        };
        let error = run_product_loopback(config).expect_err("invalid product config must fail");

        assert!(error.to_string().contains("requests must be in 1..="));
        assert!(
            !ready_path.exists(),
            "invalid config must fail before publishing product ready file"
        );
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

    fn test_dir(name: &str) -> Result<std::path::PathBuf, io::Error> {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "traffic-probe-product-fixture-{name}-{}-{unique}",
            std::process::id()
        ));
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
        fs::create_dir_all(&path)?;
        Ok(path)
    }
}
