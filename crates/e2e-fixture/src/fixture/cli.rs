use std::{error::Error, fmt, path::PathBuf};

use super::{
    http::HttpTrafficConfig,
    http1::{Http1IoMode, Http1LoopbackConfig, Http1LoopbackError, Http1LoopbackReport},
    loopback::{LoopbackCoordination, LoopbackRunOptions},
    tls::{TlsHttp1LoopbackConfig, TlsHttp1LoopbackError, TlsHttp1LoopbackReport},
};

const USAGE: &str = "\
usage: sssa-e2e-fixture <scenario> [options]

Scenarios:
  http1-loopback        Start a local TCP server and client in this process, then exchange deterministic HTTP/1 traffic.
  tls-http1-loopback    Start a local OpenSSL/libssl TLS server and client in this process, then exchange deterministic HTTP/1 traffic.

Options:
  --listen-port PORT
  --ready-file PATH
  --start-file PATH
  --requests N
  --request-body-bytes N
  --response-body-bytes N
  --write-chunks N
  --io-mode read-write|send-recv|readv-writev|sendmsg-recvmsg  (http1-loopback only)
  --connect-write-delay-ms N
  --accept-read-delay-ms N       (http1-loopback only)
  --post-exchange-delay-ms N
";

pub(crate) fn run(args: impl IntoIterator<Item = String>) -> Result<FixtureReport, FixtureError> {
    let mut args = args.into_iter();
    let Some(scenario) = args.next() else {
        return Err(FixtureError::usage("missing scenario"));
    };
    if scenario == "--help" || scenario == "-h" {
        return Ok(FixtureReport::Help(USAGE));
    }
    match scenario.as_str() {
        "http1-loopback" => {
            let scenario_args = args.collect::<Vec<_>>();
            if has_help(&scenario_args) {
                return Ok(FixtureReport::Help(USAGE));
            }
            let config = parse_http1_loopback(scenario_args)?;
            let report = super::http1::run_http1_loopback(config)?;
            Ok(FixtureReport::Http1Loopback(report))
        }
        "tls-http1-loopback" => {
            let scenario_args = args.collect::<Vec<_>>();
            if has_help(&scenario_args) {
                return Ok(FixtureReport::Help(USAGE));
            }
            let config = parse_tls_http1_loopback(scenario_args)?;
            let report = super::tls::run_tls_http1_loopback(config)?;
            Ok(FixtureReport::TlsHttp1Loopback(report))
        }
        _ => Err(FixtureError::usage(format!(
            "unknown scenario {scenario}\n\n{USAGE}"
        ))),
    }
}

pub(crate) enum FixtureReport {
    Help(&'static str),
    Http1Loopback(Http1LoopbackReport),
    TlsHttp1Loopback(TlsHttp1LoopbackReport),
}

impl fmt::Display for FixtureReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Help(usage) => write!(formatter, "{usage}"),
            Self::Http1Loopback(report) => write!(formatter, "{report}"),
            Self::TlsHttp1Loopback(report) => write!(formatter, "{report}"),
        }
    }
}

#[derive(Debug)]
pub(crate) enum FixtureError {
    Usage(String),
    Http1Scenario(Http1LoopbackError),
    TlsScenario(TlsHttp1LoopbackError),
}

impl FixtureError {
    fn usage(message: impl Into<String>) -> Self {
        Self::Usage(message.into())
    }
}

impl fmt::Display for FixtureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(message) => write!(formatter, "{message}"),
            Self::Http1Scenario(error) => write!(formatter, "{error}"),
            Self::TlsScenario(error) => write!(formatter, "{error}"),
        }
    }
}

impl Error for FixtureError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Usage(_) => None,
            Self::Http1Scenario(error) => Some(error),
            Self::TlsScenario(error) => Some(error),
        }
    }
}

impl From<Http1LoopbackError> for FixtureError {
    fn from(error: Http1LoopbackError) -> Self {
        Self::Http1Scenario(error)
    }
}

impl From<TlsHttp1LoopbackError> for FixtureError {
    fn from(error: TlsHttp1LoopbackError) -> Self {
        Self::TlsScenario(error)
    }
}

fn parse_http1_loopback(
    args: impl IntoIterator<Item = String>,
) -> Result<Http1LoopbackConfig, FixtureError> {
    let args = parse_http_loopback_args(args, PlainHttpOptions::Allowed)?;
    Ok(Http1LoopbackConfig {
        traffic: args.traffic,
        run: args.run,
        io_mode: args.io_mode.unwrap_or_default(),
        accept_read_delay_ms: args.accept_read_delay_ms,
    })
}

fn parse_tls_http1_loopback(
    args: impl IntoIterator<Item = String>,
) -> Result<TlsHttp1LoopbackConfig, FixtureError> {
    let args = parse_http_loopback_args(args, PlainHttpOptions::Rejected)?;
    Ok(TlsHttp1LoopbackConfig {
        traffic: args.traffic,
        run: args.run,
    })
}

struct ParsedHttpLoopbackArgs {
    traffic: HttpTrafficConfig,
    run: LoopbackRunOptions,
    io_mode: Option<Http1IoMode>,
    accept_read_delay_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlainHttpOptions {
    Allowed,
    Rejected,
}

fn parse_http_loopback_args(
    args: impl IntoIterator<Item = String>,
    plain_http_options: PlainHttpOptions,
) -> Result<ParsedHttpLoopbackArgs, FixtureError> {
    let mut traffic = HttpTrafficConfig::default();
    let mut run = LoopbackRunOptions::default();
    let mut io_mode = None;
    let mut accept_read_delay_ms = 0;
    let mut ready_file = None;
    let mut start_file = None;
    let mut args = args.into_iter();
    while let Some(option) = args.next() {
        if option == "--help" || option == "-h" {
            return Err(FixtureError::usage(USAGE));
        }
        let Some(value) = args.next() else {
            return Err(FixtureError::usage(format!(
                "missing value for {option}\n\n{USAGE}"
            )));
        };
        match option.as_str() {
            "--listen-port" => run.listen_port = parse_u16(&option, &value)?,
            "--connect-write-delay-ms" => {
                run.connect_write_delay_ms = parse_u64(&option, &value)?;
            }
            "--accept-read-delay-ms" => {
                reject_plain_http_option(plain_http_options, &option)?;
                accept_read_delay_ms = parse_u64(&option, &value)?;
            }
            "--post-exchange-delay-ms" => {
                run.post_exchange_delay_ms = parse_u64(&option, &value)?;
            }
            "--ready-file" => ready_file = Some(PathBuf::from(value)),
            "--start-file" => start_file = Some(PathBuf::from(value)),
            "--requests" => traffic.requests = parse_usize(&option, &value)?,
            "--request-body-bytes" => {
                traffic.request_body_bytes = parse_usize(&option, &value)?;
            }
            "--response-body-bytes" => {
                traffic.response_body_bytes = parse_usize(&option, &value)?;
            }
            "--write-chunks" => traffic.write_chunks = parse_usize(&option, &value)?,
            "--io-mode" => {
                reject_plain_http_option(plain_http_options, &option)?;
                io_mode = Some(Http1IoMode::parse(&value).ok_or_else(|| {
                    FixtureError::usage(format!(
                        "invalid value for {option}: {value}; expected read-write, send-recv, readv-writev, or sendmsg-recvmsg\n\n{USAGE}"
                    ))
                })?);
            }
            _ => {
                return Err(FixtureError::usage(format!(
                    "unknown option {option}\n\n{USAGE}"
                )));
            }
        }
    }
    run.coordination = parse_coordination(ready_file, start_file)?;
    Ok(ParsedHttpLoopbackArgs {
        traffic,
        run,
        io_mode,
        accept_read_delay_ms,
    })
}

fn reject_plain_http_option(
    plain_http_options: PlainHttpOptions,
    option: &str,
) -> Result<(), FixtureError> {
    match plain_http_options {
        PlainHttpOptions::Allowed => Ok(()),
        PlainHttpOptions::Rejected => Err(FixtureError::usage(format!(
            "{option} is only supported by http1-loopback\n\n{USAGE}"
        ))),
    }
}

fn parse_coordination(
    ready_file: Option<PathBuf>,
    start_file: Option<PathBuf>,
) -> Result<LoopbackCoordination, FixtureError> {
    match (ready_file, start_file) {
        (None, None) => Ok(LoopbackCoordination::Immediate),
        (Some(ready_file), Some(start_file)) if ready_file == start_file => {
            Err(FixtureError::usage(format!(
                "--ready-file and --start-file must be different paths\n\n{USAGE}"
            )))
        }
        (Some(ready_file), Some(start_file)) => Ok(LoopbackCoordination::TwoPhase {
            ready_file,
            start_file,
        }),
        (Some(_), None) | (None, Some(_)) => Err(FixtureError::usage(format!(
            "--ready-file and --start-file must be supplied together\n\n{USAGE}"
        ))),
    }
}

fn has_help(args: &[String]) -> bool {
    args.iter().any(|arg| arg == "--help" || arg == "-h")
}

fn parse_usize(option: &str, value: &str) -> Result<usize, FixtureError> {
    value.parse::<usize>().map_err(|error| {
        FixtureError::usage(format!(
            "invalid value for {option}: {value}: {error}\n\n{USAGE}"
        ))
    })
}

fn parse_u16(option: &str, value: &str) -> Result<u16, FixtureError> {
    value.parse::<u16>().map_err(|error| {
        FixtureError::usage(format!(
            "invalid value for {option}: {value}: {error}\n\n{USAGE}"
        ))
    })
}

fn parse_u64(option: &str, value: &str) -> Result<u64, FixtureError> {
    value.parse::<u64>().map_err(|error| {
        FixtureError::usage(format!(
            "invalid value for {option}: {value}: {error}\n\n{USAGE}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses_http1_loopback_options() -> Result<(), Box<dyn Error>> {
        let config = parse_http1_loopback([
            "--listen-port".to_string(),
            "0".to_string(),
            "--ready-file".to_string(),
            "/tmp/ready".to_string(),
            "--start-file".to_string(),
            "/tmp/start".to_string(),
            "--requests".to_string(),
            "2".to_string(),
            "--request-body-bytes".to_string(),
            "128".to_string(),
            "--response-body-bytes".to_string(),
            "64".to_string(),
            "--write-chunks".to_string(),
            "3".to_string(),
            "--connect-write-delay-ms".to_string(),
            "250".to_string(),
            "--accept-read-delay-ms".to_string(),
            "375".to_string(),
            "--post-exchange-delay-ms".to_string(),
            "500".to_string(),
        ])?;

        assert_eq!(config.run.listen_port, 0);
        assert_eq!(config.run.connect_write_delay_ms, 250);
        assert_eq!(config.accept_read_delay_ms, 375);
        assert_eq!(config.run.post_exchange_delay_ms, 500);
        assert_eq!(
            config.run.coordination,
            LoopbackCoordination::TwoPhase {
                ready_file: PathBuf::from("/tmp/ready"),
                start_file: PathBuf::from("/tmp/start")
            }
        );
        assert_eq!(config.traffic.requests, 2);
        assert_eq!(config.traffic.request_body_bytes, 128);
        assert_eq!(config.traffic.response_body_bytes, 64);
        assert_eq!(config.traffic.write_chunks, 3);
        assert_eq!(config.io_mode, Http1IoMode::ReadWrite);
        Ok(())
    }

    #[test]
    fn cli_parses_plain_http_io_mode() -> Result<(), Box<dyn Error>> {
        let config = parse_http1_loopback(["--io-mode".to_string(), "send-recv".to_string()])?;

        assert_eq!(config.io_mode, Http1IoMode::SendRecv);
        Ok(())
    }

    #[test]
    fn cli_parses_vector_http_io_modes() -> Result<(), Box<dyn Error>> {
        let readv = parse_http1_loopback(["--io-mode".to_string(), "readv-writev".to_string()])?;
        let sendmsg =
            parse_http1_loopback(["--io-mode".to_string(), "sendmsg-recvmsg".to_string()])?;

        assert_eq!(readv.io_mode, Http1IoMode::ReadvWritev);
        assert_eq!(sendmsg.io_mode, Http1IoMode::SendmsgRecvmsg);
        Ok(())
    }

    #[test]
    fn cli_parses_tls_http1_loopback_options() -> Result<(), Box<dyn Error>> {
        let config = parse_tls_http1_loopback([
            "--requests".to_string(),
            "2".to_string(),
            "--write-chunks".to_string(),
            "2".to_string(),
        ])?;

        assert_eq!(config.traffic.requests, 2);
        assert_eq!(config.traffic.write_chunks, 2);
        assert_eq!(config.run.coordination, LoopbackCoordination::Immediate);
        Ok(())
    }

    #[test]
    fn cli_rejects_tls_http1_io_mode() {
        let error = parse_tls_http1_loopback(["--io-mode".to_string(), "send-recv".to_string()])
            .expect_err("TLS fixture must not accept plain HTTP syscall mode");

        assert!(
            error
                .to_string()
                .contains("--io-mode is only supported by http1-loopback")
        );
    }

    #[test]
    fn cli_rejects_tls_http1_accept_read_delay() {
        let error =
            parse_tls_http1_loopback(["--accept-read-delay-ms".to_string(), "250".to_string()])
                .expect_err("TLS fixture must not accept plain HTTP accept-read delay");

        assert!(
            error
                .to_string()
                .contains("--accept-read-delay-ms is only supported by http1-loopback")
        );
    }

    #[test]
    fn cli_rejects_incomplete_two_phase_coordination() {
        let error = parse_http1_loopback(["--ready-file".to_string(), "/tmp/ready".to_string()])
            .expect_err("incomplete coordination must fail");

        assert!(
            error
                .to_string()
                .contains("--ready-file and --start-file must be supplied together")
        );
    }

    #[test]
    fn cli_rejects_same_two_phase_paths() {
        let error = parse_http1_loopback([
            "--ready-file".to_string(),
            "/tmp/coord".to_string(),
            "--start-file".to_string(),
            "/tmp/coord".to_string(),
        ])
        .expect_err("same coordination path must fail");

        assert!(
            error
                .to_string()
                .contains("--ready-file and --start-file must be different paths")
        );
    }

    #[test]
    fn cli_help_is_successful_report() -> Result<(), Box<dyn Error>> {
        let report = run(["--help".to_string()])?;

        assert!(report.to_string().contains("usage: sssa-e2e-fixture"));
        Ok(())
    }

    #[test]
    fn scenario_help_is_successful_report() -> Result<(), Box<dyn Error>> {
        let report = run(["tls-http1-loopback".to_string(), "--help".to_string()])?;

        assert!(report.to_string().contains("tls-http1-loopback"));
        assert!(report.to_string().contains("http1-loopback only"));
        Ok(())
    }
}
