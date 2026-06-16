use std::{error::Error, fmt, path::PathBuf};

use super::http1::{
    Http1LoopbackConfig, Http1LoopbackCoordination, Http1LoopbackError, Http1LoopbackReport,
};

const USAGE: &str = "\
usage: sssa-e2e-fixture http1-loopback [--listen-port PORT] [--ready-file PATH] [--start-file PATH] [--requests N] [--request-body-bytes N] [--response-body-bytes N] [--write-chunks N]

Scenarios:
  http1-loopback    Start a local TCP server and client in this process, then exchange deterministic HTTP/1 traffic.
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
            if scenario_args
                .iter()
                .any(|arg| arg == "--help" || arg == "-h")
            {
                return Ok(FixtureReport::Help(USAGE));
            }
            let config = parse_http1_loopback(scenario_args)?;
            let report = super::http1::run_http1_loopback(config)?;
            Ok(FixtureReport::Http1Loopback(report))
        }
        _ => Err(FixtureError::usage(format!(
            "unknown scenario {scenario}\n\n{USAGE}"
        ))),
    }
}

pub(crate) enum FixtureReport {
    Help(&'static str),
    Http1Loopback(Http1LoopbackReport),
}

impl fmt::Display for FixtureReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Help(usage) => write!(formatter, "{usage}"),
            Self::Http1Loopback(report) => write!(formatter, "{report}"),
        }
    }
}

#[derive(Debug)]
pub(crate) enum FixtureError {
    Usage(String),
    Scenario(Http1LoopbackError),
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
            Self::Scenario(error) => write!(formatter, "{error}"),
        }
    }
}

impl Error for FixtureError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Usage(_) => None,
            Self::Scenario(error) => Some(error),
        }
    }
}

impl From<Http1LoopbackError> for FixtureError {
    fn from(error: Http1LoopbackError) -> Self {
        Self::Scenario(error)
    }
}

fn parse_http1_loopback(
    args: impl IntoIterator<Item = String>,
) -> Result<Http1LoopbackConfig, FixtureError> {
    let mut config = Http1LoopbackConfig::default();
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
            "--listen-port" => config.run.listen_port = parse_u16(&option, &value)?,
            "--ready-file" => ready_file = Some(PathBuf::from(value)),
            "--start-file" => start_file = Some(PathBuf::from(value)),
            "--requests" => config.traffic.requests = parse_usize(&option, &value)?,
            "--request-body-bytes" => {
                config.traffic.request_body_bytes = parse_usize(&option, &value)?;
            }
            "--response-body-bytes" => {
                config.traffic.response_body_bytes = parse_usize(&option, &value)?;
            }
            "--write-chunks" => config.traffic.write_chunks = parse_usize(&option, &value)?,
            _ => {
                return Err(FixtureError::usage(format!(
                    "unknown option {option}\n\n{USAGE}"
                )));
            }
        }
    }
    config.run.coordination = parse_coordination(ready_file, start_file)?;
    Ok(config)
}

fn parse_coordination(
    ready_file: Option<PathBuf>,
    start_file: Option<PathBuf>,
) -> Result<Http1LoopbackCoordination, FixtureError> {
    match (ready_file, start_file) {
        (None, None) => Ok(Http1LoopbackCoordination::Immediate),
        (Some(ready_file), Some(start_file)) if ready_file == start_file => {
            Err(FixtureError::usage(format!(
                "--ready-file and --start-file must be different paths\n\n{USAGE}"
            )))
        }
        (Some(ready_file), Some(start_file)) => Ok(Http1LoopbackCoordination::TwoPhase {
            ready_file,
            start_file,
        }),
        (Some(_), None) | (None, Some(_)) => Err(FixtureError::usage(format!(
            "--ready-file and --start-file must be supplied together\n\n{USAGE}"
        ))),
    }
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
        ])?;

        assert_eq!(config.run.listen_port, 0);
        assert_eq!(
            config.run.coordination,
            Http1LoopbackCoordination::TwoPhase {
                ready_file: PathBuf::from("/tmp/ready"),
                start_file: PathBuf::from("/tmp/start")
            }
        );
        assert_eq!(config.traffic.requests, 2);
        assert_eq!(config.traffic.request_body_bytes, 128);
        assert_eq!(config.traffic.response_body_bytes, 64);
        assert_eq!(config.traffic.write_chunks, 3);
        Ok(())
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
        let report = run(["http1-loopback".to_string(), "--help".to_string()])?;

        assert!(report.to_string().contains("http1-loopback"));
        Ok(())
    }
}
