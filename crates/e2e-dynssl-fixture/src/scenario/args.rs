use std::{net::SocketAddr, path::PathBuf, time::Duration};

const USAGE: &str = "\
usage: sssa-e2e-dynssl-fixture [options]

Options:
  --server-addr ADDR
  --process-ready-file PATH
  --phase-libssl PATH
  --phase-load-start-file PATH
  --phase-library-ready-file PATH
  --phase-exchange-start-file PATH
  --request-index N
  --request-body-bytes N
  --post-write-delay-ms N
";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScenarioArgs {
    pub(crate) server_addr: SocketAddr,
    pub(crate) process_ready_file: PathBuf,
    pub(crate) phases: Vec<LibsslPhaseArgs>,
    pub(crate) request_index: usize,
    pub(crate) request_body_bytes: usize,
    pub(crate) post_write_delay: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LibsslPhaseArgs {
    pub(crate) libssl_path: PathBuf,
    pub(crate) load_start_file: PathBuf,
    pub(crate) library_ready_file: PathBuf,
    pub(crate) exchange_start_file: PathBuf,
}

pub(crate) fn parse(args: impl IntoIterator<Item = String>) -> Result<ScenarioArgs, String> {
    let mut server_addr = None;
    let mut process_ready_file = None;
    let mut phase_libssl_paths = Vec::new();
    let mut phase_load_start_files = Vec::new();
    let mut phase_library_ready_files = Vec::new();
    let mut phase_exchange_start_files = Vec::new();
    let mut request_index = 0;
    let mut request_body_bytes = 48;
    let mut post_write_delay = Duration::from_millis(500);
    let mut args = args.into_iter();
    while let Some(option) = args.next() {
        if option == "--help" || option == "-h" {
            return Err(USAGE.to_string());
        }
        let Some(value) = args.next() else {
            return Err(format!("missing value for {option}\n\n{USAGE}"));
        };
        match option.as_str() {
            "--server-addr" => server_addr = Some(parse_socket_addr(&option, &value)?),
            "--process-ready-file" => process_ready_file = Some(PathBuf::from(value)),
            "--phase-libssl" => phase_libssl_paths.push(PathBuf::from(value)),
            "--phase-load-start-file" => phase_load_start_files.push(PathBuf::from(value)),
            "--phase-library-ready-file" => phase_library_ready_files.push(PathBuf::from(value)),
            "--phase-exchange-start-file" => phase_exchange_start_files.push(PathBuf::from(value)),
            "--request-index" => request_index = parse_usize(&option, &value)?,
            "--request-body-bytes" => request_body_bytes = parse_usize(&option, &value)?,
            "--post-write-delay-ms" => {
                post_write_delay = Duration::from_millis(parse_u64(&option, &value)?);
            }
            _ => return Err(format!("unknown option {option}\n\n{USAGE}")),
        }
    }
    Ok(ScenarioArgs {
        server_addr: server_addr.ok_or_else(|| format!("missing --server-addr\n\n{USAGE}"))?,
        process_ready_file: process_ready_file
            .ok_or_else(|| format!("missing --process-ready-file\n\n{USAGE}"))?,
        phases: libssl_phases(
            phase_libssl_paths,
            phase_load_start_files,
            phase_library_ready_files,
            phase_exchange_start_files,
        )?,
        request_index,
        request_body_bytes,
        post_write_delay,
    })
}

fn libssl_phases(
    libssl_paths: Vec<PathBuf>,
    load_start_files: Vec<PathBuf>,
    library_ready_files: Vec<PathBuf>,
    exchange_start_files: Vec<PathBuf>,
) -> Result<Vec<LibsslPhaseArgs>, String> {
    let count = libssl_paths.len();
    if count == 0 {
        return Err(format!(
            "at least one --phase-libssl group is required\n\n{USAGE}"
        ));
    }
    if load_start_files.len() != count
        || library_ready_files.len() != count
        || exchange_start_files.len() != count
    {
        return Err(format!(
            "each libssl phase requires --phase-libssl, --phase-load-start-file, --phase-library-ready-file, and --phase-exchange-start-file\n\n{USAGE}"
        ));
    }
    Ok(libssl_paths
        .into_iter()
        .zip(load_start_files)
        .zip(library_ready_files)
        .zip(exchange_start_files)
        .map(
            |(((libssl_path, load_start_file), library_ready_file), exchange_start_file)| {
                LibsslPhaseArgs {
                    libssl_path,
                    load_start_file,
                    library_ready_file,
                    exchange_start_file,
                }
            },
        )
        .collect())
}

fn parse_socket_addr(option: &str, value: &str) -> Result<SocketAddr, String> {
    value
        .parse()
        .map_err(|error| format!("invalid value for {option}: {value}: {error}"))
}

fn parse_usize(option: &str, value: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|error| format!("invalid value for {option}: {value}: {error}"))
}

fn parse_u64(option: &str, value: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|error| format!("invalid value for {option}: {value}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_groups_require_matching_options() {
        let error = parse(required_args().into_iter().chain([
            "--phase-libssl".to_string(),
            "/tmp/libssl.so.3".to_string(),
            "--phase-load-start-file".to_string(),
            "/tmp/load.start".to_string(),
        ]))
        .expect_err("partial phase group must be rejected");

        assert!(error.contains("each libssl phase requires"));
    }

    #[test]
    fn parses_ordered_libssl_phases() -> Result<(), Box<dyn std::error::Error>> {
        let args = parse(required_args().into_iter().chain(phase_args([
            (
                "/tmp/libssl.so.3",
                "/tmp/load.start",
                "/tmp/library.ready",
                "/tmp/exchange.start",
            ),
            (
                "/tmp/libssl-next.so.3",
                "/tmp/reload.start",
                "/tmp/reload.ready",
                "/tmp/reload-exchange.start",
            ),
        ])))?;

        assert_eq!(args.phases.len(), 2);
        assert_eq!(
            args.phases[0].libssl_path,
            PathBuf::from("/tmp/libssl.so.3")
        );
        assert_eq!(
            args.phases[1].exchange_start_file,
            PathBuf::from("/tmp/reload-exchange.start")
        );
        Ok(())
    }

    fn required_args() -> Vec<String> {
        [
            "--server-addr",
            "127.0.0.1:8443",
            "--process-ready-file",
            "/tmp/process.ready",
        ]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect()
    }

    fn phase_args<const N: usize>(phases: [(&str, &str, &str, &str); N]) -> Vec<String> {
        phases
            .into_iter()
            .flat_map(
                |(libssl_path, load_start_file, library_ready_file, exchange_start_file)| {
                    [
                        "--phase-libssl".to_string(),
                        libssl_path.to_string(),
                        "--phase-load-start-file".to_string(),
                        load_start_file.to_string(),
                        "--phase-library-ready-file".to_string(),
                        library_ready_file.to_string(),
                        "--phase-exchange-start-file".to_string(),
                        exchange_start_file.to_string(),
                    ]
                },
            )
            .collect()
    }
}
