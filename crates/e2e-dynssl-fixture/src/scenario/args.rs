use std::{net::SocketAddr, path::PathBuf, time::Duration};

const USAGE: &str = "\
usage: sssa-e2e-dynssl-fixture [options]

Options:
  --server-addr ADDR
  --libssl PATH
  --process-ready-file PATH
  --load-start-file PATH
  --library-ready-file PATH
  --exchange-start-file PATH
  --request-index N
  --request-body-bytes N
  --post-write-delay-ms N
";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScenarioArgs {
    pub(crate) server_addr: SocketAddr,
    pub(crate) libssl_path: PathBuf,
    pub(crate) process_ready_file: PathBuf,
    pub(crate) load_start_file: PathBuf,
    pub(crate) library_ready_file: PathBuf,
    pub(crate) exchange_start_file: PathBuf,
    pub(crate) request_index: usize,
    pub(crate) request_body_bytes: usize,
    pub(crate) post_write_delay: Duration,
}

pub(crate) fn parse(args: impl IntoIterator<Item = String>) -> Result<ScenarioArgs, String> {
    let mut server_addr = None;
    let mut libssl_path = None;
    let mut process_ready_file = None;
    let mut load_start_file = None;
    let mut library_ready_file = None;
    let mut exchange_start_file = None;
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
            "--libssl" => libssl_path = Some(PathBuf::from(value)),
            "--process-ready-file" => process_ready_file = Some(PathBuf::from(value)),
            "--load-start-file" => load_start_file = Some(PathBuf::from(value)),
            "--library-ready-file" => library_ready_file = Some(PathBuf::from(value)),
            "--exchange-start-file" => exchange_start_file = Some(PathBuf::from(value)),
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
        libssl_path: libssl_path.ok_or_else(|| format!("missing --libssl\n\n{USAGE}"))?,
        process_ready_file: process_ready_file
            .ok_or_else(|| format!("missing --process-ready-file\n\n{USAGE}"))?,
        load_start_file: load_start_file
            .ok_or_else(|| format!("missing --load-start-file\n\n{USAGE}"))?,
        library_ready_file: library_ready_file
            .ok_or_else(|| format!("missing --library-ready-file\n\n{USAGE}"))?,
        exchange_start_file: exchange_start_file
            .ok_or_else(|| format!("missing --exchange-start-file\n\n{USAGE}"))?,
        request_index,
        request_body_bytes,
        post_write_delay,
    })
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
