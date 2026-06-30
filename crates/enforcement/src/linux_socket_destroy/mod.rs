use std::{
    fmt, fs,
    io::{self, Read, Write},
    net::{Ipv4Addr, TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use probe_core::FlowContext;

const SS_KILL_TIMEOUT: Duration = Duration::from_secs(2);

pub trait SsKill {
    fn kill(&mut self, request: &SsKillRequest) -> io::Result<SsKillResult>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsKillRequest {
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub remote_port: u16,
}

impl SsKillRequest {
    pub fn from_flow(flow: &FlowContext) -> Self {
        Self {
            local_address: flow.local.address.clone(),
            local_port: flow.local.port,
            remote_address: flow.remote.address.clone(),
            remote_port: flow.remote.port,
        }
    }

    pub fn args(&self) -> Vec<String> {
        vec![
            "-H".to_string(),
            "-K".to_string(),
            "-t".to_string(),
            "state".to_string(),
            "connected".to_string(),
            "src".to_string(),
            self.local_address.clone(),
            "sport".to_string(),
            "=".to_string(),
            format!(":{}", self.local_port),
            "dst".to_string(),
            self.remote_address.clone(),
            "dport".to_string(),
            "=".to_string(),
            format!(":{}", self.remote_port),
        ]
    }
}

pub struct SystemSsKill {
    command: PathBuf,
}

impl SystemSsKill {
    pub fn new(command: PathBuf) -> Self {
        Self { command }
    }
}

impl SsKill for SystemSsKill {
    fn kill(&mut self, request: &SsKillRequest) -> io::Result<SsKillResult> {
        let output = run_ss_kill_with_timeout(Command::new(&self.command).args(request.args()))?;
        Ok(SsKillResult {
            success: output.status.success(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsKillResult {
    pub success: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl SsKillResult {
    pub fn closed_any_socket(&self) -> bool {
        String::from_utf8_lossy(&self.stdout)
            .lines()
            .any(is_socket_destroy_output_row)
    }

    pub fn failure_reason(&self) -> String {
        let stderr = String::from_utf8_lossy(trim_ascii_whitespace(&self.stderr));
        if stderr.is_empty() {
            "ss -K failed without stderr".to_string()
        } else {
            format!("ss -K failed: {stderr}")
        }
    }
}

pub fn find_ss_command() -> Option<PathBuf> {
    trusted_ss_paths()
        .into_iter()
        .find(|candidate| is_executable_file(candidate))
}

fn trusted_ss_paths() -> impl IntoIterator<Item = PathBuf> {
    ["/usr/sbin/ss", "/usr/bin/ss", "/sbin/ss", "/bin/ss"].map(PathBuf::from)
}

fn is_executable_file(path: &Path) -> bool {
    fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

pub fn ss_supports_kill(command: &Path) -> bool {
    let Ok(output) = Command::new(command).arg("--help").output() else {
        return false;
    };
    let mut help = output.stdout;
    help.extend_from_slice(&output.stderr);
    let help = String::from_utf8_lossy(&help);
    help.contains("-K") && help.contains("--kill")
}

#[derive(Debug)]
struct LoopbackKillSelfTestResult {
    kill: SsKillResult,
    connection_probe: ConnectionProbeOutcome,
}

fn run_loopback_kill_self_test(command: &Path) -> io::Result<LoopbackKillSelfTestResult> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let target = listener.local_addr()?;
    let mut client = TcpStream::connect(target)?;
    let (mut server, _peer) = listener.accept()?;
    client.set_read_timeout(Some(SS_KILL_TIMEOUT))?;
    client.set_write_timeout(Some(SS_KILL_TIMEOUT))?;
    server.set_read_timeout(Some(SS_KILL_TIMEOUT))?;
    server.set_write_timeout(Some(SS_KILL_TIMEOUT))?;

    let client_addr = client.local_addr()?;
    let request = SsKillRequest {
        local_address: client_addr.ip().to_string(),
        local_port: client_addr.port(),
        remote_address: target.ip().to_string(),
        remote_port: target.port(),
    };
    let kill = SystemSsKill::new(command.to_path_buf()).kill(&request)?;
    let connection_probe = probe_connection_after_kill(&mut client, &mut server)?;
    drop(server);
    drop(client);
    Ok(LoopbackKillSelfTestResult {
        kill,
        connection_probe,
    })
}

pub fn check_loopback_socket_destroy_support(command: &Path) -> Result<(), String> {
    let result = run_loopback_kill_self_test(command)
        .map_err(|error| format!("failed to run ss -K loopback self-test: {error}"))?;
    if !result.kill.success {
        return Err(result.kill.failure_reason());
    }
    if !loopback_kill_self_test_proves_destroy(&result) {
        return Err(loopback_kill_self_test_failure(&result));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ConnectionProbeOutcome {
    Interrupted,
    Alive,
    Inconclusive {
        operation: ConnectionProbeOperation,
        error_kind: io::ErrorKind,
    },
}

impl fmt::Display for ConnectionProbeOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Interrupted => formatter.write_str("interrupted"),
            Self::Alive => formatter.write_str("alive"),
            Self::Inconclusive {
                operation,
                error_kind,
            } => write!(formatter, "inconclusive({operation}: {error_kind:?})"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionProbeOperation {
    Write,
    Read,
}

impl fmt::Display for ConnectionProbeOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Write => formatter.write_str("write"),
            Self::Read => formatter.write_str("read"),
        }
    }
}

fn probe_connection_after_kill(
    client: &mut impl Write,
    server: &mut impl Read,
) -> io::Result<ConnectionProbeOutcome> {
    const PROBE: &[u8] = b"traffic-probe-ss-kill-self-test";
    match client.write_all(PROBE) {
        Ok(()) => {}
        Err(error) => return socket_probe_error_outcome(ConnectionProbeOperation::Write, error),
    }

    let mut received = [0_u8; PROBE.len()];
    match server.read(&mut received) {
        Ok(0) => Ok(ConnectionProbeOutcome::Interrupted),
        Ok(_) => Ok(ConnectionProbeOutcome::Alive),
        Err(error) => socket_probe_error_outcome(ConnectionProbeOperation::Read, error),
    }
}

fn socket_probe_error_outcome(
    operation: ConnectionProbeOperation,
    error: io::Error,
) -> io::Result<ConnectionProbeOutcome> {
    if is_socket_interruption_error(&error) {
        Ok(ConnectionProbeOutcome::Interrupted)
    } else if is_inconclusive_socket_probe_error(&error) {
        Ok(ConnectionProbeOutcome::Inconclusive {
            operation,
            error_kind: error.kind(),
        })
    } else {
        Err(error)
    }
}

fn is_socket_interruption_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::UnexpectedEof
    )
}

fn is_inconclusive_socket_probe_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

fn loopback_kill_self_test_failure(result: &LoopbackKillSelfTestResult) -> String {
    format!(
        "ss -K loopback self-test did not prove socket destroy: reported_destroy={}, connection_probe={}",
        result.kill.closed_any_socket(),
        result.connection_probe,
    )
}

fn loopback_kill_self_test_proves_destroy(result: &LoopbackKillSelfTestResult) -> bool {
    result.kill.closed_any_socket()
        && matches!(result.connection_probe, ConnectionProbeOutcome::Interrupted)
}

fn run_ss_kill_with_timeout(command: &mut Command) -> io::Result<std::process::Output> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn()?;
    let deadline = Instant::now() + SS_KILL_TIMEOUT;
    loop {
        if child.try_wait()?.is_some() {
            return child.wait_with_output();
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("ss -K timed out after {}ms", SS_KILL_TIMEOUT.as_millis()),
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn trim_ascii_whitespace(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |index| index + 1);
    &bytes[start..end]
}

fn is_socket_destroy_output_row(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return false;
    }

    let is_header = trimmed.starts_with("Netid ")
        || trimmed.contains("Local Address:Port") && trimmed.contains("Peer Address:Port");
    !is_header
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ss_kill_request_builds_precise_tcp_filter_args() {
        let request = SsKillRequest {
            local_address: "127.0.0.1".to_string(),
            local_port: 41000,
            remote_address: "127.0.0.1".to_string(),
            remote_port: 8080,
        };

        assert_eq!(
            request.args(),
            [
                "-H",
                "-K",
                "-t",
                "state",
                "connected",
                "src",
                "127.0.0.1",
                "sport",
                "=",
                ":41000",
                "dst",
                "127.0.0.1",
                "dport",
                "=",
                ":8080",
            ]
        );
    }

    #[test]
    fn ss_kill_result_detects_socket_rows_and_ignores_headers() {
        let closed = SsKillResult {
            success: true,
            stdout: b"ESTAB 0 0 127.0.0.1:41000 127.0.0.1:8080\n".to_vec(),
            stderr: Vec::new(),
        };
        assert!(closed.closed_any_socket());

        let header_only = SsKillResult {
            success: true,
            stdout: b"Netid State Recv-Q Send-Q Local Address:Port Peer Address:PortProcess\n"
                .to_vec(),
            stderr: Vec::new(),
        };
        assert!(!header_only.closed_any_socket());

        let empty = SsKillResult {
            success: true,
            stdout: b"\n".to_vec(),
            stderr: Vec::new(),
        };
        assert!(!empty.closed_any_socket());
    }

    #[test]
    fn ss_kill_result_reports_trimmed_failure_stderr() {
        let failed_with_stderr = SsKillResult {
            success: false,
            stdout: Vec::new(),
            stderr: b"\n  permission denied  \n".to_vec(),
        };
        assert_eq!(
            failed_with_stderr.failure_reason(),
            "ss -K failed: permission denied"
        );

        let failed_without_stderr = SsKillResult {
            success: false,
            stdout: Vec::new(),
            stderr: b"\n  \t".to_vec(),
        };
        assert_eq!(
            failed_without_stderr.failure_reason(),
            "ss -K failed without stderr"
        );
    }

    #[test]
    fn probe_connection_after_kill_reports_alive_socket_pair() -> io::Result<()> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let target = listener.local_addr()?;
        let mut client = TcpStream::connect(target)?;
        let (mut server, _peer) = listener.accept()?;
        client.set_read_timeout(Some(SS_KILL_TIMEOUT))?;
        client.set_write_timeout(Some(SS_KILL_TIMEOUT))?;
        server.set_read_timeout(Some(SS_KILL_TIMEOUT))?;
        server.set_write_timeout(Some(SS_KILL_TIMEOUT))?;

        assert_eq!(
            probe_connection_after_kill(&mut client, &mut server)?,
            ConnectionProbeOutcome::Alive
        );
        Ok(())
    }

    #[test]
    fn probe_connection_after_kill_reports_closed_socket_as_interrupted() -> io::Result<()> {
        let mut writer = FailingWriter(io::ErrorKind::BrokenPipe);
        let mut reader = io::empty();

        assert_eq!(
            probe_connection_after_kill(&mut writer, &mut reader)?,
            ConnectionProbeOutcome::Interrupted
        );
        Ok(())
    }

    #[test]
    fn probe_connection_after_kill_reports_timeout_as_inconclusive() -> io::Result<()> {
        let mut timeout_writer = FailingWriter(io::ErrorKind::WouldBlock);
        let mut unused_reader = io::empty();
        assert_eq!(
            probe_connection_after_kill(&mut timeout_writer, &mut unused_reader)?,
            ConnectionProbeOutcome::Inconclusive {
                operation: ConnectionProbeOperation::Write,
                error_kind: io::ErrorKind::WouldBlock,
            }
        );

        let mut writer = Vec::new();
        let mut timeout_reader = FailingReader(io::ErrorKind::TimedOut);
        assert_eq!(
            probe_connection_after_kill(&mut writer, &mut timeout_reader)?,
            ConnectionProbeOutcome::Inconclusive {
                operation: ConnectionProbeOperation::Read,
                error_kind: io::ErrorKind::TimedOut,
            }
        );
        Ok(())
    }

    #[test]
    fn loopback_self_test_requires_reported_destroy_and_interrupted_connection() {
        let destroyed = LoopbackKillSelfTestResult {
            kill: kill_result_with_stdout(b"ESTAB 0 0 127.0.0.1:41000 127.0.0.1:8080\n"),
            connection_probe: ConnectionProbeOutcome::Interrupted,
        };
        assert!(loopback_kill_self_test_proves_destroy(&destroyed));

        let missing_report = LoopbackKillSelfTestResult {
            kill: kill_result_with_stdout(b"\n"),
            connection_probe: ConnectionProbeOutcome::Interrupted,
        };
        assert!(!loopback_kill_self_test_proves_destroy(&missing_report));
        assert!(
            loopback_kill_self_test_failure(&missing_report).contains("reported_destroy=false")
        );

        let live_connection = LoopbackKillSelfTestResult {
            kill: kill_result_with_stdout(b"ESTAB 0 0 127.0.0.1:41000 127.0.0.1:8080\n"),
            connection_probe: ConnectionProbeOutcome::Alive,
        };
        assert!(!loopback_kill_self_test_proves_destroy(&live_connection));
        assert!(
            loopback_kill_self_test_failure(&live_connection).contains("connection_probe=alive")
        );

        let inconclusive_connection = LoopbackKillSelfTestResult {
            kill: kill_result_with_stdout(b"ESTAB 0 0 127.0.0.1:41000 127.0.0.1:8080\n"),
            connection_probe: ConnectionProbeOutcome::Inconclusive {
                operation: ConnectionProbeOperation::Read,
                error_kind: io::ErrorKind::TimedOut,
            },
        };
        assert!(!loopback_kill_self_test_proves_destroy(
            &inconclusive_connection
        ));
        assert!(
            loopback_kill_self_test_failure(&inconclusive_connection)
                .contains("connection_probe=inconclusive(read: TimedOut)")
        );
    }

    fn kill_result_with_stdout(stdout: &[u8]) -> SsKillResult {
        SsKillResult {
            success: true,
            stdout: stdout.to_vec(),
            stderr: Vec::new(),
        }
    }

    struct FailingWriter(io::ErrorKind);

    impl Write for FailingWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(self.0))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct FailingReader(io::ErrorKind);

    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(self.0))
        }
    }
}
