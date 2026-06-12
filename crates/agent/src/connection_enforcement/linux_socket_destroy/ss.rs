use std::{
    fs, io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use probe_core::EventEnvelope;

const SS_KILL_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) trait SsKill {
    fn kill(&mut self, request: &SsKillRequest) -> io::Result<SsKillResult>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SsKillRequest {
    pub(super) local_address: String,
    pub(super) local_port: u16,
    pub(super) remote_address: String,
    pub(super) remote_port: u16,
}

impl SsKillRequest {
    pub(super) fn from_event(event: &EventEnvelope) -> Self {
        Self {
            local_address: event.flow.local.address.clone(),
            local_port: event.flow.local.port,
            remote_address: event.flow.remote.address.clone(),
            remote_port: event.flow.remote.port,
        }
    }

    pub(super) fn args(&self) -> Vec<String> {
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

pub(super) struct SystemSsKill {
    command: PathBuf,
}

impl SystemSsKill {
    pub(super) fn new(command: PathBuf) -> Self {
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
pub(super) struct SsKillResult {
    pub(super) success: bool,
    pub(super) stdout: Vec<u8>,
    pub(super) stderr: Vec<u8>,
}

impl SsKillResult {
    pub(super) fn closed_any_socket(&self) -> bool {
        String::from_utf8_lossy(&self.stdout)
            .lines()
            .any(is_socket_destroy_output_row)
    }

    pub(super) fn failure_reason(&self) -> String {
        let stderr = String::from_utf8_lossy(trim_ascii_whitespace(&self.stderr));
        if stderr.is_empty() {
            "ss -K failed without stderr".to_string()
        } else {
            format!("ss -K failed: {stderr}")
        }
    }
}

pub(super) fn find_ss_command() -> Option<PathBuf> {
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

pub(super) fn is_root() -> bool {
    rustix::process::geteuid().as_raw() == 0
}

pub(super) fn ss_supports_kill(command: &Path) -> bool {
    let Ok(output) = Command::new(command).arg("--help").output() else {
        return false;
    };
    let mut help = output.stdout;
    help.extend_from_slice(&output.stderr);
    let help = String::from_utf8_lossy(&help);
    help.contains("-K") && help.contains("--kill")
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
}
