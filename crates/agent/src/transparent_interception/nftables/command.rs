use std::{
    fs, io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) trait NftCommand {
    fn apply(&mut self, script: &str) -> io::Result<CommandResult>;
    fn check(&mut self, script: &str) -> io::Result<CommandResult>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CommandResult {
    pub(super) success: bool,
    pub(super) stdout: Vec<u8>,
    pub(super) stderr: Vec<u8>,
}

impl CommandResult {
    pub(super) fn failure_reason(&self, command: &str) -> String {
        let stderr = String::from_utf8_lossy(trim_ascii_whitespace(&self.stderr));
        if stderr.is_empty() {
            format!("{command} failed without stderr")
        } else {
            format!("{command} failed: {stderr}")
        }
    }
}

pub(super) struct SystemNft {
    command: PathBuf,
}

impl SystemNft {
    pub(super) fn new(command: PathBuf) -> Self {
        Self { command }
    }
}

impl NftCommand for SystemNft {
    fn apply(&mut self, script: &str) -> io::Result<CommandResult> {
        run_with_script(Command::new(&self.command).args(["-f", "-"]), script)
    }

    fn check(&mut self, script: &str) -> io::Result<CommandResult> {
        run_with_script(
            Command::new(&self.command).args(["--check", "-f", "-"]),
            script,
        )
    }
}

pub(super) fn find_nft_command() -> Option<PathBuf> {
    trusted_nft_paths()
        .into_iter()
        .find(|candidate| is_executable_file(candidate))
}

pub(super) fn is_root() -> bool {
    rustix::process::geteuid().as_raw() == 0
}

fn trusted_nft_paths() -> impl IntoIterator<Item = PathBuf> {
    ["/usr/sbin/nft", "/usr/bin/nft", "/sbin/nft", "/bin/nft"].map(PathBuf::from)
}

fn is_executable_file(path: &Path) -> bool {
    fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

fn run_with_script(command: &mut Command, script: &str) -> io::Result<CommandResult> {
    command.stdin(Stdio::piped());
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("failed to open command stdin"))?;
    use std::io::Write as _;
    stdin.write_all(script.as_bytes())?;
    drop(stdin);
    wait_with_timeout(child)
}

fn wait_with_timeout(mut child: std::process::Child) -> io::Result<CommandResult> {
    let deadline = Instant::now() + COMMAND_TIMEOUT;
    loop {
        if child.try_wait()?.is_some() {
            let output = child.wait_with_output()?;
            return Ok(CommandResult {
                success: output.status.success(),
                stdout: output.stdout,
                stderr: output.stderr,
            });
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "transparent interception command timed out after {}ms",
                    COMMAND_TIMEOUT.as_millis()
                ),
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
