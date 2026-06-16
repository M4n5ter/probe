use std::{
    collections::BTreeSet,
    env,
    ffi::OsString,
    fs, io,
    io::{Read, Write},
    os::unix::{fs::DirBuilderExt, net::UnixListener},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus},
    sync::{Arc, Mutex},
    thread,
    thread::JoinHandle,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use capture::CaptureEvent;
use probe_core::{EventEnvelope, SpoolPayloadSchema};
use rustix::process::{Pid, Signal, kill_process_group};
use signal_hook::{
    consts::signal::{SIGINT, SIGTERM},
    iterator::{Handle as SignalHandle, Signals},
};
use storage::StoredEvent;

const CHILD_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const ATOMIC_FILE_TEMP_ATTEMPTS: usize = 128;
const READY_SIGNAL_BYTES: &[u8] = b"ready\n";

pub(crate) fn create_temp_root(name: &str) -> Result<PathBuf, std::io::Error> {
    let base = env::temp_dir();
    for attempt in 0..128 {
        let path = base.join(format!(
            "sssa-probe-e2e-{name}-{}-{}-{attempt}",
            std::process::id(),
            wall_time_unix_ns()
        ));
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(e2e_error(format!(
        "failed to allocate unique e2e temp directory under {}",
        base.display()
    )))
}

pub(crate) fn cargo_executable() -> OsString {
    env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"))
}

pub(crate) fn workspace_root() -> Result<PathBuf, std::io::Error> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|crates_dir| crates_dir.parent())
        .map(Path::to_path_buf)
        .ok_or_else(|| e2e_error("failed to resolve workspace root"))
}

pub(crate) fn debug_binary(binary: &str) -> Result<PathBuf, std::io::Error> {
    let target_dir = match env::var_os("CARGO_TARGET_DIR") {
        Some(path) => {
            let path = PathBuf::from(path);
            if path.is_absolute() {
                path
            } else {
                workspace_root()?.join(path)
            }
        }
        None => workspace_root()?.join("target"),
    };
    let path = target_dir.join("debug").join(binary_name(binary));
    if path.is_file() {
        validate_debug_binary_fresh(&path)?;
        return Ok(path);
    }

    Err(e2e_error(format!(
        "missing debug binary {}; run `cargo build -p agent -p e2e-fixture -p xtask --locked` before privileged e2e",
        path.display()
    )))
}

pub(crate) fn run_in_own_process_group(command: &mut Command) -> &mut Command {
    use std::os::unix::process::CommandExt;

    command.process_group(0)
}

pub(crate) fn publish_atomic_file(path: &Path, bytes: &[u8]) -> Result<(), io::Error> {
    for attempt in 0..ATOMIC_FILE_TEMP_ATTEMPTS {
        let temp_path = sibling_temp_path(path, attempt);
        match write_new_file(&temp_path, bytes) {
            Ok(()) => {
                if let Err(error) = fs::rename(&temp_path, path) {
                    let _ = fs::remove_file(&temp_path);
                    return Err(error);
                }
                return Ok(());
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(e2e_error(format!(
        "failed to allocate atomic temp file beside {}",
        path.display()
    )))
}

pub(crate) struct UnixSocketReadySignal {
    path: PathBuf,
    listener: UnixListener,
}

impl UnixSocketReadySignal {
    pub(crate) fn bind(path: PathBuf) -> Result<Self, io::Error> {
        let listener = UnixListener::bind(&path)?;
        Ok(Self { path, listener })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn listener_mut(&mut self) -> &mut UnixListener {
        &mut self.listener
    }
}

#[derive(Clone, Copy)]
struct SupervisedChild {
    name: &'static str,
    process_group: Pid,
}

pub(crate) struct ChildSupervisor {
    children: Arc<Mutex<Vec<SupervisedChild>>>,
    signal_handle: SignalHandle,
    signal_thread: Option<JoinHandle<()>>,
}

impl ChildSupervisor {
    pub(crate) fn new() -> Result<Self, io::Error> {
        let children = Arc::new(Mutex::new(Vec::new()));
        let mut signals = Signals::new([SIGINT, SIGTERM])?;
        let signal_handle = signals.handle();
        let signal_children = Arc::clone(&children);
        let signal_thread = thread::spawn(move || {
            if let Some(signal) = (&mut signals).into_iter().next() {
                terminate_supervised_children(&signal_children);
                std::process::exit(128 + signal);
            }
        });

        Ok(Self {
            children,
            signal_handle,
            signal_thread: Some(signal_thread),
        })
    }

    pub(crate) fn watch(&self, child: Child, name: &'static str) -> ChildGuard {
        let process_group = Pid::from_child(&child);
        self.children
            .lock()
            .expect("supervised child registry poisoned")
            .push(SupervisedChild {
                name,
                process_group,
            });
        ChildGuard {
            name,
            child,
            process_group,
            children: Arc::clone(&self.children),
        }
    }
}

impl Drop for ChildSupervisor {
    fn drop(&mut self) {
        self.signal_handle.close();
        if let Some(thread) = self.signal_thread.take()
            && let Err(error) = thread.join()
        {
            eprintln!("signal supervisor thread join failed: {error:?}");
        }
    }
}

pub(crate) struct ChildGuard {
    name: &'static str,
    child: Child,
    process_group: Pid,
    children: Arc<Mutex<Vec<SupervisedChild>>>,
}

impl ChildGuard {
    pub(crate) fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }

    pub(crate) fn unwatch(&self) {
        unregister_child(&self.children, self.process_group);
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        cleanup_child(&mut self.child, self.name);
        self.unwatch();
    }
}

pub(crate) fn wait_for_file_or_child_exit(
    child: &mut Child,
    path: &Path,
    timeout: Duration,
    label: &'static str,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + timeout;
    loop {
        if path.try_exists()? {
            return Ok(());
        }
        if let Some(status) = child.try_wait()? {
            return Err(e2e_error(format!(
                "{label} file was not written before child exited with {status}"
            ))
            .into());
        }
        if Instant::now() >= deadline {
            return Err(e2e_error(format!(
                "timed out waiting for {label} file {}",
                path.display()
            ))
            .into());
        }
        thread::sleep(Duration::from_millis(20));
    }
}

pub(crate) fn wait_for_ready_signal_or_child_exit(
    child: &mut Child,
    listener: &mut UnixListener,
    timeout: Duration,
    label: &'static str,
) -> Result<(), Box<dyn std::error::Error>> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => return read_ready_signal(&mut stream, label),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
        if let Some(status) = child.try_wait()? {
            return Err(e2e_error(format!(
                "{label} signal was not written before child exited with {status}"
            ))
            .into());
        }
        if Instant::now() >= deadline {
            return Err(e2e_error(format!("timed out waiting for {label} signal")).into());
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn read_ready_signal(
    stream: &mut std::os::unix::net::UnixStream,
    label: &'static str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut received = [0_u8; READY_SIGNAL_BYTES.len()];
    stream.read_exact(&mut received)?;
    if received == READY_SIGNAL_BYTES {
        return Ok(());
    }
    Err(e2e_error(format!(
        "{label} socket returned invalid readiness payload: {:?}",
        String::from_utf8_lossy(&received)
    ))
    .into())
}

pub(crate) fn wait_for_child_exit(
    child: &mut Child,
    timeout: Duration,
    name: &'static str,
) -> Result<(), Box<dyn std::error::Error>> {
    match wait_for_exit(child, timeout)? {
        Some(status) if status.success() => Ok(()),
        Some(status) => Err(e2e_error(format!("{name} exited with {status}")).into()),
        None => {
            send_sigkill(child)?;
            let status = child.wait()?;
            Err(e2e_error(format!("{name} timed out and was killed with {status}")).into())
        }
    }
}

pub(crate) fn stop_running_child(
    child: &mut Child,
    name: &'static str,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(status) = child.try_wait()? {
        return Err(e2e_error(format!("{name} exited before shutdown with {status}")).into());
    }
    send_sigterm(child)?;
    if let Some(status) = wait_for_exit(child, CHILD_SHUTDOWN_TIMEOUT)? {
        return if status.success() {
            Ok(())
        } else {
            Err(e2e_error(format!("{name} exited after SIGTERM with {status}")).into())
        };
    }
    send_sigkill(child)?;
    let status = child.wait()?;
    Err(e2e_error(format!(
        "{name} did not exit after SIGTERM within {:?}; killed with {status}",
        CHILD_SHUTDOWN_TIMEOUT
    ))
    .into())
}

pub(crate) fn wall_time_unix_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_nanos()).unwrap_or(i64::MAX)
        })
}

fn binary_name(binary: &str) -> String {
    format!("{binary}{}", env::consts::EXE_SUFFIX)
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), io::Error> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)
}

fn sibling_temp_path(path: &Path, attempt: usize) -> PathBuf {
    let mut file_name = path
        .file_name()
        .map(OsString::from)
        .unwrap_or_else(|| OsString::from("atomic"));
    file_name.push(format!(
        ".tmp.{}.{}.{}",
        std::process::id(),
        wall_time_unix_ns(),
        attempt
    ));
    path.with_file_name(file_name)
}

fn validate_debug_binary_fresh(path: &Path) -> Result<(), io::Error> {
    let binary_mtime = fs::metadata(path)?.modified()?;
    for input in cargo_dep_info_build_inputs(path)? {
        let input_mtime = fs::metadata(&input).map_err(|source| {
            e2e_error(format!(
                "debug binary {} was built from missing or unreadable input {}; run `cargo build -p agent -p e2e-fixture -p xtask --locked` before privileged e2e: {source}",
                path.display(),
                input.display()
            ))
        })?.modified()?;
        if input_mtime > binary_mtime {
            return Err(e2e_error(format!(
                "debug binary {} is older than build input {}; run `cargo build -p agent -p e2e-fixture -p xtask --locked` before privileged e2e",
                path.display(),
                input.display()
            )));
        }
    }
    Ok(())
}

fn cargo_dep_info_build_inputs(binary_path: &Path) -> Result<Vec<PathBuf>, io::Error> {
    let root = workspace_root()?;
    let dep_info_path = binary_path.with_extension("d");
    let dep_info = fs::read_to_string(&dep_info_path).map_err(|source| {
        e2e_error(format!(
            "missing Cargo dep-info for debug binary {}; run `cargo build -p agent -p e2e-fixture -p xtask --locked` before privileged e2e: {source}",
            binary_path.display()
        ))
    })?;
    let mut inputs = parse_dep_info_dependencies(&dep_info)
        .into_iter()
        .map(|path| {
            if path.is_absolute() {
                path
            } else {
                root.join(path)
            }
        })
        .collect::<BTreeSet<_>>();
    if inputs.is_empty() {
        return Err(e2e_error(format!(
            "Cargo dep-info {} did not list any inputs for {}; rebuild before privileged e2e",
            dep_info_path.display(),
            binary_path.display()
        )));
    }
    inputs.insert(root.join("Cargo.lock"));
    inputs.insert(root.join("Cargo.toml"));
    for input in inputs.clone() {
        add_scoped_manifest_inputs(&root, &input, &mut inputs);
    }
    Ok(inputs.into_iter().collect())
}

fn add_scoped_manifest_inputs(root: &Path, input: &Path, inputs: &mut BTreeSet<PathBuf>) {
    let Ok(relative) = input.strip_prefix(root) else {
        return;
    };
    let mut components = relative.components();
    let Some(first) = components.next() else {
        return;
    };
    let Some(crate_name) = components.next() else {
        return;
    };
    if first.as_os_str() != "crates" {
        return;
    }
    let crate_root = root.join("crates").join(crate_name.as_os_str());
    for path in [crate_root.join("Cargo.toml"), crate_root.join("build.rs")] {
        if path.is_file() {
            inputs.insert(path);
        }
    }
}

fn parse_dep_info_dependencies(contents: &str) -> Vec<PathBuf> {
    let Some(section) = dep_info_dependency_section(contents) else {
        return Vec::new();
    };
    parse_makefile_tokens(section)
        .into_iter()
        .map(PathBuf::from)
        .collect()
}

fn dep_info_dependency_section(contents: &str) -> Option<&str> {
    let mut escaped = false;
    for (index, character) in contents.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' => escaped = true,
            ':' => return Some(&contents[index + character.len_utf8()..]),
            _ => {}
        }
    }
    None
}

fn parse_makefile_tokens(contents: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut characters = contents.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '\\' => match characters.next() {
                Some('\n') => {}
                Some('\r') => {
                    if matches!(characters.peek(), Some('\n')) {
                        let _ = characters.next();
                    }
                }
                Some(escaped) => token.push(escaped),
                None => token.push('\\'),
            },
            character if character.is_whitespace() => {
                if !token.is_empty() {
                    tokens.push(std::mem::take(&mut token));
                }
            }
            _ => token.push(character),
        }
    }
    if !token.is_empty() {
        tokens.push(token);
    }
    tokens
}

fn cleanup_child(child: &mut Child, name: &'static str) {
    match child.try_wait() {
        Ok(Some(_)) => return,
        Ok(None) => {}
        Err(error) => {
            eprintln!("{name} cleanup status check failed after e2e error: {error}");
            return;
        }
    }
    if let Err(error) = send_sigterm(child) {
        eprintln!("{name} cleanup SIGTERM failed after e2e error: {error}");
        try_reap_child(child, name);
        return;
    }
    match wait_for_exit(child, CHILD_SHUTDOWN_TIMEOUT) {
        Ok(Some(_)) => {}
        Ok(None) => {
            if let Err(error) = send_sigkill(child) {
                eprintln!("{name} cleanup kill failed after e2e error: {error}");
            }
            if let Err(error) = child.wait() {
                eprintln!("{name} cleanup wait failed after e2e error: {error}");
            }
        }
        Err(error) => {
            eprintln!("{name} cleanup wait failed after e2e error: {error}");
        }
    }
}

fn terminate_supervised_children(children: &Arc<Mutex<Vec<SupervisedChild>>>) {
    let children = snapshot_children(children);
    if children.is_empty() {
        return;
    }
    for child in &children {
        if let Err(error) = send_signal_to_process_group(child.process_group, Signal::TERM) {
            eprintln!("{} signal cleanup SIGTERM failed: {error}", child.name);
        }
    }
}

fn snapshot_children(children: &Arc<Mutex<Vec<SupervisedChild>>>) -> Vec<SupervisedChild> {
    children
        .lock()
        .expect("supervised child registry poisoned")
        .clone()
}

fn unregister_child(children: &Arc<Mutex<Vec<SupervisedChild>>>, process_group: Pid) {
    children
        .lock()
        .expect("supervised child registry poisoned")
        .retain(|child| child.process_group != process_group);
}

fn try_reap_child(child: &mut Child, name: &'static str) {
    match child.try_wait() {
        Ok(Some(_)) | Ok(None) => {}
        Err(error) => eprintln!("{name} cleanup reap failed after e2e error: {error}"),
    }
}

fn send_sigterm(child: &Child) -> Result<(), Box<dyn std::error::Error>> {
    let process_group = Pid::from_child(child);
    send_signal_to_process_group(process_group, Signal::TERM).map_err(|source| {
        e2e_error(format!(
            "failed to send SIGTERM to child process group {}: {source}",
            process_group.as_raw_pid()
        ))
        .into()
    })
}

fn send_sigkill(child: &Child) -> Result<(), Box<dyn std::error::Error>> {
    let process_group = Pid::from_child(child);
    send_signal_to_process_group(process_group, Signal::KILL).map_err(|source| {
        e2e_error(format!(
            "failed to send SIGKILL to child process group {}: {source}",
            process_group.as_raw_pid()
        ))
        .into()
    })
}

fn send_signal_to_process_group(
    process_group: Pid,
    signal: Signal,
) -> Result<(), rustix::io::Errno> {
    kill_process_group(process_group, signal)
}

fn wait_for_exit(
    child: &mut Child,
    timeout: Duration,
) -> Result<Option<ExitStatus>, std::io::Error> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(50));
    }
}

pub(crate) fn decode_capture_event(
    event: &StoredEvent,
) -> Result<CaptureEvent, Box<dyn std::error::Error>> {
    if event.payload.schema() != &SpoolPayloadSchema::CaptureEventJson {
        return Err(e2e_error(format!(
            "ingress record {} used unexpected schema {}",
            event.sequence,
            event.payload.schema_wire()
        ))
        .into());
    }
    serde_json::from_slice::<CaptureEvent>(event.payload.bytes()).map_err(Into::into)
}

pub(crate) fn decode_envelope(
    event: &StoredEvent,
) -> Result<EventEnvelope, Box<dyn std::error::Error>> {
    if event.payload.schema() != &SpoolPayloadSchema::EventEnvelopeJson {
        return Err(e2e_error(format!(
            "export record {} used unexpected schema {}",
            event.sequence,
            event.payload.schema_wire()
        ))
        .into());
    }
    serde_json::from_slice::<EventEnvelope>(event.payload.bytes()).map_err(Into::into)
}

pub(crate) fn e2e_error(message: impl Into<String>) -> std::io::Error {
    std::io::Error::other(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dep_info_dependencies_handle_makefile_escapes() {
        let deps = parse_dep_info_dependencies(
            "/tmp/target/debug/fixture: /tmp/src/main.rs /tmp/src/space\\ file.rs \\\n /tmp/src/next.rs\n",
        );

        assert_eq!(
            deps,
            vec![
                PathBuf::from("/tmp/src/main.rs"),
                PathBuf::from("/tmp/src/space file.rs"),
                PathBuf::from("/tmp/src/next.rs"),
            ]
        );
    }
}
