use std::{
    io::{self, Read},
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus},
    sync::{Arc, Mutex},
    thread,
    thread::JoinHandle,
    time::{Duration, Instant},
};

use rustix::process::{Pid, Signal, kill_process_group};
use signal_hook::{
    consts::signal::{SIGINT, SIGTERM},
    iterator::{Handle as SignalHandle, Signals},
};

use super::e2e_error;

const CHILD_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const READY_SIGNAL_BYTES: &[u8] = b"ready\n";

pub(crate) fn run_in_own_process_group(command: &mut Command) -> &mut Command {
    use std::os::unix::process::CommandExt;

    command.process_group(0)
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

pub(crate) fn wait_for_child_status(
    child: &mut Child,
    timeout: Duration,
    name: &'static str,
) -> Result<ExitStatus, Box<dyn std::error::Error>> {
    match wait_for_exit(child, timeout)? {
        Some(status) => Ok(status),
        None => {
            send_sigkill(child)?;
            let status = child.wait()?;
            Err(e2e_error(format!(
                "{name} did not exit within {timeout:?}; killed with {status}",
            ))
            .into())
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

fn read_ready_signal(
    stream: &mut UnixStream,
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

fn wait_for_exit(child: &mut Child, timeout: Duration) -> Result<Option<ExitStatus>, io::Error> {
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
