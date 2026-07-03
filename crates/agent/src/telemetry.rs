use std::{
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use probe_config::probe_home_path;
use rustix::fs::OFlags;
use tracing_subscriber::fmt::MakeWriter;

pub(crate) fn init_for_current_invocation() {
    if is_tui_invocation() {
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(TuiTraceWriter::open(tui_trace_log_path()))
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .init();
    }
}

fn is_tui_invocation() -> bool {
    is_tui_invocation_from(std::env::args_os())
}

fn is_tui_invocation_from(args: impl IntoIterator<Item = OsString>) -> bool {
    args.into_iter()
        .nth(1)
        .is_some_and(|arg| arg.as_os_str() == OsStr::new("tui"))
}

fn tui_trace_log_path() -> PathBuf {
    probe_home_path("log/tui.log")
}

#[derive(Debug, Clone)]
enum TuiTraceWriter {
    File(Arc<Mutex<File>>),
    Sink,
}

impl TuiTraceWriter {
    fn open(path: PathBuf) -> Self {
        match open_tui_trace_log(&path) {
            Ok(file) => Self::File(Arc::new(Mutex::new(file))),
            Err(_) => Self::Sink,
        }
    }
}

impl<'a> MakeWriter<'a> for TuiTraceWriter {
    type Writer = TuiTraceWriteGuard;

    fn make_writer(&'a self) -> Self::Writer {
        match self {
            Self::File(file) => TuiTraceWriteGuard::file(Arc::clone(file)),
            Self::Sink => TuiTraceWriteGuard::sink(),
        }
    }
}

#[derive(Debug)]
enum TuiTraceWriteGuard {
    File(Arc<Mutex<File>>),
    Sink,
}

impl TuiTraceWriteGuard {
    fn file(file: Arc<Mutex<File>>) -> Self {
        Self::File(file)
    }

    fn sink() -> Self {
        Self::Sink
    }
}

impl Write for TuiTraceWriteGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::File(file) => file.lock().map_err(|_| poisoned_trace_log())?.write(buf),
            Self::Sink => Ok(buf.len()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::File(file) => file.lock().map_err(|_| poisoned_trace_log())?.flush(),
            Self::Sink => Ok(()),
        }
    }
}

fn poisoned_trace_log() -> io::Error {
    io::Error::other("TUI trace log writer lock is poisoned")
}

fn open_tui_trace_log(path: &Path) -> io::Result<File> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "TUI log path has no parent"))?;
    ensure_private_directory(parent)?;
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(OFlags::NOFOLLOW.bits() as i32)
        .open(path)
}

fn ensure_private_directory(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::other(format!(
            "{} must be a non-symlink directory",
            path.display()
        )));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    #[test]
    fn detects_tui_invocation() {
        assert!(is_tui_invocation_from([
            OsString::from("traffic-probe"),
            OsString::from("tui"),
        ]));
        assert!(!is_tui_invocation_from([
            OsString::from("traffic-probe"),
            OsString::from("run"),
        ]));
    }

    #[test]
    fn tui_trace_log_rejects_symlink_file() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let target = temp.path().join("target.log");
        let link = temp.path().join("tui.log");
        fs::write(&target, "target")?;
        symlink(&target, &link)?;

        let error = open_tui_trace_log(&link).expect_err("symlink log file must fail closed");

        assert_eq!(
            error.raw_os_error(),
            Some(rustix::io::Errno::LOOP.raw_os_error())
        );
        assert_eq!(fs::read_to_string(target)?, "target");
        Ok(())
    }

    #[test]
    fn tui_trace_log_rejects_symlink_directory() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let real = temp.path().join("real");
        let link = temp.path().join("link");
        fs::create_dir(&real)?;
        symlink(&real, &link)?;

        let error = open_tui_trace_log(&link.join("tui.log"))
            .expect_err("symlink log directory must fail closed");

        assert_eq!(error.kind(), io::ErrorKind::Other);
        Ok(())
    }
}
