use std::{
    env,
    ffi::OsString,
    fs, io,
    io::Write,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use super::e2e_error;

const ATOMIC_FILE_TEMP_ATTEMPTS: usize = 128;

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

pub(crate) fn run_with_temp_root(
    name: &str,
    run_at: impl FnOnce(&Path) -> Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let root = create_temp_root(name)?;
    match run_at(&root) {
        Ok(()) => {
            fs::remove_dir_all(&root)?;
            Ok(())
        }
        Err(error) => {
            eprintln!("e2e artifacts retained at {}", root.display());
            Err(error)
        }
    }
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

pub(crate) fn wall_time_unix_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_nanos()).unwrap_or(i64::MAX)
        })
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
