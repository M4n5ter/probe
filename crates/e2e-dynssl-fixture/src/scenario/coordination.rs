use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const READY_FILE_TEMP_ATTEMPTS: usize = 128;
const START_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) fn publish_ready_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    for attempt in 0..READY_FILE_TEMP_ATTEMPTS {
        let temp_path = sibling_ready_temp_path(path, attempt);
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
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!(
            "failed to allocate ready file temp path beside {}",
            path.display()
        ),
    ))
}

pub(crate) fn wait_for_start_file(path: &Path, expected_nonce: &str) -> io::Result<()> {
    let deadline = Instant::now() + START_TIMEOUT;
    loop {
        match fs::read_to_string(path) {
            Ok(content) if start_nonce(&content).as_deref() == Some(expected_nonce) => {
                return Ok(());
            }
            Ok(content) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "start file {} did not contain expected nonce {expected_nonce}: {content:?}",
                        path.display()
                    ),
                ));
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(source),
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("timed out waiting for start file {}", path.display()),
            ));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

pub(crate) fn coordination_nonce() -> String {
    format!("{}-{}", std::process::id(), wall_time_unix_ns())
}

fn start_nonce(content: &str) -> Option<String> {
    content
        .lines()
        .find_map(|line| line.strip_prefix("start_nonce="))
        .map(ToOwned::to_owned)
}

fn write_new_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)
}

fn sibling_ready_temp_path(path: &Path, attempt: usize) -> PathBuf {
    let mut file_name = path
        .file_name()
        .map(OsString::from)
        .unwrap_or_else(|| OsString::from("ready"));
    file_name.push(format!(
        ".tmp.{}.{}.{}",
        std::process::id(),
        wall_time_unix_ns(),
        attempt
    ));
    path.with_file_name(file_name)
}

fn wall_time_unix_ns() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}
