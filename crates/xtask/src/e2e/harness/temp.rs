use std::{
    env,
    ffi::OsString,
    fs, io,
    io::Write,
    os::unix::ffi::OsStrExt,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use super::e2e_error;

const ATOMIC_FILE_TEMP_ATTEMPTS: usize = 128;
const TEMP_ROOT_ATTEMPTS: usize = 128;
const TEMP_ROOT_PREFIX: &str = "probe-e2e";
const TEMP_NAME_HINT_MAX_BYTES: usize = 24;
const TEMP_NAME_HINT_MIN_TRIM_BYTES: usize = 12;
const LINUX_PATHNAME_SOCKET_LIMIT_BYTES: usize = 108;
const READY_SOCKET_FILE_NAME: &str = "agent.ready.sock";

pub(crate) fn create_temp_root(name: &str) -> Result<PathBuf, std::io::Error> {
    let base = e2e_temp_base();
    let name_hint = temp_name_hint(name);
    for attempt in 0..TEMP_ROOT_ATTEMPTS {
        let path = base.join(temp_root_dir_name(
            &name_hint,
            std::process::id(),
            wall_time_unix_ns(),
            attempt,
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

fn e2e_temp_base() -> PathBuf {
    e2e_temp_base_for(&env::temp_dir())
}

fn e2e_temp_base_for(preferred: &Path) -> PathBuf {
    if can_host_pathname_unix_socket(preferred) {
        return preferred.to_path_buf();
    }
    PathBuf::from("/tmp")
}

fn can_host_pathname_unix_socket(base: &Path) -> bool {
    let longest_hint = "x".repeat(TEMP_NAME_HINT_MAX_BYTES);
    let longest_root =
        temp_root_dir_name(&longest_hint, u32::MAX, i64::MAX, TEMP_ROOT_ATTEMPTS - 1);
    let socket_path = base.join(longest_root).join(READY_SOCKET_FILE_NAME);
    socket_path.as_os_str().as_bytes().len() < LINUX_PATHNAME_SOCKET_LIMIT_BYTES
}

fn temp_root_dir_name(name_hint: &str, process_id: u32, unix_ns: i64, attempt: usize) -> String {
    format!("{TEMP_ROOT_PREFIX}-{name_hint}-{process_id}-{unix_ns}-{attempt}")
}

fn temp_name_hint(name: &str) -> String {
    let mut hint = String::new();
    let mut previous_was_separator = true;
    for byte in name.bytes() {
        let next = if byte.is_ascii_alphanumeric() {
            byte.to_ascii_lowercase() as char
        } else if previous_was_separator {
            continue;
        } else {
            '-'
        };
        if hint.len() + next.len_utf8() > TEMP_NAME_HINT_MAX_BYTES {
            break;
        }
        previous_was_separator = next == '-';
        hint.push(next);
    }
    while hint.ends_with('-') {
        hint.pop();
    }
    if let Some(separator) = hint.rfind('-')
        && hint.len() == TEMP_NAME_HINT_MAX_BYTES
        && separator >= TEMP_NAME_HINT_MIN_TRIM_BYTES
    {
        hint.truncate(separator);
    }
    if hint.is_empty() {
        return "case".to_string();
    }
    hint
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temp_name_hint_keeps_a_short_readable_case_context() {
        let tls_hint = temp_name_hint("tls-plaintext-target-lifecycle-loopback");
        assert_valid_temp_name_hint(&tls_hint);
        assert!(tls_hint.starts_with("tls-plaintext"));

        let mitm_hint = temp_name_hint("product-outbound-mitm-proxy-transparent-https-websocket");
        assert_valid_temp_name_hint(&mitm_hint);
        assert!(mitm_hint.starts_with("product-outbound"));
    }

    #[test]
    fn temp_name_hint_normalizes_invalid_path_characters() {
        let hint = temp_name_hint("  Remote.Policy Bundle!! ");
        assert_valid_temp_name_hint(&hint);
        assert!(hint.contains("remote"));
        assert!(hint.contains("policy"));
        assert!(hint.contains("bundle"));

        assert_eq!(temp_name_hint("-----"), "case");
    }

    #[test]
    fn e2e_temp_base_preserves_short_base_with_socket_budget() {
        let preferred = Path::new("/tmp");

        assert_eq!(e2e_temp_base_for(preferred), preferred);
    }

    #[test]
    fn e2e_temp_base_falls_back_when_preferred_base_exceeds_socket_budget() {
        let preferred = Path::new("/tmp").join("x".repeat(LINUX_PATHNAME_SOCKET_LIMIT_BYTES));

        assert_eq!(e2e_temp_base_for(&preferred), PathBuf::from("/tmp"));
    }

    #[test]
    fn longest_temp_root_leaves_room_for_ready_socket_under_tmp() {
        let longest_hint = "x".repeat(TEMP_NAME_HINT_MAX_BYTES);
        let root = temp_root_dir_name(&longest_hint, u32::MAX, i64::MAX, TEMP_ROOT_ATTEMPTS - 1);
        let socket_path = Path::new("/tmp").join(root).join(READY_SOCKET_FILE_NAME);

        assert!(
            socket_path.as_os_str().as_bytes().len() < LINUX_PATHNAME_SOCKET_LIMIT_BYTES,
            "{} exceeds Linux pathname Unix socket budget",
            socket_path.display()
        );
    }

    fn assert_valid_temp_name_hint(hint: &str) {
        assert!(!hint.is_empty());
        assert!(hint.len() <= TEMP_NAME_HINT_MAX_BYTES);
        assert!(!hint.starts_with('-'));
        assert!(!hint.ends_with('-'));
        assert!(
            hint.bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        );
    }
}
