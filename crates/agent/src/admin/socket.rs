use std::{
    fs,
    net::{SocketAddr, TcpListener as StdTcpListener},
    os::unix::{
        fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt},
        net::UnixStream as StdUnixStream,
    },
    path::{Path, PathBuf},
};

use thiserror::Error;
use tokio::net::{TcpListener, UnixListener};

pub(super) const ADMIN_SOCKET_MODE: u32 = 0o600;
const ROOT_UID: u32 = 0;

#[derive(Debug, Error)]
pub enum AdminError {
    #[error("admin socket path is empty")]
    EmptySocketPath,
    #[error("admin socket path {path} exists and is not a Unix socket")]
    SocketPathNotSocket { path: String },
    #[error("admin socket {path} already has a listener")]
    SocketAlreadyInUse { path: String },
    #[error("admin socket parent {path} is unsafe: {reason}")]
    UnsafeSocketParent { path: String, reason: String },
    #[error("admin socket {path} has unsafe permissions {mode:o}")]
    UnsafeSocketMode { path: String, mode: u32 },
    #[error("failed to probe existing admin socket {path}: {source}")]
    ProbeExistingSocket {
        path: String,
        source: std::io::Error,
    },
    #[error("admin socket filesystem error for {path}: {source}")]
    SocketFile {
        path: String,
        source: std::io::Error,
    },
    #[error("prometheus metrics listener {listen_addr} is unsafe: {reason}")]
    UnsafePrometheusListenAddr { listen_addr: String, reason: String },
    #[error("failed to bind prometheus metrics listener {listen_addr}: {source}")]
    PrometheusBind {
        listen_addr: String,
        source: std::io::Error,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminServerConfig {
    pub socket_path: PathBuf,
    pub prometheus: Option<PrometheusListenerConfig>,
}

impl AdminServerConfig {
    pub fn unix_socket(socket_path: PathBuf) -> Self {
        Self {
            socket_path,
            prometheus: None,
        }
    }

    pub fn with_prometheus(mut self, prometheus: PrometheusListenerConfig) -> Self {
        self.prometheus = Some(prometheus);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrometheusListenerConfig {
    pub listen_addr: SocketAddr,
}

pub(super) fn bind_admin_socket(path: &Path) -> Result<UnixListener, AdminError> {
    if path.as_os_str().is_empty() {
        return Err(AdminError::EmptySocketPath);
    }
    ensure_admin_socket_parent(path)?;
    validate_admin_socket_parent(path)?;
    remove_stale_admin_socket(path)?;
    let listener = UnixListener::bind(path).map_err(|source| AdminError::SocketFile {
        path: path.display().to_string(),
        source,
    })?;
    if let Err(error) =
        set_private_admin_socket_permissions(path).and_then(|()| validate_admin_socket_mode(path))
    {
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(listener)
}

pub(super) fn bind_prometheus_listener(
    config: PrometheusListenerConfig,
) -> Result<TcpListener, AdminError> {
    if !config.listen_addr.ip().is_loopback() {
        return Err(AdminError::UnsafePrometheusListenAddr {
            listen_addr: config.listen_addr.to_string(),
            reason: "listener must bind to a loopback address".to_string(),
        });
    }
    let listener =
        StdTcpListener::bind(config.listen_addr).map_err(|source| AdminError::PrometheusBind {
            listen_addr: config.listen_addr.to_string(),
            source,
        })?;
    listener
        .set_nonblocking(true)
        .map_err(|source| AdminError::PrometheusBind {
            listen_addr: config.listen_addr.to_string(),
            source,
        })?;
    TcpListener::from_std(listener).map_err(|source| AdminError::PrometheusBind {
        listen_addr: config.listen_addr.to_string(),
        source,
    })
}

fn ensure_admin_socket_parent(path: &Path) -> Result<(), AdminError> {
    let parent = admin_socket_parent(path)?;
    match fs::symlink_metadata(parent) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            builder.mode(0o700);
            builder.create(parent).or_else(|source| {
                if source.kind() == std::io::ErrorKind::AlreadyExists {
                    Ok(())
                } else {
                    Err(source)
                }
            })
        }
        Err(error) => Err(error),
    }
    .map_err(|source| AdminError::SocketFile {
        path: parent.display().to_string(),
        source,
    })
}

fn set_private_admin_socket_permissions(path: &Path) -> Result<(), AdminError> {
    fs::set_permissions(path, fs::Permissions::from_mode(ADMIN_SOCKET_MODE)).map_err(|source| {
        AdminError::SocketFile {
            path: path.display().to_string(),
            source,
        }
    })
}

fn validate_admin_socket_parent(path: &Path) -> Result<(), AdminError> {
    let parent = admin_socket_parent(path)?;
    let metadata = fs::symlink_metadata(parent).map_err(|source| AdminError::SocketFile {
        path: parent.display().to_string(),
        source,
    })?;
    if metadata.file_type().is_symlink() {
        return Err(AdminError::UnsafeSocketParent {
            path: parent.display().to_string(),
            reason: "parent directory cannot be a symlink".to_string(),
        });
    }
    if !metadata.file_type().is_dir() {
        return Err(AdminError::UnsafeSocketParent {
            path: parent.display().to_string(),
            reason: "parent path is not a directory".to_string(),
        });
    }
    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(AdminError::UnsafeSocketParent {
            path: parent.display().to_string(),
            reason: format!("parent directory is accessible by group/other users: {mode:o}"),
        });
    }
    let owner = metadata.uid();
    let current_euid = rustix::process::geteuid().as_raw();
    if owner != ROOT_UID && owner != current_euid {
        return Err(AdminError::UnsafeSocketParent {
            path: parent.display().to_string(),
            reason: format!(
                "parent directory owner {owner} is neither root nor current euid {current_euid}"
            ),
        });
    }
    Ok(())
}

fn admin_socket_parent(path: &Path) -> Result<&Path, AdminError> {
    path.parent().ok_or_else(|| AdminError::UnsafeSocketParent {
        path: path.display().to_string(),
        reason: "socket path has no parent directory".to_string(),
    })
}

fn validate_admin_socket_mode(path: &Path) -> Result<(), AdminError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| AdminError::SocketFile {
        path: path.display().to_string(),
        source,
    })?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode != ADMIN_SOCKET_MODE {
        return Err(AdminError::UnsafeSocketMode {
            path: path.display().to_string(),
            mode,
        });
    }
    Ok(())
}

fn remove_stale_admin_socket(path: &Path) -> Result<(), AdminError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(AdminError::SocketFile {
                path: path.display().to_string(),
                source,
            });
        }
    };
    if !metadata.file_type().is_socket() {
        return Err(AdminError::SocketPathNotSocket {
            path: path.display().to_string(),
        });
    }

    match StdUnixStream::connect(path) {
        Ok(_) => Err(AdminError::SocketAlreadyInUse {
            path: path.display().to_string(),
        }),
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
            fs::remove_file(path).map_err(|source| AdminError::SocketFile {
                path: path.display().to_string(),
                source,
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(AdminError::ProbeExistingSocket {
            path: path.display().to_string(),
            source,
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::{fs::PermissionsExt, net::UnixListener as StdUnixListener},
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{ADMIN_SOCKET_MODE, AdminError, bind_admin_socket};

    #[tokio::test]
    async fn admin_socket_uses_private_permissions() -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("admin-mode")?;
        let socket_path = temp.join("admin.sock");
        let listener = bind_admin_socket(&socket_path)?;

        let mode = fs::symlink_metadata(&socket_path)?.permissions().mode() & 0o777;

        assert_eq!(mode, ADMIN_SOCKET_MODE);
        drop(listener);
        fs::remove_file(&socket_path)?;
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn admin_socket_creates_missing_private_parent() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = test_dir("admin-create-parent")?;
        let socket_parent = temp.join("run");
        let socket_path = socket_parent.join("admin.sock");

        let listener = bind_admin_socket(&socket_path)?;
        let parent_mode = fs::symlink_metadata(&socket_parent)?.permissions().mode() & 0o777;
        let socket_mode = fs::symlink_metadata(&socket_path)?.permissions().mode() & 0o777;

        assert_eq!(parent_mode, 0o700);
        assert_eq!(socket_mode, ADMIN_SOCKET_MODE);
        drop(listener);
        fs::remove_file(&socket_path)?;
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn admin_socket_creates_missing_private_ancestors()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("admin-create-ancestors")?;
        let probe_home = temp.join("probe-home");
        let socket_parent = probe_home.join("run");
        let socket_path = socket_parent.join("admin.sock");

        let listener = bind_admin_socket(&socket_path)?;
        let parent_mode = fs::symlink_metadata(&socket_parent)?.permissions().mode() & 0o777;
        let socket_mode = fs::symlink_metadata(&socket_path)?.permissions().mode() & 0o777;

        assert_eq!(parent_mode, 0o700);
        assert_eq!(socket_mode, ADMIN_SOCKET_MODE);
        drop(listener);
        fs::remove_file(&socket_path)?;
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn admin_socket_rejects_shared_parent() -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("admin-unsafe-parent")?;
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o755))?;
        let socket_path = temp.join("admin.sock");

        let result = bind_admin_socket(&socket_path);

        assert!(matches!(result, Err(AdminError::UnsafeSocketParent { .. })));
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o700))?;
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn admin_socket_rejects_existing_non_socket() -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("admin-non-socket")?;
        let socket_path = temp.join("admin.sock");
        fs::write(&socket_path, b"not a socket")?;

        let result = bind_admin_socket(&socket_path);

        assert!(matches!(
            result,
            Err(AdminError::SocketPathNotSocket { .. })
        ));
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn admin_socket_rejects_active_listener() -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("admin-active-listener")?;
        let socket_path = temp.join("admin.sock");
        let active_listener = StdUnixListener::bind(&socket_path)?;

        let result = bind_admin_socket(&socket_path);

        assert!(matches!(result, Err(AdminError::SocketAlreadyInUse { .. })));
        drop(active_listener);
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn admin_socket_replaces_stale_socket() -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("admin-stale-socket")?;
        let socket_path = temp.join("admin.sock");
        let stale_listener = StdUnixListener::bind(&socket_path)?;
        drop(stale_listener);

        let listener = bind_admin_socket(&socket_path)?;

        drop(listener);
        fs::remove_file(&socket_path)?;
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    fn test_dir(name: &str) -> Result<PathBuf, std::io::Error> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("{name}-{nanos}"));
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
        fs::create_dir_all(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        Ok(path)
    }
}
