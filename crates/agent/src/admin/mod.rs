use std::{
    fs,
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::UnixStream as StdUnixStream,
    },
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use runtime::RuntimePlan;
use serde::{Deserialize, Serialize};
use storage::FjallSpool;
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::Notify,
    task::JoinSet,
};

use crate::status::{
    AgentStatusSnapshot, MetricsSnapshot, build_status_snapshot, collect_running_spool_status,
};

const ADMIN_REQUEST_MAX_BYTES: usize = 4 * 1024;
const ADMIN_SOCKET_MODE: u32 = 0o600;
const ADMIN_REQUEST_TIMEOUT: Duration = Duration::from_millis(500);
const ADMIN_SERVER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminServerConfig {
    pub socket_path: PathBuf,
}

pub struct AdminServerHandle {
    socket_path: PathBuf,
    stop_requested: Arc<AtomicBool>,
    shutdown: Arc<Notify>,
    task: tokio::task::JoinHandle<()>,
}

pub fn spawn_admin_server(
    plan: Arc<RuntimePlan>,
    spool: Arc<FjallSpool>,
    config: AdminServerConfig,
) -> Result<AdminServerHandle, AdminError> {
    let listener = bind_admin_socket(&config.socket_path)?;
    let stop_requested = Arc::new(AtomicBool::new(false));
    let shutdown = Arc::new(Notify::new());
    let task_stop_requested = Arc::clone(&stop_requested);
    let task_shutdown = Arc::clone(&shutdown);
    let task = tokio::spawn(async move {
        accept_admin_connections(listener, plan, spool, task_stop_requested, task_shutdown).await;
    });

    Ok(AdminServerHandle {
        socket_path: config.socket_path,
        stop_requested,
        shutdown,
        task,
    })
}

impl AdminServerHandle {
    pub async fn stop(mut self) {
        self.stop_requested.store(true, Ordering::Relaxed);
        self.shutdown.notify_one();
        match tokio::time::timeout(ADMIN_SERVER_SHUTDOWN_TIMEOUT, &mut self.task).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) if !error.is_cancelled() => {
                eprintln!("admin server stopped with error: {error}");
            }
            Ok(Err(_)) => {}
            Err(_) => {
                self.task.abort();
                if let Err(error) = self.task.await
                    && !error.is_cancelled()
                {
                    eprintln!("admin server stopped with error: {error}");
                }
            }
        }
        if let Err(error) = fs::remove_file(&self.socket_path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            eprintln!(
                "failed to remove admin socket {}: {error}",
                self.socket_path.display()
            );
        }
    }
}

fn bind_admin_socket(path: &Path) -> Result<UnixListener, AdminError> {
    if path.as_os_str().is_empty() {
        return Err(AdminError::EmptySocketPath);
    }
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

fn set_private_admin_socket_permissions(path: &Path) -> Result<(), AdminError> {
    fs::set_permissions(path, fs::Permissions::from_mode(ADMIN_SOCKET_MODE)).map_err(|source| {
        AdminError::SocketFile {
            path: path.display().to_string(),
            source,
        }
    })
}

fn validate_admin_socket_parent(path: &Path) -> Result<(), AdminError> {
    let parent = path
        .parent()
        .ok_or_else(|| AdminError::UnsafeSocketParent {
            path: path.display().to_string(),
            reason: "socket path has no parent directory".to_string(),
        })?;
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

async fn accept_admin_connections(
    listener: UnixListener,
    plan: Arc<RuntimePlan>,
    spool: Arc<FjallSpool>,
    stop_requested: Arc<AtomicBool>,
    shutdown: Arc<Notify>,
) {
    let mut handlers = JoinSet::new();
    while !stop_requested.load(Ordering::Relaxed) {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, _)) => {
                        let plan = Arc::clone(&plan);
                        let spool = Arc::clone(&spool);
                        handlers.spawn(async move {
                            if let Err(error) = handle_admin_connection(stream, plan, spool).await {
                                eprintln!("admin connection failed: {error}");
                            }
                        });
                    }
                    Err(error) => eprintln!("admin accept failed: {error}"),
                }
            }
            result = handlers.join_next(), if !handlers.is_empty() => {
                if let Some(Err(error)) = result
                    && !error.is_cancelled()
                {
                    eprintln!("admin connection task failed: {error}");
                }
            }
            () = shutdown.notified() => break,
        }
    }
    handlers.abort_all();
    while let Ok(Some(result)) =
        tokio::time::timeout(ADMIN_SERVER_SHUTDOWN_TIMEOUT, handlers.join_next()).await
    {
        if let Err(error) = result
            && !error.is_cancelled()
        {
            eprintln!("admin connection task failed during shutdown: {error}");
        }
    }
}

async fn handle_admin_connection(
    mut stream: UnixStream,
    plan: Arc<RuntimePlan>,
    spool: Arc<FjallSpool>,
) -> Result<(), std::io::Error> {
    let response =
        match tokio::time::timeout(ADMIN_REQUEST_TIMEOUT, read_admin_request(&mut stream)).await {
            Ok(Ok(request)) => handle_admin_request(request, plan.as_ref(), spool.as_ref()),
            Ok(Err(error)) => AdminResponse::Error {
                message: error.to_string(),
            },
            Err(_) => AdminResponse::Error {
                message: format!(
                    "admin request timed out after {} ms",
                    ADMIN_REQUEST_TIMEOUT.as_millis()
                ),
            },
        };
    let mut bytes = serde_json::to_vec(&response).map_err(std::io::Error::other)?;
    bytes.push(b'\n');
    stream.write_all(&bytes).await
}

async fn read_admin_request(stream: &mut UnixStream) -> Result<AdminRequest, AdminRequestError> {
    let bytes = read_admin_request_line(stream).await?;
    let trimmed = trim_ascii_whitespace(&bytes);
    if trimmed.is_empty() {
        return Err(AdminRequestError::Empty);
    }
    serde_json::from_slice(trimmed).map_err(AdminRequestError::Json)
}

async fn read_admin_request_line(stream: &mut UnixStream) -> Result<Vec<u8>, AdminRequestError> {
    let mut bytes = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        let read = stream.read(&mut byte).await?;
        if read == 0 {
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        bytes.push(byte[0]);
        if bytes.len() > ADMIN_REQUEST_MAX_BYTES {
            return Err(AdminRequestError::TooLarge {
                limit: ADMIN_REQUEST_MAX_BYTES,
            });
        }
    }
    Ok(bytes)
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

fn handle_admin_request(
    request: AdminRequest,
    plan: &RuntimePlan,
    spool: &FjallSpool,
) -> AdminResponse {
    let snapshot = build_status_snapshot(plan, collect_running_spool_status(plan, spool));
    match request {
        AdminRequest::Status => AdminResponse::Status {
            snapshot: Box::new(snapshot),
        },
        AdminRequest::Metrics => AdminResponse::Metrics {
            metrics: snapshot.metrics,
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case", tag = "command")]
enum AdminRequest {
    Status,
    Metrics,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
enum AdminResponse {
    Status { snapshot: Box<AgentStatusSnapshot> },
    Metrics { metrics: MetricsSnapshot },
    Error { message: String },
}

#[derive(Debug, Error)]
enum AdminRequestError {
    #[error("failed to read admin request: {0}")]
    Io(#[from] std::io::Error),
    #[error("admin request is empty")]
    Empty,
    #[error("admin request exceeds {limit} bytes")]
    TooLarge { limit: usize },
    #[error("failed to parse admin request JSON: {0}")]
    Json(serde_json::Error),
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        os::unix::net::UnixListener as StdUnixListener,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use probe_config::{AgentConfig, CaptureBackend, CaptureSelection, ExporterConfig};
    use probe_core::{CapabilityState, RuntimeMode, SpoolPayloadSchema};
    use runtime::{
        CaptureProviderBuilder, CaptureProviderDescriptor, ProviderRegistry, RuntimePlan,
    };
    use serde_json::json;
    use storage::SpoolPayload;
    use tokio::{io::AsyncWriteExt, net::UnixStream};

    use super::*;

    #[tokio::test]
    async fn admin_status_request_returns_running_spool_snapshot()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("admin-status")?;
        let socket_path = temp.join("admin.sock");
        let spool_path = temp.join("spool");
        let spool = Arc::new(FjallSpool::open(&spool_path)?);
        spool.append_export(SpoolPayload::new(
            SpoolPayloadSchema::from_wire("test.schema"),
            b"one",
        ))?;
        let plan = Arc::new(runtime_plan(spool_path)?);
        let server = spawn_admin_server(
            Arc::clone(&plan),
            Arc::clone(&spool),
            AdminServerConfig {
                socket_path: socket_path.clone(),
            },
        )?;

        let response = send_admin_request(&socket_path, json!({ "command": "status" })).await?;

        assert_eq!(response["kind"], json!("status"));
        assert_eq!(
            response["snapshot"]["spool"]["mode"],
            json!(RuntimeMode::Available)
        );
        assert_eq!(
            response["snapshot"]["spool"]["export_last_sequence"],
            json!(1)
        );
        assert_eq!(response["snapshot"]["exporters"][0]["cursor"], json!(0));
        server.stop().await;
        assert!(!socket_path.exists());
        drop(spool);
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn admin_metrics_request_returns_metrics_envelope()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("admin-metrics")?;
        let socket_path = temp.join("admin.sock");
        let spool_path = temp.join("spool");
        let spool = Arc::new(FjallSpool::open(&spool_path)?);
        let plan = Arc::new(runtime_plan(spool_path)?);
        let server = spawn_admin_server(
            Arc::clone(&plan),
            Arc::clone(&spool),
            AdminServerConfig {
                socket_path: socket_path.clone(),
            },
        )?;

        let response = send_admin_request(&socket_path, json!({ "command": "metrics" })).await?;

        assert_eq!(response["kind"], json!("metrics"));
        assert_eq!(response["metrics"]["export"]["sink_count"], json!(1));
        server.stop().await;
        drop(spool);
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn admin_socket_uses_private_permissions() -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("admin-mode")?;
        let socket_path = temp.join("admin.sock");
        let spool_path = temp.join("spool");
        let spool = Arc::new(FjallSpool::open(&spool_path)?);
        let plan = Arc::new(runtime_plan(spool_path)?);
        let server = spawn_admin_server(
            Arc::clone(&plan),
            Arc::clone(&spool),
            AdminServerConfig {
                socket_path: socket_path.clone(),
            },
        )?;

        let mode = fs::symlink_metadata(&socket_path)?.permissions().mode() & 0o777;

        assert_eq!(mode, ADMIN_SOCKET_MODE);
        server.stop().await;
        drop(spool);
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn admin_socket_rejects_shared_parent() -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("admin-unsafe-parent")?;
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o755))?;
        let socket_path = temp.join("admin.sock");
        let spool_path = temp.join("spool");
        let spool = Arc::new(FjallSpool::open(&spool_path)?);
        let plan = Arc::new(runtime_plan(spool_path)?);

        let result = spawn_admin_server(
            Arc::clone(&plan),
            Arc::clone(&spool),
            AdminServerConfig { socket_path },
        );

        assert!(matches!(result, Err(AdminError::UnsafeSocketParent { .. })));
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o700))?;
        drop(spool);
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn admin_socket_rejects_existing_non_socket() -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("admin-non-socket")?;
        let socket_path = temp.join("admin.sock");
        fs::write(&socket_path, b"not a socket")?;
        let spool_path = temp.join("spool");
        let spool = Arc::new(FjallSpool::open(&spool_path)?);
        let plan = Arc::new(runtime_plan(spool_path)?);

        let result = spawn_admin_server(
            Arc::clone(&plan),
            Arc::clone(&spool),
            AdminServerConfig { socket_path },
        );

        assert!(matches!(
            result,
            Err(AdminError::SocketPathNotSocket { .. })
        ));
        drop(spool);
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn admin_socket_rejects_active_listener() -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("admin-active-listener")?;
        let socket_path = temp.join("admin.sock");
        let active_listener = StdUnixListener::bind(&socket_path)?;
        let spool_path = temp.join("spool");
        let spool = Arc::new(FjallSpool::open(&spool_path)?);
        let plan = Arc::new(runtime_plan(spool_path)?);

        let result = spawn_admin_server(
            Arc::clone(&plan),
            Arc::clone(&spool),
            AdminServerConfig {
                socket_path: socket_path.clone(),
            },
        );

        assert!(matches!(result, Err(AdminError::SocketAlreadyInUse { .. })));
        drop(active_listener);
        drop(spool);
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn admin_socket_replaces_stale_socket() -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("admin-stale-socket")?;
        let socket_path = temp.join("admin.sock");
        let stale_listener = StdUnixListener::bind(&socket_path)?;
        drop(stale_listener);
        let spool_path = temp.join("spool");
        let spool = Arc::new(FjallSpool::open(&spool_path)?);
        let plan = Arc::new(runtime_plan(spool_path)?);

        let server = spawn_admin_server(
            Arc::clone(&plan),
            Arc::clone(&spool),
            AdminServerConfig {
                socket_path: socket_path.clone(),
            },
        )?;
        let response = send_admin_request(&socket_path, json!({ "command": "metrics" })).await?;

        assert_eq!(response["kind"], json!("metrics"));
        server.stop().await;
        drop(spool);
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn admin_request_without_newline_times_out() -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("admin-timeout")?;
        let socket_path = temp.join("admin.sock");
        let spool_path = temp.join("spool");
        let spool = Arc::new(FjallSpool::open(&spool_path)?);
        let plan = Arc::new(runtime_plan(spool_path)?);
        let server = spawn_admin_server(
            Arc::clone(&plan),
            Arc::clone(&spool),
            AdminServerConfig {
                socket_path: socket_path.clone(),
            },
        )?;
        let mut stream = UnixStream::connect(&socket_path).await?;
        stream.write_all(b"{\"command\":\"status\"").await?;

        let response = read_admin_response(&mut stream).await?;

        assert_eq!(response["kind"], json!("error"));
        assert!(
            response["message"]
                .as_str()
                .is_some_and(|message| message.contains("timed out"))
        );
        server.stop().await;
        drop(spool);
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    async fn send_admin_request(
        path: &Path,
        request: serde_json::Value,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let mut stream = UnixStream::connect(path).await?;
        let mut request_bytes = serde_json::to_vec(&request)?;
        request_bytes.push(b'\n');
        stream.write_all(&request_bytes).await?;
        read_admin_response(&mut stream).await
    }

    async fn read_admin_response(
        stream: &mut UnixStream,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let mut response = Vec::new();
        loop {
            let mut byte = [0_u8; 1];
            let read = stream.read(&mut byte).await?;
            if read == 0 || byte[0] == b'\n' {
                break;
            }
            response.push(byte[0]);
        }
        Ok(serde_json::from_slice(&response)?)
    }

    fn runtime_plan(storage_path: PathBuf) -> Result<RuntimePlan, runtime::RuntimeError> {
        let registry = ProviderRegistry::new(
            vec![CaptureProviderDescriptor::available(
                CaptureBackend::Replay,
                CaptureProviderBuilder::Replay,
            )],
            Vec::<CapabilityState>::new(),
        );
        RuntimePlan::build(config_with_storage_path(storage_path), &registry)
    }

    fn config_with_storage_path(storage_path: PathBuf) -> AgentConfig {
        AgentConfig {
            capture: probe_config::CaptureConfig {
                selection: CaptureSelection::Replay,
                ..Default::default()
            },
            storage: probe_config::StorageConfig {
                path: storage_path,
                ..Default::default()
            },
            exporters: vec![ExporterConfig {
                id: "primary".to_string(),
                transport: probe_config::ExporterTransport::Webhook,
                endpoint: "https://collector.example/batches".to_string(),
                codec: probe_config::CompressionCodecName::None,
                headers: BTreeMap::new(),
                tls: Default::default(),
            }],
            ..AgentConfig::default()
        }
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
