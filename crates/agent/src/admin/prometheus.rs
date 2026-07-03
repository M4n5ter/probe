use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use storage::FjallSpool;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Notify,
    task::JoinSet,
};

use super::server::{AdminRuntimeState, build_admin_status_snapshot};
use crate::runtime_plan::RuntimePlanHandle;
use crate::status::{PROMETHEUS_TEXT_CONTENT_TYPE, render_prometheus_metrics};

const PROMETHEUS_REQUEST_TIMEOUT: Duration = Duration::from_millis(500);
const PROMETHEUS_SERVER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const PROMETHEUS_MAX_REQUEST_BYTES: usize = 8 * 1024;

pub(super) async fn accept_connections(
    listener: TcpListener,
    plan: RuntimePlanHandle,
    spool: Arc<FjallSpool>,
    runtime_state: Arc<AdminRuntimeState>,
    stop_requested: Arc<AtomicBool>,
    shutdown: Arc<Notify>,
) {
    let mut handlers = JoinSet::new();
    while !stop_requested.load(Ordering::Relaxed) {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, _)) => {
                        let plan = plan.clone();
                        let spool = Arc::clone(&spool);
                        let runtime_state = Arc::clone(&runtime_state);
                        handlers.spawn(async move {
                            if let Err(error) = handle_connection(stream, plan, spool, runtime_state).await {
                                eprintln!("prometheus metrics connection failed: {error}");
                            }
                        });
                    }
                    Err(error) => eprintln!("prometheus metrics accept failed: {error}"),
                }
            }
            result = handlers.join_next(), if !handlers.is_empty() => {
                if let Some(Err(error)) = result
                    && !error.is_cancelled()
                {
                    eprintln!("prometheus metrics connection task failed: {error}");
                }
            }
            () = shutdown.notified() => break,
        }
    }
    handlers.abort_all();
    while let Ok(Some(result)) =
        tokio::time::timeout(PROMETHEUS_SERVER_SHUTDOWN_TIMEOUT, handlers.join_next()).await
    {
        if let Err(error) = result
            && !error.is_cancelled()
        {
            eprintln!("prometheus metrics connection task failed during shutdown: {error}");
        }
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    plan: RuntimePlanHandle,
    spool: Arc<FjallSpool>,
    runtime_state: Arc<AdminRuntimeState>,
) -> Result<(), std::io::Error> {
    let request =
        match tokio::time::timeout(PROMETHEUS_REQUEST_TIMEOUT, read_request(&mut stream)).await {
            Ok(Ok(request)) => request,
            Ok(Err(error)) => {
                write_error_response(&mut stream, "400 Bad Request", &error.to_string()).await?;
                return Ok(());
            }
            Err(_) => {
                write_error_response(
                    &mut stream,
                    "408 Request Timeout",
                    &format!(
                        "prometheus metrics request timed out after {} ms",
                        PROMETHEUS_REQUEST_TIMEOUT.as_millis()
                    ),
                )
                .await?;
                return Ok(());
            }
        };

    match request_target(&request) {
        RequestTarget::Metrics => {
            let plan = plan.snapshot();
            let snapshot =
                build_admin_status_snapshot(plan.as_ref(), spool.as_ref(), &runtime_state);
            let metrics = render_prometheus_metrics(&snapshot);
            write_response(
                &mut stream,
                "200 OK",
                PROMETHEUS_TEXT_CONTENT_TYPE,
                &metrics,
                None,
            )
            .await
        }
        RequestTarget::MethodNotAllowed => {
            write_response(
                &mut stream,
                "405 Method Not Allowed",
                "text/plain; charset=utf-8",
                "method not allowed\n",
                Some("allow: GET\r\n"),
            )
            .await
        }
        RequestTarget::NotFound => {
            write_error_response(&mut stream, "404 Not Found", "not found").await
        }
        RequestTarget::BadRequest => {
            write_error_response(&mut stream, "400 Bad Request", "bad request").await
        }
    }
}

async fn read_request(stream: &mut TcpStream) -> Result<Vec<u8>, std::io::Error> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
        if request.len() > PROMETHEUS_MAX_REQUEST_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "prometheus metrics request headers are too large",
            ));
        }
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }
    Ok(request)
}

enum RequestTarget {
    Metrics,
    MethodNotAllowed,
    NotFound,
    BadRequest,
}

fn request_target(request: &[u8]) -> RequestTarget {
    let Ok(request) = std::str::from_utf8(request) else {
        return RequestTarget::BadRequest;
    };
    let Some(request_line) = request.lines().next() else {
        return RequestTarget::BadRequest;
    };
    let mut parts = request_line.split_whitespace();
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return RequestTarget::BadRequest;
    };
    if version != "HTTP/1.0" && version != "HTTP/1.1" {
        return RequestTarget::BadRequest;
    }
    if method != "GET" {
        return RequestTarget::MethodNotAllowed;
    }
    if target != "/metrics" {
        return RequestTarget::NotFound;
    }
    RequestTarget::Metrics
}

async fn write_error_response(
    stream: &mut TcpStream,
    status: &str,
    message: &str,
) -> Result<(), std::io::Error> {
    write_response(
        stream,
        status,
        "text/plain; charset=utf-8",
        &format!("{message}\n"),
        None,
    )
    .await
}

async fn write_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
    extra_headers: Option<&str>,
) -> Result<(), std::io::Error> {
    let extra_headers = extra_headers.unwrap_or_default();
    let response = format!(
        "HTTP/1.1 {status}\r\ncontent-type: {content_type}\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n{extra_headers}\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap, net::SocketAddr, os::unix::fs::PermissionsExt, path::PathBuf,
        sync::Arc,
    };

    use probe_config::{
        AgentConfig, CaptureBackend, CaptureSelection, CompressionCodecName, ExporterConfig,
        ExporterTransportConfig,
    };
    use probe_core::{CapabilityKind, CapabilityState};
    use runtime::{
        CaptureProviderBuilder, CaptureProviderDescriptor, ProviderRegistry, RuntimePlan,
    };
    use storage::FjallSpool;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
    };

    use super::*;
    use crate::admin::{
        AdminRuntimeState, AdminServerConfig, PrometheusListenerConfig, spawn_admin_server,
    };

    #[tokio::test]
    async fn listener_serves_read_only_loopback_metrics() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = tempfile::Builder::new()
            .prefix("prometheus-listener-")
            .tempdir()?;
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))?;
        let socket_path = temp.path().join("admin.sock");
        let spool_path = temp.path().join("spool");
        let spool = Arc::new(FjallSpool::open(&spool_path)?);
        let plan = Arc::new(runtime_plan(spool_path)?);
        let server = spawn_admin_server(
            RuntimePlanHandle::new(Arc::clone(&plan)),
            Arc::clone(&spool),
            AdminServerConfig::unix_socket(socket_path).with_prometheus(PrometheusListenerConfig {
                listen_addr: "127.0.0.1:0".parse()?,
            }),
            AdminRuntimeState::default(),
        )?;
        let listen_addr = server
            .prometheus_listen_addr()
            .expect("prometheus listener should expose its bound address");

        let response =
            send_request(listen_addr, "GET /metrics HTTP/1.1\r\nHost: probe\r\n\r\n").await?;

        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains(&format!("content-type: {PROMETHEUS_TEXT_CONTENT_TYPE}\r\n")));
        assert!(response.contains(
            "traffic_probe_capability_state{capability=\"replay_capture\",mode=\"available\"} 1\n"
        ));

        let status_response =
            send_request(listen_addr, "GET /status HTTP/1.1\r\nHost: probe\r\n\r\n").await?;

        assert!(status_response.starts_with("HTTP/1.1 404 Not Found\r\n"));

        let method_response =
            send_request(listen_addr, "POST /metrics HTTP/1.1\r\nHost: probe\r\n\r\n").await?;

        assert!(method_response.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
        assert!(method_response.contains("allow: GET\r\n"));

        server.stop().await;
        drop(spool);
        Ok(())
    }

    async fn send_request(
        address: SocketAddr,
        request: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let mut stream = TcpStream::connect(address).await?;
        stream.write_all(request.as_bytes()).await?;
        let mut response = String::new();
        stream.read_to_string(&mut response).await?;
        Ok(response)
    }

    fn runtime_plan(storage_path: PathBuf) -> Result<RuntimePlan, runtime::RuntimeError> {
        let registry = ProviderRegistry::new(
            vec![CaptureProviderDescriptor::available(
                CaptureBackend::Replay,
                CaptureProviderBuilder::Replay,
            )],
            test_platform_capabilities(),
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
                transport: ExporterTransportConfig::Webhook {
                    endpoint: "https://collector.example/batches".to_string(),
                    headers: BTreeMap::new(),
                    tls: Default::default(),
                },
                codec: CompressionCodecName::None,
                worker: Default::default(),
            }],
            ..AgentConfig::default()
        }
    }

    fn test_platform_capabilities() -> Vec<CapabilityState> {
        vec![
            CapabilityState::available(CapabilityKind::Http1),
            CapabilityState::available(CapabilityKind::Sse),
            CapabilityState::available(CapabilityKind::WebSocketHandoff),
            CapabilityState::available(CapabilityKind::WebSocketFrame),
            CapabilityState::unavailable(CapabilityKind::LibsslUprobe, "not built"),
            CapabilityState::available(CapabilityKind::DryRunEnforcement),
            CapabilityState::unavailable(CapabilityKind::ConnectionEnforcement, "not built"),
            CapabilityState::unavailable(CapabilityKind::TransparentInterception, "not built"),
        ]
    }
}
