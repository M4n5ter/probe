use std::{
    future::Future,
    path::{Path, PathBuf},
    time::Duration,
};

use thiserror::Error;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
};

use super::protocol::AdminRequest;

const ADMIN_RESPONSE_MAX_BYTES: usize = 16 * 1024 * 1024;
const ADMIN_CLIENT_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) async fn send_admin_json_request(
    socket_path: &Path,
    request: AdminRequest,
) -> Result<serde_json::Value, AdminClientError> {
    send_admin_json_request_with_timeout(socket_path, request, ADMIN_CLIENT_TIMEOUT).await
}

pub(crate) async fn send_admin_json_request_with_timeout(
    socket_path: &Path,
    request: AdminRequest,
    timeout: Duration,
) -> Result<serde_json::Value, AdminClientError> {
    let mut stream = tokio::time::timeout(timeout, UnixStream::connect(socket_path))
        .await
        .map_err(|_| AdminClientError::Timeout)?
        .map_err(|source| AdminClientError::Connect {
            path: socket_path.to_path_buf(),
            source,
        })?;
    let mut request = serde_json::to_vec(&request)?;
    request.push(b'\n');
    with_timeout(stream.write_all(&request), timeout).await?;
    with_timeout(stream.shutdown(), timeout).await?;
    let response = read_bounded_response(&mut stream, timeout).await?;
    serde_json::from_slice(&response).map_err(AdminClientError::Json)
}

async fn read_bounded_response(
    stream: &mut UnixStream,
    timeout: Duration,
) -> Result<Vec<u8>, AdminClientError> {
    let reader = BufReader::new(stream);
    let mut limited = reader.take((ADMIN_RESPONSE_MAX_BYTES + 1) as u64);
    let mut response = Vec::new();
    let read = with_timeout(limited.read_until(b'\n', &mut response), timeout).await?;
    if read == 0 {
        return Err(AdminClientError::EmptyResponse);
    }
    if response.len() > ADMIN_RESPONSE_MAX_BYTES {
        return Err(AdminClientError::ResponseTooLarge {
            limit: ADMIN_RESPONSE_MAX_BYTES,
        });
    }
    Ok(response)
}

async fn with_timeout<F, T>(future: F, timeout: Duration) -> Result<T, AdminClientError>
where
    F: Future<Output = Result<T, std::io::Error>>,
{
    tokio::time::timeout(timeout, future)
        .await
        .map_err(|_| AdminClientError::Timeout)?
        .map_err(AdminClientError::Io)
}

#[derive(Debug, Error)]
pub(crate) enum AdminClientError {
    #[error("failed to connect to admin socket {path}: {source}")]
    Connect {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("admin socket I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to encode admin request JSON: {0}")]
    RequestJson(#[from] serde_json::Error),
    #[error("admin response is empty")]
    EmptyResponse,
    #[error("admin response exceeds {limit} bytes")]
    ResponseTooLarge { limit: usize },
    #[error("admin request timed out")]
    Timeout,
    #[error("failed to parse admin response JSON: {0}")]
    Json(serde_json::Error),
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;
    use tempfile::{TempDir, tempdir};
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        net::UnixListener,
        task::JoinHandle,
    };

    use super::*;

    #[tokio::test]
    async fn client_reads_one_json_line_without_waiting_for_eof()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_temp, socket, handle) = spawn_admin_client_test_server(
            b"{\"kind\":\"metrics\"}\n{\"kind\":\"status\"}\n".to_vec(),
            true,
        )?;

        let response = send_admin_json_request(&socket, AdminRequest::Metrics).await?;

        assert_eq!(response["kind"], json!("metrics"));
        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn client_rejects_oversized_response_line() -> Result<(), Box<dyn std::error::Error>> {
        let response = vec![b'a'; ADMIN_RESPONSE_MAX_BYTES + 1];
        let (_temp, socket, handle) = spawn_admin_client_test_server(response, false)?;

        let error = send_admin_json_request(&socket, AdminRequest::Status)
            .await
            .expect_err("oversized response should fail");

        assert!(matches!(error, AdminClientError::ResponseTooLarge { .. }));
        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn client_rejects_malformed_response_json() -> Result<(), Box<dyn std::error::Error>> {
        let (_temp, socket, handle) =
            spawn_admin_client_test_server(b"not-json\n".to_vec(), false)?;

        let error = send_admin_json_request(&socket, AdminRequest::Status)
            .await
            .expect_err("malformed response should fail");

        assert!(matches!(error, AdminClientError::Json(_)));
        handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn client_times_out_waiting_for_response_line() -> Result<(), Box<dyn std::error::Error>>
    {
        let (_temp, socket, handle) =
            spawn_admin_client_test_server(b"{\"kind\":\"status\"}".to_vec(), true)?;

        let error = send_admin_json_request_with_timeout(
            &socket,
            AdminRequest::Status,
            Duration::from_millis(100),
        )
        .await
        .expect_err("unterminated response line should time out");

        assert!(matches!(error, AdminClientError::Timeout));
        handle.abort();
        Ok(())
    }

    fn spawn_admin_client_test_server(
        response: Vec<u8>,
        keep_open: bool,
    ) -> Result<(TempDir, PathBuf, JoinHandle<()>), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let socket_path = temp.path().join("admin.sock");
        let listener = UnixListener::bind(&socket_path)?;
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept admin client");
            {
                let mut reader = BufReader::new(&mut stream);
                let mut request = Vec::new();
                reader
                    .read_until(b'\n', &mut request)
                    .await
                    .expect("read admin request line");
            }
            stream
                .write_all(&response)
                .await
                .expect("write admin response");
            if keep_open {
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });
        Ok((temp, socket_path, handle))
    }
}
