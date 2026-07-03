use std::{path::Path, time::Duration};

use probe_core::{EventType, Selector};
use serde_json::Value;
use thiserror::Error;

use crate::admin::{
    AdminClientError, AdminRequest, EventDetailSnapshot, EventDetailTooLargeSnapshot,
    EventTailAttributionMode, EventTailSnapshot, send_admin_json_request_with_timeout,
};

const TAIL_TIMEOUT: Duration = Duration::from_secs(1);
const DETAIL_TIMEOUT: Duration = Duration::from_secs(2);
const TAIL_LIMIT: usize = 256;
const TAIL_RETRY_DIVISOR: usize = 4;

pub(super) async fn request_tail_events(
    socket_path: &Path,
    after_sequence: u64,
    latest: bool,
    selector: Selector,
    attribution_mode: EventTailAttributionMode,
    event_types: &[EventType],
) -> Result<EventTailSnapshot, TrafficClientError> {
    let mut limit = TAIL_LIMIT;
    loop {
        let result = request_tail_events_with_limit(
            socket_path,
            after_sequence,
            latest,
            selector.clone(),
            attribution_mode,
            event_types,
            limit,
        )
        .await;
        match result {
            Ok(snapshot) => return Ok(snapshot),
            Err(error)
                if matches!(
                    error,
                    TrafficClientError::AdminClient(AdminClientError::ResponseTooLarge { .. })
                ) && let Some(next_limit) = next_tail_retry_limit(limit) =>
            {
                limit = next_limit;
            }
            Err(error) => return Err(error),
        }
    }
}

async fn request_tail_events_with_limit(
    socket_path: &Path,
    after_sequence: u64,
    latest: bool,
    selector: Selector,
    attribution_mode: EventTailAttributionMode,
    event_types: &[EventType],
    limit: usize,
) -> Result<EventTailSnapshot, TrafficClientError> {
    let response = send_admin_json_request_with_timeout(
        socket_path,
        AdminRequest::TailEvents {
            after_sequence,
            latest,
            limit,
            selector: Some(selector),
            attribution_mode,
            event_types: event_types.to_vec(),
        },
        TAIL_TIMEOUT,
    )
    .await?;
    match response.get("kind").and_then(Value::as_str) {
        Some("event_tail") => {
            let tail =
                response
                    .get("tail")
                    .cloned()
                    .ok_or(TrafficClientError::MissingResponseField {
                        command: "tail_events",
                        field: "tail",
                    })?;
            serde_json::from_value(tail).map_err(|source| TrafficClientError::Json {
                command: "tail_events",
                source,
            })
        }
        Some("error") => Err(admin_command_error("tail_events", &response)),
        other => Err(TrafficClientError::UnexpectedResponse {
            kind: other.unwrap_or("<missing>").to_string(),
        }),
    }
}

fn next_tail_retry_limit(limit: usize) -> Option<usize> {
    (limit > 1).then(|| (limit / TAIL_RETRY_DIVISOR).max(1))
}

pub(super) async fn request_event_detail(
    socket_path: &Path,
    sequence: u64,
) -> Result<EventDetailSnapshot, TrafficClientError> {
    let response = send_admin_json_request_with_timeout(
        socket_path,
        AdminRequest::EventDetail { sequence },
        DETAIL_TIMEOUT,
    )
    .await?;
    match response.get("kind").and_then(Value::as_str) {
        Some("event_detail") => {
            let detail = response.get("detail").cloned().ok_or(
                TrafficClientError::MissingResponseField {
                    command: "event_detail",
                    field: "detail",
                },
            )?;
            serde_json::from_value(detail).map_err(|source| TrafficClientError::Json {
                command: "event_detail",
                source,
            })
        }
        Some("event_detail_too_large") => {
            let detail = response.get("detail").cloned().ok_or(
                TrafficClientError::MissingResponseField {
                    command: "event_detail",
                    field: "detail",
                },
            )?;
            let detail: EventDetailTooLargeSnapshot =
                serde_json::from_value(detail).map_err(|source| TrafficClientError::Json {
                    command: "event_detail",
                    source,
                })?;
            Err(TrafficClientError::DetailTooLarge {
                sequence: detail.sequence,
                payload_bytes: detail.payload_bytes,
                max_payload_bytes: detail.max_payload_bytes,
            })
        }
        Some("error") => Err(admin_command_error("event_detail", &response)),
        other => Err(TrafficClientError::UnexpectedResponse {
            kind: other.unwrap_or("<missing>").to_string(),
        }),
    }
}

fn admin_command_error(command: &'static str, response: &Value) -> TrafficClientError {
    TrafficClientError::AdminCommandFailed {
        command,
        message: response
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("admin command returned an error")
            .to_string(),
    }
}

#[derive(Debug, Error)]
pub(super) enum TrafficClientError {
    #[error("admin client error: {0}")]
    AdminClient(#[from] AdminClientError),
    #[error("admin {command} response is missing {field}")]
    MissingResponseField {
        command: &'static str,
        field: &'static str,
    },
    #[error(
        "admin event_detail exceeds single-response budget: sequence {sequence} has {payload_bytes} bytes, max {max_payload_bytes} bytes"
    )]
    DetailTooLarge {
        sequence: u64,
        payload_bytes: usize,
        max_payload_bytes: usize,
    },
    #[error("admin {command} failed: {message}")]
    AdminCommandFailed {
        command: &'static str,
        message: String,
    },
    #[error("unexpected admin response kind: {kind}")]
    UnexpectedResponse { kind: String },
    #[error("failed to parse admin {command} response: {source}")]
    Json {
        command: &'static str,
        source: serde_json::Error,
    },
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use tempfile::tempdir;
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        net::{UnixListener, UnixStream},
    };

    use super::*;

    #[tokio::test]
    async fn tail_events_retries_with_smaller_limit_after_oversized_admin_response()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let temp = tempdir()?;
        let socket_path = temp.path().join("admin.sock");
        let listener = UnixListener::bind(&socket_path)?;
        let server = tokio::spawn(async move {
            let mut first = accept_request(&listener).await?;
            let first_request = read_request(&mut first).await?;
            assert_eq!(first_request["limit"], json!(TAIL_LIMIT));
            first.write_all(&vec![b'a'; 16 * 1024 * 1024 + 1]).await?;
            first.shutdown().await?;

            let mut second = accept_request(&listener).await?;
            let second_request = read_request(&mut second).await?;
            assert_eq!(
                second_request["limit"],
                json!(TAIL_LIMIT / TAIL_RETRY_DIVISOR)
            );
            write_tail_response(&mut second, TAIL_LIMIT / TAIL_RETRY_DIVISOR).await?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        });

        let tail = request_tail_events(
            &socket_path,
            0,
            false,
            Selector::default(),
            EventTailAttributionMode::Strict,
            &[],
        )
        .await?;

        assert_eq!(tail.limit, TAIL_LIMIT / TAIL_RETRY_DIVISOR);
        server.await??;
        Ok(())
    }

    async fn accept_request(listener: &UnixListener) -> Result<UnixStream, std::io::Error> {
        listener.accept().await.map(|(stream, _)| stream)
    }

    async fn read_request(
        stream: &mut UnixStream,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let mut line = Vec::new();
        let mut reader = BufReader::new(stream);
        reader.read_until(b'\n', &mut line).await?;
        Ok(serde_json::from_slice(&line)?)
    }

    async fn write_tail_response(
        stream: &mut UnixStream,
        limit: usize,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let response = json!({
            "kind": "event_tail",
            "tail": {
                "after_sequence": 0,
                "next_after_sequence": 0,
                "last_export_sequence": 0,
                "limit": limit,
                "scanned": 0,
                "budget": {
                    "max_event_payload_bytes": 524288,
                    "max_response_payload_bytes": 2097152,
                    "included_payload_bytes": 0,
                    "truncated": false
                },
                "events": [],
                "omissions": []
            }
        });
        let mut bytes = serde_json::to_vec(&response)?;
        bytes.push(b'\n');
        stream.write_all(&bytes).await?;
        stream.shutdown().await?;
        Ok(())
    }
}
