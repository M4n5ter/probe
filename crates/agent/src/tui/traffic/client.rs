use std::{path::Path, time::Duration};

use probe_core::{EventType, Selector};
use serde_json::Value;
use thiserror::Error;

use crate::admin::{
    AdminClientError, AdminRequest, EventDetailSnapshot, EventDetailTooLargeSnapshot,
    EventTailSnapshot, default_tail_scan_limit, send_admin_json_request_with_timeout,
};

const TAIL_TIMEOUT: Duration = Duration::from_secs(2);
const DETAIL_TIMEOUT: Duration = Duration::from_secs(2);
const INITIAL_TAIL_LIMIT: usize = 1_024;
const LIVE_TAIL_LIMIT: usize = 128;
const TAIL_RETRY_DIVISOR: usize = 4;

pub(super) async fn request_tail_events(
    socket_path: &Path,
    after_sequence: u64,
    latest: bool,
    selector: Selector,
    event_types: &[EventType],
) -> Result<EventTailSnapshot, TrafficClientError> {
    let mut limit = tail_limit(latest);
    let scan_limit = default_tail_scan_limit(latest);
    loop {
        let result = request_tail_events_with_limit(
            socket_path,
            after_sequence,
            latest,
            selector.clone(),
            event_types,
            limit,
            scan_limit,
        )
        .await;
        match result {
            Ok(snapshot) => return Ok(snapshot),
            Err(TrafficClientError::AdminClient(AdminClientError::ResponseTooLarge {
                command: _,
                limit: response_limit_bytes,
            })) => {
                if let Some(next_limit) = next_tail_retry_limit(limit) {
                    limit = next_limit;
                    continue;
                }
                return Err(TrafficClientError::TailResponseTooLarge {
                    event_limit: limit,
                    response_limit_bytes,
                });
            }
            Err(error) => return Err(error),
        }
    }
}

fn tail_limit(latest: bool) -> usize {
    if latest {
        INITIAL_TAIL_LIMIT
    } else {
        LIVE_TAIL_LIMIT
    }
}

async fn request_tail_events_with_limit(
    socket_path: &Path,
    after_sequence: u64,
    latest: bool,
    selector: Selector,
    event_types: &[EventType],
    limit: usize,
    scan_limit: usize,
) -> Result<EventTailSnapshot, TrafficClientError> {
    let response = send_admin_json_request_with_timeout(
        socket_path,
        AdminRequest::TailEvents {
            after_sequence,
            latest,
            limit,
            scan_limit: Some(scan_limit),
            selector: Some(selector),
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
    #[error(
        "admin tail_events response exceeds {response_limit_bytes} bytes even with limit {event_limit}"
    )]
    TailResponseTooLarge {
        event_limit: usize,
        response_limit_bytes: usize,
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

    const TAIL_FIXTURE_MAX_EVENT_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;
    const TAIL_FIXTURE_MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;

    #[tokio::test]
    async fn tail_events_retries_with_smaller_limit_after_oversized_admin_response()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let temp = tempdir()?;
        let socket_path = temp.path().join("admin.sock");
        let listener = UnixListener::bind(&socket_path)?;
        let server = tokio::spawn(async move {
            let mut first = accept_request(&listener).await?;
            let first_request = read_request(&mut first).await?;
            assert_eq!(first_request["limit"], json!(LIVE_TAIL_LIMIT));
            assert_eq!(
                first_request["scan_limit"],
                json!(default_tail_scan_limit(false))
            );
            first.write_all(&vec![b'a'; 16 * 1024 * 1024 + 1]).await?;
            first.shutdown().await?;

            let mut second = accept_request(&listener).await?;
            let second_request = read_request(&mut second).await?;
            assert_eq!(
                second_request["limit"],
                json!(LIVE_TAIL_LIMIT / TAIL_RETRY_DIVISOR)
            );
            assert_eq!(
                second_request["scan_limit"],
                json!(default_tail_scan_limit(false))
            );
            write_tail_response(
                &mut second,
                LIVE_TAIL_LIMIT / TAIL_RETRY_DIVISOR,
                default_tail_scan_limit(false),
            )
            .await?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        });

        let tail = request_tail_events(&socket_path, 0, false, Selector::default(), &[]).await?;

        assert_eq!(tail.limit, LIVE_TAIL_LIMIT / TAIL_RETRY_DIVISOR);
        assert_eq!(tail.scan_limit, default_tail_scan_limit(false));
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn latest_tail_events_start_with_initial_window_limit()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let temp = tempdir()?;
        let socket_path = temp.path().join("admin.sock");
        let listener = UnixListener::bind(&socket_path)?;
        let server = tokio::spawn(async move {
            let mut stream = accept_request(&listener).await?;
            let request = read_request(&mut stream).await?;
            assert_eq!(request["latest"], json!(true));
            assert_eq!(request["limit"], json!(INITIAL_TAIL_LIMIT));
            assert_eq!(request["scan_limit"], json!(default_tail_scan_limit(true)));
            write_tail_response(
                &mut stream,
                INITIAL_TAIL_LIMIT,
                default_tail_scan_limit(true),
            )
            .await?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        });

        let tail = request_tail_events(&socket_path, 0, true, Selector::default(), &[]).await?;

        assert_eq!(tail.limit, INITIAL_TAIL_LIMIT);
        assert_eq!(tail.scan_limit, default_tail_scan_limit(true));
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn latest_tail_events_preserve_filtered_backfill_scan_depth()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let temp = tempdir()?;
        let socket_path = temp.path().join("admin.sock");
        let listener = UnixListener::bind(&socket_path)?;
        let server = tokio::spawn(async move {
            let mut stream = accept_request(&listener).await?;
            let request = read_request(&mut stream).await?;
            assert_eq!(request["latest"], json!(true));
            assert_eq!(request["event_types"], json!(["http_request_headers"]));
            assert_eq!(request["limit"], json!(1_024));
            assert_eq!(request["scan_limit"], json!(default_tail_scan_limit(true)));
            write_tail_response(&mut stream, 1_024, default_tail_scan_limit(true)).await?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        });

        let tail = request_tail_events(
            &socket_path,
            0,
            true,
            Selector::default(),
            &[EventType::HttpRequestHeaders],
        )
        .await?;

        assert_eq!(tail.limit, 1_024);
        assert_eq!(tail.scan_limit, default_tail_scan_limit(true));
        server.await??;
        Ok(())
    }

    #[tokio::test]
    async fn tail_events_reports_final_response_budget_after_retry_floor()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let temp = tempdir()?;
        let socket_path = temp.path().join("admin.sock");
        let listener = UnixListener::bind(&socket_path)?;
        let server = tokio::spawn(async move {
            for expected_limit in [128, 32, 8, 2, 1] {
                let mut stream = accept_request(&listener).await?;
                let request = read_request(&mut stream).await?;
                assert_eq!(request["limit"], json!(expected_limit));
                assert_eq!(request["scan_limit"], json!(default_tail_scan_limit(false)));
                stream.write_all(&vec![b'a'; 16 * 1024 * 1024 + 1]).await?;
                stream.shutdown().await?;
            }
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        });

        let error = request_tail_events(&socket_path, 0, false, Selector::default(), &[])
            .await
            .expect_err("tail_events should report final response budget");

        assert!(matches!(
            error,
            TrafficClientError::TailResponseTooLarge {
                event_limit: 1,
                response_limit_bytes: 16_777_216
            }
        ));
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
        scan_limit: usize,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let response = json!({
            "kind": "event_tail",
            "tail": {
                "after_sequence": 0,
                "next_after_sequence": 0,
                "last_export_sequence": 0,
                "attribution_mode": "strict",
                "limit": limit,
                "scan_limit": scan_limit,
                "scanned": 0,
                "budget": {
                    "max_event_payload_bytes": TAIL_FIXTURE_MAX_EVENT_PAYLOAD_BYTES,
                    "max_record_bytes": TAIL_FIXTURE_MAX_RECORD_BYTES,
                    "included_record_bytes": 0,
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
