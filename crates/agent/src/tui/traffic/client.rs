use std::{path::Path, time::Duration};

use probe_core::{EventType, Selector};
use serde_json::Value;
use thiserror::Error;

use crate::admin::{
    AdminClientError, AdminRequest, EventDetailSnapshot, EventDetailTooLargeSnapshot,
    EventTailSnapshot, send_admin_json_request_with_timeout,
};

const TAIL_TIMEOUT: Duration = Duration::from_secs(1);
const DETAIL_TIMEOUT: Duration = Duration::from_secs(2);
const TAIL_LIMIT: usize = 64;

pub(super) async fn request_tail_events(
    socket_path: &Path,
    after_sequence: u64,
    selector: Selector,
    event_types: &[EventType],
) -> Result<EventTailSnapshot, TrafficClientError> {
    let response = send_admin_json_request_with_timeout(
        socket_path,
        AdminRequest::TailEvents {
            after_sequence,
            limit: TAIL_LIMIT,
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
