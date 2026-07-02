use std::{path::Path, time::Duration};

use probe_core::Selector;
use serde_json::Value;
use thiserror::Error;

use crate::admin::{
    AdminClientError, AdminRequest, EventTailSnapshot, send_admin_json_request_with_timeout,
};

const ADMIN_TIMEOUT: Duration = Duration::from_millis(150);
const TAIL_LIMIT: usize = 64;

pub(super) async fn request_tail_events(
    socket_path: &Path,
    after_sequence: u64,
    selector: Selector,
) -> Result<EventTailSnapshot, TrafficClientError> {
    let response = send_admin_json_request_with_timeout(
        socket_path,
        AdminRequest::TailEvents {
            after_sequence,
            limit: TAIL_LIMIT,
            selector: Some(selector),
        },
        ADMIN_TIMEOUT,
    )
    .await?;
    match response.get("kind").and_then(Value::as_str) {
        Some("event_tail") => {
            let tail = response
                .get("tail")
                .cloned()
                .ok_or(TrafficClientError::MissingTail)?;
            serde_json::from_value(tail).map_err(TrafficClientError::Json)
        }
        Some("error") => Err(TrafficClientError::Admin(
            response
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("admin tail_events returned an error")
                .to_string(),
        )),
        other => Err(TrafficClientError::UnexpectedResponse {
            kind: other.unwrap_or("<missing>").to_string(),
        }),
    }
}

#[derive(Debug, Error)]
pub(super) enum TrafficClientError {
    #[error("admin client error: {0}")]
    AdminClient(#[from] AdminClientError),
    #[error("admin tail response is missing tail")]
    MissingTail,
    #[error("admin tail_events failed: {0}")]
    Admin(String),
    #[error("unexpected admin response kind: {kind}")]
    UnexpectedResponse { kind: String },
    #[error("failed to parse admin tail response: {0}")]
    Json(serde_json::Error),
}
