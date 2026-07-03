use std::{future::Future, path::Path, time::Duration};

use serde_json::Value;
use tokio::time::{Instant, sleep};

use crate::{
    admin::{AdminClientError, AdminRequest, send_admin_json_request_with_timeout},
    runtime_generation::{RuntimeGenerationReloadResultSnapshot, RuntimeGenerationSnapshot},
};

const RUNTIME_GENERATION_WAIT_TIMEOUT: Duration = Duration::from_secs(10);
const RUNTIME_GENERATION_POLL_INTERVAL: Duration = Duration::from_millis(200);
const RUNTIME_GENERATION_STATUS_TIMEOUT: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum RuntimeGenerationWaitOutcome {
    Applied {
        generation: u64,
        config_version: String,
    },
    Failed {
        message: String,
    },
    StillPending,
}

#[derive(Debug, thiserror::Error)]
pub(super) enum RuntimeGenerationStatusError {
    #[error("admin client error: {0}")]
    AdminClient(AdminClientError),
    #[error("unexpected admin response kind: {kind}")]
    UnexpectedResponse { kind: String },
    #[error("runtime generation status is missing from admin status response")]
    MissingRuntimeGeneration,
    #[error("failed to parse runtime generation status: {0}")]
    Json(serde_json::Error),
}

pub(super) async fn wait_for_runtime_generation_outcome(
    socket_path: &Path,
    request_id: u64,
) -> Result<RuntimeGenerationWaitOutcome, RuntimeGenerationStatusError> {
    let socket_path = socket_path.to_path_buf();
    wait_for_runtime_generation_outcome_with(
        request_id,
        RUNTIME_GENERATION_WAIT_TIMEOUT,
        RUNTIME_GENERATION_POLL_INTERVAL,
        move |timeout| {
            let socket_path = socket_path.clone();
            async move { fetch_runtime_generation_status(&socket_path, timeout).await }
        },
        sleep,
    )
    .await
}

async fn wait_for_runtime_generation_outcome_with<F, Fut, S, SleepFut>(
    request_id: u64,
    wait_timeout: Duration,
    poll_interval: Duration,
    mut fetch_status: F,
    mut sleep_for: S,
) -> Result<RuntimeGenerationWaitOutcome, RuntimeGenerationStatusError>
where
    F: FnMut(Duration) -> Fut,
    Fut: Future<Output = Result<Value, RuntimeGenerationStatusError>>,
    S: FnMut(Duration) -> SleepFut,
    SleepFut: Future<Output = ()>,
{
    let deadline = Instant::now() + wait_timeout;
    loop {
        let response = match fetch_status(RUNTIME_GENERATION_STATUS_TIMEOUT).await {
            Ok(response) => response,
            Err(RuntimeGenerationStatusError::AdminClient(AdminClientError::Timeout)) => {
                if Instant::now() >= deadline {
                    return Ok(RuntimeGenerationWaitOutcome::StillPending);
                }
                sleep_for(poll_interval).await;
                continue;
            }
            Err(error) => return Err(error),
        };
        match parse_runtime_generation_status(&response, request_id)? {
            RuntimeGenerationPollStatus::Applied {
                generation,
                config_version,
            } => {
                return Ok(RuntimeGenerationWaitOutcome::Applied {
                    generation,
                    config_version,
                });
            }
            RuntimeGenerationPollStatus::Failed { message } => {
                return Ok(RuntimeGenerationWaitOutcome::Failed { message });
            }
            RuntimeGenerationPollStatus::Pending => {}
        }
        if Instant::now() >= deadline {
            return Ok(RuntimeGenerationWaitOutcome::StillPending);
        }
        sleep_for(poll_interval).await;
    }
}

async fn fetch_runtime_generation_status(
    socket_path: &Path,
    timeout: Duration,
) -> Result<Value, RuntimeGenerationStatusError> {
    send_admin_json_request_with_timeout(socket_path, AdminRequest::Status, timeout)
        .await
        .map_err(RuntimeGenerationStatusError::AdminClient)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RuntimeGenerationPollStatus {
    Applied {
        generation: u64,
        config_version: String,
    },
    Failed {
        message: String,
    },
    Pending,
}

fn parse_runtime_generation_status(
    response: &Value,
    request_id: u64,
) -> Result<RuntimeGenerationPollStatus, RuntimeGenerationStatusError> {
    match response.get("kind").and_then(Value::as_str) {
        Some("status") => {}
        other => {
            return Err(RuntimeGenerationStatusError::UnexpectedResponse {
                kind: other.unwrap_or("<missing>").to_string(),
            });
        }
    }
    let runtime_generation = response
        .pointer("/snapshot/runtime_generation")
        .ok_or(RuntimeGenerationStatusError::MissingRuntimeGeneration)?;
    let snapshot = serde_json::from_value::<RuntimeGenerationSnapshot>(runtime_generation.clone())
        .map_err(RuntimeGenerationStatusError::Json)?;
    Ok(classify_runtime_generation_snapshot(&snapshot, request_id))
}

fn classify_runtime_generation_snapshot(
    snapshot: &RuntimeGenerationSnapshot,
    request_id: u64,
) -> RuntimeGenerationPollStatus {
    if snapshot
        .pending
        .as_ref()
        .is_some_and(|pending| pending.request_id == request_id)
        || snapshot
            .applying
            .as_ref()
            .is_some_and(|applying| applying.request.request_id == request_id)
    {
        return RuntimeGenerationPollStatus::Pending;
    }
    let Some(outcome) = &snapshot.last_outcome else {
        return RuntimeGenerationPollStatus::Pending;
    };
    if outcome.request_id != request_id {
        return RuntimeGenerationPollStatus::Pending;
    }
    match &outcome.result {
        RuntimeGenerationReloadResultSnapshot::Applied {
            generation,
            config_version,
        } => RuntimeGenerationPollStatus::Applied {
            generation: *generation,
            config_version: config_version.clone(),
        },
        RuntimeGenerationReloadResultSnapshot::Failed { message } => {
            RuntimeGenerationPollStatus::Failed {
                message: message.clone(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use serde_json::json;

    use super::*;

    #[test]
    fn runtime_generation_status_parser_reads_applied_outcome() {
        let response = json!({
            "kind": "status",
            "snapshot": {
                "runtime_generation": {
                    "active": { "generation": 2, "config_version": "candidate" },
                    "pending": null,
                    "applying": null,
                    "last_outcome": {
                        "request_id": 7,
                        "completed_unix_ns": 1,
                        "result": {
                            "result": "applied",
                            "generation": 2,
                            "config_version": "candidate"
                        }
                    },
                    "capture_control": {
                        "safe_points": 1,
                        "last_safe_point_unix_ns": 1
                    }
                }
            }
        });

        let status = parse_runtime_generation_status(&response, 7)
            .expect("runtime generation status should parse");

        assert_eq!(
            status,
            RuntimeGenerationPollStatus::Applied {
                generation: 2,
                config_version: "candidate".to_string()
            }
        );
    }

    #[test]
    fn runtime_generation_status_parser_reports_pending_request() {
        let response = json!({
            "kind": "status",
            "snapshot": {
                "runtime_generation": {
                    "active": { "generation": 1, "config_version": "current" },
                    "pending": {
                        "request_id": 7,
                        "candidate_path": "/tmp/candidate.toml",
                        "current_config_version": "current",
                        "candidate_config_version": "candidate",
                        "changed_sections": ["capture"],
                        "requested_unix_ns": 1
                    },
                    "applying": null,
                    "last_outcome": null,
                    "capture_control": {
                        "safe_points": 0,
                        "last_safe_point_unix_ns": null
                    }
                }
            }
        });

        let status = parse_runtime_generation_status(&response, 7)
            .expect("runtime generation status should parse");

        assert_eq!(status, RuntimeGenerationPollStatus::Pending);
    }

    #[test]
    fn runtime_generation_status_parser_reads_failed_outcome() {
        let response = status_response(json!({
            "active": { "generation": 1, "config_version": "current" },
            "pending": null,
            "applying": null,
            "last_outcome": {
                "request_id": 7,
                "completed_unix_ns": 1,
                "result": {
                    "result": "failed",
                    "message": "provider open failed"
                }
            },
            "capture_control": {
                "safe_points": 1,
                "last_safe_point_unix_ns": 1
            }
        }));

        let status = parse_runtime_generation_status(&response, 7)
            .expect("runtime generation status should parse");

        assert_eq!(
            status,
            RuntimeGenerationPollStatus::Failed {
                message: "provider open failed".to_string()
            }
        );
    }

    #[test]
    fn runtime_generation_status_parser_rejects_missing_runtime_generation_status() {
        let response = json!({
            "kind": "status",
            "snapshot": {}
        });

        let error = parse_runtime_generation_status(&response, 7)
            .expect_err("missing runtime generation status should be rejected");

        assert!(matches!(
            error,
            RuntimeGenerationStatusError::MissingRuntimeGeneration
        ));
    }

    #[tokio::test]
    async fn runtime_generation_wait_returns_after_pending_request_applies() {
        let mut responses = VecDeque::from([
            pending_status_response(7),
            applied_status_response(7, 2, "candidate"),
        ]);

        let outcome = wait_for_runtime_generation_outcome_with(
            7,
            Duration::from_secs(1),
            Duration::ZERO,
            |_| {
                let response = responses
                    .pop_front()
                    .expect("test should provide enough status responses");
                async move { Ok(response) }
            },
            |_| async {},
        )
        .await
        .expect("wait should finish successfully");

        assert_eq!(
            outcome,
            RuntimeGenerationWaitOutcome::Applied {
                generation: 2,
                config_version: "candidate".to_string()
            }
        );
    }

    #[tokio::test]
    async fn runtime_generation_wait_treats_status_timeout_as_transient_pending() {
        let mut responses = VecDeque::from([
            Err(RuntimeGenerationStatusError::AdminClient(
                AdminClientError::Timeout,
            )),
            Ok(applied_status_response(7, 2, "candidate")),
        ]);

        let outcome = wait_for_runtime_generation_outcome_with(
            7,
            Duration::from_secs(1),
            Duration::ZERO,
            |_| {
                let response = responses
                    .pop_front()
                    .expect("test should provide enough status responses");
                async move { response }
            },
            |_| async {},
        )
        .await
        .expect("transient timeout should not fail the wait");

        assert_eq!(
            outcome,
            RuntimeGenerationWaitOutcome::Applied {
                generation: 2,
                config_version: "candidate".to_string()
            }
        );
    }

    #[tokio::test]
    async fn runtime_generation_wait_returns_failed_outcome() {
        let mut responses = VecDeque::from([failed_status_response(7, "provider open failed")]);

        let outcome = wait_for_runtime_generation_outcome_with(
            7,
            Duration::from_secs(1),
            Duration::ZERO,
            |_| {
                let response = responses
                    .pop_front()
                    .expect("test should provide enough status responses");
                async move { Ok(response) }
            },
            |_| async {},
        )
        .await
        .expect("wait should finish successfully");

        assert_eq!(
            outcome,
            RuntimeGenerationWaitOutcome::Failed {
                message: "provider open failed".to_string()
            }
        );
    }

    #[tokio::test]
    async fn runtime_generation_wait_times_out_when_request_stays_pending() {
        let outcome = wait_for_runtime_generation_outcome_with(
            7,
            Duration::ZERO,
            Duration::ZERO,
            |_| async { Ok(pending_status_response(7)) },
            |_| async {},
        )
        .await
        .expect("wait should finish successfully");

        assert_eq!(outcome, RuntimeGenerationWaitOutcome::StillPending);
    }

    #[tokio::test]
    async fn runtime_generation_wait_propagates_status_fetch_error() {
        let error = wait_for_runtime_generation_outcome_with(
            7,
            Duration::from_secs(1),
            Duration::ZERO,
            |_| async {
                Err(RuntimeGenerationStatusError::UnexpectedResponse {
                    kind: "error".to_string(),
                })
            },
            |_| async {},
        )
        .await
        .expect_err("fetch errors should propagate");

        assert!(matches!(
            error,
            RuntimeGenerationStatusError::UnexpectedResponse { kind } if kind == "error"
        ));
    }

    fn pending_status_response(request_id: u64) -> serde_json::Value {
        status_response(json!({
            "active": { "generation": 1, "config_version": "current" },
            "pending": {
                "request_id": request_id,
                "candidate_path": "/tmp/candidate.toml",
                "current_config_version": "current",
                "candidate_config_version": "candidate",
                "changed_sections": ["capture"],
                "requested_unix_ns": 1
            },
            "applying": null,
            "last_outcome": null,
            "capture_control": {
                "safe_points": 0,
                "last_safe_point_unix_ns": null
            }
        }))
    }

    fn applied_status_response(
        request_id: u64,
        generation: u64,
        config_version: &str,
    ) -> serde_json::Value {
        status_response(json!({
            "active": { "generation": generation, "config_version": config_version },
            "pending": null,
            "applying": null,
            "last_outcome": {
                "request_id": request_id,
                "completed_unix_ns": 1,
                "result": {
                    "result": "applied",
                    "generation": generation,
                    "config_version": config_version
                }
            },
            "capture_control": {
                "safe_points": 1,
                "last_safe_point_unix_ns": 1
            }
        }))
    }

    fn failed_status_response(request_id: u64, message: &str) -> serde_json::Value {
        status_response(json!({
            "active": { "generation": 1, "config_version": "current" },
            "pending": null,
            "applying": null,
            "last_outcome": {
                "request_id": request_id,
                "completed_unix_ns": 1,
                "result": {
                    "result": "failed",
                    "message": message
                }
            },
            "capture_control": {
                "safe_points": 1,
                "last_safe_point_unix_ns": 1
            }
        }))
    }

    fn status_response(runtime_generation: serde_json::Value) -> serde_json::Value {
        json!({
            "kind": "status",
            "snapshot": {
                "runtime_generation": runtime_generation
            }
        })
    }
}
