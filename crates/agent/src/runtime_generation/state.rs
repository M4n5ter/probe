use std::{
    fmt,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use probe_config::AgentConfig;
use serde::Serialize;

#[derive(Clone)]
pub(crate) struct RuntimeGenerationState {
    inner: Arc<Mutex<RuntimeGenerationControl>>,
}

#[derive(Debug, Clone)]
pub(crate) struct RuntimeGenerationReloadRequestInput {
    pub candidate_path: PathBuf,
    pub candidate_config: AgentConfig,
    pub current_config_version: String,
    pub candidate_config_version: Option<String>,
    pub changed_sections: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct RuntimeGenerationReloadRequest {
    pub snapshot: RuntimeGenerationReloadRequestSnapshot,
    pub candidate_config: AgentConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuntimeGenerationReloadQueueError {
    pending_request_id: Option<u64>,
    applying_request_id: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct RuntimeGenerationReloadRequestSnapshot {
    pub request_id: u64,
    pub candidate_path: PathBuf,
    pub current_config_version: String,
    pub candidate_config_version: Option<String>,
    pub changed_sections: Vec<String>,
    pub requested_unix_ns: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub(crate) struct RuntimeGenerationSnapshot {
    pub active: ActiveRuntimeGenerationSnapshot,
    pub pending: Option<RuntimeGenerationReloadRequestSnapshot>,
    pub applying: Option<RuntimeGenerationReloadApplyingSnapshot>,
    pub last_outcome: Option<RuntimeGenerationReloadOutcomeSnapshot>,
    pub capture_control: CaptureControlSafePointSnapshot,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub(crate) struct ActiveRuntimeGenerationSnapshot {
    pub generation: u64,
    pub config_version: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub(crate) struct CaptureControlSafePointSnapshot {
    pub safe_points: u64,
    pub last_safe_point_unix_ns: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct RuntimeGenerationReloadApplyingSnapshot {
    pub request: RuntimeGenerationReloadRequestSnapshot,
    pub started_unix_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct RuntimeGenerationReloadOutcomeSnapshot {
    pub request_id: u64,
    pub completed_unix_ns: u64,
    pub result: RuntimeGenerationReloadResultSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "result")]
pub(crate) enum RuntimeGenerationReloadResultSnapshot {
    Applied {
        generation: u64,
        config_version: String,
    },
    Failed {
        message: String,
    },
}

#[derive(Debug, Default)]
struct RuntimeGenerationControl {
    snapshot: RuntimeGenerationSnapshot,
    pending_candidate_config: Option<AgentConfig>,
    next_request_id: u64,
}

impl RuntimeGenerationState {
    pub(crate) fn for_config_version(config_version: impl Into<String>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(RuntimeGenerationControl {
                snapshot: RuntimeGenerationSnapshot {
                    active: ActiveRuntimeGenerationSnapshot {
                        generation: 1,
                        config_version: config_version.into(),
                    },
                    pending: None,
                    applying: None,
                    last_outcome: None,
                    capture_control: CaptureControlSafePointSnapshot::default(),
                },
                pending_candidate_config: None,
                next_request_id: 1,
            })),
        }
    }

    pub(crate) fn snapshot(&self) -> RuntimeGenerationSnapshot {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .snapshot
            .clone()
    }

    pub(crate) fn request_reload(
        &self,
        request: RuntimeGenerationReloadRequestInput,
    ) -> Result<RuntimeGenerationReloadRequestSnapshot, RuntimeGenerationReloadQueueError> {
        let mut control = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if control.snapshot.pending.is_some() || control.snapshot.applying.is_some() {
            return Err(RuntimeGenerationReloadQueueError {
                pending_request_id: control
                    .snapshot
                    .pending
                    .as_ref()
                    .map(|request| request.request_id),
                applying_request_id: control
                    .snapshot
                    .applying
                    .as_ref()
                    .map(|applying| applying.request.request_id),
            });
        }
        let request_id = control.next_request_id;
        control.next_request_id = control.next_request_id.saturating_add(1);
        let snapshot = RuntimeGenerationReloadRequestSnapshot {
            request_id,
            candidate_path: request.candidate_path,
            current_config_version: request.current_config_version,
            candidate_config_version: request.candidate_config_version,
            changed_sections: request.changed_sections,
            requested_unix_ns: current_unix_time_ns(),
        };
        control.pending_candidate_config = Some(request.candidate_config);
        control.snapshot.pending = Some(snapshot.clone());
        Ok(snapshot)
    }

    pub(crate) fn begin_pending_reload(&self) -> Option<RuntimeGenerationReloadRequest> {
        let mut control = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let snapshot = control.snapshot.pending.take()?;
        let candidate_config = control.pending_candidate_config.take()?;
        control.snapshot.applying = Some(RuntimeGenerationReloadApplyingSnapshot {
            request: snapshot.clone(),
            started_unix_ns: current_unix_time_ns(),
        });
        Some(RuntimeGenerationReloadRequest {
            snapshot,
            candidate_config,
        })
    }

    pub(crate) fn record_reload_applied(&self, request_id: u64, config_version: impl Into<String>) {
        let mut control = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let config_version = config_version.into();
        control.snapshot.active.generation = control.snapshot.active.generation.saturating_add(1);
        control.snapshot.active.config_version = config_version.clone();
        control.snapshot.applying = None;
        control.snapshot.last_outcome = Some(RuntimeGenerationReloadOutcomeSnapshot {
            request_id,
            completed_unix_ns: current_unix_time_ns(),
            result: RuntimeGenerationReloadResultSnapshot::Applied {
                generation: control.snapshot.active.generation,
                config_version,
            },
        });
    }

    pub(crate) fn record_reload_failed(&self, request_id: u64, message: impl Into<String>) {
        let mut control = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        control.snapshot.applying = None;
        control.snapshot.last_outcome = Some(RuntimeGenerationReloadOutcomeSnapshot {
            request_id,
            completed_unix_ns: current_unix_time_ns(),
            result: RuntimeGenerationReloadResultSnapshot::Failed {
                message: message.into(),
            },
        });
    }

    pub(crate) fn record_capture_safe_point(&self) {
        let mut control = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        control.snapshot.capture_control.safe_points = control
            .snapshot
            .capture_control
            .safe_points
            .saturating_add(1);
        control.snapshot.capture_control.last_safe_point_unix_ns = Some(current_unix_time_ns());
    }
}

impl fmt::Display for RuntimeGenerationReloadQueueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.pending_request_id, self.applying_request_id) {
            (Some(pending), Some(applying)) => write!(
                f,
                "runtime generation reload is busy: pending request {pending}, applying request {applying}"
            ),
            (Some(pending), None) => write!(
                f,
                "runtime generation reload is busy: pending request {pending}"
            ),
            (None, Some(applying)) => write!(
                f,
                "runtime generation reload is busy: applying request {applying}"
            ),
            (None, None) => write!(f, "runtime generation reload is busy"),
        }
    }
}

impl std::error::Error for RuntimeGenerationReloadQueueError {}

impl Default for RuntimeGenerationState {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(RuntimeGenerationControl::default())),
        }
    }
}

fn current_unix_time_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_generation_starts_at_first_active_generation() {
        let state = RuntimeGenerationState::for_config_version("local");

        let snapshot = state.snapshot();

        assert_eq!(snapshot.active.generation, 1);
        assert_eq!(snapshot.active.config_version, "local");
        assert_eq!(snapshot.pending, None);
        assert_eq!(snapshot.applying, None);
        assert_eq!(snapshot.last_outcome, None);
        assert_eq!(snapshot.capture_control.safe_points, 0);
        assert_eq!(snapshot.capture_control.last_safe_point_unix_ns, None);
    }

    #[test]
    fn runtime_generation_records_capture_safe_points() {
        let state = RuntimeGenerationState::for_config_version("local");

        state.record_capture_safe_point();
        state.record_capture_safe_point();

        let snapshot = state.snapshot();
        assert_eq!(snapshot.capture_control.safe_points, 2);
        assert!(
            snapshot
                .capture_control
                .last_safe_point_unix_ns
                .is_some_and(|timestamp| timestamp > 0)
        );
    }

    #[test]
    fn runtime_generation_rejects_reload_while_pending_request_exists() {
        let state = RuntimeGenerationState::for_config_version("local");

        let first = state
            .request_reload(reload_request("candidate-a.toml", "candidate-a"))
            .expect("first request should queue");
        let second = state.request_reload(reload_request("candidate-b.toml", "candidate-b"));

        let snapshot = state.snapshot();
        assert_eq!(first.request_id, 1);
        assert!(matches!(
            second,
            Err(RuntimeGenerationReloadQueueError {
                pending_request_id: Some(1),
                applying_request_id: None,
            })
        ));
        assert_eq!(snapshot.pending, Some(first));
    }

    #[test]
    fn runtime_generation_moves_pending_request_to_applying() {
        let state = RuntimeGenerationState::for_config_version("local");
        let queued = state
            .request_reload(reload_request("candidate.toml", "candidate"))
            .expect("request should queue");

        let applying = state
            .begin_pending_reload()
            .expect("queued request should begin");
        let snapshot = state.snapshot();

        assert_eq!(applying.snapshot, queued);
        assert_eq!(snapshot.pending, None);
        assert_eq!(
            snapshot.applying.as_ref().map(|applying| &applying.request),
            Some(&queued)
        );
    }

    #[test]
    fn runtime_generation_rejects_reload_while_request_is_applying() {
        let state = RuntimeGenerationState::for_config_version("local");
        state
            .request_reload(reload_request("candidate-a.toml", "candidate-a"))
            .expect("first request should queue");
        state.begin_pending_reload();

        let second = state.request_reload(reload_request("candidate-b.toml", "candidate-b"));

        assert!(matches!(
            second,
            Err(RuntimeGenerationReloadQueueError {
                pending_request_id: None,
                applying_request_id: Some(1),
            })
        ));
    }

    #[test]
    fn runtime_generation_records_failed_reload_outcome() {
        let state = RuntimeGenerationState::for_config_version("local");
        let queued = state
            .request_reload(reload_request("candidate.toml", "candidate"))
            .expect("request should queue");
        state.begin_pending_reload();

        state.record_reload_failed(queued.request_id, "candidate is not usable");

        let snapshot = state.snapshot();
        assert_eq!(snapshot.active.config_version, "local");
        assert_eq!(snapshot.applying, None);
        assert!(matches!(
            snapshot.last_outcome.map(|outcome| outcome.result),
            Some(RuntimeGenerationReloadResultSnapshot::Failed { message })
                if message == "candidate is not usable"
        ));
    }

    #[test]
    fn runtime_generation_records_applied_reload_outcome() {
        let state = RuntimeGenerationState::for_config_version("local");
        let queued = state
            .request_reload(reload_request("candidate.toml", "candidate"))
            .expect("request should queue");
        state.begin_pending_reload();

        state.record_reload_applied(queued.request_id, "candidate");

        let snapshot = state.snapshot();
        assert_eq!(snapshot.active.generation, 2);
        assert_eq!(snapshot.active.config_version, "candidate");
        assert_eq!(snapshot.applying, None);
        assert!(matches!(
            snapshot.last_outcome.map(|outcome| outcome.result),
            Some(RuntimeGenerationReloadResultSnapshot::Applied {
                generation: 2,
                config_version
            }) if config_version == "candidate"
        ));
    }

    fn reload_request(path: &str, candidate_version: &str) -> RuntimeGenerationReloadRequestInput {
        let candidate_config = AgentConfig {
            config_version: candidate_version.to_string(),
            ..Default::default()
        };
        RuntimeGenerationReloadRequestInput {
            candidate_path: PathBuf::from(path),
            candidate_config,
            current_config_version: "local".to_string(),
            candidate_config_version: Some(candidate_version.to_string()),
            changed_sections: vec!["capture".to_string()],
        }
    }
}
