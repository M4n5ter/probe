use std::sync::{Arc, Mutex};

use runtime::RuntimePlan;
use serde::Serialize;

use super::plan::TlsSessionSecretAutoBindingPlan;

#[derive(Debug, Clone)]
pub(crate) struct TlsDecryptHintRuntimeState {
    inner: Arc<Mutex<TlsDecryptHintRuntimeSnapshot>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsDecryptHintRuntimeSnapshot {
    pub session_secret_refresh: TlsSessionSecretRefreshRuntimeSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsSessionSecretRefreshRuntimeSnapshot {
    pub mode: TlsSessionSecretRefreshRuntimeMode,
    pub configured_ref_count: u64,
    pub enabled_ref_count: u64,
    pub generation: u64,
    pub attempts: u64,
    pub pending: u64,
    pub failures: u64,
    pub last_failure: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsSessionSecretRefreshRuntimeMode {
    NotConfigured,
    Disabled,
    Pending,
    Active,
    Failed,
}

pub(super) enum TlsSessionSecretRefreshRuntimeTransition {
    InitialReady,
    InitialPending,
    RefreshReady,
    RefreshPending,
    RefreshFailed { reason: String },
}

impl TlsDecryptHintRuntimeState {
    pub(crate) fn for_plan(plan: &RuntimePlan) -> Self {
        let configured_ref_count = plan.tls.plaintext.decrypt_hints.session_secrets.len() as u64;
        let enabled_ref_count = match TlsSessionSecretAutoBindingPlan::for_runtime(plan) {
            TlsSessionSecretAutoBindingPlan::Disabled => 0,
            TlsSessionSecretAutoBindingPlan::Enabled { materials } => materials.len() as u64,
        };
        let mode = match (configured_ref_count, enabled_ref_count) {
            (0, _) => TlsSessionSecretRefreshRuntimeMode::NotConfigured,
            (_, 0) => TlsSessionSecretRefreshRuntimeMode::Disabled,
            _ => TlsSessionSecretRefreshRuntimeMode::Pending,
        };
        Self {
            inner: Arc::new(Mutex::new(TlsDecryptHintRuntimeSnapshot {
                session_secret_refresh: TlsSessionSecretRefreshRuntimeSnapshot {
                    mode,
                    configured_ref_count,
                    enabled_ref_count,
                    generation: 0,
                    attempts: 0,
                    pending: 0,
                    failures: 0,
                    last_failure: None,
                },
            })),
        }
    }

    pub(crate) fn snapshot(&self) -> TlsDecryptHintRuntimeSnapshot {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub(super) fn record_session_secret_refresh(
        &self,
        transition: TlsSessionSecretRefreshRuntimeTransition,
    ) {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let refresh = &mut inner.session_secret_refresh;
        match transition {
            TlsSessionSecretRefreshRuntimeTransition::InitialReady => {
                record_ready_refresh(refresh);
            }
            TlsSessionSecretRefreshRuntimeTransition::InitialPending => {
                record_pending_refresh(refresh);
            }
            TlsSessionSecretRefreshRuntimeTransition::RefreshReady => {
                record_refresh_attempt(refresh);
                record_ready_refresh(refresh);
            }
            TlsSessionSecretRefreshRuntimeTransition::RefreshPending => {
                record_refresh_attempt(refresh);
                record_pending_refresh(refresh);
            }
            TlsSessionSecretRefreshRuntimeTransition::RefreshFailed { reason } => {
                record_refresh_attempt(refresh);
                record_failed_refresh(refresh, reason);
            }
        }
    }
}

fn record_ready_refresh(refresh: &mut TlsSessionSecretRefreshRuntimeSnapshot) {
    refresh.mode = TlsSessionSecretRefreshRuntimeMode::Active;
    refresh.generation = refresh.generation.saturating_add(1);
    refresh.last_failure = None;
}

fn record_pending_refresh(refresh: &mut TlsSessionSecretRefreshRuntimeSnapshot) {
    if refresh.generation == 0 {
        refresh.mode = TlsSessionSecretRefreshRuntimeMode::Pending;
    }
    refresh.pending = refresh.pending.saturating_add(1);
}

fn record_failed_refresh(refresh: &mut TlsSessionSecretRefreshRuntimeSnapshot, reason: String) {
    if refresh.generation == 0 {
        refresh.mode = TlsSessionSecretRefreshRuntimeMode::Failed;
    }
    refresh.failures = refresh.failures.saturating_add(1);
    refresh.last_failure = Some(reason);
}

fn record_refresh_attempt(refresh: &mut TlsSessionSecretRefreshRuntimeSnapshot) {
    refresh.attempts = refresh.attempts.saturating_add(1);
}
