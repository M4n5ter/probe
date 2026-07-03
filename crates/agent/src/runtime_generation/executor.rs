use capture::CaptureProvider;
use probe_config::AgentConfig;
use runtime::{RuntimePlan, validate_static_runtime_config};

use crate::{
    artifacts::hydrate_runtime_artifact_paths,
    capture_provider::{
        CaptureProviderPreflight, CaptureProviderRuntimeState, build_capture_provider,
    },
    l7_mitm::L7MitmRuntimeHandle,
    runtime_composition::build_runtime_composition,
    runtime_plan::RuntimePlanHandle,
    runtime_reload::{
        RuntimeReloadGate,
        config_reload::{
            ConfigReloadDecision, ConfigReloadPlanSnapshot, plan_config_reload_for_candidate,
            runtime_generation_reload_request,
        },
    },
    tls_plaintext::{TlsDecryptHintRuntimeState, TlsPlaintextRuntimeState},
};

use super::RuntimeGenerationState;

pub(crate) struct RuntimeGenerationExecutor {
    runtime_generation: RuntimeGenerationState,
    plan_handle: RuntimePlanHandle,
    config_apply_gate: RuntimeReloadGate,
    capture_runtime: CaptureProviderRuntimeState,
    tls_decrypt_hint_runtime: TlsDecryptHintRuntimeState,
    tls_plaintext_runtime: TlsPlaintextRuntimeState,
    l7_mitm_runtime: L7MitmRuntimeHandle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RuntimeGenerationProcessResult {
    NoPendingReload,
    Applied { config_version: String },
    Failed,
}

impl RuntimeGenerationExecutor {
    pub(crate) fn new(
        runtime_generation: RuntimeGenerationState,
        plan_handle: RuntimePlanHandle,
        config_apply_gate: RuntimeReloadGate,
        capture_runtime: CaptureProviderRuntimeState,
        tls_decrypt_hint_runtime: TlsDecryptHintRuntimeState,
        tls_plaintext_runtime: TlsPlaintextRuntimeState,
        l7_mitm_runtime: L7MitmRuntimeHandle,
    ) -> Self {
        Self {
            runtime_generation,
            plan_handle,
            config_apply_gate,
            capture_runtime,
            tls_decrypt_hint_runtime,
            tls_plaintext_runtime,
            l7_mitm_runtime,
        }
    }

    pub(crate) fn process_capture_safe_point(
        &self,
        active_plan: &mut RuntimePlan,
        provider: &mut Box<dyn CaptureProvider>,
        on_applied_config_version: impl FnOnce(&str),
    ) -> RuntimeGenerationProcessResult {
        let Some(request) = self.runtime_generation.begin_pending_reload() else {
            return RuntimeGenerationProcessResult::NoPendingReload;
        };
        let shared_plan = self.plan_handle.snapshot();
        *active_plan = shared_plan.as_ref().clone();
        let reload_plan = plan_config_reload_for_candidate(
            &active_plan.config,
            &request.snapshot.candidate_path,
            &request.candidate_config,
        );
        if !reload_plan_allows_runtime_generation(&reload_plan, &request.candidate_config) {
            self.runtime_generation.record_reload_failed(
                request.snapshot.request_id,
                "candidate no longer contains only supported runtime generation changes against the active plan",
            );
            return RuntimeGenerationProcessResult::Failed;
        }
        match build_runtime_generation_candidate(request.candidate_config) {
            Ok(candidate) => {
                let _apply_guard = self.config_apply_gate.blocking_lock();
                let shared_plan = self.plan_handle.snapshot();
                *active_plan = shared_plan.as_ref().clone();
                let reload_plan = plan_config_reload_for_candidate(
                    &active_plan.config,
                    &request.snapshot.candidate_path,
                    &candidate.plan.config,
                );
                if !reload_plan_allows_runtime_generation(&reload_plan, &candidate.plan.config) {
                    self.runtime_generation.record_reload_failed(
                        request.snapshot.request_id,
                        "candidate no longer contains only supported runtime generation changes against the active plan",
                    );
                    return RuntimeGenerationProcessResult::Failed;
                }
                match self.build_capture_provider(&candidate.plan) {
                    Ok(next_provider) => {
                        let config_version = candidate.plan.config.config_version.clone();
                        on_applied_config_version(&config_version);
                        *provider = next_provider;
                        self.plan_handle.replace(candidate.plan.clone());
                        *active_plan = candidate.plan;
                        self.runtime_generation.record_reload_applied(
                            request.snapshot.request_id,
                            config_version.clone(),
                        );
                        RuntimeGenerationProcessResult::Applied { config_version }
                    }
                    Err(message) => {
                        self.runtime_generation
                            .record_reload_failed(request.snapshot.request_id, message);
                        RuntimeGenerationProcessResult::Failed
                    }
                }
            }
            Err(message) => {
                self.runtime_generation
                    .record_reload_failed(request.snapshot.request_id, message);
                RuntimeGenerationProcessResult::Failed
            }
        }
    }

    fn build_capture_provider(
        &self,
        plan: &RuntimePlan,
    ) -> Result<Box<dyn CaptureProvider>, String> {
        self.with_runtime_snapshot_rollback(plan, || self.try_build_capture_provider(plan))
    }

    fn with_runtime_snapshot_rollback<T>(
        &self,
        plan: &RuntimePlan,
        build: impl FnOnce() -> Result<T, String>,
    ) -> Result<T, String> {
        let tls_decrypt_hint_snapshot = self.tls_decrypt_hint_runtime.snapshot();
        let tls_plaintext_snapshot = self.tls_plaintext_runtime.snapshot();
        let l7_mitm_plaintext_bridge_snapshot =
            self.l7_mitm_runtime.snapshot().plaintext_bridge.clone();
        self.tls_decrypt_hint_runtime.record_plan_reconfigured(plan);
        let result = build();
        if result.is_err() {
            self.tls_decrypt_hint_runtime
                .restore_snapshot(tls_decrypt_hint_snapshot);
            self.tls_plaintext_runtime
                .restore_snapshot(tls_plaintext_snapshot);
            self.l7_mitm_runtime
                .restore_plaintext_bridge_snapshot(l7_mitm_plaintext_bridge_snapshot);
        }
        result
    }

    fn try_build_capture_provider(
        &self,
        plan: &RuntimePlan,
    ) -> Result<Box<dyn CaptureProvider>, String> {
        let preflight = CaptureProviderPreflight::build(
            plan,
            Some(&self.tls_decrypt_hint_runtime),
            &self.l7_mitm_runtime,
        )
        .map_err(|error| format!("candidate capture provider preflight failed: {error}"))?;
        let built_provider = build_capture_provider(
            plan,
            Some(&self.tls_plaintext_runtime),
            &self.l7_mitm_runtime,
            preflight,
        )
        .map_err(|error| format!("candidate capture provider failed to open: {error}"))?;
        self.capture_runtime.record(built_provider.runtime);
        Ok(self
            .capture_runtime
            .observe_capture_input(built_provider.provider))
    }
}

fn reload_plan_allows_runtime_generation(
    reload_plan: &ConfigReloadPlanSnapshot,
    candidate_config: &AgentConfig,
) -> bool {
    matches!(
        reload_plan.decision,
        ConfigReloadDecision::QueueRuntimeGeneration { .. }
    ) && runtime_generation_reload_request(reload_plan, candidate_config).is_some()
}

struct RuntimeGenerationCandidate {
    plan: RuntimePlan,
}

fn build_runtime_generation_candidate(
    mut config: AgentConfig,
) -> Result<RuntimeGenerationCandidate, String> {
    require_runtime_artifacts(&mut config)
        .map_err(|error| format!("failed to hydrate runtime artifacts: {error}"))?;
    validate_static_runtime_config(&config)
        .map_err(|error| format!("candidate config failed static runtime validation: {error}"))?;
    let plan = build_runtime_composition(config)
        .map_err(|error| format!("candidate runtime composition failed: {error}"))?
        .into_plan();
    Ok(RuntimeGenerationCandidate { plan })
}

fn require_runtime_artifacts(config: &mut AgentConfig) -> Result<(), crate::error::AgentError> {
    hydrate_runtime_artifact_paths(config)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, sync::Arc};

    use probe_config::{
        CaptureBackend, CaptureSelection, PolicyConfig, PolicySourceConfig, TlsMaterialConfig,
        TlsMaterialKind,
    };

    use super::*;
    use crate::{
        error::AgentError,
        l7_mitm::L7MitmPlaintextBridgeMode,
        runtime_generation::{RuntimeGenerationReloadRequestInput, RuntimeGenerationState},
        tls_plaintext::TlsPlaintextInstrumentationBuild,
    };

    #[test]
    fn runtime_generation_reload_rejects_candidate_that_no_longer_matches_supported_diff() {
        let runtime_generation = RuntimeGenerationState::for_config_version("local");
        let candidate = AgentConfig::default();
        let request = runtime_generation
            .request_reload(RuntimeGenerationReloadRequestInput {
                candidate_path: PathBuf::from("/tmp/probe-stale-runtime-generation.toml"),
                candidate_config: candidate,
                current_config_version: "local".to_string(),
                candidate_config_version: None,
                changed_sections: vec!["capture".to_string()],
            })
            .expect("runtime generation request should queue");

        let mut runtime = RuntimeGenerationReloadTestRuntime::new(AgentConfig::default())
            .expect("runtime generation test runtime should build");
        runtime.process_reload(&runtime_generation);

        let snapshot = runtime_generation.snapshot();
        assert_eq!(snapshot.pending, None);
        assert_eq!(snapshot.applying, None);
        let outcome = serde_json::to_value(snapshot.last_outcome)
            .expect("runtime generation outcome should serialize");
        assert_eq!(outcome["request_id"], request.request_id);
        assert_eq!(outcome["result"]["result"], "failed");
        assert!(
            outcome["result"]["message"]
                .as_str()
                .is_some_and(|message| message
                    .contains("no longer contains only supported runtime generation changes"))
        );
    }

    #[test]
    fn runtime_generation_reload_swaps_capture_provider_for_supported_sections()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let feed_path = temp.path().join("events.jsonl");
        std::fs::write(&feed_path, "")?;
        let candidate_path = temp.path().join("candidate.toml");
        let mut candidate = AgentConfig::default();
        candidate.capture.selection = CaptureSelection::CaptureEventFeed;
        candidate.capture.capture_event_feed.path = Some(feed_path);
        candidate.capture.capture_event_feed.follow = Some(false);
        std::fs::write(&candidate_path, toml::to_string(&candidate)?)?;
        let runtime_generation = RuntimeGenerationState::for_config_version("local");
        let request = runtime_generation.request_reload(RuntimeGenerationReloadRequestInput {
            candidate_path,
            candidate_config: candidate.clone(),
            current_config_version: "local".to_string(),
            candidate_config_version: Some(candidate.config_version.clone()),
            changed_sections: vec!["capture".to_string()],
        })?;
        let mut runtime = RuntimeGenerationReloadTestRuntime::new(AgentConfig::default())?;

        runtime.process_reload(&runtime_generation);

        let snapshot = runtime_generation.snapshot();
        assert_eq!(snapshot.active.generation, 2);
        assert_eq!(snapshot.active.config_version, candidate.config_version);
        assert_eq!(snapshot.pending, None);
        assert_eq!(snapshot.applying, None);
        let outcome = serde_json::to_value(snapshot.last_outcome)
            .expect("runtime generation outcome should serialize");
        assert_eq!(outcome["request_id"], request.request_id);
        assert_eq!(outcome["result"]["result"], "applied");
        assert_eq!(
            runtime
                .plan_handle
                .snapshot()
                .capture
                .selected_backend
                .expect("candidate capture backend should be selected"),
            CaptureBackend::CaptureEventFeed
        );
        assert_eq!(runtime.provider.name(), "capture_event_feed_jsonl");
        assert_eq!(
            runtime
                .capture_runtime
                .snapshot()
                .expect("capture runtime should record candidate provider")
                .selected_backend,
            CaptureBackend::CaptureEventFeed
        );
        Ok(())
    }

    #[test]
    fn runtime_generation_reload_returns_applied_config_version_for_live_handoff()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let feed_path = temp.path().join("events.jsonl");
        std::fs::write(&feed_path, "")?;
        let mut candidate = AgentConfig {
            config_version: "candidate".to_string(),
            ..AgentConfig::default()
        };
        candidate.capture.selection = CaptureSelection::CaptureEventFeed;
        candidate.capture.capture_event_feed.path = Some(feed_path);
        candidate.capture.capture_event_feed.follow = Some(false);
        let runtime_generation = RuntimeGenerationState::for_config_version("local");
        runtime_generation.request_reload(RuntimeGenerationReloadRequestInput {
            candidate_path: temp.path().join("candidate.toml"),
            candidate_config: candidate,
            current_config_version: "local".to_string(),
            candidate_config_version: Some("candidate".to_string()),
            changed_sections: vec!["agent_identity".to_string(), "capture".to_string()],
        })?;
        let mut runtime = RuntimeGenerationReloadTestRuntime::new(AgentConfig::default())?;

        let mut handoff_config_version = None;
        let result = runtime.process_reload_with(&runtime_generation, |config_version| {
            handoff_config_version = Some(config_version.to_string());
        });

        assert_eq!(
            result,
            RuntimeGenerationProcessResult::Applied {
                config_version: "candidate".to_string()
            }
        );
        assert_eq!(handoff_config_version.as_deref(), Some("candidate"));
        Ok(())
    }

    #[test]
    fn runtime_generation_reload_updates_tls_decrypt_hint_runtime_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let feed_path = temp.path().join("events.jsonl");
        std::fs::write(&feed_path, "")?;
        let mut candidate = AgentConfig::default();
        candidate.capture.selection = CaptureSelection::CaptureEventFeed;
        candidate.capture.capture_event_feed.path = Some(feed_path);
        candidate.capture.capture_event_feed.follow = Some(false);
        candidate.tls.plaintext.decrypt_hints.key_log_refs = vec!["ssl-key-log".to_string()];
        candidate.tls.materials = vec![TlsMaterialConfig {
            id: Some("ssl-key-log".to_string()),
            kind: TlsMaterialKind::KeyLogFile,
            path: temp.path().join("sslkeys.log"),
        }];
        let runtime_generation = RuntimeGenerationState::for_config_version("local");
        runtime_generation.request_reload(RuntimeGenerationReloadRequestInput {
            candidate_path: temp.path().join("candidate.toml"),
            candidate_config: candidate,
            current_config_version: "local".to_string(),
            candidate_config_version: Some("local".to_string()),
            changed_sections: vec!["capture".to_string(), "tls".to_string()],
        })?;
        let mut runtime = RuntimeGenerationReloadTestRuntime::new(AgentConfig::default())?;

        runtime.process_reload(&runtime_generation);

        let refresh = runtime
            .tls_decrypt_hint_runtime
            .snapshot()
            .session_secret_refresh;
        assert_eq!(refresh.configured_ref_count, 1);
        assert_eq!(refresh.enabled_ref_count, 0);
        assert_eq!(runtime.provider.name(), "capture_event_feed_jsonl");
        Ok(())
    }

    #[test]
    fn runtime_generation_reload_rolls_back_tls_decrypt_hint_runtime_state_after_provider_failure()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let mut candidate = AgentConfig::default();
        candidate.capture.selection = CaptureSelection::CaptureEventFeed;
        candidate.capture.capture_event_feed.path = Some(temp.path().join("missing.jsonl"));
        candidate.capture.capture_event_feed.follow = Some(false);
        candidate.tls.plaintext.decrypt_hints.key_log_refs = vec!["ssl-key-log".to_string()];
        candidate.tls.materials = vec![TlsMaterialConfig {
            id: Some("ssl-key-log".to_string()),
            kind: TlsMaterialKind::KeyLogFile,
            path: temp.path().join("sslkeys.log"),
        }];
        let runtime_generation = RuntimeGenerationState::for_config_version("local");
        runtime_generation.request_reload(RuntimeGenerationReloadRequestInput {
            candidate_path: temp.path().join("candidate.toml"),
            candidate_config: candidate,
            current_config_version: "local".to_string(),
            candidate_config_version: Some("local".to_string()),
            changed_sections: vec!["capture".to_string(), "tls".to_string()],
        })?;
        let mut runtime = RuntimeGenerationReloadTestRuntime::new(AgentConfig::default())?;
        let before = runtime.tls_decrypt_hint_runtime.snapshot();

        runtime.process_reload(&runtime_generation);

        assert_eq!(runtime.tls_decrypt_hint_runtime.snapshot(), before);
        assert_eq!(runtime.provider.name(), "finished");
        Ok(())
    }

    #[test]
    fn runtime_generation_snapshot_rollback_restores_l7_mitm_plaintext_bridge_after_candidate_failure()
    -> Result<(), Box<dyn std::error::Error>> {
        let base_plan = build_runtime_composition(AgentConfig::default())?.into_plan();
        let l7_mitm_runtime = L7MitmRuntimeHandle::for_test(
            crate::l7_mitm::L7MitmBackendHealthSnapshot::disabled(),
            crate::l7_mitm::L7MitmPlaintextBridgeSnapshot {
                mode: L7MitmPlaintextBridgeMode::Configured,
                disable_reason: None,
            },
            1,
        );
        let executor = RuntimeGenerationExecutor::new(
            RuntimeGenerationState::for_config_version("local"),
            RuntimePlanHandle::new(Arc::new(base_plan.clone())),
            RuntimeReloadGate::default(),
            CaptureProviderRuntimeState::default(),
            TlsDecryptHintRuntimeState::for_plan(&base_plan),
            TlsPlaintextRuntimeState::for_plan(&base_plan),
            l7_mitm_runtime.clone(),
        );
        let before = l7_mitm_runtime.snapshot().plaintext_bridge;
        assert_eq!(before.mode, L7MitmPlaintextBridgeMode::Configured);

        let result: Result<(), String> =
            executor.with_runtime_snapshot_rollback(&base_plan, || {
                l7_mitm_runtime.record_plaintext_bridge_ready();
                Err("candidate provider failed".to_string())
            });

        assert!(result.is_err());
        assert_eq!(l7_mitm_runtime.snapshot().plaintext_bridge, before);
        Ok(())
    }

    #[test]
    fn runtime_generation_snapshot_rollback_restores_tls_plaintext_runtime_after_candidate_failure()
    -> Result<(), Box<dyn std::error::Error>> {
        let base_plan = build_runtime_composition(AgentConfig::default())?.into_plan();
        let runtime = RuntimeGenerationReloadTestRuntime::new(AgentConfig::default())?;
        let before = runtime.tls_plaintext_runtime.snapshot();
        let executor = RuntimeGenerationExecutor::new(
            RuntimeGenerationState::for_config_version("local"),
            runtime.plan_handle.clone(),
            RuntimeReloadGate::default(),
            CaptureProviderRuntimeState::default(),
            runtime.tls_decrypt_hint_runtime.clone(),
            runtime.tls_plaintext_runtime.clone(),
            runtime.l7_mitm_runtime.clone(),
        );

        let result: Result<(), String> =
            executor.with_runtime_snapshot_rollback(&base_plan, || {
                runtime.tls_plaintext_runtime.record_instrumentation_build(
                    &TlsPlaintextInstrumentationBuild::Enabled(Box::new(FinishedProvider)),
                );
                Err("candidate provider failed".to_string())
            });

        assert!(result.is_err());
        assert_eq!(runtime.tls_plaintext_runtime.snapshot(), before);
        Ok(())
    }

    #[test]
    fn runtime_generation_reload_does_not_overwrite_newer_shared_plan()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let feed_path = temp.path().join("events.jsonl");
        std::fs::write(&feed_path, "")?;
        let mut candidate = AgentConfig::default();
        candidate.capture.selection = CaptureSelection::CaptureEventFeed;
        candidate.capture.capture_event_feed.path = Some(feed_path);
        candidate.capture.capture_event_feed.follow = Some(false);
        let runtime_generation = RuntimeGenerationState::for_config_version("local");
        let request = runtime_generation.request_reload(RuntimeGenerationReloadRequestInput {
            candidate_path: temp.path().join("candidate.toml"),
            candidate_config: candidate.clone(),
            current_config_version: "local".to_string(),
            candidate_config_version: Some(candidate.config_version.clone()),
            changed_sections: vec!["capture".to_string()],
        })?;
        let mut runtime = RuntimeGenerationReloadTestRuntime::new(AgentConfig::default())?;
        let mut newer_config = AgentConfig::default();
        newer_config.policies.push(PolicyConfig {
            id: "guard".to_string(),
            source: PolicySourceConfig::LocalDirectory {
                path: temp.path().join("guard.bundle"),
            },
            ..PolicyConfig::default()
        });
        runtime
            .plan_handle
            .replace(build_runtime_composition(newer_config)?.into_plan());

        runtime.process_reload(&runtime_generation);

        let snapshot = runtime_generation.snapshot();
        assert_eq!(snapshot.active.generation, 1);
        let outcome = serde_json::to_value(snapshot.last_outcome)
            .expect("runtime generation outcome should serialize");
        assert_eq!(outcome["request_id"], request.request_id);
        assert_eq!(outcome["result"]["result"], "failed");
        assert_eq!(runtime.plan_handle.snapshot().config.policies.len(), 1);
        assert_eq!(runtime.provider.name(), "finished");
        Ok(())
    }

    #[test]
    fn runtime_generation_reload_rejects_unsupported_sections_after_candidate_validation()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let candidate_path = temp.path().join("candidate.toml");
        let candidate = AgentConfig::default();
        std::fs::write(&candidate_path, toml::to_string(&candidate)?)?;
        let runtime_generation = RuntimeGenerationState::for_config_version("local");
        let request = runtime_generation.request_reload(RuntimeGenerationReloadRequestInput {
            candidate_path,
            candidate_config: candidate.clone(),
            current_config_version: "local".to_string(),
            candidate_config_version: Some(candidate.config_version.clone()),
            changed_sections: vec!["tls".to_string()],
        })?;
        let mut runtime = RuntimeGenerationReloadTestRuntime::new(AgentConfig::default())?;

        runtime.process_reload(&runtime_generation);

        let snapshot = runtime_generation.snapshot();
        assert_eq!(snapshot.active.config_version, "local");
        assert_eq!(snapshot.pending, None);
        assert_eq!(snapshot.applying, None);
        let outcome = serde_json::to_value(snapshot.last_outcome)
            .expect("runtime generation outcome should serialize");
        assert_eq!(outcome["request_id"], request.request_id);
        assert_eq!(outcome["result"]["result"], "failed");
        assert!(
            outcome["result"]["message"]
                .as_str()
                .is_some_and(|message| message
                    .contains("no longer contains only supported runtime generation changes"))
        );
        Ok(())
    }

    struct RuntimeGenerationReloadTestRuntime {
        active_plan: RuntimePlan,
        plan_handle: RuntimePlanHandle,
        config_apply_gate: RuntimeReloadGate,
        provider: Box<dyn capture::CaptureProvider>,
        capture_runtime: CaptureProviderRuntimeState,
        tls_decrypt_hint_runtime: TlsDecryptHintRuntimeState,
        tls_plaintext_runtime: TlsPlaintextRuntimeState,
        l7_mitm_runtime: L7MitmRuntimeHandle,
    }

    impl RuntimeGenerationReloadTestRuntime {
        fn new(config: AgentConfig) -> Result<Self, AgentError> {
            let (plan, _, l7_mitm, _) = build_runtime_composition(config)?.into_run_parts();
            let plan_handle = RuntimePlanHandle::new(Arc::new(plan.clone()));
            Ok(Self {
                tls_decrypt_hint_runtime: TlsDecryptHintRuntimeState::for_plan(&plan),
                tls_plaintext_runtime: TlsPlaintextRuntimeState::for_plan(&plan),
                l7_mitm_runtime: l7_mitm.handle(),
                active_plan: plan,
                plan_handle,
                config_apply_gate: RuntimeReloadGate::default(),
                provider: Box::new(FinishedProvider),
                capture_runtime: CaptureProviderRuntimeState::default(),
            })
        }

        fn process_reload(
            &mut self,
            runtime_generation: &RuntimeGenerationState,
        ) -> RuntimeGenerationProcessResult {
            self.process_reload_with(runtime_generation, |_| {})
        }

        fn process_reload_with(
            &mut self,
            runtime_generation: &RuntimeGenerationState,
            on_applied_config_version: impl FnOnce(&str),
        ) -> RuntimeGenerationProcessResult {
            let executor = RuntimeGenerationExecutor::new(
                runtime_generation.clone(),
                self.plan_handle.clone(),
                self.config_apply_gate.clone(),
                self.capture_runtime.clone(),
                self.tls_decrypt_hint_runtime.clone(),
                self.tls_plaintext_runtime.clone(),
                self.l7_mitm_runtime.clone(),
            );
            executor.process_capture_safe_point(
                &mut self.active_plan,
                &mut self.provider,
                on_applied_config_version,
            )
        }
    }

    struct FinishedProvider;

    impl capture::CaptureProvider for FinishedProvider {
        fn name(&self) -> &'static str {
            "finished"
        }

        fn capabilities(&self) -> Vec<probe_core::CapabilityState> {
            Vec::new()
        }

        fn poll_next(&mut self) -> Result<capture::CapturePoll, capture::CaptureError> {
            Ok(capture::CapturePoll::Finished)
        }

        fn drain_before_handoff(&mut self) -> Result<capture::CapturePoll, capture::CaptureError> {
            Ok(capture::CapturePoll::Finished)
        }
    }
}
