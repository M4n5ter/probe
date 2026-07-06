use std::time::Instant;

use capture::{CaptureMultiplexer, CaptureProvider, LibpcapProvider, MultiplexedProvider};
use probe_config::{CaptureBackend, CaptureSelection};
use probe_core::{CancellationToken, RuntimeMode};
use runtime::{CaptureInputSource, CaptureProviderDescriptor, RuntimeError, RuntimePlan};

use super::{
    OpenedLiveCaptureBackend,
    ebpf::build_ebpf_capture_provider,
    mitm_plaintext_bridge::{
        MitmPlaintextBridgePreflight, build_mitm_capture_event_feed_provider,
        build_mitm_capture_event_feed_provider_after_live_failures as build_mitm_capture_event_feed_provider_with_failures,
        preflight_mitm_plaintext_bridge_provider, with_mitm_plaintext_bridge_provider,
    },
    procfs_resolver::procfs_tcp_process_resolver_for_plan,
};
use crate::{
    capture_event_feed::load_capture_event_feed_provider,
    capture_provider::{CaptureProviderOpenFailureSnapshot, CaptureProviderRuntimeSnapshot},
    capture_registry::libpcap_config_from_agent,
    error::AgentError,
    l7_mitm::L7MitmRuntimeHandle,
    plaintext_feed::load_plaintext_feed_provider,
    tls_plaintext::{
        TlsDecryptHintRuntimeState, TlsPlaintextInstrumentationBuild, TlsPlaintextRuntimeState,
        TlsSessionSecretAutoBindingBuild, build_tls_plaintext_instrumentation,
        build_tls_session_secret_auto_binding_with_runtime,
    },
};

pub(crate) struct CaptureProviderPreflight {
    session_secret_auto_binding: TlsSessionSecretAutoBindingBuild,
    mitm_plaintext_bridge: MitmPlaintextBridgePreflight,
}

pub(crate) struct BuiltCaptureProvider {
    pub(crate) provider: Box<dyn CaptureProvider>,
    pub(crate) runtime: CaptureProviderRuntimeSnapshot,
}

impl CaptureProviderPreflight {
    pub(crate) fn build(
        plan: &RuntimePlan,
        tls_decrypt_hint_runtime: Option<&TlsDecryptHintRuntimeState>,
        l7_mitm_runtime: &L7MitmRuntimeHandle,
    ) -> Result<Self, AgentError> {
        let session_secret_auto_binding =
            build_tls_session_secret_auto_binding_with_runtime(plan, tls_decrypt_hint_runtime)?;
        let mitm_plaintext_bridge =
            preflight_mitm_plaintext_bridge_provider(plan, l7_mitm_runtime)?;
        Ok(Self {
            session_secret_auto_binding,
            mitm_plaintext_bridge,
        })
    }
}

pub(crate) fn build_capture_provider(
    plan: &RuntimePlan,
    tls_plaintext_runtime: Option<&TlsPlaintextRuntimeState>,
    l7_mitm_runtime: &L7MitmRuntimeHandle,
    preflight: CaptureProviderPreflight,
) -> Result<BuiltCaptureProvider, AgentError> {
    build_capture_provider_with_cancellation(
        plan,
        tls_plaintext_runtime,
        l7_mitm_runtime,
        preflight,
        CancellationToken::default(),
    )
}

pub(crate) fn build_capture_provider_with_cancellation(
    plan: &RuntimePlan,
    tls_plaintext_runtime: Option<&TlsPlaintextRuntimeState>,
    l7_mitm_runtime: &L7MitmRuntimeHandle,
    preflight: CaptureProviderPreflight,
    cancellation: CancellationToken,
) -> Result<BuiltCaptureProvider, AgentError> {
    match plan.capture.selected_backend {
        Some(CaptureBackend::PlaintextFeed) => Ok(BuiltCaptureProvider {
            provider: build_plaintext_feed_provider(plan)?,
            runtime: CaptureProviderRuntimeSnapshot {
                selected_backend: CaptureBackend::PlaintextFeed,
                selected_input_source: CaptureInputSource::PlaintextFeed,
                plan_mode: plan.capture.mode,
                provider_runtime_mode: RuntimeMode::Available,
                evidence_mode: plan
                    .capture
                    .selected_evidence_mode
                    .unwrap_or(runtime::CaptureEvidenceMode::Nominal),
                evidence_reason: plan.capture.evidence_reason.clone(),
                reason: None,
                open_failures: Vec::new(),
                provider: None,
            },
        }),
        Some(CaptureBackend::CaptureEventFeed) => {
            let provider = if plan.capture.selected_input_source
                == Some(CaptureInputSource::MitmPlaintextBridge)
            {
                build_mitm_capture_event_feed_provider(
                    plan,
                    l7_mitm_runtime,
                    preflight.mitm_plaintext_bridge,
                )?
            } else {
                build_capture_event_feed_provider(plan)?
            };
            Ok(BuiltCaptureProvider {
                provider,
                runtime: CaptureProviderRuntimeSnapshot {
                    selected_backend: CaptureBackend::CaptureEventFeed,
                    selected_input_source: plan
                        .capture
                        .selected_input_source
                        .unwrap_or(CaptureInputSource::ConfiguredCaptureEventFeed),
                    plan_mode: plan.capture.mode,
                    provider_runtime_mode: RuntimeMode::Available,
                    evidence_mode: plan
                        .capture
                        .selected_evidence_mode
                        .unwrap_or(runtime::CaptureEvidenceMode::Nominal),
                    evidence_reason: plan.capture.evidence_reason.clone(),
                    reason: None,
                    open_failures: Vec::new(),
                    provider: None,
                },
            })
        }
        _ => build_live_capture_provider(
            plan,
            tls_plaintext_runtime,
            l7_mitm_runtime,
            preflight.session_secret_auto_binding,
            preflight.mitm_plaintext_bridge,
            cancellation,
        ),
    }
}

fn build_live_capture_provider(
    plan: &RuntimePlan,
    tls_plaintext_runtime: Option<&TlsPlaintextRuntimeState>,
    l7_mitm_runtime: &L7MitmRuntimeHandle,
    session_secret_auto_binding: TlsSessionSecretAutoBindingBuild,
    mitm_plaintext_bridge: MitmPlaintextBridgePreflight,
    cancellation: CancellationToken,
) -> Result<BuiltCaptureProvider, AgentError> {
    plan.require_live_capture()?;
    let started = Instant::now();
    let outcome = match try_build_live_primary_with_fallback(plan, cancellation.clone())? {
        LiveCaptureOpenAttempt::Open(outcome) => outcome,
        LiveCaptureOpenAttempt::Failed(open_failures) => {
            if cancellation.is_cancelled() {
                return Err(capture_startup_cancelled_error());
            }
            return build_mitm_capture_event_feed_provider_after_live_failures(
                plan,
                l7_mitm_runtime,
                mitm_plaintext_bridge,
                open_failures,
            );
        }
    };
    log_capture_provider_startup_stage(started, "opened live primary backend");
    let descriptor = outcome.descriptor;
    let OpenedLiveCaptureBackend {
        provider: primary,
        provider_details,
    } = outcome.provider;
    let primary = session_secret_auto_binding.wrap(primary);
    log_capture_provider_startup_stage(started, "applied TLS session secret binding");
    let provider =
        with_tls_plaintext_provider(plan, primary, tls_plaintext_runtime, cancellation.clone())?;
    log_capture_provider_startup_stage(started, "built TLS plaintext wrapper");
    let provider = with_mitm_plaintext_bridge_provider(
        plan,
        provider,
        l7_mitm_runtime,
        mitm_plaintext_bridge,
    )?;
    log_capture_provider_startup_stage(started, "built MITM plaintext bridge wrapper");
    Ok(BuiltCaptureProvider {
        provider,
        runtime: CaptureProviderRuntimeSnapshot {
            selected_backend: descriptor.backend,
            selected_input_source: CaptureInputSource::LiveHost,
            plan_mode: descriptor.plan_mode(),
            provider_runtime_mode: descriptor.runtime_mode,
            evidence_mode: descriptor.evidence_mode,
            evidence_reason: descriptor.evidence_reason,
            reason: descriptor.reason,
            open_failures: outcome.open_failures,
            provider: provider_details,
        },
    })
}

fn try_build_live_primary_with_fallback(
    plan: &RuntimePlan,
    cancellation: CancellationToken,
) -> Result<LiveCaptureOpenAttempt<OpenedLiveCaptureBackend>, AgentError> {
    try_open_live_backend_with_fallback(plan, cancellation.clone(), |backend| {
        build_live_capture_backend(plan, backend, cancellation.clone())
    })
}

#[derive(Debug)]
struct LiveCaptureOpenOutcome<T> {
    provider: T,
    descriptor: CaptureProviderDescriptor,
    open_failures: Vec<CaptureProviderOpenFailureSnapshot>,
}

#[derive(Debug)]
enum LiveCaptureOpenAttempt<T> {
    Open(LiveCaptureOpenOutcome<T>),
    Failed(Vec<CaptureProviderOpenFailureSnapshot>),
}

#[cfg(test)]
fn open_live_backend_with_fallback<T>(
    plan: &RuntimePlan,
    open_backend: impl FnMut(CaptureBackend) -> Result<T, AgentError>,
) -> Result<LiveCaptureOpenOutcome<T>, AgentError> {
    match try_open_live_backend_with_fallback(plan, CancellationToken::default(), open_backend)? {
        LiveCaptureOpenAttempt::Open(outcome) => Ok(outcome),
        LiveCaptureOpenAttempt::Failed(failures) => Err(no_live_capture_error(plan, failures)),
    }
}

fn try_open_live_backend_with_fallback<T>(
    plan: &RuntimePlan,
    cancellation: CancellationToken,
    mut open_backend: impl FnMut(CaptureBackend) -> Result<T, AgentError>,
) -> Result<LiveCaptureOpenAttempt<T>, AgentError> {
    let mut failures = Vec::new();
    for descriptor in plan.capture.live_provider_open_candidates() {
        if cancellation.is_cancelled() {
            return Err(capture_startup_cancelled_error());
        }
        let backend = descriptor.backend;
        let backend_started = Instant::now();
        match open_backend(backend) {
            Ok(provider) => {
                log_live_backend_open_attempt(backend, backend_started, Ok(()));
                return Ok(LiveCaptureOpenAttempt::Open(LiveCaptureOpenOutcome {
                    provider,
                    descriptor: descriptor.with_runtime_open_success(),
                    open_failures: failures,
                }));
            }
            Err(error) if plan.effective_config.capture.selection == CaptureSelection::Auto => {
                log_live_backend_open_attempt(backend, backend_started, Err(error.to_string()));
                failures.push(CaptureProviderOpenFailureSnapshot {
                    backend,
                    reason: error.to_string(),
                });
                if cancellation.is_cancelled() {
                    return Err(capture_startup_cancelled_error());
                }
            }
            Err(error) => {
                log_live_backend_open_attempt(backend, backend_started, Err(error.to_string()));
                return Err(error);
            }
        }
    }
    Ok(LiveCaptureOpenAttempt::Failed(failures))
}

fn log_live_backend_open_attempt(
    backend: CaptureBackend,
    started: Instant,
    result: Result<(), String>,
) {
    match result {
        Ok(()) => eprintln!(
            "agent startup capture backend {backend:?} opened after {:.3}s",
            started.elapsed().as_secs_f64()
        ),
        Err(error) => eprintln!(
            "agent startup capture backend {backend:?} failed after {:.3}s: {error}",
            started.elapsed().as_secs_f64()
        ),
    }
}

fn log_capture_provider_startup_stage(started: Instant, stage: &str) {
    eprintln!(
        "agent startup capture provider {stage} after {:.3}s",
        started.elapsed().as_secs_f64()
    );
}

fn no_live_capture_error(
    plan: &RuntimePlan,
    failures: Vec<CaptureProviderOpenFailureSnapshot>,
) -> AgentError {
    AgentError::Runtime(RuntimeError::NoLiveCapture {
        reason: live_capture_failure_reason(plan, failures),
    })
}

fn build_live_capture_backend(
    plan: &RuntimePlan,
    backend: CaptureBackend,
    cancellation: CancellationToken,
) -> Result<OpenedLiveCaptureBackend, AgentError> {
    match backend {
        CaptureBackend::Ebpf => match build_ebpf_capture_provider(plan, cancellation.clone()) {
            Ok(provider) => Ok(provider),
            Err(_) if cancellation.is_cancelled() => Err(capture_startup_cancelled_error()),
            Err(error) => Err(error),
        },
        CaptureBackend::Libpcap => Ok(OpenedLiveCaptureBackend {
            provider: Box::new(LibpcapProvider::open_with_process_resolver(
                libpcap_config_from_agent(&plan.effective_config),
                procfs_tcp_process_resolver_for_plan(plan),
            )?) as Box<dyn CaptureProvider>,
            provider_details: None,
        }),
        backend => Err(AgentError::Runtime(RuntimeError::NoLiveCapture {
            reason: format!("{backend:?} capture provider is selected but has no agent builder"),
        })),
    }
}

fn capture_startup_cancelled_error() -> AgentError {
    AgentError::StartupCancelled("capture provider startup cancelled")
}

fn live_capture_failure_reason(
    plan: &RuntimePlan,
    failures: Vec<CaptureProviderOpenFailureSnapshot>,
) -> String {
    if failures.is_empty() {
        return plan
            .capture
            .reason
            .clone()
            .unwrap_or_else(|| "capture plan did not select a live backend".to_string());
    }
    format!(
        "all auto live capture providers failed to open: {}",
        failures
            .into_iter()
            .map(|failure| format!("{:?}: {}", failure.backend, failure.reason))
            .collect::<Vec<_>>()
            .join("; ")
    )
}

fn with_tls_plaintext_provider(
    plan: &RuntimePlan,
    primary: Box<dyn CaptureProvider>,
    tls_plaintext_runtime: Option<&TlsPlaintextRuntimeState>,
    cancellation: CancellationToken,
) -> Result<Box<dyn CaptureProvider>, AgentError> {
    let instrumentation_build =
        build_tls_plaintext_instrumentation(plan, tls_plaintext_runtime, cancellation)?;
    if let Some(runtime) = tls_plaintext_runtime {
        runtime.record_instrumentation_build(&instrumentation_build);
    }
    match instrumentation_build {
        TlsPlaintextInstrumentationBuild::NotConfigured => Ok(primary),
        TlsPlaintextInstrumentationBuild::Enabled(plaintext) => {
            let plaintext = match tls_plaintext_runtime {
                Some(runtime) => {
                    let runtime = runtime.clone();
                    MultiplexedProvider::best_effort_with_disable_handler(
                        plaintext,
                        move |reason| {
                            runtime.record_instrumentation_disabled(reason);
                        },
                    )
                }
                None => MultiplexedProvider::best_effort(plaintext),
            };
            Ok(Box::new(CaptureMultiplexer::from_providers([
                MultiplexedProvider::required(primary),
                plaintext,
            ])))
        }
        TlsPlaintextInstrumentationBuild::Disabled { .. } => Ok(primary),
    }
}

fn build_mitm_capture_event_feed_provider_after_live_failures(
    plan: &RuntimePlan,
    l7_mitm_runtime: &L7MitmRuntimeHandle,
    preflight: MitmPlaintextBridgePreflight,
    open_failures: Vec<CaptureProviderOpenFailureSnapshot>,
) -> Result<BuiltCaptureProvider, AgentError> {
    let descriptor = plan
        .capture
        .auto_mitm_plaintext_bridge_open_candidate()
        .ok_or_else(|| no_live_capture_error(plan, open_failures.clone()))?;
    let built_provider = build_mitm_capture_event_feed_provider_with_failures(
        plan,
        l7_mitm_runtime,
        preflight,
        descriptor,
        open_failures,
    )?;
    Ok(BuiltCaptureProvider {
        provider: built_provider.provider,
        runtime: built_provider.runtime,
    })
}

fn build_plaintext_feed_provider(
    plan: &RuntimePlan,
) -> Result<Box<dyn CaptureProvider>, AgentError> {
    let path = plan
        .config
        .capture
        .plaintext_feed
        .path
        .as_ref()
        .ok_or_else(|| {
            AgentError::UnsupportedRunConfig(
                "plaintext_feed capture requires capture.plaintext_feed.path".to_string(),
            )
        })?;
    Ok(Box::new(load_plaintext_feed_provider(path)?))
}

fn build_capture_event_feed_provider(
    plan: &RuntimePlan,
) -> Result<Box<dyn CaptureProvider>, AgentError> {
    let config = &plan.effective_config.capture.capture_event_feed;
    let path = config.path.as_ref().ok_or_else(|| {
        AgentError::UnsupportedRunConfig(
            "capture_event_feed capture requires capture.capture_event_feed.path".to_string(),
        )
    })?;
    Ok(Box::new(load_capture_event_feed_provider(
        path,
        config.follow_enabled(),
    )?))
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use capture::{CaptureEvent, CapturedLoss};
    use probe_config::{
        AgentConfig, CaptureBackend, CaptureSelection, EnforcementPolicySourceConfig,
        TlsMaterialConfig, TlsMaterialKind, TransparentInterceptionMitmBackendConfig,
        TransparentInterceptionMitmBackendReadinessProbeConfig,
        TransparentInterceptionMitmPlaintextBridgeModeConfig,
        TransparentInterceptionStrategyConfig,
    };
    use probe_core::{
        CapabilityKind, CapabilityState, CaptureLoss, CaptureOrigin, CaptureSource, Direction,
        EnforcementEvidence, EnforcementMode, ProcessSelector, RuntimeMode, Selector, Timestamp,
        TrafficSelector,
    };
    use runtime::{
        CaptureEvidenceMode, CaptureProviderBuilder, CaptureProviderDescriptor, ProviderRegistry,
        RuntimePlan, TransparentInterceptionMitmPlaintextBridgePlan,
    };
    use tempfile::NamedTempFile;

    use crate::l7_mitm::{
        L7MitmBackendHealthSnapshot, L7MitmPlaintextBridgeMode, L7MitmPlaintextBridgeSnapshot,
        L7MitmRuntimeHandle,
    };

    use super::*;

    #[test]
    fn auto_capture_open_falls_back_after_degraded_ebpf_open_failure()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = auto_plan_with_degraded_ebpf_and_available_libpcap()?;
        let mut attempted = Vec::new();

        let outcome = open_live_backend_with_fallback(&plan, |backend| {
            attempted.push(backend);
            match backend {
                CaptureBackend::Ebpf => Err(AgentError::Runtime(RuntimeError::NoLiveCapture {
                    reason: "eBPF attach failed".to_string(),
                })),
                CaptureBackend::Libpcap => Ok(backend),
                backend => panic!("unexpected backend {backend:?}"),
            }
        })?;

        assert_eq!(attempted, [CaptureBackend::Ebpf, CaptureBackend::Libpcap]);
        assert_eq!(outcome.provider, CaptureBackend::Libpcap);
        assert_eq!(outcome.descriptor.backend, CaptureBackend::Libpcap);
        assert_eq!(outcome.open_failures.len(), 1);
        assert_eq!(outcome.open_failures[0].backend, CaptureBackend::Ebpf);
        assert!(
            outcome.open_failures[0]
                .reason
                .contains("eBPF attach failed")
        );
        Ok(())
    }

    #[test]
    fn auto_capture_open_still_attempts_preflight_unavailable_libpcap_after_ebpf_open_failure()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = plan_with_registry_and_providers(
            AgentConfig::default(),
            vec![
                CaptureProviderDescriptor::degraded(
                    CaptureBackend::Ebpf,
                    CaptureProviderBuilder::Ebpf,
                    "eBPF provider is best-effort",
                ),
                CaptureProviderDescriptor::unavailable(
                    CaptureBackend::Libpcap,
                    CaptureProviderBuilder::Libpcap,
                    "libpcap preflight could not open a capture socket",
                )
                .with_auto_live_open_retry(),
            ],
        )?;
        let mut attempted = Vec::new();

        let error = open_live_backend_with_fallback(&plan, |backend| {
            attempted.push(backend);
            Err::<CaptureBackend, _>(AgentError::Runtime(RuntimeError::NoLiveCapture {
                reason: match backend {
                    CaptureBackend::Ebpf => "eBPF attach failed".to_string(),
                    CaptureBackend::Libpcap => "libpcap open failed".to_string(),
                    backend => format!("{backend:?} should not be attempted"),
                },
            }))
        })
        .expect_err("all live providers should fail");

        assert_eq!(attempted, [CaptureBackend::Ebpf, CaptureBackend::Libpcap]);
        let error = error.to_string();
        assert!(error.contains("eBPF attach failed"), "{error}");
        assert!(error.contains("libpcap open failed"), "{error}");
        Ok(())
    }

    #[test]
    fn auto_capture_open_success_normalizes_preflight_unavailable_fallback_descriptor()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = plan_with_registry_and_providers(
            AgentConfig::default(),
            vec![
                CaptureProviderDescriptor::degraded(
                    CaptureBackend::Ebpf,
                    CaptureProviderBuilder::Ebpf,
                    "eBPF provider is best-effort",
                ),
                CaptureProviderDescriptor::unavailable(
                    CaptureBackend::Libpcap,
                    CaptureProviderBuilder::Libpcap,
                    "libpcap preflight could not open a capture socket",
                )
                .with_auto_live_open_retry(),
            ],
        )?;
        let mut attempted = Vec::new();

        let outcome = open_live_backend_with_fallback(&plan, |backend| {
            attempted.push(backend);
            match backend {
                CaptureBackend::Ebpf => Err(AgentError::Runtime(RuntimeError::NoLiveCapture {
                    reason: "eBPF attach failed".to_string(),
                })),
                CaptureBackend::Libpcap => Ok(backend),
                backend => panic!("unexpected backend {backend:?}"),
            }
        })?;

        assert_eq!(attempted, [CaptureBackend::Ebpf, CaptureBackend::Libpcap]);
        assert_eq!(outcome.provider, CaptureBackend::Libpcap);
        assert_eq!(outcome.descriptor.backend, CaptureBackend::Libpcap);
        assert_eq!(outcome.descriptor.runtime_mode, RuntimeMode::Available);
        assert_eq!(outcome.descriptor.capability_mode, RuntimeMode::Available);
        assert_eq!(outcome.descriptor.reason, None);
        assert_eq!(
            outcome.descriptor.evidence_mode,
            CaptureEvidenceMode::BestEffort
        );
        assert!(
            outcome
                .descriptor
                .evidence_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("preflight could not open"))
        );
        Ok(())
    }

    #[test]
    fn explicit_capture_open_does_not_fallback_after_ebpf_open_failure()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Ebpf;
        let plan = plan_with_registry(config)?;
        let mut attempted = Vec::new();

        let error = open_live_backend_with_fallback(&plan, |backend| {
            attempted.push(backend);
            Err::<CaptureBackend, _>(AgentError::Runtime(RuntimeError::NoLiveCapture {
                reason: "eBPF attach failed".to_string(),
            }))
        })
        .expect_err("explicit eBPF must fail fast");

        assert_eq!(attempted, [CaptureBackend::Ebpf]);
        assert!(error.to_string().contains("eBPF attach failed"));
        Ok(())
    }

    #[test]
    fn auto_live_open_failures_fall_back_to_mitm_plaintext_bridge()
    -> Result<(), Box<dyn std::error::Error>> {
        let bridge_file = NamedTempFile::new()?;
        let bridge_path = bridge_file.path().to_path_buf();
        fs::write(
            &bridge_path,
            format!(
                "{}\n",
                serde_json::to_string(&mitm_loss_event("mitm after live failures"))?
            ),
        )?;
        let mut plan = auto_plan_with_live_and_mitm_plaintext_bridge(bridge_path)?;
        set_mitm_plaintext_bridge_follow(&mut plan, false);
        let attempt =
            try_open_live_backend_with_fallback(&plan, CancellationToken::default(), |backend| {
                Err::<OpenedLiveCaptureBackend, _>(AgentError::Runtime(
                    RuntimeError::NoLiveCapture {
                        reason: format!("{backend:?} open failed"),
                    },
                ))
            })?;
        let LiveCaptureOpenAttempt::Failed(open_failures) = attempt else {
            panic!("live providers should fail during the test");
        };
        let l7_mitm_runtime = configured_l7_mitm_runtime();
        let preflight = CaptureProviderPreflight::build(&plan, None, &l7_mitm_runtime)?;

        let built_provider = build_mitm_capture_event_feed_provider_after_live_failures(
            &plan,
            &l7_mitm_runtime,
            preflight.mitm_plaintext_bridge,
            open_failures,
        )?;
        let mut provider = built_provider.provider;

        assert_eq!(
            built_provider.runtime.selected_backend,
            CaptureBackend::CaptureEventFeed
        );
        assert_eq!(
            built_provider.runtime.selected_input_source,
            runtime::CaptureInputSource::MitmPlaintextBridge
        );
        assert_eq!(built_provider.runtime.open_failures.len(), 2);
        assert_eq!(
            built_provider.runtime.open_failures[0].backend,
            CaptureBackend::Ebpf
        );
        assert_eq!(
            built_provider.runtime.open_failures[1].backend,
            CaptureBackend::Libpcap
        );
        assert_loss_reason(provider.next()?, "mitm after live failures");
        assert_eq!(
            l7_mitm_runtime.snapshot().plaintext_bridge.mode,
            L7MitmPlaintextBridgeMode::Active
        );
        Ok(())
    }

    fn set_mitm_plaintext_bridge_follow(plan: &mut RuntimePlan, follow: bool) {
        let TransparentInterceptionMitmPlaintextBridgePlan::CaptureEventFeed {
            follow: planned_follow,
            ..
        } = &mut plan.enforcement.interception.mitm.plaintext_bridge
        else {
            panic!("expected capture-event MITM bridge plan");
        };
        *planned_follow = follow;
    }

    fn configured_l7_mitm_runtime() -> L7MitmRuntimeHandle {
        L7MitmRuntimeHandle::for_test(
            L7MitmBackendHealthSnapshot::disabled(),
            L7MitmPlaintextBridgeSnapshot {
                mode: L7MitmPlaintextBridgeMode::Configured,
                disable_reason: None,
            },
            1,
        )
    }

    fn auto_plan_with_degraded_ebpf_and_available_libpcap()
    -> Result<RuntimePlan, runtime::RuntimeError> {
        plan_with_registry(AgentConfig::default())
    }

    fn plan_with_registry(config: AgentConfig) -> Result<RuntimePlan, runtime::RuntimeError> {
        plan_with_registry_and_providers(
            config,
            vec![
                CaptureProviderDescriptor::degraded(
                    CaptureBackend::Ebpf,
                    CaptureProviderBuilder::Ebpf,
                    "eBPF provider is best-effort",
                ),
                CaptureProviderDescriptor::available(
                    CaptureBackend::Libpcap,
                    CaptureProviderBuilder::Libpcap,
                ),
            ],
        )
    }

    fn plan_with_registry_and_providers(
        config: AgentConfig,
        providers: Vec<CaptureProviderDescriptor>,
    ) -> Result<RuntimePlan, runtime::RuntimeError> {
        RuntimePlan::build(
            config,
            &ProviderRegistry::new(providers, test_platform_capabilities()),
        )
    }

    fn auto_plan_with_live_and_mitm_plaintext_bridge(
        bridge_path: PathBuf,
    ) -> Result<RuntimePlan, runtime::RuntimeError> {
        RuntimePlan::build(
            external_mitm_plaintext_bridge_config(bridge_path),
            &ProviderRegistry::new(
                vec![
                    CaptureProviderDescriptor::available(
                        CaptureBackend::Ebpf,
                        CaptureProviderBuilder::Ebpf,
                    ),
                    CaptureProviderDescriptor::available(
                        CaptureBackend::Libpcap,
                        CaptureProviderBuilder::Libpcap,
                    ),
                    CaptureProviderDescriptor::available(
                        CaptureBackend::CaptureEventFeed,
                        CaptureProviderBuilder::CaptureEventFeed,
                    ),
                ],
                mitm_bridge_platform_capabilities(),
            ),
        )
    }

    fn external_mitm_plaintext_bridge_config(bridge_path: PathBuf) -> AgentConfig {
        let mut config = AgentConfig::default();
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::InboundTproxyMitm;
        config.enforcement.interception.proxy.listen_port = Some(15002);
        config.enforcement.interception.mitm.backend =
            TransparentInterceptionMitmBackendConfig::external(
                TransparentInterceptionMitmBackendReadinessProbeConfig {
                    target: Some("127.0.0.1:15002".to_string()),
                    ..TransparentInterceptionMitmBackendReadinessProbeConfig::default()
                },
            );
        config.enforcement.interception.mitm.plaintext_bridge.mode =
            TransparentInterceptionMitmPlaintextBridgeModeConfig::CaptureEventFeed;
        config.enforcement.interception.mitm.plaintext_bridge.path = Some(bridge_path);
        config.enforcement.interception.mitm.client_trust.mode =
            probe_config::TransparentInterceptionMitmClientTrustModeConfig::OperatorManaged;
        config.enforcement.interception.mitm.ca_certificate_ref = Some("mitm-ca".to_string());
        config.enforcement.interception.mitm.ca_private_key_ref = Some("mitm-ca-key".to_string());
        config.enforcement.interception.selector = Some(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                local_ports: vec![8443],
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        ));
        config.enforcement.policy.source = EnforcementPolicySourceConfig::File {
            path: "/tmp/traffic-probe-enforcement.toml".into(),
        };
        config.tls.materials = vec![
            TlsMaterialConfig {
                id: Some("mitm-ca".to_string()),
                kind: TlsMaterialKind::MitmCaCertificate,
                path: "/etc/traffic-probe/mitm-ca.pem".into(),
            },
            TlsMaterialConfig {
                id: Some("mitm-ca-key".to_string()),
                kind: TlsMaterialKind::MitmCaPrivateKey,
                path: "/etc/traffic-probe/mitm-ca.key".into(),
            },
        ];
        config
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
        ]
    }

    fn mitm_bridge_platform_capabilities() -> Vec<CapabilityState> {
        let mut capabilities = test_platform_capabilities();
        capabilities.push(CapabilityState::available(
            CapabilityKind::TransparentInterception,
        ));
        capabilities.push(CapabilityState::available(CapabilityKind::L7Mitm));
        capabilities
    }

    fn mitm_loss_event(reason: &str) -> CaptureEvent {
        loss_event_with_source(reason, CaptureSource::L7MitmPlaintext)
    }

    fn loss_event_with_source(reason: &str, source: CaptureSource) -> CaptureEvent {
        CaptureEvent::Loss(CapturedLoss {
            timestamp: Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            origin: CaptureOrigin::from_source(source),
            enforcement_evidence: EnforcementEvidence::default(),
            loss: CaptureLoss {
                lost_events: 1,
                reason: reason.to_string(),
            },
        })
    }

    fn assert_loss_reason(event: Option<CaptureEvent>, reason: &str) {
        let Some(CaptureEvent::Loss(loss)) = event else {
            panic!("expected capture loss event, got {event:?}");
        };
        assert_eq!(loss.loss.reason, reason);
    }
}
