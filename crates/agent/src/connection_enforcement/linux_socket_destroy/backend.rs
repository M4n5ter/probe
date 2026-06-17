use enforcement::{EnforcementBackend, EnforcementBackendDecision, EnforcementBackendRequest};
use probe_core::TransportProtocol;

use super::{
    owner::{FlowOwnerVerification, FlowOwnerVerifier},
    ss::{SsKill, SsKillRequest},
};

pub(super) struct LinuxSocketDestroyBackend<R, V> {
    runner: R,
    owner_verifier: V,
}

impl<R, V> LinuxSocketDestroyBackend<R, V> {
    pub(super) fn new(runner: R, owner_verifier: V) -> Self {
        Self {
            runner,
            owner_verifier,
        }
    }
}

impl<R, V> EnforcementBackend for LinuxSocketDestroyBackend<R, V>
where
    R: SsKill + Send,
    V: FlowOwnerVerifier + Send,
{
    fn apply(
        &mut self,
        request: EnforcementBackendRequest<'_>,
    ) -> Result<EnforcementBackendDecision, enforcement::EnforcementError> {
        if !request.trigger.origin().source().is_live_host_observation() {
            return Ok(EnforcementBackendDecision::unsupported(format!(
                "linux socket destroy enforcement requires a live host capture event; requested source {:?}",
                request.trigger.origin().source()
            )));
        }

        let Some(flow) = request.trigger.flow() else {
            return Ok(EnforcementBackendDecision::unsupported(
                "linux socket destroy enforcement requires a flow-scoped trigger event".to_string(),
            ));
        };

        if flow.protocol != TransportProtocol::Tcp {
            return Ok(EnforcementBackendDecision::unsupported(format!(
                "linux socket destroy enforcement only supports TCP flows; requested {:?}",
                flow.protocol
            )));
        }

        let (socket_inode, confidence) = match self.owner_verifier.verify(request.trigger) {
            FlowOwnerVerification::Matched {
                socket_inode,
                confidence,
            } => (socket_inode, confidence),
            FlowOwnerVerification::Unsupported { reason } => {
                return Ok(EnforcementBackendDecision::unsupported(reason));
            }
        };

        let command = SsKillRequest::from_flow(flow);
        let result = self
            .runner
            .kill(&command)
            .map_err(|error| enforcement::EnforcementError::Backend(error.to_string()))?;
        if !result.success {
            return Err(enforcement::EnforcementError::Backend(
                result.failure_reason(),
            ));
        }
        if !result.closed_any_socket() {
            return Ok(EnforcementBackendDecision::unsupported(format!(
                "ss -K did not close a socket for flow {}",
                flow.id.0
            )));
        }

        Ok(EnforcementBackendDecision::applied(format!(
            "ss -K destroyed TCP socket for flow {} using {:?} after procfs owner verification matched inode {} with confidence {}",
            flow.id.0, request.verdict.action, socket_inode, confidence
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        io,
        sync::{Arc, Mutex},
    };

    use enforcement::{EnforcementPlanRequest, EnforcementPlanner, ScopedEnforcementPlanner};
    use probe_core::{
        Action, AddressPort, CaptureOrigin, CaptureSource, Direction, EnforcementDecision,
        EventEnvelope, EventKind, FlowContext, FlowIdentity, OpaqueStream, ProcessContext,
        ProcessIdentity, ProtectiveActionProfile, Timestamp, Verdict, VerdictScope,
    };

    use super::super::ss::SsKillResult;
    use super::*;

    #[test]
    fn linux_socket_destroy_backend_invokes_ss_for_owner_verified_flow()
    -> Result<(), Box<dyn std::error::Error>> {
        let runner = FakeSsKill::with_results([Ok(SsKillResult {
            success: true,
            stdout: b"ESTAB 0 0 127.0.0.1:41000 127.0.0.1:8080\n".to_vec(),
            stderr: Vec::new(),
        })]);
        let verifier = FakeFlowOwnerVerifier::matched();
        let mut planner = planner_with_runner_and_verifier(runner.clone(), verifier.clone())?;
        let trigger = event_with_protocol(TransportProtocol::Tcp);

        let decision = evaluate_protective(&mut planner, &trigger, Action::Reset)?;

        let requests = runner.requests();
        assert_eq!(
            requests,
            vec![SsKillRequest {
                local_address: "127.0.0.1".to_string(),
                local_port: 41000,
                remote_address: "127.0.0.1".to_string(),
                remote_port: 8080,
            }]
        );
        assert_eq!(
            verifier.verified_flows(),
            vec![
                trigger
                    .flow()
                    .expect("test trigger is flow scoped")
                    .id
                    .0
                    .clone()
            ]
        );
        assert_eq!(decision.outcome, probe_core::EnforcementOutcome::Applied);
        assert_eq!(decision.effective_action, Action::Reset);
        Ok(())
    }

    #[test]
    fn linux_socket_destroy_backend_reports_no_matching_socket_as_unsupported()
    -> Result<(), Box<dyn std::error::Error>> {
        let runner = FakeSsKill::with_results([Ok(SsKillResult {
            success: true,
            stdout: b"\n".to_vec(),
            stderr: Vec::new(),
        })]);
        let mut planner = planner_with_runner(runner)?;
        let trigger = event_with_protocol(TransportProtocol::Tcp);

        let decision = evaluate_protective(&mut planner, &trigger, Action::Deny)?;

        assert_eq!(
            decision.outcome,
            probe_core::EnforcementOutcome::Unsupported
        );
        assert_eq!(decision.effective_action, Action::Observe);
        Ok(())
    }

    #[test]
    fn linux_socket_destroy_backend_requires_current_socket_owner_match()
    -> Result<(), Box<dyn std::error::Error>> {
        let runner = FakeSsKill::with_results([]);
        let verifier = FakeFlowOwnerVerifier::unsupported("owner changed");
        let mut planner = planner_with_runner_and_verifier(runner.clone(), verifier.clone())?;
        let trigger = event_with_protocol(TransportProtocol::Tcp);

        let decision = evaluate_protective(&mut planner, &trigger, Action::Reset)?;

        assert_eq!(
            decision.outcome,
            probe_core::EnforcementOutcome::Unsupported
        );
        assert_eq!(decision.effective_action, Action::Observe);
        assert_eq!(
            verifier.verified_flows(),
            vec![
                trigger
                    .flow()
                    .expect("test trigger is flow scoped")
                    .id
                    .0
                    .clone()
            ]
        );
        assert!(
            runner.requests().is_empty(),
            "owner verification failure must not invoke ss -K"
        );
        Ok(())
    }

    #[test]
    fn linux_socket_destroy_backend_rejects_non_tcp_flows() -> Result<(), Box<dyn std::error::Error>>
    {
        let runner = FakeSsKill::with_results([]);
        let verifier = FakeFlowOwnerVerifier::matched();
        let mut planner = planner_with_runner_and_verifier(runner.clone(), verifier.clone())?;
        let trigger = event_with_protocol(TransportProtocol::Udp);

        let decision = evaluate_protective(&mut planner, &trigger, Action::Quarantine)?;

        assert_eq!(
            decision.outcome,
            probe_core::EnforcementOutcome::Unsupported
        );
        assert!(
            runner.requests().is_empty(),
            "non-TCP flows must not invoke ss -K"
        );
        assert!(
            verifier.verified_flows().is_empty(),
            "non-TCP flows must not invoke owner verification"
        );
        Ok(())
    }

    #[test]
    fn linux_socket_destroy_backend_rejects_replay_source() -> Result<(), Box<dyn std::error::Error>>
    {
        let runner = FakeSsKill::with_results([]);
        let verifier = FakeFlowOwnerVerifier::matched();
        let mut planner = planner_with_runner_and_verifier(runner.clone(), verifier.clone())?;
        let trigger = event_with_protocol_and_source(TransportProtocol::Tcp, CaptureSource::Replay);

        let decision = evaluate_protective(&mut planner, &trigger, Action::Reset)?;

        assert_eq!(
            decision.outcome,
            probe_core::EnforcementOutcome::Unsupported
        );
        assert_eq!(decision.effective_action, Action::Observe);
        assert!(
            runner.requests().is_empty(),
            "replay events must not invoke ss -K"
        );
        assert!(
            verifier.verified_flows().is_empty(),
            "replay events must not invoke owner verification"
        );
        Ok(())
    }

    #[derive(Clone)]
    struct FakeSsKill {
        state: Arc<Mutex<FakeSsKillState>>,
    }

    struct FakeSsKillState {
        requests: Vec<SsKillRequest>,
        results: VecDeque<io::Result<SsKillResult>>,
    }

    impl FakeSsKill {
        fn with_results(results: impl IntoIterator<Item = io::Result<SsKillResult>>) -> Self {
            Self {
                state: Arc::new(Mutex::new(FakeSsKillState {
                    requests: Vec::new(),
                    results: results.into_iter().collect(),
                })),
            }
        }

        fn requests(&self) -> Vec<SsKillRequest> {
            self.state
                .lock()
                .expect("fake ss state poisoned")
                .requests
                .clone()
        }
    }

    impl SsKill for FakeSsKill {
        fn kill(&mut self, request: &SsKillRequest) -> io::Result<SsKillResult> {
            let mut state = self.state.lock().expect("fake ss state poisoned");
            state.requests.push(request.clone());
            state
                .results
                .pop_front()
                .unwrap_or_else(|| panic!("missing fake ss -K result"))
        }
    }

    #[derive(Clone)]
    struct FakeFlowOwnerVerifier {
        state: Arc<Mutex<FakeFlowOwnerVerifierState>>,
    }

    struct FakeFlowOwnerVerifierState {
        verified_flows: Vec<String>,
        results: VecDeque<FlowOwnerVerification>,
    }

    impl FakeFlowOwnerVerifier {
        fn matched() -> Self {
            Self::with_results([FlowOwnerVerification::Matched {
                socket_inode: 123,
                confidence: 60,
            }])
        }

        fn unsupported(reason: impl Into<String>) -> Self {
            Self::with_results([FlowOwnerVerification::unsupported(reason)])
        }

        fn with_results(results: impl IntoIterator<Item = FlowOwnerVerification>) -> Self {
            Self {
                state: Arc::new(Mutex::new(FakeFlowOwnerVerifierState {
                    verified_flows: Vec::new(),
                    results: results.into_iter().collect(),
                })),
            }
        }

        fn verified_flows(&self) -> Vec<String> {
            self.state
                .lock()
                .expect("fake owner verifier state poisoned")
                .verified_flows
                .clone()
        }
    }

    impl FlowOwnerVerifier for FakeFlowOwnerVerifier {
        fn verify(&mut self, event: &EventEnvelope) -> FlowOwnerVerification {
            let mut state = self
                .state
                .lock()
                .expect("fake owner verifier state poisoned");
            let flow = event.flow().expect("test trigger is flow scoped");
            state.verified_flows.push(flow.id.0.clone());
            state
                .results
                .pop_front()
                .unwrap_or_else(|| panic!("missing fake owner verification result"))
        }
    }

    fn planner_with_runner(
        runner: FakeSsKill,
    ) -> Result<ScopedEnforcementPlanner, enforcement::EnforcementError> {
        planner_with_runner_and_verifier(runner, FakeFlowOwnerVerifier::matched())
    }

    fn planner_with_runner_and_verifier(
        runner: FakeSsKill,
        verifier: FakeFlowOwnerVerifier,
    ) -> Result<ScopedEnforcementPlanner, enforcement::EnforcementError> {
        ScopedEnforcementPlanner::with_backend(
            None,
            ProtectiveActionProfile::default(),
            LinuxSocketDestroyBackend::new(runner, verifier),
        )
    }

    fn evaluate_protective(
        planner: &mut ScopedEnforcementPlanner,
        trigger: &EventEnvelope,
        action: Action,
    ) -> Result<EnforcementDecision, enforcement::EnforcementError> {
        let verdict = protective_verdict(action);
        Ok(planner
            .evaluate(EnforcementPlanRequest {
                verdict: &verdict,
                trigger,
            })
            .expect("protective verdict should produce enforcement decision"))
    }

    fn protective_verdict(action: Action) -> Verdict {
        Verdict {
            action,
            scope: VerdictScope::Flow,
            reason: "policy".to_string(),
            confidence: 100,
            ttl_ms: None,
        }
    }

    fn event_with_protocol(protocol: TransportProtocol) -> EventEnvelope {
        event_with_protocol_and_source(protocol, CaptureSource::Libpcap)
    }

    fn event_with_protocol_and_source(
        protocol: TransportProtocol,
        source: CaptureSource,
    ) -> EventEnvelope {
        EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            FlowContext {
                id: FlowIdentity("flow-1".to_string()),
                process: ProcessContext {
                    identity: ProcessIdentity {
                        pid: 42,
                        tgid: 42,
                        start_time_ticks: 7,
                        boot_id: "boot".to_string(),
                        exe_path: "/usr/bin/app".to_string(),
                        cmdline_hash: "hash".to_string(),
                        uid: 1000,
                        gid: 1000,
                        cgroup: None,
                        systemd_service: None,
                        container_id: None,
                        runtime_hint: None,
                    },
                    name: "app".to_string(),
                    cmdline: vec!["app".to_string()],
                },
                local: AddressPort {
                    address: "127.0.0.1".to_string(),
                    port: 41000,
                },
                remote: AddressPort {
                    address: "127.0.0.1".to_string(),
                    port: 8080,
                },
                protocol,
                start_monotonic_ns: 1,
                socket_cookie: None,
                attribution_confidence: 100,
            },
            CaptureOrigin::from_source(source),
            "test-config",
            EventKind::OpaqueStream(OpaqueStream {
                direction: Direction::Outbound,
                fingerprint: Vec::new(),
                reason: "test".to_string(),
            }),
        )
    }
}
