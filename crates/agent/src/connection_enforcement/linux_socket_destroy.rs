use std::{
    fs, io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use enforcement::{EnforcementBackend, EnforcementBackendDecision, EnforcementBackendRequest};
use probe_core::{CapabilityKind, CapabilityState, EventEnvelope, TransportProtocol};

use super::ConnectionEnforcementRuntime;

const SS_KILL_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) fn resolve() -> ConnectionEnforcementRuntime {
    match LinuxSocketDestroyProbe::default().resolve() {
        LinuxSocketDestroyProbeResult::Available { command } => {
            ConnectionEnforcementRuntime::available_with_note(
                LinuxSocketDestroyBackend::new(SystemSsKill::new(command)),
                "linux socket destroy entrypoint is available; each flow may still return unsupported if the event is not from live host capture, the socket is gone, or the kernel/namespace does not report a destroyed socket",
            )
        }
        LinuxSocketDestroyProbeResult::Unavailable(capability) => {
            ConnectionEnforcementRuntime::without_backend(capability)
        }
    }
}

struct LinuxSocketDestroyProbe {
    command: Option<PathBuf>,
    running_as_root: bool,
}

impl Default for LinuxSocketDestroyProbe {
    fn default() -> Self {
        Self {
            command: find_ss_command(),
            running_as_root: is_root(),
        }
    }
}

enum LinuxSocketDestroyProbeResult {
    Available { command: PathBuf },
    Unavailable(CapabilityState),
}

impl LinuxSocketDestroyProbe {
    fn resolve(&self) -> LinuxSocketDestroyProbeResult {
        if !cfg!(target_os = "linux") {
            return LinuxSocketDestroyProbeResult::Unavailable(CapabilityState::unavailable(
                CapabilityKind::ConnectionEnforcement,
                "linux socket destroy enforcement requires Linux",
            ));
        }

        let Some(command) = self.command.clone() else {
            return LinuxSocketDestroyProbeResult::Unavailable(CapabilityState::unavailable(
                CapabilityKind::ConnectionEnforcement,
                "linux socket destroy enforcement requires ss at a trusted system path",
            ));
        };

        if !self.running_as_root {
            return LinuxSocketDestroyProbeResult::Unavailable(CapabilityState::unavailable(
                CapabilityKind::ConnectionEnforcement,
                "linux socket destroy enforcement requires root because the ss child process must retain socket destroy privileges after exec",
            ));
        }

        if !ss_supports_kill(&command) {
            return LinuxSocketDestroyProbeResult::Unavailable(CapabilityState::unavailable(
                CapabilityKind::ConnectionEnforcement,
                format!(
                    "ss command at {} does not advertise -K/--kill socket destroy support",
                    command.display()
                ),
            ));
        }

        LinuxSocketDestroyProbeResult::Available { command }
    }
}

struct LinuxSocketDestroyBackend<R> {
    runner: R,
}

impl<R> LinuxSocketDestroyBackend<R> {
    fn new(runner: R) -> Self {
        Self { runner }
    }
}

impl<R> EnforcementBackend for LinuxSocketDestroyBackend<R>
where
    R: SsKill + Send,
{
    fn apply(
        &mut self,
        request: EnforcementBackendRequest<'_>,
    ) -> Result<EnforcementBackendDecision, enforcement::EnforcementError> {
        if !request.trigger.source.is_live_host_observation() {
            return Ok(EnforcementBackendDecision::unsupported(format!(
                "linux socket destroy enforcement requires a live host capture event; requested source {:?}",
                request.trigger.source
            )));
        }

        if request.trigger.flow.protocol != TransportProtocol::Tcp {
            return Ok(EnforcementBackendDecision::unsupported(format!(
                "linux socket destroy enforcement only supports TCP flows; requested {:?}",
                request.trigger.flow.protocol
            )));
        }

        let command = SsKillRequest::from_event(request.trigger);
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
                request.trigger.flow.id.0
            )));
        }

        Ok(EnforcementBackendDecision::applied(format!(
            "ss -K destroyed TCP socket for flow {} using {:?}",
            request.trigger.flow.id.0, request.verdict.action
        )))
    }
}

trait SsKill {
    fn kill(&mut self, request: &SsKillRequest) -> io::Result<SsKillResult>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SsKillRequest {
    local_address: String,
    local_port: u16,
    remote_address: String,
    remote_port: u16,
}

impl SsKillRequest {
    fn from_event(event: &EventEnvelope) -> Self {
        Self {
            local_address: event.flow.local.address.clone(),
            local_port: event.flow.local.port,
            remote_address: event.flow.remote.address.clone(),
            remote_port: event.flow.remote.port,
        }
    }

    fn args(&self) -> Vec<String> {
        vec![
            "-H".to_string(),
            "-K".to_string(),
            "-t".to_string(),
            "state".to_string(),
            "connected".to_string(),
            "src".to_string(),
            self.local_address.clone(),
            "sport".to_string(),
            "=".to_string(),
            format!(":{}", self.local_port),
            "dst".to_string(),
            self.remote_address.clone(),
            "dport".to_string(),
            "=".to_string(),
            format!(":{}", self.remote_port),
        ]
    }
}

struct SystemSsKill {
    command: PathBuf,
}

impl SystemSsKill {
    fn new(command: PathBuf) -> Self {
        Self { command }
    }
}

impl SsKill for SystemSsKill {
    fn kill(&mut self, request: &SsKillRequest) -> io::Result<SsKillResult> {
        let output = run_ss_kill_with_timeout(Command::new(&self.command).args(request.args()))?;
        Ok(SsKillResult {
            success: output.status.success(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SsKillResult {
    success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl SsKillResult {
    fn closed_any_socket(&self) -> bool {
        String::from_utf8_lossy(&self.stdout)
            .lines()
            .any(is_socket_destroy_output_row)
    }

    fn failure_reason(&self) -> String {
        let stderr = String::from_utf8_lossy(trim_ascii_whitespace(&self.stderr));
        if stderr.is_empty() {
            "ss -K failed without stderr".to_string()
        } else {
            format!("ss -K failed: {stderr}")
        }
    }
}

fn find_ss_command() -> Option<PathBuf> {
    trusted_ss_paths()
        .into_iter()
        .find(|candidate| is_executable_file(candidate))
}

fn trusted_ss_paths() -> impl IntoIterator<Item = PathBuf> {
    ["/usr/sbin/ss", "/usr/bin/ss", "/sbin/ss", "/bin/ss"].map(PathBuf::from)
}

fn is_executable_file(path: &Path) -> bool {
    fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

fn is_root() -> bool {
    rustix::process::geteuid().as_raw() == 0
}

fn ss_supports_kill(command: &Path) -> bool {
    let Ok(output) = Command::new(command).arg("--help").output() else {
        return false;
    };
    let mut help = output.stdout;
    help.extend_from_slice(&output.stderr);
    let help = String::from_utf8_lossy(&help);
    help.contains("-K") && help.contains("--kill")
}

fn run_ss_kill_with_timeout(command: &mut Command) -> io::Result<std::process::Output> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn()?;
    let deadline = Instant::now() + SS_KILL_TIMEOUT;
    loop {
        if child.try_wait()?.is_some() {
            return child.wait_with_output();
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("ss -K timed out after {}ms", SS_KILL_TIMEOUT.as_millis()),
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn trim_ascii_whitespace(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |index| index + 1);
    &bytes[start..end]
}

fn is_socket_destroy_output_row(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return false;
    }

    let is_header = trimmed.starts_with("Netid ")
        || trimmed.contains("Local Address:Port") && trimmed.contains("Peer Address:Port");
    !is_header
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };

    use enforcement::{EnforcementPlanRequest, EnforcementPlanner, ScopedEnforcementPlanner};
    use probe_core::{
        Action, AddressPort, CaptureSource, Direction, EventKind, FlowContext, FlowIdentity,
        OpaqueStream, ProcessContext, ProcessIdentity, ProtectiveActionProfile, RuntimeMode,
        Timestamp, Verdict, VerdictScope,
    };

    use super::*;

    #[test]
    fn linux_socket_destroy_backend_builds_precise_ss_kill_filter()
    -> Result<(), Box<dyn std::error::Error>> {
        let runner = FakeSsKill::with_results([Ok(SsKillResult {
            success: true,
            stdout: b"ESTAB 0 0 127.0.0.1:41000 127.0.0.1:8080\n".to_vec(),
            stderr: Vec::new(),
        })]);
        let mut planner = planner_with_runner(runner.clone())?;
        let trigger = event_with_protocol(TransportProtocol::Tcp);
        let verdict = protective_verdict(Action::Reset);

        let decision = planner
            .evaluate(EnforcementPlanRequest {
                verdict: &verdict,
                trigger: &trigger,
            })?
            .expect("protective verdict should produce enforcement decision");

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
            requests[0].args(),
            [
                "-H",
                "-K",
                "-t",
                "state",
                "connected",
                "src",
                "127.0.0.1",
                "sport",
                "=",
                ":41000",
                "dst",
                "127.0.0.1",
                "dport",
                "=",
                ":8080",
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
        let verdict = protective_verdict(Action::Deny);

        let decision = planner
            .evaluate(EnforcementPlanRequest {
                verdict: &verdict,
                trigger: &trigger,
            })?
            .expect("protective verdict should produce enforcement decision");

        assert_eq!(
            decision.outcome,
            probe_core::EnforcementOutcome::Unsupported
        );
        assert_eq!(decision.effective_action, Action::Observe);
        Ok(())
    }

    #[test]
    fn linux_socket_destroy_backend_ignores_ss_header_output()
    -> Result<(), Box<dyn std::error::Error>> {
        let runner = FakeSsKill::with_results([Ok(SsKillResult {
            success: true,
            stdout: b"Netid State Recv-Q Send-Q Local Address:Port Peer Address:PortProcess\n"
                .to_vec(),
            stderr: Vec::new(),
        })]);
        let mut planner = planner_with_runner(runner)?;
        let trigger = event_with_protocol(TransportProtocol::Tcp);
        let verdict = protective_verdict(Action::Reset);

        let decision = planner
            .evaluate(EnforcementPlanRequest {
                verdict: &verdict,
                trigger: &trigger,
            })?
            .expect("protective verdict should produce enforcement decision");

        assert_eq!(
            decision.outcome,
            probe_core::EnforcementOutcome::Unsupported
        );
        assert_eq!(decision.effective_action, Action::Observe);
        Ok(())
    }

    #[test]
    fn linux_socket_destroy_backend_rejects_non_tcp_flows() -> Result<(), Box<dyn std::error::Error>>
    {
        let runner = FakeSsKill::with_results([]);
        let mut planner = planner_with_runner(runner.clone())?;
        let trigger = event_with_protocol(TransportProtocol::Udp);
        let verdict = protective_verdict(Action::Quarantine);

        let decision = planner
            .evaluate(EnforcementPlanRequest {
                verdict: &verdict,
                trigger: &trigger,
            })?
            .expect("protective verdict should produce enforcement decision");

        assert_eq!(
            decision.outcome,
            probe_core::EnforcementOutcome::Unsupported
        );
        assert!(
            runner.requests().is_empty(),
            "non-TCP flows must not invoke ss -K"
        );
        Ok(())
    }

    #[test]
    fn linux_socket_destroy_backend_rejects_replay_source() -> Result<(), Box<dyn std::error::Error>>
    {
        let runner = FakeSsKill::with_results([]);
        let mut planner = planner_with_runner(runner.clone())?;
        let trigger = event_with_protocol_and_source(TransportProtocol::Tcp, CaptureSource::Replay);
        let verdict = protective_verdict(Action::Reset);

        let decision = planner
            .evaluate(EnforcementPlanRequest {
                verdict: &verdict,
                trigger: &trigger,
            })?
            .expect("protective verdict should produce enforcement decision");

        assert_eq!(
            decision.outcome,
            probe_core::EnforcementOutcome::Unsupported
        );
        assert_eq!(decision.effective_action, Action::Observe);
        assert!(
            runner.requests().is_empty(),
            "replay events must not invoke ss -K"
        );
        Ok(())
    }

    #[test]
    fn linux_socket_destroy_probe_reports_missing_command_and_root_reasons() {
        let missing_command = unavailable_probe_reason(LinuxSocketDestroyProbe {
            command: None,
            running_as_root: true,
        });
        assert!(missing_command.contains("trusted system path"));

        let missing_root = unavailable_probe_reason(LinuxSocketDestroyProbe {
            command: Some(PathBuf::from("/not/executed")),
            running_as_root: false,
        });
        assert!(missing_root.contains("requires root"));
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

    fn planner_with_runner(
        runner: FakeSsKill,
    ) -> Result<ScopedEnforcementPlanner, enforcement::EnforcementError> {
        ScopedEnforcementPlanner::with_backend(
            None,
            ProtectiveActionProfile::default(),
            LinuxSocketDestroyBackend::new(runner),
        )
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
        EventEnvelope::new(
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
            source,
            "test-config",
            EventKind::OpaqueStream(OpaqueStream {
                direction: Direction::Outbound,
                fingerprint: Vec::new(),
                reason: "test".to_string(),
            }),
        )
    }

    fn unavailable_probe_reason(probe: LinuxSocketDestroyProbe) -> String {
        match probe.resolve() {
            LinuxSocketDestroyProbeResult::Available { .. } => {
                panic!("probe should be unavailable")
            }
            LinuxSocketDestroyProbeResult::Unavailable(capability) => {
                assert_eq!(capability.kind, CapabilityKind::ConnectionEnforcement);
                assert_eq!(capability.mode, RuntimeMode::Unavailable);
                capability.reason.expect("unavailable reason")
            }
        }
    }
}
