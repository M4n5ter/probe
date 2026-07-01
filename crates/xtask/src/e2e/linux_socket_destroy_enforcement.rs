use std::{fs, path::Path, process::ExitStatus, time::Duration};

use enforcement::linux_socket_destroy::check_socket_destroy_capability;
use probe_config::{
    AgentConfig, CaptureSelection, ConnectionEnforcementBackendConfig, EnforcementPolicyManifest,
    EnforcementPolicySourceConfig, PolicyConfig,
};
use probe_core::{
    Action, CaptureProviderKind, CaptureSource, Direction, EnforcementMode, EnforcementOutcome,
    EventKind, ProcessSelector, ProtectiveActionProfile, Selector, TrafficSelector, VerdictScope,
};
use storage::FjallSpool;

use super::{
    E2eOutcome,
    harness::{
        ChildSupervisor, UnixSocketReadySignal, create_temp_root, decode_envelope, e2e_error,
        ensure_e2e_packages_built, stop_running_child, wait_for_child_status,
    },
    loopback::{
        Http1LoopbackFixtureConfig, PlainHttp1LoopbackFixtureConfig,
        assert_no_policy_runtime_errors, spawn_agent, spawn_http1_loopback_fixture,
        start_http1_loopback_fixture, wait_for_agent_enforcement_decision_count_at_least,
        wait_for_agent_ready, wait_for_http1_loopback_fixture_ready,
    },
};

const E2E_EXPORT_CURSOR_OWNER: &str = "e2e-linux-socket-destroy-enforcement";
const INTERFACE: &str = "any";
const POLICY_ID: &str = "e2e-linux-socket-destroy-policy";
const POLICY_VERSION: &str = "e2e";
const EXPECTED_POLICY_VERSION: &str = "e2e-linux-socket-destroy-policy@e2e";
const MANIFEST_ID: &str = "e2e-linux-socket-destroy";
const MANIFEST_VERSION: &str = "e2e";
const REQUEST_BODY_BYTES: usize = 32;
const RESPONSE_BODY_BYTES: usize = 16;
const WRITE_CHUNKS: usize = 2;
const ACCEPT_READ_DELAY_MS: u64 = 3_000;
const POLICY_REASON_PREFIX: &str = "linux socket destroy e2e";
const FIXTURE_PROCESS_NAME: &str = "traffic-probe-e2e-fixture";
const FIXTURE_EXE_GLOB: &str = "**/traffic-probe-e2e-fixture";

pub(crate) fn run() -> E2eOutcome {
    match run_inner() {
        Ok(RunOutcome::Passed) => E2eOutcome::Passed,
        Ok(RunOutcome::Skipped(reason)) => E2eOutcome::Skipped(reason),
        Err(error) => {
            eprintln!("e2e linux socket destroy enforcement failed: {error}");
            E2eOutcome::Failed
        }
    }
}

enum RunOutcome {
    Passed,
    Skipped(String),
}

fn run_inner() -> Result<RunOutcome, Box<dyn std::error::Error>> {
    if !is_root() {
        return Err(e2e_error("e2e linux socket destroy enforcement must run as root").into());
    }
    ensure_e2e_packages_built(["agent", "e2e-fixture"])?;
    if let Some(reason) = linux_socket_destroy_unavailable_reason()? {
        return Ok(RunOutcome::Skipped(reason));
    }
    let root = create_temp_root("linux-socket-destroy-enforcement")?;
    match run_at(&root) {
        Ok(()) => {
            fs::remove_dir_all(&root)?;
            Ok(RunOutcome::Passed)
        }
        Err(error) => {
            eprintln!("e2e artifacts retained at {}", root.display());
            Err(error)
        }
    }
}

fn linux_socket_destroy_unavailable_reason() -> Result<Option<String>, Box<dyn std::error::Error>> {
    if let Err(error) = check_socket_destroy_capability() {
        return Ok(Some(format!(
            "linux socket destroy enforcement capability is unavailable: {error}",
        )));
    }
    Ok(None)
}

fn is_root() -> bool {
    rustix::process::geteuid().as_raw() == 0
}

fn run_at(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(root)?;
    let fixture_ready_path = root.join("fixture.ready");
    let fixture_start_path = root.join("fixture.start");
    let agent_ready_socket_path = root.join("agent.ready.sock");
    let admin_socket_path = root.join("admin.sock");
    let policy_path = root.join("linux-socket-destroy-policy.bundle");
    let enforcement_manifest_path = root.join("enforcement.toml");
    let config_path = root.join("agent.toml");
    let spool_path = root.join("spool");

    let supervisor = ChildSupervisor::new()?;
    let mut fixture = supervisor.watch(
        spawn_http1_loopback_fixture(&fixture_ready_path, &fixture_start_path, fixture_config())?,
        "fixture",
    );
    let fixture_ready =
        wait_for_http1_loopback_fixture_ready(fixture.child_mut(), &fixture_ready_path)?;

    write_policy_bundle(&policy_path)?;
    write_enforcement_manifest(&enforcement_manifest_path, fixture_ready.listen_port)?;
    write_agent_config(
        &config_path,
        &policy_path,
        &enforcement_manifest_path,
        &spool_path,
        &admin_socket_path,
        fixture_ready.listen_port,
    )?;

    let mut ready_signal = UnixSocketReadySignal::bind(agent_ready_socket_path)?;
    let mut agent = supervisor.watch(spawn_agent(&config_path, &ready_signal)?, "agent");
    wait_for_agent_ready(agent.child_mut(), &mut ready_signal)?;

    start_http1_loopback_fixture(&fixture_start_path, &fixture_ready.start_nonce)?;
    wait_for_agent_enforcement_decision_count_at_least(agent.child_mut(), &admin_socket_path, 1)?;
    let fixture_status =
        wait_for_child_status(fixture.child_mut(), Duration::from_secs(20), "fixture")?;
    fixture.unwatch();

    stop_running_child(agent.child_mut(), "agent")?;
    agent.unwatch();
    assert_spool_outputs(&spool_path, fixture_ready.listen_port, fixture_status)?;
    Ok(())
}

fn fixture_config() -> PlainHttp1LoopbackFixtureConfig {
    PlainHttp1LoopbackFixtureConfig {
        shared: Http1LoopbackFixtureConfig {
            listen_port: None,
            requests: 1,
            request_body_bytes: REQUEST_BODY_BYTES,
            response_body_bytes: RESPONSE_BODY_BYTES,
            write_chunks: WRITE_CHUNKS,
            connect_write_delay_ms: 0,
            post_exchange_delay_ms: 0,
        },
        accept_read_delay_ms: ACCEPT_READ_DELAY_MS,
    }
}

fn write_policy_bundle(path: &Path) -> Result<(), std::io::Error> {
    fs::create_dir_all(path)?;
    fs::write(
        path.join("manifest.toml"),
        format!(
            r#"
id = "{POLICY_ID}"
version = "{POLICY_VERSION}"
hooks = ["on_http_request_headers"]
"#
        ),
    )?;
    fs::write(
        path.join("main.lua"),
        format!(
            r#"
function on_http_request_headers(event)
  local target = event.kind.target or ""
  local prefix = "/traffic-probe-e2e/"
  if string.sub(target, 1, #prefix) ~= prefix then
    return nil
  end
  return probe.verdict({{
    action = "deny",
    scope = "request",
    reason = "{POLICY_REASON_PREFIX} " .. target,
    confidence = 100,
  }})
end
"#
        ),
    )
}

fn write_enforcement_manifest(
    path: &Path,
    listen_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = EnforcementPolicyManifest {
        id: MANIFEST_ID.to_string(),
        version: MANIFEST_VERSION.to_string(),
        selectors: Default::default(),
        selector: Some(Selector::term(
            ProcessSelector {
                exe_path_globs: vec![FIXTURE_EXE_GLOB.to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector {
                remote_ports: vec![listen_port],
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
        )),
        protective_actions: ProtectiveActionProfile::new([Action::Deny])?,
    };
    fs::write(path, toml::to_string(&manifest)?)?;
    Ok(())
}

fn write_agent_config(
    path: &Path,
    policy_path: &Path,
    enforcement_manifest_path: &Path,
    spool_path: &Path,
    admin_socket_path: &Path,
    listen_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = AgentConfig {
        agent_id: "e2e-linux-socket-destroy-agent".to_string(),
        config_version: "e2e-linux-socket-destroy".to_string(),
        ..AgentConfig::default()
    };
    config.capture.selection = CaptureSelection::Libpcap;
    config.capture.libpcap.interface = Some(INTERFACE.to_string());
    config.capture.libpcap.bpf_filter = format!("tcp and port {listen_port}");
    config.capture.libpcap.read_timeout_ms = 50;
    config.storage.path = spool_path.to_path_buf();
    config.export.worker.enabled = false;
    config.admin.enabled = true;
    config.admin.socket_path = admin_socket_path.to_path_buf();
    config.enforcement.mode = EnforcementMode::Enforce;
    config.enforcement.backend = ConnectionEnforcementBackendConfig::LinuxSocketDestroy;
    config.enforcement.policy.source = EnforcementPolicySourceConfig::File {
        path: enforcement_manifest_path.to_path_buf(),
    };
    config.policies.push(PolicyConfig {
        id: POLICY_ID.to_string(),
        source: probe_config::PolicySourceConfig::LocalDirectory {
            path: policy_path.to_path_buf(),
        },
        enabled: true,
        selector: None,
        ..PolicyConfig::default()
    });
    fs::write(path, toml::to_string(&config)?)?;
    Ok(())
}

fn assert_spool_outputs(
    spool_path: &Path,
    listen_port: u16,
    fixture_status: ExitStatus,
) -> Result<(), Box<dyn std::error::Error>> {
    let spool = FjallSpool::open(spool_path)?;
    let envelopes = spool
        .read_export_batch(E2E_EXPORT_CURSOR_OWNER, 512)?
        .iter()
        .map(decode_envelope)
        .collect::<Result<Vec<_>, _>>()?;
    assert_no_policy_runtime_errors(&envelopes)?;

    let decision = envelopes.iter().find_map(|envelope| {
        let EventKind::EnforcementDecision(decision) = envelope.kind() else {
            return None;
        };
        if envelope.origin().source() != CaptureSource::Libpcap
            || envelope.origin().provider() != CaptureProviderKind::Libpcap
            || envelope.policy_version() != Some(EXPECTED_POLICY_VERSION)
            || decision.mode != EnforcementMode::Enforce
            || decision.requested_action != Action::Deny
            || decision.outcome != EnforcementOutcome::Applied
            || decision.effective_action != Action::Deny
            || decision.scope != VerdictScope::Request
            || !decision.selector_matched
            || !decision.reason.contains(POLICY_REASON_PREFIX)
            || !decision
                .reason
                .contains("netlink SOCK_DESTROY destroyed TCP socket")
        {
            return None;
        }
        let flow = envelope.flow()?;
        (flow.remote.port == listen_port
            && flow
                .process
                .identity
                .exe_path
                .contains(FIXTURE_PROCESS_NAME))
        .then_some(decision)
    });
    let Some(decision) = decision else {
        let observed = envelopes
            .iter()
            .filter_map(|envelope| {
                let EventKind::EnforcementDecision(decision) = envelope.kind() else {
                    return None;
                };
                let flow = envelope.flow()?;
                Some(format!(
                    "source={:?}/{:?} policy={:?} mode={:?} requested={:?} outcome={:?} effective={:?} selector_matched={} local={}:{} remote={}:{} process={} exe={} reason={}",
                    envelope.origin().source(),
                    envelope.origin().provider(),
                    envelope.policy_version(),
                    decision.mode,
                    decision.requested_action,
                    decision.outcome,
                    decision.effective_action,
                    decision.selector_matched,
                    flow.local.address,
                    flow.local.port,
                    flow.remote.address,
                    flow.remote.port,
                    flow.process.name,
                    flow.process.identity.exe_path,
                    decision.reason,
                ))
            })
            .collect::<Vec<_>>();
        return Err(e2e_error(format!(
            "missing applied linux socket destroy enforcement decision for port {listen_port}; fixture exited with {fixture_status}; observed {} export records; decisions={observed:?}",
            envelopes.len(),
        ))
        .into());
    };

    if fixture_status.success() {
        return Err(e2e_error(format!(
            "linux socket destroy enforcement reported applied but fixture completed successfully; \
             expected the protected connection to be interrupted; decision={decision:?}",
        ))
        .into());
    }

    println!(
        "e2e linux socket destroy enforcement observed applied decision {:?}; fixture exited with {fixture_status}",
        decision.requested_action
    );
    Ok(())
}
