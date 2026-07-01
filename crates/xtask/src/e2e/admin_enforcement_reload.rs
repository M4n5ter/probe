use std::{fs, path::Path, process::ExitCode};

use probe_config::{
    AgentConfig, CaptureSelection, EnforcementPolicyManifest, EnforcementPolicySourceConfig,
    PolicyConfig,
};
use probe_core::{
    Action, CaptureProviderKind, CaptureSource, Direction, EnforcementMode, EnforcementOutcome,
    EventKind, FlowContext, ProcessSelector, ProtectiveActionProfile, Selector, TrafficSelector,
    VerdictScope,
};
use storage::FjallSpool;

use super::{
    agent_admin::{
        assert_no_policy_runtime_errors, send_admin_request,
        wait_for_agent_enforcement_decision_count_above,
        wait_for_agent_enforcement_decision_count_at_least,
    },
    harness::{
        ChildSupervisor, UnixSocketReadySignal, create_temp_root, decode_envelope, e2e_error,
        ensure_e2e_packages_built, stop_running_child,
    },
    loopback::{
        Http1LoopbackFixtureConfig, PlainHttp1LoopbackFixtureConfig, spawn_agent,
        spawn_http1_loopback_fixture, start_http1_loopback_fixture, wait_for_agent_ready,
        wait_for_http1_loopback_fixture_exit, wait_for_http1_loopback_fixture_ready,
    },
};

const E2E_EXPORT_CURSOR_OWNER: &str = "e2e-admin-enforcement-reload";
const INTERFACE: &str = "any";
const POLICY_ID: &str = "e2e-admin-enforcement-policy";
const STATIC_POLICY_VERSION: &str = "e2e";
const OLD_POLICY_VERSION: &str = "old";
const NEW_POLICY_VERSION: &str = "new";
const MANIFEST_ID: &str = "e2e-admin-enforcement";
const OLD_MANIFEST_VERSION: &str = "old";
const NEW_MANIFEST_VERSION: &str = "new";
const FIRST_REQUESTS: usize = 1;
const SECOND_REQUESTS: usize = 1;
const REQUEST_BODY_BYTES: usize = 32;
const RESPONSE_BODY_BYTES: usize = 16;
const WRITE_CHUNKS: usize = 2;
const POLICY_REASON_PREFIX: &str = "admin enforcement reload";

type ReloadResponseAssertion = fn(&serde_json::Value) -> Result<(), Box<dyn std::error::Error>>;

#[derive(Debug, Clone, Copy)]
struct AdminReloadCase {
    temp_root_name: &'static str,
    label: &'static str,
    agent_id: &'static str,
    config_version: &'static str,
    initial_policy_version: &'static str,
    reloaded_policy_version: Option<&'static str>,
    reload_command: &'static str,
    assert_reload_response: ReloadResponseAssertion,
}

const ENFORCEMENT_RELOAD_CASE: AdminReloadCase = AdminReloadCase {
    temp_root_name: "admin-enforcement-reload",
    label: "e2e admin enforcement reload",
    agent_id: "e2e-admin-enforcement-reload-agent",
    config_version: "e2e-admin-enforcement-reload",
    initial_policy_version: STATIC_POLICY_VERSION,
    reloaded_policy_version: None,
    reload_command: "reload_enforcement_policy",
    assert_reload_response: assert_enforcement_reload_response,
};

const RUNTIME_ACTIONS_RELOAD_CASE: AdminReloadCase = AdminReloadCase {
    temp_root_name: "admin-runtime-actions-reload",
    label: "e2e admin runtime actions reload",
    agent_id: "e2e-admin-runtime-actions-reload-agent",
    config_version: "e2e-admin-runtime-actions-reload",
    initial_policy_version: OLD_POLICY_VERSION,
    reloaded_policy_version: Some(NEW_POLICY_VERSION),
    reload_command: "reload_runtime_actions",
    assert_reload_response: assert_runtime_actions_reload_response,
};

impl AdminReloadCase {
    fn expected_reloaded_policy_version(self) -> &'static str {
        self.reloaded_policy_version
            .unwrap_or(self.initial_policy_version)
    }

    fn assert_response(
        self,
        response: &serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error>> {
        (self.assert_reload_response)(response)
    }
}

pub(crate) fn run() -> ExitCode {
    run_case(ENFORCEMENT_RELOAD_CASE)
}

pub(crate) fn run_runtime_actions() -> ExitCode {
    run_case(RUNTIME_ACTIONS_RELOAD_CASE)
}

fn run_case(case: AdminReloadCase) -> ExitCode {
    match run_inner(case) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{} failed: {error}", case.label);
            ExitCode::FAILURE
        }
    }
}

fn run_inner(case: AdminReloadCase) -> Result<(), Box<dyn std::error::Error>> {
    ensure_e2e_packages_built(["agent", "e2e-fixture"])?;
    let root = create_temp_root(case.temp_root_name)?;
    match run_at(&root, case) {
        Ok(()) => {
            fs::remove_dir_all(&root)?;
            println!("{} passed", case.label);
            Ok(())
        }
        Err(error) => {
            eprintln!("e2e artifacts retained at {}", root.display());
            Err(error)
        }
    }
}

fn run_at(root: &Path, case: AdminReloadCase) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(root)?;
    let first_ready_path = root.join("first-fixture.ready");
    let first_start_path = root.join("first-fixture.start");
    let second_ready_path = root.join("second-fixture.ready");
    let second_start_path = root.join("second-fixture.start");
    let agent_ready_socket_path = root.join("agent.ready.sock");
    let admin_socket_path = root.join("admin.sock");
    let policy_path = root.join("e2e-admin-enforcement-policy.bundle");
    let enforcement_manifest_path = root.join("enforcement.toml");
    let config_path = root.join("agent.toml");
    let spool_path = root.join("spool");

    let supervisor = ChildSupervisor::new()?;
    let mut first_fixture = supervisor.watch(
        spawn_http1_loopback_fixture(
            &first_ready_path,
            &first_start_path,
            fixture_config(FIRST_REQUESTS),
        )?,
        "first fixture",
    );
    let first_ready =
        wait_for_http1_loopback_fixture_ready(first_fixture.child_mut(), &first_ready_path)?;
    let mut second_fixture = supervisor.watch(
        spawn_http1_loopback_fixture(
            &second_ready_path,
            &second_start_path,
            fixture_config(SECOND_REQUESTS),
        )?,
        "second fixture",
    );
    let second_ready =
        wait_for_http1_loopback_fixture_ready(second_fixture.child_mut(), &second_ready_path)?;

    write_policy_bundle(
        &policy_path,
        case.initial_policy_version,
        first_ready.listen_port,
        second_ready.listen_port,
    )?;
    write_enforcement_manifest(
        &enforcement_manifest_path,
        OLD_MANIFEST_VERSION,
        first_ready.listen_port,
        Action::Deny,
    )?;
    write_agent_config(
        &config_path,
        &policy_path,
        &enforcement_manifest_path,
        &spool_path,
        &admin_socket_path,
        [first_ready.listen_port, second_ready.listen_port],
        case,
    )?;

    let mut ready_signal = UnixSocketReadySignal::bind(agent_ready_socket_path)?;
    let mut agent = supervisor.watch(spawn_agent(&config_path, &ready_signal)?, "agent");
    wait_for_agent_ready(agent.child_mut(), &mut ready_signal)?;

    start_http1_loopback_fixture(&first_start_path, &first_ready.start_nonce)?;
    wait_for_http1_loopback_fixture_exit(first_fixture.child_mut())?;
    first_fixture.unwatch();
    let first_decision_count = wait_for_agent_enforcement_decision_count_at_least(
        agent.child_mut(),
        &admin_socket_path,
        1,
    )?;

    if let Some(policy_version) = case.reloaded_policy_version {
        write_policy_bundle(
            &policy_path,
            policy_version,
            first_ready.listen_port,
            second_ready.listen_port,
        )?;
    }
    write_enforcement_manifest(
        &enforcement_manifest_path,
        NEW_MANIFEST_VERSION,
        second_ready.listen_port,
        Action::Reset,
    )?;
    case.assert_response(&send_admin_request(
        &admin_socket_path,
        serde_json::json!({ "command": case.reload_command }),
    )?)?;

    start_http1_loopback_fixture(&second_start_path, &second_ready.start_nonce)?;
    wait_for_http1_loopback_fixture_exit(second_fixture.child_mut())?;
    second_fixture.unwatch();
    wait_for_agent_enforcement_decision_count_above(
        agent.child_mut(),
        &admin_socket_path,
        first_decision_count,
    )?;

    stop_running_child(agent.child_mut(), "agent")?;
    agent.unwatch();
    assert_spool_outputs(
        &spool_path,
        [first_ready.listen_port, second_ready.listen_port],
        case,
    )?;
    Ok(())
}

fn fixture_config(requests: usize) -> PlainHttp1LoopbackFixtureConfig {
    PlainHttp1LoopbackFixtureConfig {
        shared: Http1LoopbackFixtureConfig {
            listen_port: None,
            requests,
            request_body_bytes: REQUEST_BODY_BYTES,
            response_body_bytes: RESPONSE_BODY_BYTES,
            write_chunks: WRITE_CHUNKS,
            connect_write_delay_ms: 0,
            post_exchange_delay_ms: 0,
        },
        accept_read_delay_ms: 0,
        vector_first_payload_slice_bytes: None,
    }
}

fn write_policy_bundle(
    path: &Path,
    version: &str,
    first_listen_port: u16,
    second_listen_port: u16,
) -> Result<(), std::io::Error> {
    fs::create_dir_all(path)?;
    fs::write(
        path.join("manifest.toml"),
        format!(
            r#"
id = "{POLICY_ID}"
version = "{version}"
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
  local local_port = event.flow.local_endpoint.port or 0
  local remote_port = event.flow.remote_endpoint.port or 0
  local action = nil
  if local_port == {second_listen_port} or remote_port == {second_listen_port} then
    action = "reset"
  elseif local_port == {first_listen_port} or remote_port == {first_listen_port} then
    action = "deny"
  else
    return nil
  end
  return probe.verdict({{
    action = action,
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
    version: &str,
    remote_port: u16,
    action: Action,
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = EnforcementPolicyManifest {
        id: MANIFEST_ID.to_string(),
        version: version.to_string(),
        selectors: Default::default(),
        selector: Some(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                remote_ports: vec![remote_port],
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
        )),
        protective_actions: ProtectiveActionProfile::new([action])?,
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
    listen_ports: [u16; 2],
    case: AdminReloadCase,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = AgentConfig {
        agent_id: case.agent_id.to_string(),
        config_version: case.config_version.to_string(),
        ..AgentConfig::default()
    };
    config.capture.selection = CaptureSelection::Libpcap;
    config.capture.libpcap.interface = Some(INTERFACE.to_string());
    config.capture.libpcap.bpf_filter = format!(
        "tcp and (port {} or port {})",
        listen_ports[0], listen_ports[1]
    );
    config.capture.libpcap.read_timeout_ms = 100;
    config.storage.path = spool_path.to_path_buf();
    config.export.worker.enabled = false;
    config.admin.enabled = true;
    config.admin.socket_path = admin_socket_path.to_path_buf();
    config.enforcement.mode = EnforcementMode::DryRun;
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

fn assert_enforcement_reload_response(
    response: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    if response["kind"] != serde_json::json!("enforcement_policy_reload") {
        return Err(e2e_error(format!(
            "unexpected enforcement reload response kind: {response}"
        ))
        .into());
    }
    assert_enforcement_reload_payload(response, "enforcement reload response")
}

fn assert_runtime_actions_reload_response(
    response: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    if response["kind"] != serde_json::json!("runtime_actions_reload") {
        return Err(e2e_error(format!(
            "unexpected runtime actions reload response kind: {response}"
        ))
        .into());
    }
    let policy = runtime_action_outcome(response, "reload_policies")?;
    let enforcement = runtime_action_outcome(response, "reload_enforcement_policy")?;
    assert_policy_reload_success(policy, "runtime actions policy outcome")?;
    if enforcement["result"] != serde_json::json!("succeeded") {
        return Err(e2e_error(format!(
            "unexpected runtime actions enforcement outcome result: {enforcement}"
        ))
        .into());
    }
    assert_enforcement_reload_payload(enforcement, "runtime actions enforcement outcome")
}

fn assert_policy_reload_success(
    value: &serde_json::Value,
    context: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if value["result"] == serde_json::json!("succeeded")
        && value["loaded_count"] == serde_json::json!(1)
        && value["policies"][0]["id"] == serde_json::json!(POLICY_ID)
        && value["active_set_updated"] == serde_json::json!(true)
    {
        return Ok(());
    }
    Err(e2e_error(format!("unexpected {context}: {value}")).into())
}

fn assert_enforcement_reload_payload(
    value: &serde_json::Value,
    context: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if value["source"]["manifest"]["id"] == serde_json::json!(MANIFEST_ID)
        && value["source"]["manifest"]["version"] == serde_json::json!(NEW_MANIFEST_VERSION)
        && value["source"]["manifest"]["selector_configured"] == serde_json::json!(true)
        && value["effective_selector_configured"] == serde_json::json!(true)
        && value["manifest_selector_configured"] == serde_json::json!(true)
        && value["protective_actions"] == serde_json::json!(["reset"])
    {
        return Ok(());
    }
    Err(e2e_error(format!("unexpected {context}: {value}")).into())
}

fn runtime_action_outcome<'a>(
    response: &'a serde_json::Value,
    action_name: &str,
) -> Result<&'a serde_json::Value, Box<dyn std::error::Error>> {
    response["actions"]
        .as_array()
        .and_then(|actions| {
            actions
                .iter()
                .find(|action| action["action"] == serde_json::json!(action_name))
        })
        .map(|action| &action["outcome"])
        .ok_or_else(|| {
            e2e_error(format!(
                "runtime actions reload response omitted {action_name}: {response}"
            ))
            .into()
        })
}

fn assert_spool_outputs(
    spool_path: &Path,
    listen_ports: [u16; 2],
    case: AdminReloadCase,
) -> Result<(), Box<dyn std::error::Error>> {
    let spool = FjallSpool::open(spool_path)?;
    let envelopes = spool
        .read_export_batch(E2E_EXPORT_CURSOR_OWNER, 512)?
        .iter()
        .map(decode_envelope)
        .collect::<Result<Vec<_>, _>>()?;
    assert_no_policy_runtime_errors(&envelopes)?;

    let mut observed = collect_enforcement_decision_facts(&envelopes, listen_ports)?;
    observed.sort();
    let mut expected = expected_enforcement_decision_facts(listen_ports, case);
    expected.sort();
    if observed != expected {
        return Err(e2e_error(format!(
            "unexpected enforcement decision facts; expected {expected:?}, observed {observed:?}"
        ))
        .into());
    }

    println!(
        "{} observed {} export records and {} enforcement decisions",
        case.label,
        envelopes.len(),
        observed.len()
    );
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct EnforcementDecisionFact {
    policy_version: String,
    listen_port: u16,
    requested_action: &'static str,
    outcome: &'static str,
    effective_action: &'static str,
    selector_matched: bool,
    reason: String,
}

fn collect_enforcement_decision_facts(
    envelopes: &[probe_core::EventEnvelope],
    listen_ports: [u16; 2],
) -> Result<Vec<EnforcementDecisionFact>, Box<dyn std::error::Error>> {
    let mut facts = Vec::new();
    for envelope in envelopes {
        let EventKind::EnforcementDecision(decision) = envelope.kind() else {
            continue;
        };
        let Some(policy_version) = envelope.policy_version() else {
            continue;
        };
        if envelope.origin().source() != CaptureSource::Libpcap
            || envelope.origin().provider() != CaptureProviderKind::Libpcap
            || !policy_version.starts_with(&format!("{POLICY_ID}@"))
            || decision.mode != EnforcementMode::DryRun
            || decision.scope != VerdictScope::Request
            || !decision.reason.contains(POLICY_REASON_PREFIX)
        {
            continue;
        }
        let flow = envelope.flow().ok_or_else(|| {
            e2e_error("libpcap enforcement decision did not carry a flow subject")
        })?;
        let listen_port = matched_listen_port(flow, listen_ports).ok_or_else(|| {
            e2e_error(format!(
                "libpcap enforcement decision did not match fixture listen ports {:?}: local={}, remote={}",
                listen_ports, flow.local.port, flow.remote.port
            ))
        })?;
        let policy_reason = matched_policy_reason(&decision.reason).ok_or_else(|| {
            e2e_error(format!(
                "libpcap enforcement decision reason did not contain expected policy reason: {}",
                decision.reason
            ))
        })?;
        facts.push(EnforcementDecisionFact {
            policy_version: policy_version.to_string(),
            listen_port,
            requested_action: action_name(decision.requested_action),
            outcome: outcome_name(decision.outcome),
            effective_action: action_name(decision.effective_action),
            selector_matched: decision.selector_matched,
            reason: policy_reason,
        });
    }
    Ok(facts)
}

fn expected_enforcement_decision_facts(
    listen_ports: [u16; 2],
    case: AdminReloadCase,
) -> Vec<EnforcementDecisionFact> {
    vec![
        EnforcementDecisionFact {
            policy_version: format!("{POLICY_ID}@{}", case.initial_policy_version),
            listen_port: listen_ports[0],
            requested_action: "deny",
            outcome: "dry_run",
            effective_action: "observe",
            selector_matched: true,
            reason: format!("{POLICY_REASON_PREFIX} /traffic-probe-e2e/0"),
        },
        EnforcementDecisionFact {
            policy_version: format!("{POLICY_ID}@{}", case.expected_reloaded_policy_version()),
            listen_port: listen_ports[1],
            requested_action: "reset",
            outcome: "dry_run",
            effective_action: "observe",
            selector_matched: true,
            reason: format!("{POLICY_REASON_PREFIX} /traffic-probe-e2e/0"),
        },
    ]
}

fn action_name(action: Action) -> &'static str {
    match action {
        Action::Allow => "allow",
        Action::Observe => "observe",
        Action::Alert => "alert",
        Action::Deny => "deny",
        Action::Reset => "reset",
        Action::Quarantine => "quarantine",
    }
}

fn outcome_name(outcome: EnforcementOutcome) -> &'static str {
    match outcome {
        EnforcementOutcome::Disabled => "disabled",
        EnforcementOutcome::AuditOnly => "audit_only",
        EnforcementOutcome::DryRun => "dry_run",
        EnforcementOutcome::SelectorMiss => "selector_miss",
        EnforcementOutcome::Unsupported => "unsupported",
        EnforcementOutcome::Failed => "failed",
        EnforcementOutcome::Delegated => "delegated",
        EnforcementOutcome::Applied => "applied",
    }
}

fn matched_policy_reason(reason: &str) -> Option<String> {
    let expected = format!("{POLICY_REASON_PREFIX} /traffic-probe-e2e/0");
    reason.contains(&expected).then_some(expected)
}

fn matched_listen_port(flow: &FlowContext, listen_ports: [u16; 2]) -> Option<u16> {
    listen_ports
        .into_iter()
        .find(|port| flow.local.port == *port || flow.remote.port == *port)
}
