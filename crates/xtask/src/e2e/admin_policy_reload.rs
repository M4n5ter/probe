use std::{collections::BTreeSet, fs, path::Path, process::ExitCode};

use probe_config::{AgentConfig, CaptureSelection, PolicyConfig};
use probe_core::{CaptureProviderKind, CaptureSource, EventKind, FlowContext};
use storage::FjallSpool;

use super::{
    harness::{
        ChildSupervisor, UnixSocketReadySignal, create_temp_root, decode_envelope, e2e_error,
        ensure_e2e_packages_built, stop_running_child,
    },
    loopback::{
        Http1LoopbackFixtureConfig, PlainHttp1LoopbackFixtureConfig,
        assert_no_policy_runtime_errors, send_admin_request, spawn_agent,
        spawn_http1_loopback_fixture, start_http1_loopback_fixture,
        wait_for_agent_policy_alert_count_above, wait_for_agent_policy_alert_count_at_least,
        wait_for_agent_ready, wait_for_http1_loopback_fixture_exit,
        wait_for_http1_loopback_fixture_ready,
    },
};

const E2E_EXPORT_CURSOR_OWNER: &str = "e2e-admin-policy-reload";
const INTERFACE: &str = "any";
const POLICY_ID: &str = "e2e-admin-policy";
const OLD_POLICY_VERSION: &str = "old";
const NEW_POLICY_VERSION: &str = "new";
const OLD_POLICY_ALERT_PREFIX: &str = "old policy observed ";
const NEW_POLICY_ALERT_PREFIX: &str = "new policy observed ";
const FIRST_REQUESTS: usize = 1;
const SECOND_REQUESTS: usize = 2;
const REQUEST_BODY_BYTES: usize = 32;
const RESPONSE_BODY_BYTES: usize = 16;
const WRITE_CHUNKS: usize = 2;

pub(crate) fn run() -> ExitCode {
    match run_inner() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("e2e admin policy reload failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_inner() -> Result<(), Box<dyn std::error::Error>> {
    ensure_e2e_packages_built(["agent", "e2e-fixture"])?;
    let root = create_temp_root("admin-policy-reload")?;
    match run_at(&root) {
        Ok(()) => {
            fs::remove_dir_all(&root)?;
            println!("e2e admin policy reload passed");
            Ok(())
        }
        Err(error) => {
            eprintln!("e2e artifacts retained at {}", root.display());
            Err(error)
        }
    }
}

fn run_at(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(root)?;
    let first_ready_path = root.join("first-fixture.ready");
    let first_start_path = root.join("first-fixture.start");
    let second_ready_path = root.join("second-fixture.ready");
    let second_start_path = root.join("second-fixture.start");
    let agent_ready_socket_path = root.join("agent.ready.sock");
    let admin_socket_path = root.join("admin.sock");
    let policy_path = root.join("e2e-admin-policy.bundle");
    let config_path = root.join("agent.toml");
    let spool_path = root.join("spool");

    let supervisor = ChildSupervisor::new()?;
    write_policy_bundle(&policy_path, OLD_POLICY_VERSION, OLD_POLICY_ALERT_PREFIX)?;
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
    write_agent_config(
        &config_path,
        &policy_path,
        &spool_path,
        &admin_socket_path,
        [first_ready.listen_port, second_ready.listen_port],
    )?;
    let mut ready_signal = UnixSocketReadySignal::bind(agent_ready_socket_path)?;
    let mut agent = supervisor.watch(spawn_agent(&config_path, &ready_signal)?, "agent");
    wait_for_agent_ready(agent.child_mut(), &mut ready_signal)?;

    start_http1_loopback_fixture(&first_start_path, &first_ready.start_nonce)?;
    wait_for_http1_loopback_fixture_exit(first_fixture.child_mut())?;
    first_fixture.unwatch();
    let first_alert_count =
        wait_for_agent_policy_alert_count_at_least(agent.child_mut(), &admin_socket_path, 1)?;

    write_policy_bundle(&policy_path, NEW_POLICY_VERSION, NEW_POLICY_ALERT_PREFIX)?;
    assert_policy_reload_response(&send_admin_request(
        &admin_socket_path,
        serde_json::json!({ "command": "reload_policies" }),
    )?)?;

    start_http1_loopback_fixture(&second_start_path, &second_ready.start_nonce)?;
    wait_for_http1_loopback_fixture_exit(second_fixture.child_mut())?;
    second_fixture.unwatch();
    wait_for_agent_policy_alert_count_above(
        agent.child_mut(),
        &admin_socket_path,
        first_alert_count,
    )?;

    stop_running_child(agent.child_mut(), "agent")?;
    agent.unwatch();
    assert_spool_outputs(
        &spool_path,
        [first_ready.listen_port, second_ready.listen_port],
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
    }
}

fn write_policy_bundle(
    path: &Path,
    version: &str,
    alert_prefix: &str,
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
  if string.sub(target, 1, 10) == "/sssa-e2e/" then
    return probe.emit_alert("{alert_prefix}" .. target)
  end
end
"#
        ),
    )
}

fn write_agent_config(
    path: &Path,
    policy_path: &Path,
    spool_path: &Path,
    admin_socket_path: &Path,
    listen_ports: [u16; 2],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = AgentConfig {
        agent_id: "e2e-admin-policy-reload-agent".to_string(),
        config_version: "e2e-admin-policy-reload".to_string(),
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
    config.policies.push(PolicyConfig {
        id: POLICY_ID.to_string(),
        path: policy_path.to_path_buf(),
        enabled: true,
        selector: None,
    });
    fs::write(path, toml::to_string(&config)?)?;
    Ok(())
}

fn assert_policy_reload_response(
    response: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    if response["kind"] == serde_json::json!("policy_reload")
        && response["loaded_count"] == serde_json::json!(1)
        && response["policies"][0]["id"] == serde_json::json!(POLICY_ID)
    {
        Ok(())
    } else {
        Err(e2e_error(format!("unexpected policy reload response: {response}")).into())
    }
}

fn assert_spool_outputs(
    spool_path: &Path,
    listen_ports: [u16; 2],
) -> Result<(), Box<dyn std::error::Error>> {
    let spool = FjallSpool::open(spool_path)?;
    let envelopes = spool
        .read_export_batch(E2E_EXPORT_CURSOR_OWNER, 512)?
        .iter()
        .map(decode_envelope)
        .collect::<Result<Vec<_>, _>>()?;
    assert_no_policy_runtime_errors(&envelopes)?;

    let alerts = collect_policy_alert_facts(&envelopes, listen_ports)?;
    let expected = expected_policy_alert_facts(listen_ports);
    if alerts != expected {
        return Err(e2e_error(format!(
            "unexpected policy alert facts; expected {expected:?}, observed {alerts:?}"
        ))
        .into());
    }

    println!(
        "e2e admin policy reload observed {} export records and {} policy alerts",
        envelopes.len(),
        alerts.len()
    );
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PolicyAlertFact {
    policy_version: String,
    listen_port: u16,
    message: String,
}

fn collect_policy_alert_facts(
    envelopes: &[probe_core::EventEnvelope],
    listen_ports: [u16; 2],
) -> Result<BTreeSet<PolicyAlertFact>, Box<dyn std::error::Error>> {
    let mut facts = BTreeSet::new();
    for envelope in envelopes {
        let EventKind::PolicyAlert(alert) = envelope.kind() else {
            continue;
        };
        if envelope.origin().source() != CaptureSource::Libpcap
            || envelope.origin().provider() != CaptureProviderKind::Libpcap
        {
            continue;
        }
        let flow = envelope
            .flow()
            .ok_or_else(|| e2e_error("libpcap policy alert did not carry a flow subject"))?;
        let listen_port = matched_listen_port(flow, listen_ports).ok_or_else(|| {
            e2e_error(format!(
                "libpcap policy alert did not match fixture listen ports {:?}: local={}, remote={}",
                listen_ports, flow.local.port, flow.remote.port
            ))
        })?;
        facts.insert(PolicyAlertFact {
            policy_version: envelope.policy_version().unwrap_or_default().to_string(),
            listen_port,
            message: alert.message.clone(),
        });
    }
    Ok(facts)
}

fn expected_policy_alert_facts(listen_ports: [u16; 2]) -> BTreeSet<PolicyAlertFact> {
    let [first_port, second_port] = listen_ports;
    let old_version = format!("{POLICY_ID}@{OLD_POLICY_VERSION}");
    let new_version = format!("{POLICY_ID}@{NEW_POLICY_VERSION}");
    (0..FIRST_REQUESTS)
        .map(|request| PolicyAlertFact {
            policy_version: old_version.clone(),
            listen_port: first_port,
            message: format!("{OLD_POLICY_ALERT_PREFIX}/sssa-e2e/{request}"),
        })
        .chain((0..SECOND_REQUESTS).map(|request| PolicyAlertFact {
            policy_version: new_version.clone(),
            listen_port: second_port,
            message: format!("{NEW_POLICY_ALERT_PREFIX}/sssa-e2e/{request}"),
        }))
        .collect()
}

fn matched_listen_port(flow: &FlowContext, listen_ports: [u16; 2]) -> Option<u16> {
    listen_ports
        .into_iter()
        .find(|port| flow.local.port == *port || flow.remote.port == *port)
}
