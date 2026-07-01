use std::{
    fs,
    io::{self, Read, Write},
    net::{Ipv4Addr, Shutdown, TcpListener, TcpStream},
    path::Path,
    process::{Child, ExitCode},
    thread,
    time::{Duration, Instant},
};

use probe_config::{AgentConfig, CaptureSelection, PolicyConfig};

use super::{
    agent_admin::{
        send_admin_request, wait_for_agent_pipeline_progress, wait_for_agent_policy_progress,
    },
    harness::{
        ChildSupervisor, UnixSocketReadySignal, create_temp_root, e2e_error,
        ensure_e2e_packages_built, stop_running_child,
    },
    loopback::{merge_labeled_run_results, spawn_agent, wait_for_agent_ready},
};

mod assertions;
mod fixture;
mod scenario;

use assertions::assert_spool_outputs;
use fixture::SyntheticTls13AutoBindingFixture;
use scenario::AutoBindingScenario;

const INTERFACE: &str = "any";
const POLICY_ID: &str = "tls-material-e2e-policy";
const POLICY_VERSION: &str = "e2e";
const TRAFFIC_DELAY: Duration = Duration::from_millis(25);
const MATERIAL_REFRESH_INTERVAL_MS: u64 = 10;
const MATERIAL_REFRESH_WAIT_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) fn run() -> ExitCode {
    run_case(AutoBindingScenario::SESSION_SECRET_PRELOADED)
}

pub(crate) fn run_refresh() -> ExitCode {
    run_case(AutoBindingScenario::SESSION_SECRET_REFRESH)
}

pub(crate) fn run_key_log() -> ExitCode {
    run_case(AutoBindingScenario::KEY_LOG_PRELOADED)
}

pub(crate) fn run_key_log_refresh() -> ExitCode {
    run_case(AutoBindingScenario::KEY_LOG_REFRESH)
}

fn run_case(scenario: AutoBindingScenario) -> ExitCode {
    match run_inner(scenario) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "e2e TLS material {} loopback failed: {error}",
                scenario.display_name()
            );
            ExitCode::FAILURE
        }
    }
}

fn run_inner(scenario: AutoBindingScenario) -> Result<(), Box<dyn std::error::Error>> {
    ensure_e2e_packages_built(["agent"])?;
    let temp_root_prefix = scenario.temp_root_prefix();
    let root = create_temp_root(&temp_root_prefix)?;
    match run_at(&root, scenario) {
        Ok(()) => {
            fs::remove_dir_all(&root)?;
            println!(
                "e2e TLS material {} loopback passed",
                scenario.display_name()
            );
            Ok(())
        }
        Err(error) => {
            eprintln!("e2e artifacts retained at {}", root.display());
            Err(error)
        }
    }
}

fn run_at(root: &Path, scenario: AutoBindingScenario) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(root)?;
    let fixture = SyntheticTls13AutoBindingFixture;
    fixture.validate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let listen_port = listener.local_addr()?.port();
    let agent_ready_socket_path = root.join("agent.ready.sock");
    let admin_socket_path = root.join("admin.sock");
    let policy_path = root.join("tls-material-e2e-policy.bundle");
    let config_path = root.join("agent.toml");
    let spool_path = root.join("spool");
    let material_path = root.join(scenario.material_file_name());

    let supervisor = ChildSupervisor::new()?;
    write_policy_bundle(&policy_path, fixture)?;
    scenario.write_initial_material(&material_path, fixture)?;
    write_agent_config(
        &config_path,
        &policy_path,
        &spool_path,
        &admin_socket_path,
        &material_path,
        listen_port,
        scenario,
    )?;

    let mut ready_signal = UnixSocketReadySignal::bind(agent_ready_socket_path)?;
    let mut agent = supervisor.watch(spawn_agent(&config_path, &ready_signal)?, "agent");
    wait_for_agent_ready(agent.child_mut(), &mut ready_signal)?;

    let traffic_result = run_synthetic_tls_traffic(
        listener,
        fixture,
        &material_path,
        scenario,
        agent.child_mut(),
        &admin_socket_path,
    );
    let progress_result = match &traffic_result {
        Ok(()) => wait_for_agent_policy_progress(agent.child_mut(), &admin_socket_path, 1),
        Err(_) => Ok(()),
    };
    let agent_result = stop_running_child(agent.child_mut(), "agent");
    agent.unwatch();
    let spool_result = match (&traffic_result, &agent_result) {
        (Ok(()), Ok(())) => assert_spool_outputs(&spool_path, fixture),
        _ => Ok(()),
    };

    merge_labeled_run_results([
        ("synthetic TLS traffic", traffic_result),
        ("agent policy progress", progress_result),
        ("agent", agent_result),
        ("spool assertion", spool_result),
    ])?;
    Ok(())
}

fn run_synthetic_tls_traffic(
    listener: TcpListener,
    fixture: SyntheticTls13AutoBindingFixture,
    material_path: &Path,
    scenario: AutoBindingScenario,
    agent: &mut Child,
    admin_socket_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let listen_addr = listener.local_addr()?;
    let server = thread::spawn(move || drain_server_connection(listener));
    let mut client = TcpStream::connect(listen_addr)?;
    client.set_nodelay(true)?;
    client.write_all(&fixture.client_hello_record())?;
    let mut server_hello = vec![0; fixture.server_hello_record().len()];
    client.read_exact(&mut server_hello)?;
    if server_hello != fixture.server_hello_record() {
        return Err(e2e_error("synthetic TLS server sent unexpected ServerHello").into());
    }
    prepare_material_before_application_data(
        scenario,
        material_path,
        fixture,
        agent,
        admin_socket_path,
    )?;
    client.write_all(fixture.application_record())?;
    client.shutdown(Shutdown::Write)?;
    let server_result = server
        .join()
        .map_err(|_| e2e_error("synthetic TLS server thread panicked"))?;
    server_result?;
    Ok(())
}

fn prepare_material_before_application_data(
    scenario: AutoBindingScenario,
    material_path: &Path,
    fixture: SyntheticTls13AutoBindingFixture,
    agent: &mut Child,
    admin_socket_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(refresh) = scenario.material_refresh() else {
        thread::sleep(TRAFFIC_DELAY);
        return Ok(());
    };

    // Only ClientHello and ServerHello have crossed the fixture at this point.
    // Final spool assertions verify those exact records after the agent exits.
    wait_for_agent_pipeline_progress(agent, admin_socket_path, 0, 2, 0)?;
    refresh.apply(material_path, fixture)?;
    wait_for_material_refresh_generation(admin_socket_path, 1)?;
    Ok(())
}

fn drain_server_connection(listener: TcpListener) -> Result<(), std::io::Error> {
    let (mut stream, _) = listener.accept()?;
    let fixture = SyntheticTls13AutoBindingFixture;
    let mut client_hello = vec![0; fixture.client_hello_record().len()];
    stream.read_exact(&mut client_hello)?;
    if client_hello != fixture.client_hello_record() {
        return Err(io::Error::other(
            "synthetic TLS client sent unexpected ClientHello",
        ));
    }
    stream.write_all(&fixture.server_hello_record())?;
    let mut remaining = Vec::new();
    stream.read_to_end(&mut remaining)?;
    Ok(())
}

fn write_policy_bundle(
    path: &Path,
    fixture: SyntheticTls13AutoBindingFixture,
) -> Result<(), std::io::Error> {
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
  if target == "{}" then
    return probe.emit_alert("tls session secret policy observed " .. target)
  end
end
"#,
            fixture.target()
        ),
    )
}

fn write_agent_config(
    path: &Path,
    policy_path: &Path,
    spool_path: &Path,
    admin_socket_path: &Path,
    material_path: &Path,
    listen_port: u16,
    scenario: AutoBindingScenario,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = AgentConfig {
        agent_id: "e2e-tls-material-agent".to_string(),
        config_version: scenario.config_version().to_string(),
        ..AgentConfig::default()
    };
    config.capture.selection = CaptureSelection::Libpcap;
    config.capture.libpcap.interface = Some(INTERFACE.to_string());
    config.capture.libpcap.bpf_filter = format!("tcp and port {listen_port}");
    config.capture.libpcap.read_timeout_ms = 100;
    config.storage.path = spool_path.to_path_buf();
    config.export.worker.enabled = false;
    config.admin.enabled = true;
    config.admin.socket_path = admin_socket_path.to_path_buf();
    scenario.configure_material(&mut config, material_path);
    config.tls.plaintext.decrypt_hints.refresh_interval_ms = MATERIAL_REFRESH_INTERVAL_MS;
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

fn wait_for_material_refresh_generation(
    admin_socket_path: &Path,
    expected_generation: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + MATERIAL_REFRESH_WAIT_TIMEOUT;
    loop {
        let response =
            send_admin_request(admin_socket_path, serde_json::json!({"command": "status"}))?;
        let refresh = response
            .pointer("/snapshot/tls/plaintext/decrypt_hints/runtime/session_secret_refresh")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let generation = refresh
            .get("generation")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or_default();
        let mode = refresh
            .get("mode")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("missing");
        if generation >= expected_generation && mode == "active" {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(e2e_error(format!(
                "timed out waiting for TLS decrypt-hint material refresh generation {expected_generation}; last refresh status {refresh}"
            ))
            .into());
        }
        thread::sleep(TRAFFIC_DELAY);
    }
}
