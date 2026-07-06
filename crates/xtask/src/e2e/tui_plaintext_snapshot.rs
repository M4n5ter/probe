use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    process::{Command, ExitCode},
};

use capture::CaptureEvent;
use probe_config::{
    AgentConfig, CaptureSelection, ObservationDataPathMode, ProcessObservationConfig,
};
use probe_core::{Direction, ProcessSelector, Selector, TrafficSelector};

use super::{
    agent_admin::wait_for_agent_pipeline_progress,
    harness::{
        ChildSupervisor, UnixSocketReadySignal, debug_binary, e2e_error, ensure_e2e_packages_built,
        run_with_temp_root, stop_running_child, workspace_root,
    },
    loopback::{spawn_agent, wait_for_agent_ready},
    plaintext_scenario::{PlaintextFeedCase, PlaintextFeedRecord, PlaintextFlow, PlaintextProcess},
};

const AGENT_ID: &str = "tui-snapshot-agent";
const CONFIG_VERSION: &str = "tui-plaintext-snapshot";
const CONNECTION_ID: &str = "tui-snapshot-conn";
const POLICY_ID: &str = "tui-snapshot-policy";
const POLICY_VERSION: &str = "tui";
const REQUEST_TARGET: &str = "/tui-snapshot";
const REQUEST_BODY: &[u8] = b"request-body";
const RESPONSE_BODY: &[u8] = b"response-body";
const CAPTURE_EVENT_COUNT: u64 = 4;
const EXPORT_EVENT_FLOOR: u64 = 7;
const SNAPSHOT_WIDTH: u16 = 220;
const SNAPSHOT_HEIGHT: u16 = 100;
const RESPONSE_DETAIL_SCROLL_LINES: usize = 24;

pub(crate) fn run() -> ExitCode {
    match run_inner() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("e2e TUI plaintext snapshot failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_inner() -> Result<(), Box<dyn std::error::Error>> {
    ensure_e2e_packages_built(["agent"])?;
    run_with_temp_root("tui-plaintext-snapshot", run_at)?;
    println!(
        "e2e TUI plaintext snapshot passed: capture_event_feed -> HTTP parser -> admin tail -> TUI traffic table/detail"
    );
    Ok(())
}

fn run_at(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(root)?;
    let feed_path = root.join("capture-events.jsonl");
    let policy_path = root.join("tui-snapshot-policy.bundle");
    let config_path = root.join("agent.toml");
    let tui_config_path = root.join("tui.toml");
    let spool_path = root.join("spool");
    let admin_socket_path = root.join("admin.sock");
    let agent_ready_socket_path = root.join("agent.ready.sock");
    let probe_home = root.join("probe-home");

    fs::File::create(&feed_path)?;
    write_policy_bundle(&policy_path)?;
    let observed_binary = std::env::current_exe()?;
    let scenario = scenario(&observed_binary, std::process::id());
    write_runtime_config(
        &scenario,
        &config_path,
        &feed_path,
        &policy_path,
        &spool_path,
        &admin_socket_path,
    )?;
    write_tui_config(
        &scenario,
        &tui_config_path,
        &feed_path,
        &policy_path,
        &spool_path,
        &admin_socket_path,
        &observed_binary,
    )?;

    let supervisor = ChildSupervisor::new()?;
    let mut ready_signal = UnixSocketReadySignal::bind(agent_ready_socket_path)?;
    let mut agent = supervisor.watch(spawn_agent(&config_path, &ready_signal)?, "agent");
    wait_for_agent_ready(agent.child_mut(), &mut ready_signal)?;
    append_capture_events(&feed_path, &scenario.capture_events(feed_records()?))?;
    wait_for_agent_pipeline_progress(
        agent.child_mut(),
        &admin_socket_path,
        1,
        CAPTURE_EVENT_COUNT,
        EXPORT_EVENT_FLOOR,
    )?;

    let table_snapshot = render_tui_snapshot(&tui_config_path, &probe_home, false, 0)?;
    assert_snapshot_contains(&table_snapshot, "HTTP Exchanges")?;
    assert_snapshot_contains(&table_snapshot, "POST")?;
    assert_snapshot_contains(&table_snapshot, REQUEST_TARGET)?;
    assert_snapshot_contains(&table_snapshot, "200")?;
    assert_snapshot_contains(&table_snapshot, "Req Body")?;
    assert_snapshot_contains(&table_snapshot, "Resp Body")?;
    assert_snapshot_contains(&table_snapshot, "resp 13 B")?;

    let detail_snapshot = render_tui_snapshot(&tui_config_path, &probe_home, true, 0)?;
    assert_snapshot_contains(&detail_snapshot, "HTTP Exchange Detail")?;
    assert_snapshot_contains(&detail_snapshot, "Request body")?;
    assert_snapshot_contains(&detail_snapshot, "Body payload: request-body")?;

    let response_detail_snapshot = render_tui_snapshot(
        &tui_config_path,
        &probe_home,
        true,
        RESPONSE_DETAIL_SCROLL_LINES,
    )?;
    assert_snapshot_contains(&response_detail_snapshot, "Response body")?;
    assert_snapshot_contains(&response_detail_snapshot, "Body payload: response-body")?;

    stop_running_child(agent.child_mut(), "agent")?;
    agent.unwatch();
    Ok(())
}

fn scenario(observed_binary: &Path, pid: u32) -> PlaintextFeedCase {
    PlaintextFeedCase::new(
        AGENT_ID,
        CONFIG_VERSION,
        CONNECTION_ID,
        PlaintextFlow::new(
            52_300,
            8_080,
            12_345,
            PlaintextProcess::new(
                pid,
                99_001,
                "xtask",
                observed_binary.display().to_string(),
                "tui-snapshot-hash",
            ),
        ),
    )
}

fn write_runtime_config(
    scenario: &PlaintextFeedCase,
    path: &Path,
    feed_path: &Path,
    policy_path: &Path,
    spool_path: &Path,
    admin_socket_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = runtime_config(
        scenario,
        feed_path,
        policy_path,
        spool_path,
        admin_socket_path,
    );
    fs::write(path, toml::to_string(&config)?)?;
    Ok(())
}

fn write_tui_config(
    scenario: &PlaintextFeedCase,
    path: &Path,
    feed_path: &Path,
    policy_path: &Path,
    spool_path: &Path,
    admin_socket_path: &Path,
    observed_exe_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = runtime_config(
        scenario,
        feed_path,
        policy_path,
        spool_path,
        admin_socket_path,
    );
    // Runtime observation profiles project into live capture planning. This snapshot config is
    // only used to drive the TUI process filter; the running agent stays on capture_event_feed.
    config
        .observations
        .push(process_observation(observed_exe_path));
    fs::write(path, toml::to_string(&config)?)?;
    Ok(())
}

fn runtime_config(
    scenario: &PlaintextFeedCase,
    feed_path: &Path,
    policy_path: &Path,
    spool_path: &Path,
    admin_socket_path: &Path,
) -> AgentConfig {
    let mut config = scenario.agent_config_with_policy(
        feed_path.to_path_buf(),
        policy_path.to_path_buf(),
        spool_path.to_path_buf(),
        POLICY_ID,
    );
    config.capture.selection = CaptureSelection::CaptureEventFeed;
    config.capture.plaintext_feed.path = None;
    config.capture.capture_event_feed.path = Some(feed_path.to_path_buf());
    config.capture.capture_event_feed.follow = Some(true);
    config.admin.enabled = true;
    config.admin.socket_path = admin_socket_path.to_path_buf();
    config.export.worker.enabled = false;
    config
}

fn process_observation(exe_path: &Path) -> ProcessObservationConfig {
    let exe_path = exe_path.display().to_string();
    ProcessObservationConfig {
        id: format!("exe:{exe_path}"),
        selector: Selector::term(
            ProcessSelector {
                exe_path_globs: vec![exe_path],
                ..ProcessSelector::default()
            },
            TrafficSelector::default(),
        ),
        data_path: ObservationDataPathMode::Auto,
        directions: vec![Direction::Inbound, Direction::Outbound],
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
        r#"
function on_http_request_headers(event)
  return probe.emit_alert("tui snapshot observed " .. event.kind.target)
end
"#,
    )
}

fn feed_records() -> Result<Vec<PlaintextFeedRecord>, Box<dyn std::error::Error>> {
    Ok(vec![
        PlaintextFeedRecord::connection_opened(),
        PlaintextFeedRecord::bytes(Direction::Outbound, 0, request_bytes()),
        PlaintextFeedRecord::bytes(Direction::Inbound, 0, response_bytes()),
        PlaintextFeedRecord::connection_closed(),
    ])
}

fn request_bytes() -> Vec<u8> {
    let mut bytes = format!(
        "POST {REQUEST_TARGET} HTTP/1.1\r\nHost: tui.snapshot.test\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
        REQUEST_BODY.len()
    )
    .into_bytes();
    bytes.extend_from_slice(REQUEST_BODY);
    bytes
}

fn response_bytes() -> Vec<u8> {
    let mut bytes = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
        RESPONSE_BODY.len()
    )
    .into_bytes();
    bytes.extend_from_slice(RESPONSE_BODY);
    bytes
}

fn append_capture_events(
    path: &Path,
    events: &[CaptureEvent],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new().append(true).open(path)?;
    for event in events {
        serde_json::to_writer(&mut file, event)?;
        file.write_all(b"\n")?;
    }
    file.flush()?;
    file.sync_data()?;
    Ok(())
}

fn render_tui_snapshot(
    config_path: &Path,
    probe_home: &Path,
    open_detail: bool,
    detail_scroll: usize,
) -> Result<String, Box<dyn std::error::Error>> {
    let agent = debug_binary("agent")?;
    let width = SNAPSHOT_WIDTH.to_string();
    let height = SNAPSHOT_HEIGHT.to_string();
    let mut command = Command::new(&agent);
    command
        .current_dir(workspace_root()?)
        .env("PROBE_HOME", probe_home)
        .args([
            "tui",
            "--snapshot",
            "--width",
            &width,
            "--height",
            &height,
            "--tab",
            "traffic",
        ]);
    if open_detail {
        command.arg("--open-detail");
    }
    if detail_scroll > 0 {
        command
            .arg("--detail-scroll")
            .arg(detail_scroll.to_string());
    }
    let output = command
        .arg("--config")
        .arg(config_path)
        .output()
        .map_err(|source| {
            e2e_error(format!(
                "failed to run TUI snapshot via {}: {source}",
                agent.display()
            ))
        })?;
    if output.status.success() {
        return Ok(String::from_utf8(output.stdout)?);
    }

    Err(e2e_error(format!(
        "TUI snapshot exited with {}; stdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
    .into())
}

fn assert_snapshot_contains(snapshot: &str, expected: &str) -> Result<(), std::io::Error> {
    if snapshot.contains(expected) {
        return Ok(());
    }
    Err(e2e_error(format!(
        "TUI snapshot omitted {expected:?}; rendered snapshot:\n{snapshot}"
    )))
}
