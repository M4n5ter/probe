use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    process::{Child, ExitCode},
    thread,
    time::{Duration, Instant},
};

use capture::CaptureEvent;
use exporter::CompressionCodec;
use probe_config::{
    AgentConfig, CaptureSelection, CompressionCodecName, ExportFailureBackoffConfig,
    ExportWorkerScheduleConfig, ExporterConfig, ExporterTransportConfig,
};
use probe_core::{EventEnvelope, ProcessSelector, Selector, TrafficSelector};

use super::{
    agent_admin::{send_admin_request, wait_for_agent_pipeline_progress},
    harness::{
        ChildSupervisor, UnixSocketReadySignal, e2e_error, ensure_e2e_packages_built,
        run_with_temp_root, stop_running_child,
    },
    loopback::{spawn_agent, wait_for_agent_ready},
    plaintext_export_batches::{
        assert_batch_sequence_contract, assert_expected_export_set,
        assert_file_export_batch_records, decode_and_assert_event_records,
    },
    plaintext_scenario::{
        PLAINTEXT_FEED_EVENT_COUNT, PLAINTEXT_FEED_EXPORT_EVENT_COUNT, PlaintextFeedScenario,
        PlaintextFlow, PlaintextHttpRequest, PlaintextPolicy, PlaintextProcess,
        PlaintextScenarioIds,
    },
};

const AGENT_ID: &str = "local-validation-agent";
const CONFIG_VERSION: &str = "local-validation";
const POLICY_ID: &str = "local-validation-policy";
const POLICY_VERSION: &str = "local";
const RELOADED_POLICY_VERSION: &str = "reloaded";
const CONNECTION_ID: &str = "local-validation-conn";
const RELOADED_CONNECTION_ID: &str = "local-validation-reloaded-conn";
const REQUEST_TARGET: &str = "/local-validation";
const RELOADED_REQUEST_TARGET: &str = "/local-validation-reloaded";
const FILE_SINK: &str = "local-validation-file";
const FILE_CODEC: CompressionCodec = CompressionCodec::None;
const EXPORT_WAIT_TIMEOUT: Duration = Duration::from_secs(15);
const EXPORT_WAIT_INTERVAL: Duration = Duration::from_millis(100);
const CURSOR_WAIT_TIMEOUT: Duration = Duration::from_secs(15);
const CURSOR_WAIT_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileExportObservation {
    cursor: u64,
    events: usize,
}

#[derive(Clone, Copy)]
struct ReloadValidation<'a> {
    process_exe_path: &'a str,
    rounds: [&'a PlaintextFeedScenario; 2],
}

impl<'a> ReloadValidation<'a> {
    fn new(
        initial: &'a PlaintextFeedScenario,
        reloaded: &'a PlaintextFeedScenario,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let process_exe_path = initial.process_exe_path();
        if reloaded.process_exe_path() != process_exe_path {
            return Err(e2e_error(format!(
                "local validation reload rounds must share one process selector, got {process_exe_path} and {}",
                reloaded.process_exe_path()
            ))
            .into());
        }
        Ok(Self {
            process_exe_path,
            rounds: [initial, reloaded],
        })
    }

    fn round_count(self) -> usize {
        self.rounds.len()
    }

    fn expected_ingress_event_count(self) -> usize {
        PLAINTEXT_FEED_EVENT_COUNT * self.round_count()
    }

    fn expected_export_event_count(self) -> usize {
        PLAINTEXT_FEED_EXPORT_EVENT_COUNT * self.round_count()
    }
}

pub(crate) fn run() -> ExitCode {
    match run_inner() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("local validation failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_inner() -> Result<(), Box<dyn std::error::Error>> {
    ensure_e2e_packages_built(["agent"])?;
    run_with_temp_root("local-validation", run_at)?;
    println!(
        "local validation passed: capture_event_feed -> HTTP parser -> Lua policy -> durable export -> admin tail -> file exporter; admin apply_config_reload switched policy between traffic rounds"
    );
    Ok(())
}

fn run_at(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(root)?;
    let feed_path = root.join("capture-events.jsonl");
    let policy_path = root.join("local-validation-policy.bundle");
    let reloaded_policy_path = root.join("local-validation-policy-reloaded.bundle");
    let config_path = root.join("agent.toml");
    let candidate_config_path = root.join("agent-reloaded.toml");
    let spool_path = root.join("spool");
    let admin_socket_path = root.join("admin.sock");
    let agent_ready_socket_path = root.join("agent.ready.sock");
    let export_path = root.join("export.jsonl");

    let scenario = initial_scenario();
    let reloaded = reloaded_scenario();
    let validation = ReloadValidation::new(&scenario, &reloaded)?;
    fs::File::create(&feed_path)?;
    scenario.write_policy_bundle(&policy_path)?;
    reloaded.write_policy_bundle(&reloaded_policy_path)?;
    write_agent_config(
        &scenario,
        &config_path,
        &feed_path,
        &policy_path,
        &spool_path,
        &admin_socket_path,
        &export_path,
    )?;
    write_agent_config(
        &reloaded,
        &candidate_config_path,
        &feed_path,
        &reloaded_policy_path,
        &spool_path,
        &admin_socket_path,
        &export_path,
    )?;

    let supervisor = ChildSupervisor::new()?;
    let mut ready_signal = UnixSocketReadySignal::bind(agent_ready_socket_path)?;
    let mut agent = supervisor.watch(spawn_agent(&config_path, &ready_signal)?, "agent");
    wait_for_agent_ready(agent.child_mut(), &mut ready_signal)?;
    append_capture_events(&feed_path, &scenario.capture_events())?;
    wait_for_agent_pipeline_progress(
        agent.child_mut(),
        &admin_socket_path,
        1,
        u64::try_from(PLAINTEXT_FEED_EVENT_COUNT)?,
        u64::try_from(PLAINTEXT_FEED_EXPORT_EVENT_COUNT)?,
    )?;
    assert_config_reload_plan_and_apply(&admin_socket_path, &candidate_config_path, &reloaded)?;
    append_capture_events(&feed_path, &reloaded.capture_events())?;
    wait_for_agent_pipeline_progress(
        agent.child_mut(),
        &admin_socket_path,
        u64::try_from(validation.round_count())?,
        u64::try_from(validation.expected_ingress_event_count())?,
        u64::try_from(validation.expected_export_event_count())?,
    )?;
    let exported = wait_for_file_export(agent.child_mut(), &export_path, &validation)?;
    wait_for_export_cursor(
        agent.child_mut(),
        &admin_socket_path,
        FILE_SINK,
        exported.cursor,
    )?;
    let tailed = assert_admin_tail(&admin_socket_path, &validation)?;
    assert_admin_tail_selector_miss(&admin_socket_path, validation.expected_export_event_count())?;
    stop_running_child(agent.child_mut(), "agent")?;
    agent.unwatch();

    println!(
        "local validation observed {tailed} tailed event(s), {} exported event(s), and cursor {}",
        exported.events, exported.cursor
    );
    Ok(())
}

fn initial_scenario() -> PlaintextFeedScenario {
    PlaintextFeedScenario::new(
        PlaintextScenarioIds::new(
            AGENT_ID,
            CONFIG_VERSION,
            POLICY_ID,
            POLICY_VERSION,
            CONNECTION_ID,
        ),
        PlaintextHttpRequest::get(REQUEST_TARGET, "local.validation.test"),
        PlaintextPolicy::alerting("local validation observed "),
    )
    .with_flow(PlaintextFlow::new(
        52_100,
        8_080,
        4_242,
        PlaintextProcess::new(
            4_242,
            7_777,
            "traffic-probe-local-validation",
            "/usr/bin/traffic-probe-local-validation",
            "local-validation-hash",
        ),
    ))
}

fn reloaded_scenario() -> PlaintextFeedScenario {
    PlaintextFeedScenario::new(
        PlaintextScenarioIds::new(
            AGENT_ID,
            CONFIG_VERSION,
            POLICY_ID,
            RELOADED_POLICY_VERSION,
            RELOADED_CONNECTION_ID,
        ),
        PlaintextHttpRequest::get(RELOADED_REQUEST_TARGET, "local.validation.test"),
        PlaintextPolicy::alerting("reloaded local validation observed "),
    )
    .with_flow(PlaintextFlow::new(
        52_101,
        8_081,
        4_243,
        PlaintextProcess::new(
            4_242,
            7_777,
            "traffic-probe-local-validation",
            "/usr/bin/traffic-probe-local-validation",
            "local-validation-hash",
        ),
    ))
}

fn write_agent_config(
    scenario: &PlaintextFeedScenario,
    path: &Path,
    feed_path: &Path,
    policy_path: &Path,
    spool_path: &Path,
    admin_socket_path: &Path,
    export_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = agent_config(
        scenario,
        feed_path,
        policy_path,
        spool_path,
        admin_socket_path,
        export_path,
    );
    fs::write(path, toml::to_string(&config)?)?;
    Ok(())
}

fn agent_config(
    scenario: &PlaintextFeedScenario,
    feed_path: &Path,
    policy_path: &Path,
    spool_path: &Path,
    admin_socket_path: &Path,
    export_path: &Path,
) -> AgentConfig {
    let mut config = scenario.agent_config(
        feed_path.to_path_buf(),
        policy_path.to_path_buf(),
        spool_path.to_path_buf(),
    );
    config.capture.selection = CaptureSelection::CaptureEventFeed;
    config.capture.plaintext_feed.path = None;
    config.capture.capture_event_feed.path = Some(feed_path.to_path_buf());
    config.capture.capture_event_feed.follow = Some(true);
    config.admin.enabled = true;
    config.admin.socket_path = admin_socket_path.to_path_buf();
    config.export.worker.enabled = true;
    config.export.worker.schedule = ExportWorkerScheduleConfig::FixedIntervalBounded {
        interval_ms: 100,
        batches_per_sink_per_tick: 4,
        sink_timeout_ms: 5_000,
        failure_backoff: ExportFailureBackoffConfig {
            initial_ms: 100,
            max_ms: 1_000,
            multiplier: 2,
        },
    };
    config.exporters.push(ExporterConfig {
        id: FILE_SINK.to_string(),
        transport: ExporterTransportConfig::File {
            path: export_path.to_path_buf(),
        },
        codec: CompressionCodecName::None,
        worker: Default::default(),
    });
    config
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

fn assert_config_reload_plan_and_apply(
    admin_socket_path: &Path,
    candidate_config_path: &Path,
    reloaded: &PlaintextFeedScenario,
) -> Result<(), Box<dyn std::error::Error>> {
    let plan = send_admin_request(
        admin_socket_path,
        serde_json::json!({
            "command": "plan_config_reload",
            "path": candidate_config_path,
        }),
    )?;
    if plan["kind"] != serde_json::json!("config_reload_plan")
        || plan["plan"]["decision"]["kind"] != serde_json::json!("apply_online")
        || !changed_sections_include_apply_online_policy(&plan["plan"]["changed_sections"])
    {
        return Err(e2e_error(format!(
            "admin config reload plan did not describe an online policy reload: {plan}"
        ))
        .into());
    }

    let apply = send_admin_request(
        admin_socket_path,
        serde_json::json!({
            "command": "apply_config_reload",
            "path": candidate_config_path,
        }),
    )?;
    if apply["kind"] != serde_json::json!("config_reload_apply")
        || apply["apply"]["plan"]["decision"]["kind"] != serde_json::json!("apply_online")
        || apply["apply"]["active_plan_updated"] != serde_json::json!(true)
        || !reload_policies_action_succeeded(&apply["apply"]["actions"])
    {
        return Err(e2e_error(format!(
            "admin config reload apply did not reload policies online: {apply}"
        ))
        .into());
    }

    let status = send_admin_request(
        admin_socket_path,
        serde_json::json!({
            "command": "status",
        }),
    )?;
    if status["kind"] != serde_json::json!("status")
        || !status_policy_version_is_active(&status, &reloaded.expected_policy_version())
    {
        return Err(e2e_error(format!(
            "admin status did not expose reloaded policy version {}: {status}",
            reloaded.expected_policy_version()
        ))
        .into());
    }
    Ok(())
}

fn changed_sections_include_apply_online_policy(changed_sections: &serde_json::Value) -> bool {
    changed_sections.as_array().is_some_and(|changes| {
        changes.iter().any(|change| {
            change["section"] == serde_json::json!("policies")
                && change["reload_mode"] == serde_json::json!("apply_online")
        })
    })
}

fn reload_policies_action_succeeded(actions: &serde_json::Value) -> bool {
    actions.as_array().is_some_and(|actions| {
        actions.iter().any(|action| {
            action["action"] == serde_json::json!("reload_policies")
                && action["outcome"]["result"] == serde_json::json!("succeeded")
        })
    })
}

fn status_policy_version_is_active(status: &serde_json::Value, expected: &str) -> bool {
    status["snapshot"]["policy"]["active"]
        .as_array()
        .is_some_and(|policies| {
            policies
                .iter()
                .any(|policy| policy["runtime"]["policy_version"].as_str() == Some(expected))
        })
}

fn assert_admin_tail(
    admin_socket_path: &Path,
    validation: &ReloadValidation<'_>,
) -> Result<usize, Box<dyn std::error::Error>> {
    let selector = Selector::term(
        ProcessSelector {
            exe_path_globs: vec![validation.process_exe_path.to_string()],
            ..ProcessSelector::default()
        },
        TrafficSelector::default(),
    );
    let response = send_admin_request(admin_socket_path, tail_events_request(selector))?;
    if response["kind"] != serde_json::json!("event_tail") {
        return Err(e2e_error(format!(
            "admin tail returned unexpected response: {response}"
        ))
        .into());
    }
    let tail = &response["tail"];
    let records = tail["events"].as_array().ok_or_else(|| {
        e2e_error(format!(
            "admin tail omitted event array in response: {response}"
        ))
    })?;
    assert_expected_compact_tail_sets(records, validation)?;
    let next_after_sequence = tail["next_after_sequence"].as_u64().ok_or_else(|| {
        e2e_error(format!(
            "admin tail omitted next_after_sequence in response: {response}"
        ))
    })?;
    let expected_export_events = validation.expected_export_event_count();
    if next_after_sequence < u64::try_from(expected_export_events)? {
        return Err(e2e_error(format!(
            "admin tail advanced only to sequence {next_after_sequence}, expected at least {expected_export_events}"
        ))
        .into());
    }
    Ok(records.len())
}

fn assert_expected_compact_tail_sets(
    records: &[serde_json::Value],
    validation: &ReloadValidation<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let expected = validation.expected_export_event_count();
    if records.len() != expected {
        return Err(e2e_error(format!(
            "local validation admin tail expected {expected} compact events, got {}",
            records.len()
        ))
        .into());
    }
    for scenario in validation.rounds {
        let expected_flow_id = scenario.expected_flow_id();
        let matching = records
            .iter()
            .filter(|record| {
                compact_tail_event_flow_id(&record["event"]) == Some(expected_flow_id.as_str())
            })
            .collect::<Vec<_>>();
        assert_expected_compact_tail_set(&matching, scenario)?;
    }
    Ok(())
}

fn assert_expected_compact_tail_set(
    records: &[&serde_json::Value],
    scenario: &PlaintextFeedScenario,
) -> Result<(), Box<dyn std::error::Error>> {
    if records.len() != PLAINTEXT_FEED_EXPORT_EVENT_COUNT {
        return Err(e2e_error(format!(
            "local validation admin tail expected {PLAINTEXT_FEED_EXPORT_EVENT_COUNT} compact events, got {}",
            records.len()
        ))
        .into());
    }
    let mut request_count = 0;
    let mut policy_alert_count = 0;
    let mut opened_count = 0;
    let mut closed_count = 0;
    let expected_policy_version = scenario.expected_policy_version();
    let expected_alert_message = scenario.expected_policy_alert_message();
    for record in records {
        let event = &record["event"];
        assert_compact_tail_event_scope(event, scenario)?;
        let kind = event.get("kind").ok_or_else(|| {
            e2e_error(format!(
                "local validation admin tail event omitted kind: {record}"
            ))
        })?;
        match kind["type"].as_str() {
            Some("http_request_headers")
                if kind["method"].as_str() == Some("GET")
                    && kind["target"].as_str() == Some(scenario.request_target()) =>
            {
                request_count += 1;
            }
            Some("policy_alert")
                if event["policy_version"].as_str() == Some(expected_policy_version.as_str())
                    && kind["message"].as_str() == Some(expected_alert_message.as_str()) =>
            {
                policy_alert_count += 1;
            }
            Some("connection_opened") => opened_count += 1,
            Some("connection_closed") => closed_count += 1,
            _ => {}
        }
    }
    if (
        request_count,
        policy_alert_count,
        opened_count,
        closed_count,
    ) != (1, 1, 1, 1)
    {
        return Err(e2e_error(format!(
            "local validation admin tail unexpected compact event set: request={request_count}, policy_alert={policy_alert_count}, opened={opened_count}, closed={closed_count}"
        ))
        .into());
    }
    Ok(())
}

fn assert_compact_tail_event_scope(
    event: &serde_json::Value,
    scenario: &PlaintextFeedScenario,
) -> Result<(), Box<dyn std::error::Error>> {
    let expected_flow_id = scenario.expected_flow_id();
    if event.get("subject").is_some() {
        return Err(e2e_error(format!(
            "local validation admin tail returned legacy subject field: {event}"
        ))
        .into());
    }
    if event["origin"]["source"].as_str() != Some("external_plaintext_feed")
        || event["origin"]["provider"].as_str() != Some("plaintext")
    {
        return Err(e2e_error(format!(
            "local validation admin tail carried an unexpected source or provider: {event}"
        ))
        .into());
    }
    let flow = event.get("flow").ok_or_else(|| {
        e2e_error(format!(
            "local validation admin tail omitted compact flow projection: {event}"
        ))
    })?;
    if flow["id"].as_str() != Some(expected_flow_id.as_str())
        || flow["process"]["identity"]["exe_path"].as_str() != Some(scenario.process_exe_path())
    {
        return Err(e2e_error(format!(
            "local validation admin tail carried an unexpected compact flow projection: {event}"
        ))
        .into());
    }
    Ok(())
}

fn compact_tail_event_flow_id(event: &serde_json::Value) -> Option<&str> {
    event["flow"]["id"].as_str()
}

fn assert_admin_tail_selector_miss(
    admin_socket_path: &Path,
    expected_export_events: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let selector = Selector::term(
        ProcessSelector {
            exe_path_globs: vec!["/usr/bin/traffic-probe-local-validation-miss".to_string()],
            ..ProcessSelector::default()
        },
        TrafficSelector::default(),
    );
    let response = send_admin_request(admin_socket_path, tail_events_request(selector))?;
    if response["kind"] != serde_json::json!("event_tail") {
        return Err(e2e_error(format!(
            "admin tail selector miss returned unexpected response: {response}"
        ))
        .into());
    }
    let tail = &response["tail"];
    let records = tail["events"].as_array().ok_or_else(|| {
        e2e_error(format!(
            "admin tail selector miss omitted event array in response: {response}"
        ))
    })?;
    if !records.is_empty() {
        return Err(e2e_error(format!(
            "admin tail selector miss returned {} event(s): {response}",
            records.len()
        ))
        .into());
    }
    let next_after_sequence = tail["next_after_sequence"].as_u64().ok_or_else(|| {
        e2e_error(format!(
            "admin tail selector miss omitted next_after_sequence in response: {response}"
        ))
    })?;
    if next_after_sequence < u64::try_from(expected_export_events)? {
        return Err(e2e_error(format!(
            "admin tail selector miss scanned only to sequence {next_after_sequence}, expected at least {expected_export_events}"
        ))
        .into());
    }
    Ok(())
}

fn tail_events_request(selector: Selector) -> serde_json::Value {
    serde_json::json!({
        "command": "tail_events",
        "after_sequence": 0,
        "latest": false,
        "limit": 16,
        "selector": selector,
        "event_types": [],
    })
}

fn wait_for_file_export(
    agent: &mut Child,
    path: &Path,
    validation: &ReloadValidation<'_>,
) -> Result<FileExportObservation, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + EXPORT_WAIT_TIMEOUT;
    let mut last_error = None::<String>;
    loop {
        if let Some(status) = agent.try_wait()? {
            return Err(e2e_error(format!(
                "agent exited with {status} before file export was complete; last check: {}",
                last_error.as_deref().unwrap_or("no file export check ran")
            ))
            .into());
        }
        if Instant::now() >= deadline {
            return Err(e2e_error(format!(
                "timed out waiting for file export {}; last check: {}",
                path.display(),
                last_error.as_deref().unwrap_or("no file export check ran")
            ))
            .into());
        }
        match assert_file_export(path, validation) {
            Ok(exported) => return Ok(exported),
            Err(error) => last_error = Some(error.to_string()),
        }
        thread::sleep(EXPORT_WAIT_INTERVAL);
    }
}

fn assert_file_export(
    path: &Path,
    validation: &ReloadValidation<'_>,
) -> Result<FileExportObservation, Box<dyn std::error::Error>> {
    let (_records, batches) = assert_file_export_batch_records(
        path,
        AGENT_ID,
        FILE_SINK,
        FILE_CODEC,
        "local validation file exporter",
    )?;
    let cursor = assert_batch_sequence_contract(
        &batches,
        AGENT_ID,
        FILE_SINK,
        validation.expected_export_event_count(),
        "local validation file exporter",
    )?;
    let envelopes = decode_and_assert_event_records(&batches, "local validation file exporter")?;
    assert_expected_export_sets(&envelopes, validation, "local validation file exporter")?;
    Ok(FileExportObservation {
        cursor,
        events: envelopes.len(),
    })
}

fn assert_expected_export_sets(
    envelopes: &[EventEnvelope],
    validation: &ReloadValidation<'_>,
    label: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let expected = validation.expected_export_event_count();
    if envelopes.len() != expected {
        return Err(e2e_error(format!(
            "{label} expected {expected} exported events, got {}",
            envelopes.len()
        ))
        .into());
    }
    for scenario in validation.rounds {
        let matching = envelopes
            .iter()
            .filter(|envelope| scenario.feed_case().matches_export_flow(envelope))
            .cloned()
            .collect::<Vec<_>>();
        let scenario_label = format!("{label} {}", scenario.request_target());
        assert_expected_export_set(&matching, scenario, &scenario_label)?;
    }
    Ok(())
}

fn wait_for_export_cursor(
    agent: &mut Child,
    admin_socket_path: &Path,
    sink_id: &str,
    expected_cursor: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + CURSOR_WAIT_TIMEOUT;
    let mut last_cursor = None;
    loop {
        match read_export_cursor(admin_socket_path, sink_id) {
            Ok(cursor) if cursor >= expected_cursor => return Ok(()),
            Ok(cursor) => last_cursor = Some(cursor),
            Err(error) => {
                if let Some(status) = agent.try_wait()? {
                    return Err(e2e_error(format!(
                        "agent exited with {status} before export cursor {sink_id}>={expected_cursor}: {error}"
                    ))
                    .into());
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(e2e_error(format!(
                "timed out waiting for export cursor {sink_id}>={expected_cursor}; last cursor: {}",
                last_cursor
                    .map(|cursor| cursor.to_string())
                    .unwrap_or_else(|| "unavailable".to_string())
            ))
            .into());
        }
        thread::sleep(CURSOR_WAIT_INTERVAL);
    }
}

fn read_export_cursor(
    admin_socket_path: &Path,
    sink_id: &str,
) -> Result<u64, Box<dyn std::error::Error>> {
    let response = send_admin_request(
        admin_socket_path,
        serde_json::json!({
            "command": "status",
        }),
    )?;
    if response["kind"] != serde_json::json!("status") {
        return Err(e2e_error(format!(
            "admin status returned unexpected response: {response}"
        ))
        .into());
    }
    let exporters = response["snapshot"]["exporters"]
        .as_array()
        .ok_or_else(|| {
            e2e_error(format!(
                "admin status omitted exporters array in response: {response}"
            ))
        })?;
    let exporter = exporters
        .iter()
        .find(|exporter| exporter["id"].as_str() == Some(sink_id))
        .ok_or_else(|| {
            e2e_error(format!(
                "admin status omitted exporter {sink_id} in response: {response}"
            ))
        })?;
    exporter["cursor"].as_u64().ok_or_else(|| {
        e2e_error(format!(
            "admin status omitted cursor for exporter {sink_id}: {response}"
        ))
        .into()
    })
}
