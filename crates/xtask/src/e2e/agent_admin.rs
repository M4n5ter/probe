use std::{
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    path::Path,
    process::Child,
    thread,
    time::{Duration, Instant},
};

use probe_core::{EventEnvelope, EventKind};

use super::harness::e2e_error;

const AGENT_PROGRESS_TIMEOUT: Duration = Duration::from_secs(15);
const AGENT_PROGRESS_INTERVAL: Duration = Duration::from_millis(100);
const AGENT_PROGRESS_STABLE_POLLS: u8 = 3;

pub(crate) fn wait_for_agent_policy_progress(
    agent: &mut Child,
    admin_socket_path: &Path,
    expected_alert_floor: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    wait_for_agent_progress(
        agent,
        admin_socket_path,
        AgentProgressExpectation {
            policy_alert_floor: expected_alert_floor,
            capture_event_floor: 0,
            export_event_floor: 0,
        },
    )
}

pub(crate) fn wait_for_agent_policy_alert_count_at_least(
    agent: &mut Child,
    admin_socket_path: &Path,
    expected: u64,
) -> Result<u64, Box<dyn std::error::Error>> {
    wait_for_agent_counter_until(
        agent,
        admin_socket_path,
        AgentProgressCounter::PolicyAlerts,
        format!("policy_alerts>={expected}"),
        |value| value >= expected,
    )
}

pub(crate) fn wait_for_agent_policy_alert_count_above(
    agent: &mut Child,
    admin_socket_path: &Path,
    previous: u64,
) -> Result<u64, Box<dyn std::error::Error>> {
    wait_for_agent_counter_until(
        agent,
        admin_socket_path,
        AgentProgressCounter::PolicyAlerts,
        format!("policy_alerts>{previous}"),
        |value| value > previous,
    )
}

pub(crate) fn wait_for_agent_enforcement_decision_count_at_least(
    agent: &mut Child,
    admin_socket_path: &Path,
    expected: u64,
) -> Result<u64, Box<dyn std::error::Error>> {
    wait_for_agent_counter_until(
        agent,
        admin_socket_path,
        AgentProgressCounter::EnforcementDecisions,
        format!("enforcement_decisions>={expected}"),
        |value| value >= expected,
    )
}

pub(crate) fn wait_for_agent_enforcement_decision_count_above(
    agent: &mut Child,
    admin_socket_path: &Path,
    previous: u64,
) -> Result<u64, Box<dyn std::error::Error>> {
    wait_for_agent_counter_until(
        agent,
        admin_socket_path,
        AgentProgressCounter::EnforcementDecisions,
        format!("enforcement_decisions>{previous}"),
        |value| value > previous,
    )
}

pub(crate) fn wait_for_agent_linux_socket_destroy_execution_count_at_least(
    agent: &mut Child,
    admin_socket_path: &Path,
    expected: u64,
) -> Result<u64, Box<dyn std::error::Error>> {
    wait_for_agent_counter_until(
        agent,
        admin_socket_path,
        AgentProgressCounter::LinuxSocketDestroyExecutions,
        format!("linux_socket_destroy_executions>={expected}"),
        |value| value >= expected,
    )
}

pub(crate) fn wait_for_agent_l7_mitm_proxy_hook_execution_count_at_least(
    agent: &mut Child,
    admin_socket_path: &Path,
    expected: u64,
) -> Result<u64, Box<dyn std::error::Error>> {
    wait_for_agent_counter_until(
        agent,
        admin_socket_path,
        AgentProgressCounter::L7MitmProxyHookExecutions,
        format!("l7_mitm_proxy_hook_executions>={expected}"),
        |value| value >= expected,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CaptureLossMetrics {
    pub(crate) events: u64,
    pub(crate) lost_events: u64,
}

pub(crate) fn wait_for_agent_capture_loss_metrics_at_least(
    agent: &mut Child,
    admin_socket_path: &Path,
    expected_events: u64,
    expected_lost_events: u64,
    context: &str,
) -> Result<CaptureLossMetrics, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + AGENT_PROGRESS_TIMEOUT;
    let mut last_metrics = None;
    loop {
        match read_agent_capture_loss_metrics(admin_socket_path) {
            Ok(metrics)
                if metrics.events >= expected_events
                    && metrics.lost_events >= expected_lost_events =>
            {
                return Ok(metrics);
            }
            Ok(metrics) => last_metrics = Some(metrics),
            Err(error) => {
                if let Some(status) = agent.try_wait()? {
                    return Err(e2e_error(format!(
                        "agent exited with {status} before {context} capture loss metrics were available: {error}"
                    ))
                    .into());
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(e2e_error(format!(
                "timed out waiting for {context} capture loss metrics; expected events>={expected_events} lost_events>={expected_lost_events}, last metrics {last_metrics:?}"
            ))
            .into());
        }
        thread::sleep(AGENT_PROGRESS_INTERVAL);
    }
}

pub(crate) fn assert_agent_capture_loss_prometheus_metrics(
    admin_socket_path: &Path,
    expected_events: u64,
    expected_lost_events: u64,
    context: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = send_admin_request(
        admin_socket_path,
        serde_json::json!({ "command": "prometheus_metrics" }),
    )?;
    if response["kind"] != serde_json::json!("prometheus_metrics") {
        return Err(e2e_error(format!(
            "unexpected prometheus metrics response for {context}: {response}"
        ))
        .into());
    }
    let metrics = response["metrics"].as_str().ok_or_else(|| {
        e2e_error(format!(
            "prometheus metrics response omitted text for {context}: {response}"
        ))
    })?;
    let expected_events =
        format!("traffic_probe_pipeline_capture_loss_events_total {expected_events}\n");
    if !metrics.contains(&expected_events) {
        return Err(e2e_error(format!(
            "prometheus metrics omitted {context} capture loss event counter {expected_events:?}: {metrics}"
        ))
        .into());
    }
    let expected_lost_events =
        format!("traffic_probe_pipeline_capture_lost_events_total {expected_lost_events}\n");
    if !metrics.contains(&expected_lost_events) {
        return Err(e2e_error(format!(
            "prometheus metrics omitted {context} capture lost event counter {expected_lost_events:?}: {metrics}"
        ))
        .into());
    }
    Ok(())
}

pub(crate) fn wait_for_agent_pipeline_progress(
    agent: &mut Child,
    admin_socket_path: &Path,
    expected_alert_floor: u64,
    expected_capture_event_floor: u64,
    expected_export_event_floor: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    wait_for_agent_progress(
        agent,
        admin_socket_path,
        AgentProgressExpectation {
            policy_alert_floor: expected_alert_floor,
            capture_event_floor: expected_capture_event_floor,
            export_event_floor: expected_export_event_floor,
        },
    )
}

fn wait_for_agent_progress(
    agent: &mut Child,
    admin_socket_path: &Path,
    expectation: AgentProgressExpectation,
) -> Result<(), Box<dyn std::error::Error>> {
    wait_for_agent_progress_until(
        agent,
        admin_socket_path,
        expectation.describe(),
        |metrics| metrics.satisfies(expectation),
    )?;
    Ok(())
}

fn wait_for_agent_progress_until(
    agent: &mut Child,
    admin_socket_path: &Path,
    expectation: String,
    predicate: impl Fn(AgentProgressMetrics) -> bool,
) -> Result<AgentProgressMetrics, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + AGENT_PROGRESS_TIMEOUT;
    let mut stable_polls = 0u8;
    let mut last_metrics = None;
    loop {
        match read_agent_progress_metrics(admin_socket_path) {
            Ok(policy) if policy.errors > 0 => {
                return Err(e2e_error(format!(
                    "agent policy metrics reported {} runtime errors before expected alerts",
                    policy.errors
                ))
                .into());
            }
            Ok(metrics) if predicate(metrics) => {
                stable_polls = match last_metrics {
                    Some(previous) if previous == metrics => stable_polls.saturating_add(1),
                    _ => 1,
                };
                last_metrics = Some(metrics);
                if stable_polls >= AGENT_PROGRESS_STABLE_POLLS {
                    return Ok(metrics);
                }
            }
            Ok(metrics) => {
                stable_polls = 0;
                last_metrics = Some(metrics);
            }
            Err(error) => {
                if let Some(status) = agent.try_wait()? {
                    return Err(e2e_error(format!(
                        "agent exited with {status} before progress reached {expectation}: {error}",
                    ))
                    .into());
                }
                if Instant::now() >= deadline {
                    return Err(e2e_error(format!(
                        "timed out waiting for agent progress to reach {expectation}: {error}",
                    ))
                    .into());
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(e2e_error(format!(
                "timed out waiting for agent progress to reach {expectation}",
            ))
            .into());
        }
        thread::sleep(AGENT_PROGRESS_INTERVAL);
    }
}

fn wait_for_agent_counter_until(
    agent: &mut Child,
    admin_socket_path: &Path,
    counter: AgentProgressCounter,
    expectation: String,
    predicate: impl Fn(u64) -> bool,
) -> Result<u64, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + AGENT_PROGRESS_TIMEOUT;
    let mut stable_polls = 0u8;
    let mut last_value = None;
    loop {
        match read_agent_progress_counter(admin_socket_path, counter) {
            Ok(value) if predicate(value) => {
                stable_polls = match last_value {
                    Some(previous) if previous == value => stable_polls.saturating_add(1),
                    _ => 1,
                };
                last_value = Some(value);
                if stable_polls >= AGENT_PROGRESS_STABLE_POLLS {
                    return Ok(value);
                }
            }
            Ok(value) => {
                stable_polls = 0;
                last_value = Some(value);
            }
            Err(error) => {
                if let Some(status) = agent.try_wait()? {
                    return Err(e2e_error(format!(
                        "agent exited with {status} before progress reached {expectation}: {error}",
                    ))
                    .into());
                }
                if Instant::now() >= deadline {
                    return Err(e2e_error(format!(
                        "timed out waiting for agent progress to reach {expectation}: {error}",
                    ))
                    .into());
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(e2e_error(format!(
                "timed out waiting for agent progress to reach {expectation}",
            ))
            .into());
        }
        thread::sleep(AGENT_PROGRESS_INTERVAL);
    }
}

pub(crate) fn assert_no_policy_runtime_errors(
    envelopes: &[EventEnvelope],
) -> Result<(), Box<dyn std::error::Error>> {
    let runtime_errors = envelopes
        .iter()
        .filter(|envelope| matches!(envelope.kind(), EventKind::PolicyRuntimeError(_)))
        .count();
    if runtime_errors == 0 {
        return Ok(());
    }

    Err(e2e_error(format!(
        "observed {runtime_errors} policy runtime error event(s)"
    ))
    .into())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AgentProgressExpectation {
    policy_alert_floor: u64,
    capture_event_floor: u64,
    export_event_floor: u64,
}

impl AgentProgressExpectation {
    fn describe(self) -> String {
        format!(
            "policy_alerts>={}, capture_events_read>={}, export_events_written>={}",
            self.policy_alert_floor, self.capture_event_floor, self.export_event_floor
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AgentProgressMetrics {
    capture_events_read: u64,
    export_events_written: u64,
    alerts: u64,
    errors: u64,
}

impl AgentProgressMetrics {
    fn satisfies(self, expectation: AgentProgressExpectation) -> bool {
        self.alerts >= expectation.policy_alert_floor
            && self.capture_events_read >= expectation.capture_event_floor
            && self.export_events_written >= expectation.export_event_floor
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AgentProgressCounter {
    PolicyAlerts,
    EnforcementDecisions,
    LinuxSocketDestroyExecutions,
    L7MitmProxyHookExecutions,
}

impl AgentProgressCounter {
    fn read_from(self, response: &serde_json::Value) -> Result<u64, Box<dyn std::error::Error>> {
        match self {
            Self::PolicyAlerts => {
                let policy = &response["metrics"]["pipeline"]["policy"];
                Ok(policy["alerts"].as_u64().ok_or_else(|| {
                    e2e_error(format!(
                        "admin metrics response omitted policy alert count: {response}"
                    ))
                })?)
            }
            Self::EnforcementDecisions => {
                let enforcement = &response["metrics"]["pipeline"]["enforcement"];
                Ok(enforcement["decisions"].as_u64().ok_or_else(|| {
                    e2e_error(format!(
                        "admin metrics response omitted enforcement decision count: {response}"
                    ))
                })?)
            }
            Self::LinuxSocketDestroyExecutions => {
                let connection_backend = &response["metrics"]["pipeline"]["enforcement"]["execution"]
                    ["connection_backend"];
                Ok(connection_backend["linux_socket_destroy"]
                    .as_u64()
                    .ok_or_else(|| {
                        e2e_error(format!(
                            "admin metrics response omitted linux socket destroy execution count: {response}"
                        ))
                    })?)
            }
            Self::L7MitmProxyHookExecutions => {
                let proxy_side_hook =
                    &response["metrics"]["pipeline"]["enforcement"]["execution"]["proxy_side_hook"];
                Ok(proxy_side_hook["l7_mitm"].as_u64().ok_or_else(|| {
                    e2e_error(format!(
                        "admin metrics response omitted L7 MITM proxy hook execution count: {response}"
                    ))
                })?)
            }
        }
    }
}

fn read_agent_progress_counter(
    admin_socket_path: &Path,
    counter: AgentProgressCounter,
) -> Result<u64, Box<dyn std::error::Error>> {
    let response = send_admin_request(
        admin_socket_path,
        serde_json::json!({ "command": "metrics" }),
    )?;
    let errors = read_policy_error_count(&response)?;
    if errors > 0 {
        return Err(e2e_error(format!(
            "agent policy metrics reported {errors} runtime errors before expected progress"
        ))
        .into());
    }
    counter.read_from(&response)
}

fn read_agent_capture_loss_metrics(
    admin_socket_path: &Path,
) -> Result<CaptureLossMetrics, Box<dyn std::error::Error>> {
    let response = send_admin_request(
        admin_socket_path,
        serde_json::json!({ "command": "metrics" }),
    )?;
    let errors = read_policy_error_count(&response)?;
    if errors > 0 {
        return Err(e2e_error(format!(
            "agent policy metrics reported {errors} runtime errors before expected capture loss metrics"
        ))
        .into());
    }
    let capture_loss = &response["metrics"]["pipeline"]["capture_loss"];
    let events = capture_loss["events"].as_u64().ok_or_else(|| {
        e2e_error(format!(
            "admin metrics response omitted capture loss event count: {response}"
        ))
    })?;
    let lost_events = capture_loss["lost_events"].as_u64().ok_or_else(|| {
        e2e_error(format!(
            "admin metrics response omitted capture lost event count: {response}"
        ))
    })?;
    Ok(CaptureLossMetrics {
        events,
        lost_events,
    })
}

fn read_agent_progress_metrics(
    admin_socket_path: &Path,
) -> Result<AgentProgressMetrics, Box<dyn std::error::Error>> {
    let response = send_admin_request(
        admin_socket_path,
        serde_json::json!({ "command": "metrics" }),
    )?;
    let pipeline = &response["metrics"]["pipeline"];
    let capture_events_read = pipeline["capture_events_read"].as_u64().ok_or_else(|| {
        e2e_error(format!(
            "admin metrics response omitted capture event count: {response}"
        ))
    })?;
    let export_events_written = pipeline["export_events_written"].as_u64().ok_or_else(|| {
        e2e_error(format!(
            "admin metrics response omitted export event count: {response}"
        ))
    })?;
    let policy = &pipeline["policy"];
    let alerts = policy["alerts"].as_u64().ok_or_else(|| {
        e2e_error(format!(
            "admin metrics response omitted policy alert count: {response}"
        ))
    })?;
    let errors = read_policy_error_count(&response)?;
    Ok(AgentProgressMetrics {
        capture_events_read,
        export_events_written,
        alerts,
        errors,
    })
}

fn read_policy_error_count(
    response: &serde_json::Value,
) -> Result<u64, Box<dyn std::error::Error>> {
    let policy = &response["metrics"]["pipeline"]["policy"];
    Ok(policy["errors"].as_u64().ok_or_else(|| {
        e2e_error(format!(
            "admin metrics response omitted policy error count: {response}"
        ))
    })?)
}

pub(crate) fn send_admin_request(
    admin_socket_path: &Path,
    request: serde_json::Value,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let mut stream = UnixStream::connect(admin_socket_path)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut request = serde_json::to_vec(&request)?;
    request.push(b'\n');
    stream.write_all(&request)?;

    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line)?;
    Ok(serde_json::from_str(&line)?)
}
