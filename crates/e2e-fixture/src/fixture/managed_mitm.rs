use std::{
    error::Error,
    fmt,
    fs::OpenOptions,
    io::{self, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use e2e_support::{
    http_json::{
        HttpJsonRequest, read_request as read_http_json_request,
        write_response as write_json_response,
    },
    mitm_bridge,
};
use serde_json::{Value, json};

use super::loopback::{LoopbackError, bind_loopback_listener};

const SCENARIO: &str = "managed-mitm-backend";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ManagedMitmBackendConfig {
    pub listen_addr: SocketAddr,
    pub pid_file: PathBuf,
    pub bridge_feed_file: PathBuf,
    pub policy_hook: Option<ManagedMitmPolicyHookConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ManagedMitmPolicyHookConfig {
    pub listen_addr: SocketAddr,
    pub action_report_file: PathBuf,
}

#[derive(Debug)]
pub(crate) enum ManagedMitmBackendError {
    Invalid(String),
    Loopback(LoopbackError),
    Feed(Box<dyn Error>),
    Json(serde_json::Error),
    Io {
        action: &'static str,
        source: io::Error,
    },
}

impl fmt::Display for ManagedMitmBackendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => write!(formatter, "{reason}"),
            Self::Loopback(error) => write!(formatter, "{error}"),
            Self::Feed(error) => write!(formatter, "failed to write capture event feed: {error}"),
            Self::Json(error) => write!(
                formatter,
                "failed to serialize policy action report: {error}"
            ),
            Self::Io { action, source } => write!(formatter, "failed to {action}: {source}"),
        }
    }
}

impl Error for ManagedMitmBackendError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Invalid(_) => None,
            Self::Loopback(error) => Some(error),
            Self::Feed(error) => Some(error.as_ref()),
            Self::Json(error) => Some(error),
            Self::Io { source, .. } => Some(source),
        }
    }
}

impl From<LoopbackError> for ManagedMitmBackendError {
    fn from(error: LoopbackError) -> Self {
        Self::Loopback(error)
    }
}

pub(crate) fn run_managed_mitm_backend(
    config: ManagedMitmBackendConfig,
) -> Result<(), ManagedMitmBackendError> {
    validate_listen_addr(config.listen_addr)?;
    if let Some(policy_hook) = &config.policy_hook {
        validate_policy_hook_config(policy_hook)?;
    }
    mitm_bridge::create_empty_capture_event_feed(&config.bridge_feed_file)
        .map_err(|source| io_error("create managed MITM bridge feed", source))?;
    let listener = bind_loopback_listener(config.listen_addr.port())?;
    let policy_hook_listener = config
        .policy_hook
        .as_ref()
        .map(|policy_hook| bind_loopback_listener(policy_hook.listen_addr.port()))
        .transpose()?;
    write_pid_file(&config.pid_file)?;

    let mut state = ManagedMitmState::default();
    loop {
        let accepted_mitm =
            accept_mitm_connection(&listener, &config.bridge_feed_file, &mut state)?;
        let accepted_hook = match (&policy_hook_listener, &config.policy_hook) {
            (Some(listener), Some(policy_hook)) => {
                accept_policy_hook_connection(listener, policy_hook, &mut state)?
            }
            _ => false,
        };
        if !accepted_mitm && !accepted_hook {
            thread::sleep(Duration::from_millis(20));
        }
    }
}

#[derive(Default)]
struct ManagedMitmState {
    flow_ready: bool,
    action_report_written: bool,
}

fn accept_mitm_connection(
    listener: &TcpListener,
    bridge_feed_file: &Path,
    state: &mut ManagedMitmState,
) -> Result<bool, ManagedMitmBackendError> {
    match listener.accept() {
        Ok((stream, _peer)) => {
            drop(stream);
            if !state.flow_ready {
                mitm_bridge::append_capture_event_feed(bridge_feed_file)
                    .map_err(ManagedMitmBackendError::Feed)?;
                state.flow_ready = true;
            }
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
        Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(false),
        Err(source) => Err(io_error("accept managed MITM readiness connection", source)),
    }
}

fn accept_policy_hook_connection(
    listener: &TcpListener,
    policy_hook: &ManagedMitmPolicyHookConfig,
    state: &mut ManagedMitmState,
) -> Result<bool, ManagedMitmBackendError> {
    match listener.accept() {
        Ok((stream, _peer)) => {
            handle_policy_hook_request(stream, policy_hook, state)?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
        Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(false),
        Err(source) => Err(io_error(
            "accept managed MITM policy hook connection",
            source,
        )),
    }
}

fn handle_policy_hook_request(
    mut stream: TcpStream,
    policy_hook: &ManagedMitmPolicyHookConfig,
    state: &mut ManagedMitmState,
) -> Result<(), ManagedMitmBackendError> {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|source| io_error("set managed MITM policy hook read timeout", source))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|source| io_error("set managed MITM policy hook write timeout", source))?;

    let request = match read_http_json_request(&mut stream) {
        Ok(request) => request,
        Err(error) => {
            write_policy_hook_response(
                &mut stream,
                400,
                json!({"outcome": "unsupported", "reason": error.to_string()}),
            )?;
            return Ok(());
        }
    };
    let expected_host = policy_hook.listen_addr.to_string();
    let decision = validate_policy_hook_request(&request, expected_host.as_str(), state);
    match decision {
        Ok(report) => {
            write_policy_action_report(&policy_hook.action_report_file, &report)?;
            state.action_report_written = true;
            write_policy_hook_response(
                &mut stream,
                200,
                json!({
                    "outcome": "delegated",
                    "executed_action": report.executed_action,
                    "reason": report.reason,
                }),
            )
        }
        Err(reason) => write_policy_hook_response(
            &mut stream,
            200,
            json!({"outcome": "unsupported", "reason": reason}),
        ),
    }
}

#[derive(Debug)]
struct PolicyActionReport {
    flow_id: String,
    target: String,
    requested_action: String,
    executed_action: String,
    reason: String,
}

fn validate_policy_hook_request(
    request: &HttpJsonRequest,
    expected_host: &str,
    state: &ManagedMitmState,
) -> Result<PolicyActionReport, String> {
    if !state.flow_ready {
        return Err("managed MITM backend has not observed a plaintext bridge flow".to_string());
    }
    if state.action_report_written {
        return Err("managed MITM backend already executed a policy action".to_string());
    }

    validate_policy_hook_http_contract(request, expected_host)?;
    let body = &request.body;
    let requested_action = string_field(body, &["requested_action"])?;
    if requested_action != "deny" {
        return Err(format!(
            "managed MITM backend only supports deny in this fixture, got {requested_action}"
        ));
    }
    let verdict_action = string_field(body, &["verdict", "action"])?;
    if verdict_action != requested_action {
        return Err(format!(
            "verdict action {verdict_action} did not match requested action {requested_action}"
        ));
    }
    let target = string_field(body, &["trigger", "kind", "target"])?;
    if target != mitm_bridge::REQUEST_TARGET {
        return Err(format!(
            "managed MITM backend expected target {}, got {target}",
            mitm_bridge::REQUEST_TARGET
        ));
    }
    let flow_id = string_field(body, &["trigger", "subject", "flow", "id"])?;
    if flow_id != mitm_bridge::FLOW_ID {
        return Err(format!(
            "managed MITM backend expected flow {}, got {flow_id}",
            mitm_bridge::FLOW_ID
        ));
    }

    Ok(PolicyActionReport {
        flow_id: flow_id.to_string(),
        target: target.to_string(),
        requested_action: requested_action.to_string(),
        executed_action: requested_action.to_string(),
        reason: mitm_bridge::POLICY_HOOK_RESPONSE_REASON.to_string(),
    })
}

fn validate_policy_hook_http_contract(
    request: &HttpJsonRequest,
    expected_host: &str,
) -> Result<(), String> {
    if request.method != mitm_bridge::POLICY_HOOK_METHOD
        || request.path != mitm_bridge::POLICY_HOOK_PATH
    {
        return Err(format!(
            "managed MITM backend expected {} {}, got {} {}",
            mitm_bridge::POLICY_HOOK_METHOD,
            mitm_bridge::POLICY_HOOK_PATH,
            request.method,
            request.path
        ));
    }
    require_header(request, "host", expected_host)?;
    require_header(
        request,
        "content-type",
        mitm_bridge::POLICY_HOOK_CONTENT_TYPE,
    )?;
    require_header(request, "accept", mitm_bridge::POLICY_HOOK_ACCEPT)
}

fn require_header(request: &HttpJsonRequest, name: &str, expected: &str) -> Result<(), String> {
    let observed = request
        .headers
        .iter()
        .find_map(|(header, value)| header.eq_ignore_ascii_case(name).then_some(value.as_str()));
    if observed == Some(expected) {
        return Ok(());
    }
    Err(format!(
        "managed MITM backend expected header {name}: {expected:?}, got {observed:?}"
    ))
}

fn string_field<'a>(value: &'a Value, path: &[&str]) -> Result<&'a str, String> {
    let mut current = value;
    for key in path {
        current = current
            .get(*key)
            .ok_or_else(|| format!("missing JSON field {}", path.join(".")))?;
    }
    current
        .as_str()
        .ok_or_else(|| format!("JSON field {} was not a string", path.join(".")))
}

fn write_policy_action_report(
    path: &Path,
    report: &PolicyActionReport,
) -> Result<(), ManagedMitmBackendError> {
    let value = json!({
        "flow_id": report.flow_id,
        "target": report.target,
        "requested_action": report.requested_action,
        "executed_action": report.executed_action,
        "reason": report.reason,
    });
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| io_error("create managed MITM action report", source))?;
    serde_json::to_writer(&mut file, &value).map_err(ManagedMitmBackendError::Json)?;
    file.write_all(b"\n")
        .map_err(|source| io_error("write managed MITM action report newline", source))?;
    file.flush()
        .map_err(|source| io_error("flush managed MITM action report", source))
}

fn write_policy_hook_response(
    stream: &mut TcpStream,
    status: u16,
    body: Value,
) -> Result<(), ManagedMitmBackendError> {
    write_json_response(stream, status, &body)
        .map_err(|source| io_error("write managed MITM policy hook response", source))
}

fn write_pid_file(path: &Path) -> Result<(), ManagedMitmBackendError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| io_error("create managed MITM pid file", source))?;
    file.write_all(std::process::id().to_string().as_bytes())
        .map_err(|source| io_error("write managed MITM pid file", source))
}

fn validate_listen_addr(listen_addr: SocketAddr) -> Result<(), ManagedMitmBackendError> {
    match listen_addr {
        SocketAddr::V4(addr) if *addr.ip() == Ipv4Addr::LOCALHOST && addr.port() != 0 => Ok(()),
        _ => Err(ManagedMitmBackendError::Invalid(format!(
            "{SCENARIO} requires a fixed 127.0.0.1 listen address, got {listen_addr}"
        ))),
    }
}

fn validate_policy_hook_config(
    config: &ManagedMitmPolicyHookConfig,
) -> Result<(), ManagedMitmBackendError> {
    validate_listen_addr(config.listen_addr)?;
    Ok(())
}

fn io_error(action: &'static str, source: io::Error) -> ManagedMitmBackendError {
    ManagedMitmBackendError::Io { action, source }
}

#[cfg(test)]
mod tests {
    use std::{error::Error, fs};

    use serde_json::json;

    use super::*;

    #[test]
    fn pid_file_creation_does_not_truncate_existing_feed_file() -> Result<(), Box<dyn Error>> {
        let root = tempfile::tempdir()?;
        let shared_path = root.path().join("managed-mitm");
        fs::write(&shared_path, "feed")?;

        let error = write_pid_file(&shared_path)
            .expect_err("pid file creation must reject an existing feed path");

        assert!(error.to_string().contains("create managed MITM pid file"));
        assert_eq!(fs::read_to_string(shared_path)?, "feed");
        Ok(())
    }

    #[test]
    fn policy_hook_rejects_action_before_backend_owns_flow() {
        let state = ManagedMitmState::default();

        let error =
            validate_policy_hook_request(&policy_hook_request(), policy_hook_host(), &state)
                .expect_err("policy hook must not execute before seeing a flow");

        assert!(error.contains("has not observed a plaintext bridge flow"));
    }

    #[test]
    fn policy_hook_action_report_requires_owned_flow() -> Result<(), Box<dyn Error>> {
        let state = ManagedMitmState {
            flow_ready: true,
            action_report_written: false,
        };

        let report =
            validate_policy_hook_request(&policy_hook_request(), policy_hook_host(), &state)?;

        assert_eq!(report.flow_id, mitm_bridge::FLOW_ID);
        assert_eq!(report.target, mitm_bridge::REQUEST_TARGET);
        assert_eq!(report.requested_action, "deny");
        assert_eq!(report.executed_action, "deny");
        assert_eq!(report.reason, mitm_bridge::POLICY_HOOK_RESPONSE_REASON);
        Ok(())
    }

    #[test]
    fn policy_hook_action_report_requires_endpoint_contract() {
        let state = ManagedMitmState {
            flow_ready: true,
            action_report_written: false,
        };
        let request = HttpJsonRequest {
            path: "/wrong-policy-hook".to_string(),
            ..policy_hook_request()
        };

        let error = validate_policy_hook_request(&request, policy_hook_host(), &state)
            .expect_err("policy hook must reject the wrong endpoint");

        assert!(error.contains("expected POST /mitm-policy-hook"));
    }

    fn policy_hook_request() -> HttpJsonRequest {
        HttpJsonRequest {
            method: mitm_bridge::POLICY_HOOK_METHOD.to_string(),
            path: mitm_bridge::POLICY_HOOK_PATH.to_string(),
            headers: vec![
                ("Host".to_string(), policy_hook_host().to_string()),
                (
                    "Content-Type".to_string(),
                    mitm_bridge::POLICY_HOOK_CONTENT_TYPE.to_string(),
                ),
                (
                    "Accept".to_string(),
                    mitm_bridge::POLICY_HOOK_ACCEPT.to_string(),
                ),
            ],
            body: policy_hook_body(),
        }
    }

    fn policy_hook_host() -> &'static str {
        "127.0.0.1:65518"
    }

    fn policy_hook_body() -> Value {
        json!({
            "requested_action": "deny",
            "verdict": {
                "action": "deny"
            },
            "trigger": {
                "kind": {
                    "target": mitm_bridge::REQUEST_TARGET
                },
                "subject": {
                    "flow": {
                        "id": mitm_bridge::FLOW_ID
                    }
                }
            }
        })
    }
}
