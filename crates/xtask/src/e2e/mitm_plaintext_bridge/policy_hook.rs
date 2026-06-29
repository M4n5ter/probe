use std::{
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use e2e_support::mitm_bridge;
use probe_core::Action;
use serde_json::{Value, json};

use super::{
    backend::MitmBridgeCase,
    feed::{POLICY_HOOK_REASON_PREFIX, POLICY_HOOK_RESPONSE_REASON},
};
use crate::e2e::harness::e2e_error;

const HOOK_PATH: &str = "/mitm-policy-hook";
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(10);
const READ_TIMEOUT: Duration = Duration::from_secs(2);
const READ_BUFFER_BYTES: usize = 4096;

pub(super) struct MitmPolicyHookServer {
    target: SocketAddr,
    requests: Arc<Mutex<Vec<ObservedPolicyHookRequest>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<io::Result<()>>>,
}

impl MitmPolicyHookServer {
    pub(super) fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        listener.set_nonblocking(true)?;
        let target = listener.local_addr()?;
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_requests = Arc::clone(&requests);
        let thread_stop = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            accept_policy_hook_requests(listener, thread_requests, thread_stop)
        });
        Ok(Self {
            target,
            requests,
            stop,
            thread: Some(thread),
        })
    }

    pub(super) fn endpoint(&self) -> String {
        format!("http://{}{}", self.target, HOOK_PATH)
    }

    pub(super) fn observed_requests(
        &self,
    ) -> Result<Vec<ObservedPolicyHookRequest>, Box<dyn std::error::Error>> {
        Ok(self
            .requests
            .lock()
            .map_err(|_| e2e_error("MITM policy hook request recorder was poisoned"))?
            .clone())
    }

    fn stop(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.stop.store(true, Ordering::Relaxed);
        let Some(thread) = self.thread.take() else {
            return Ok(());
        };
        match thread.join() {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(error.into()),
            Err(_) => Err(e2e_error("MITM policy hook accept thread panicked").into()),
        }
    }
}

impl Drop for MitmPolicyHookServer {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

pub(super) fn assert_policy_hook_requests(
    case: MitmBridgeCase,
    server: Option<&MitmPolicyHookServer>,
) -> Result<(), Box<dyn std::error::Error>> {
    if !case.policy_hook_enabled() {
        return Ok(());
    }
    let Some(server) = server else {
        return Err(e2e_error("MITM policy hook case did not start a hook server").into());
    };
    let requests = server.observed_requests()?;
    let [request] = requests.as_slice() else {
        return Err(e2e_error(format!(
            "expected exactly one MITM policy hook request, got {}: {requests:?}",
            requests.len()
        ))
        .into());
    };
    assert_hook_request_payload(request, server.target.to_string().as_str())
}

fn accept_policy_hook_requests(
    listener: TcpListener,
    requests: Arc<Mutex<Vec<ObservedPolicyHookRequest>>>,
    stop: Arc<AtomicBool>,
) -> io::Result<()> {
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _peer)) => handle_policy_hook_request(stream, &requests)?,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL_INTERVAL);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn handle_policy_hook_request(
    mut stream: TcpStream,
    requests: &Arc<Mutex<Vec<ObservedPolicyHookRequest>>>,
) -> io::Result<()> {
    stream.set_read_timeout(Some(READ_TIMEOUT))?;
    let request = match read_http_json_request(&mut stream) {
        Ok(request) => request,
        Err(error) => {
            let _ = write_json_response(
                &mut stream,
                400,
                json!({"outcome": "unsupported", "reason": error.to_string()}),
            );
            return Ok(());
        }
    };
    let Some(executed_action) = request
        .body
        .get("requested_action")
        .cloned()
        .and_then(|value| serde_json::from_value::<Action>(value).ok())
    else {
        return write_json_response(
            &mut stream,
            400,
            json!({
                "outcome": "unsupported",
                "reason": "MITM policy hook request omitted requested_action"
            }),
        );
    };
    requests
        .lock()
        .map_err(|_| io::Error::other("MITM policy hook request recorder was poisoned"))?
        .push(request);
    write_json_response(
        &mut stream,
        200,
        json!({
            "outcome": "delegated",
            "executed_action": executed_action,
            "reason": POLICY_HOOK_RESPONSE_REASON
        }),
    )
}

#[derive(Debug, Clone)]
pub(super) struct ObservedPolicyHookRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Value,
}

fn read_http_json_request(stream: &mut TcpStream) -> io::Result<ObservedPolicyHookRequest> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; READ_BUFFER_BYTES];
    loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if complete_http_request_len(&buffer)?.is_some_and(|expected| buffer.len() >= expected) {
            break;
        }
    }
    let Some(header_end) = find_header_end(&buffer) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP request omitted header terminator",
        ));
    };
    let head = parse_http_head(&buffer[..header_end])?;
    let content_length = parse_content_length(&buffer[..header_end])?;
    let body_start = header_end + b"\r\n\r\n".len();
    let body_end = body_start + content_length;
    if buffer.len() < body_end {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "HTTP request body ended before Content-Length",
        ));
    }
    let body = serde_json::from_slice(&buffer[body_start..body_end])
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(ObservedPolicyHookRequest {
        method: head.method,
        path: head.path,
        headers: head.headers,
        body,
    })
}

fn complete_http_request_len(buffer: &[u8]) -> io::Result<Option<usize>> {
    let Some(header_end) = find_header_end(buffer) else {
        return Ok(None);
    };
    let content_length = parse_content_length(&buffer[..header_end])?;
    Ok(Some(header_end + b"\r\n\r\n".len() + content_length))
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(b"\r\n\r\n".len())
        .position(|window| window == b"\r\n\r\n")
}

struct ParsedHttpHead {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
}

fn parse_http_head(head: &[u8]) -> io::Result<ParsedHttpHead> {
    let head = std::str::from_utf8(head)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut lines = head.lines();
    let Some(line) = lines.next() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP request omitted request line",
        ));
    };
    let mut parts = line.split_whitespace();
    let Some(method) = parts.next() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP request omitted method",
        ));
    };
    let Some(path) = parts.next() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP request omitted path",
        ));
    };
    if parts.next().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP request omitted version",
        ));
    }
    let headers = lines
        .filter_map(|line| {
            line.split_once(':')
                .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
        })
        .collect::<Vec<_>>();
    Ok(ParsedHttpHead {
        method: method.to_string(),
        path: path.to_string(),
        headers,
    })
}

fn parse_content_length(head: &[u8]) -> io::Result<usize> {
    let head = std::str::from_utf8(head)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut lengths = head.lines().filter_map(|line| {
        line.split_once(':').and_then(|(name, value)| {
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim())
        })
    });
    let Some(raw) = lengths.next() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP request omitted Content-Length",
        ));
    };
    if lengths.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP request included duplicate Content-Length",
        ));
    }
    raw.parse::<usize>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn write_json_response(stream: &mut TcpStream, status: u16, body: Value) -> Result<(), io::Error> {
    let body = serde_json::to_vec(&body).map_err(io::Error::other)?;
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        _ => "Error",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(&body)?;
    stream.flush()
}

fn assert_hook_request_payload(
    request: &ObservedPolicyHookRequest,
    expected_host: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if request.method != "POST" || request.path != HOOK_PATH {
        return Err(e2e_error(format!(
            "MITM policy hook request target mismatch: expected POST {HOOK_PATH}, got {} {}; request={request:?}",
            request.method, request.path
        ))
        .into());
    }
    assert_header(request, "host", expected_host)?;
    assert_header(request, "content-type", "application/json")?;
    assert_header(request, "accept", "application/json")?;
    let body = &request.body;
    let expected = [
        ("requested_action", &body["requested_action"], json!("deny")),
        ("verdict.action", &body["verdict"]["action"], json!("deny")),
        ("verdict.scope", &body["verdict"]["scope"], json!("request")),
        (
            "trigger.kind.type",
            &body["trigger"]["kind"]["type"],
            json!("http_request_headers"),
        ),
        (
            "trigger.kind.target",
            &body["trigger"]["kind"]["target"],
            json!(mitm_bridge::REQUEST_TARGET),
        ),
        (
            "trigger.subject.flow.process.name",
            &body["trigger"]["subject"]["flow"]["process"]["name"],
            json!("traffic-probe-e2e-mitm-bridge"),
        ),
    ];
    for (field, observed, expected) in expected {
        if *observed != expected {
            return Err(e2e_error(format!(
                "MITM policy hook request {field} mismatch: expected {expected}, got {observed}; request={request:?}"
            ))
            .into());
        }
    }
    let Some(reason) = body["verdict"]["reason"].as_str() else {
        return Err(e2e_error(format!(
            "MITM policy hook request verdict.reason was not a string: {request:?}"
        ))
        .into());
    };
    if !reason.starts_with(POLICY_HOOK_REASON_PREFIX) {
        return Err(e2e_error(format!(
            "MITM policy hook request verdict.reason did not start with {POLICY_HOOK_REASON_PREFIX:?}: {reason}"
        ))
        .into());
    }
    Ok(())
}

fn assert_header(
    request: &ObservedPolicyHookRequest,
    name: &str,
    expected: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let observed = request
        .headers
        .iter()
        .find_map(|(header, value)| header.eq_ignore_ascii_case(name).then_some(value.as_str()));
    if observed == Some(expected) {
        return Ok(());
    }
    Err(e2e_error(format!(
        "MITM policy hook request header {name} mismatch: expected {expected:?}, got {observed:?}; request={request:?}"
    ))
    .into())
}
