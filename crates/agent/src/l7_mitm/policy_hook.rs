use std::{
    convert::TryFrom,
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    num::NonZeroU32,
    time::{Duration, Instant},
};

use enforcement::{
    EnforcementBackendRequest, EnforcementError, ProxySideEnforcementHook,
    ProxySideEnforcementHookDecision,
};
use probe_core::{Action, EventEnvelope, Verdict};
use probe_io::{TcpConnectOptions, TcpSocketMark, connect_tcp};
use runtime::{
    TransparentInterceptionMitmPolicyHookEndpointPlan, TransparentInterceptionMitmPolicyHookPlan,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_RESPONSE_HEADER_BYTES: usize = 16 * 1024;

pub(crate) fn hook_from_plan(
    plan: &TransparentInterceptionMitmPolicyHookPlan,
    connection: L7MitmPolicyHookConnectionOptions,
) -> Result<Box<dyn ProxySideEnforcementHook>, L7MitmPolicyHookError> {
    match plan {
        TransparentInterceptionMitmPolicyHookPlan::Disabled => Err(L7MitmPolicyHookError::Disabled),
        TransparentInterceptionMitmPolicyHookPlan::HttpJson {
            endpoint,
            timeout_ms,
            max_response_bytes,
        } => Ok(Box::new(HttpJsonL7MitmPolicyHook::new(
            endpoint,
            *timeout_ms,
            *max_response_bytes,
            connection,
        )?)),
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct L7MitmPolicyHookConnectionOptions {
    socket_mark: Option<TcpSocketMark>,
}

impl L7MitmPolicyHookConnectionOptions {
    pub(crate) fn with_socket_mark(mut self, mark: NonZeroU32) -> Self {
        self.socket_mark = Some(TcpSocketMark::new(mark));
        self
    }

    fn tcp_connect_options(self, timeout: Duration) -> TcpConnectOptions {
        let mut options = TcpConnectOptions::new(timeout);
        if let Some(mark) = self.socket_mark {
            options = options.with_socket_mark(mark);
        }
        options
    }
}

#[derive(Debug, Error)]
pub(crate) enum L7MitmPolicyHookError {
    #[error("MITM policy hook plan is disabled")]
    Disabled,
    #[error("invalid MITM policy hook endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("MITM policy hook request serialization failed: {0}")]
    Serialize(#[source] serde_json::Error),
    #[error("MITM policy hook I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("MITM policy hook timed out")]
    Timeout,
    #[error("MITM policy hook response exceeded {limit} bytes")]
    ResponseTooLarge { limit: usize },
    #[error("invalid MITM policy hook HTTP response: {0}")]
    InvalidResponse(String),
    #[error("MITM policy hook returned HTTP status {status}")]
    Status { status: u16 },
    #[error("MITM policy hook response JSON failed: {0}")]
    Deserialize(#[source] serde_json::Error),
}

struct HttpJsonL7MitmPolicyHook {
    endpoint: HttpJsonEndpoint,
    connection: L7MitmPolicyHookConnectionOptions,
    timeout: Duration,
    max_response_bytes: usize,
}

impl HttpJsonL7MitmPolicyHook {
    fn new(
        endpoint: &TransparentInterceptionMitmPolicyHookEndpointPlan,
        timeout_ms: u64,
        max_response_bytes: u64,
        connection: L7MitmPolicyHookConnectionOptions,
    ) -> Result<Self, L7MitmPolicyHookError> {
        Ok(Self {
            endpoint: HttpJsonEndpoint::from_plan(endpoint),
            connection,
            timeout: Duration::from_millis(timeout_ms),
            max_response_bytes: usize::try_from(max_response_bytes).map_err(|_| {
                L7MitmPolicyHookError::InvalidEndpoint(
                    "max_response_bytes does not fit this platform".to_string(),
                )
            })?,
        })
    }

    fn delegate_inner(
        &self,
        request: EnforcementBackendRequest<'_>,
    ) -> Result<ProxySideEnforcementHookDecision, L7MitmPolicyHookError> {
        let payload = serde_json::to_vec(&HttpJsonHookRequest {
            requested_action: request.verdict.action,
            verdict: request.verdict,
            trigger: request.trigger,
        })
        .map_err(L7MitmPolicyHookError::Serialize)?;
        let deadline = HookDeadline::after(self.timeout);
        let mut stream = connect_tcp(
            self.endpoint.address,
            self.connection.tcp_connect_options(deadline.remaining()?),
        )?;
        write_hook_request(&mut stream, &self.endpoint, &payload, &deadline)?;
        let response = read_hook_response(stream, self.max_response_bytes, &deadline)?;
        parse_hook_response(response)
    }
}

impl ProxySideEnforcementHook for HttpJsonL7MitmPolicyHook {
    fn delegate(
        &mut self,
        request: EnforcementBackendRequest<'_>,
    ) -> Result<ProxySideEnforcementHookDecision, EnforcementError> {
        self.delegate_inner(request)
            .map_err(|error| EnforcementError::Backend(error.to_string()))
    }
}

struct HttpJsonEndpoint {
    address: SocketAddr,
    authority: String,
    path_and_query: String,
}

impl HttpJsonEndpoint {
    fn from_plan(endpoint: &TransparentInterceptionMitmPolicyHookEndpointPlan) -> Self {
        Self {
            address: endpoint.address,
            authority: endpoint.authority.clone(),
            path_and_query: endpoint.path_and_query.clone(),
        }
    }
}

#[derive(Serialize)]
struct HttpJsonHookRequest<'a> {
    requested_action: Action,
    verdict: &'a Verdict,
    trigger: &'a EventEnvelope,
}

#[derive(Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
enum HttpJsonHookResponse {
    Delegated { reason: Option<String> },
    Unsupported { reason: Option<String> },
}

fn write_hook_request(
    stream: &mut TcpStream,
    endpoint: &HttpJsonEndpoint,
    payload: &[u8],
    deadline: &HookDeadline,
) -> Result<(), L7MitmPolicyHookError> {
    let head = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nAccept: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        endpoint.path_and_query,
        endpoint.authority,
        payload.len()
    );
    write_all_with_deadline(stream, head.as_bytes(), deadline)?;
    write_all_with_deadline(stream, payload, deadline)?;
    deadline.set_write_timeout(stream)?;
    stream.flush()?;
    Ok(())
}

#[derive(Debug)]
struct HttpJsonHookHttpResponse {
    status: u16,
    body: Vec<u8>,
}

fn read_hook_response(
    mut stream: TcpStream,
    max_response_bytes: usize,
    deadline: &HookDeadline,
) -> Result<HttpJsonHookHttpResponse, L7MitmPolicyHookError> {
    let ResponseHead {
        status,
        content_length,
        prefetched_body,
    } = read_response_head(&mut stream, deadline)?;
    let body = read_response_body(
        &mut stream,
        prefetched_body,
        content_length,
        max_response_bytes,
        deadline,
    )?;
    Ok(HttpJsonHookHttpResponse { status, body })
}

fn parse_hook_response(
    response: HttpJsonHookHttpResponse,
) -> Result<ProxySideEnforcementHookDecision, L7MitmPolicyHookError> {
    if !(200..300).contains(&response.status) {
        return Err(L7MitmPolicyHookError::Status {
            status: response.status,
        });
    }
    match serde_json::from_slice::<HttpJsonHookResponse>(&response.body)
        .map_err(L7MitmPolicyHookError::Deserialize)?
    {
        HttpJsonHookResponse::Delegated { reason } => {
            Ok(ProxySideEnforcementHookDecision::delegated(
                reason.unwrap_or_else(|| "policy hook accepted action".to_string()),
            ))
        }
        HttpJsonHookResponse::Unsupported { reason } => {
            Ok(ProxySideEnforcementHookDecision::unsupported(
                reason.unwrap_or_else(|| "policy hook does not support action".to_string()),
            ))
        }
    }
}

#[derive(Debug)]
struct ResponseHead {
    status: u16,
    content_length: usize,
    prefetched_body: Vec<u8>,
}

fn read_response_head(
    stream: &mut TcpStream,
    deadline: &HookDeadline,
) -> Result<ResponseHead, L7MitmPolicyHookError> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 512];
    loop {
        if let Some(header_end) = find_header_terminator(&buffer) {
            if header_end > MAX_RESPONSE_HEADER_BYTES {
                return Err(L7MitmPolicyHookError::InvalidResponse(format!(
                    "response headers exceeded {MAX_RESPONSE_HEADER_BYTES} bytes"
                )));
            }
            let head = parse_response_head(&buffer[..header_end])?;
            return Ok(ResponseHead {
                status: head.status,
                content_length: head.content_length,
                prefetched_body: buffer[header_end + 4..].to_vec(),
            });
        }
        if buffer.len() > MAX_RESPONSE_HEADER_BYTES {
            return Err(L7MitmPolicyHookError::InvalidResponse(format!(
                "response headers exceeded {MAX_RESPONSE_HEADER_BYTES} bytes"
            )));
        }
        deadline.set_read_timeout(stream)?;
        let bytes_read = stream.read(&mut chunk)?;
        if bytes_read == 0 {
            return Err(L7MitmPolicyHookError::InvalidResponse(
                "response ended before header terminator".to_string(),
            ));
        }
        buffer.extend_from_slice(&chunk[..bytes_read]);
    }
}

fn read_response_body(
    stream: &mut TcpStream,
    prefetched_body: Vec<u8>,
    content_length: usize,
    max_response_bytes: usize,
    deadline: &HookDeadline,
) -> Result<Vec<u8>, L7MitmPolicyHookError> {
    if content_length > max_response_bytes {
        return Err(L7MitmPolicyHookError::ResponseTooLarge {
            limit: max_response_bytes,
        });
    }
    let mut body = Vec::with_capacity(content_length);
    body.extend_from_slice(&prefetched_body[..prefetched_body.len().min(content_length)]);
    let mut chunk = [0_u8; 512];
    while body.len() < content_length {
        deadline.set_read_timeout(stream)?;
        let remaining = content_length - body.len();
        let read_capacity = remaining.min(chunk.len());
        let bytes_read = stream.read(&mut chunk[..read_capacity])?;
        if bytes_read == 0 {
            return Err(L7MitmPolicyHookError::InvalidResponse(
                "response ended before body was complete".to_string(),
            ));
        }
        body.extend_from_slice(&chunk[..bytes_read]);
    }
    Ok(body)
}

fn find_header_terminator(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

#[derive(Debug, PartialEq, Eq)]
struct ParsedResponseHead {
    status: u16,
    content_length: usize,
}

fn parse_response_head(head: &[u8]) -> Result<ParsedResponseHead, L7MitmPolicyHookError> {
    let head = std::str::from_utf8(head).map_err(|error| {
        L7MitmPolicyHookError::InvalidResponse(format!("response headers are not UTF-8: {error}"))
    })?;
    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| L7MitmPolicyHookError::InvalidResponse("missing status line".to_string()))?;
    let status = parse_status(status_line)?;
    let mut content_length = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(L7MitmPolicyHookError::InvalidResponse(format!(
                "malformed response header: {line}"
            )));
        };
        if name.eq_ignore_ascii_case("transfer-encoding")
            && value
                .split(',')
                .any(|encoding| encoding.trim().eq_ignore_ascii_case("chunked"))
        {
            return Err(L7MitmPolicyHookError::InvalidResponse(
                "chunked response bodies are not supported".to_string(),
            ));
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(L7MitmPolicyHookError::InvalidResponse(
                    "duplicate Content-Length".to_string(),
                ));
            }
            content_length = Some(value.trim().parse::<usize>().map_err(|error| {
                L7MitmPolicyHookError::InvalidResponse(format!("invalid Content-Length: {error}"))
            })?);
        }
    }
    Ok(ParsedResponseHead {
        status,
        content_length: content_length.ok_or_else(|| {
            L7MitmPolicyHookError::InvalidResponse("missing Content-Length".to_string())
        })?,
    })
}

fn parse_status(status_line: &str) -> Result<u16, L7MitmPolicyHookError> {
    let mut parts = status_line.split_whitespace();
    let version = parts.next();
    let status = parts.next();
    if version != Some("HTTP/1.1") && version != Some("HTTP/1.0") {
        return Err(L7MitmPolicyHookError::InvalidResponse(
            "status line must start with HTTP/1.1 or HTTP/1.0".to_string(),
        ));
    }
    status
        .ok_or_else(|| L7MitmPolicyHookError::InvalidResponse("missing status code".to_string()))?
        .parse::<u16>()
        .map_err(|error| {
            L7MitmPolicyHookError::InvalidResponse(format!("invalid status code: {error}"))
        })
}

struct HookDeadline {
    expires_at: Instant,
}

impl HookDeadline {
    fn after(timeout: Duration) -> Self {
        Self {
            expires_at: Instant::now()
                .checked_add(timeout)
                .expect("validated timeout must fit Instant"),
        }
    }

    fn remaining(&self) -> Result<Duration, L7MitmPolicyHookError> {
        self.expires_at
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(L7MitmPolicyHookError::Timeout)
    }

    fn set_read_timeout(&self, stream: &TcpStream) -> Result<(), L7MitmPolicyHookError> {
        stream.set_read_timeout(Some(self.remaining()?))?;
        Ok(())
    }

    fn set_write_timeout(&self, stream: &TcpStream) -> Result<(), L7MitmPolicyHookError> {
        stream.set_write_timeout(Some(self.remaining()?))?;
        Ok(())
    }
}

fn write_all_with_deadline(
    stream: &mut TcpStream,
    mut bytes: &[u8],
    deadline: &HookDeadline,
) -> Result<(), L7MitmPolicyHookError> {
    while !bytes.is_empty() {
        deadline.set_write_timeout(stream)?;
        match stream.write(bytes) {
            Ok(0) => {
                return Err(L7MitmPolicyHookError::Io(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write MITM policy hook request",
                )));
            }
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        io::{BufRead, BufReader},
        net::TcpListener,
        thread,
    };

    use enforcement::{
        EnforcementPlanRequest, EnforcementPlanner, PlannerPolicy, ProxySideEnforcementSurface,
        ScopedEnforcementPlanner,
    };
    use probe_core::{
        AddressPort, CaptureOrigin, CaptureSource, Direction, EnforcementOutcome, EventKind,
        FlowContext, FlowIdentity, OpaqueStream, ProcessContext, ProcessIdentity,
        ProtectiveActionProfile, Timestamp, TransportProtocol, VerdictScope,
    };

    use super::*;

    #[test]
    fn http_json_hook_delegates_action_from_loopback_endpoint()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let endpoint = endpoint_plan(listener.local_addr()?);
        let server = thread::spawn(move || -> Result<String, String> {
            let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
            let body = read_request_body(&stream)?;
            write_response(
                &mut stream,
                r#"{"outcome":"delegated","reason":"local proxy accepted"}"#,
            )?;
            Ok(body)
        });
        let hook = HttpJsonL7MitmPolicyHook::new(
            &endpoint,
            1_000,
            4_096,
            L7MitmPolicyHookConnectionOptions::default(),
        )?;
        let verdict = Verdict {
            action: Action::Deny,
            scope: VerdictScope::Flow,
            reason: "blocked".to_string(),
            confidence: 100,
            ttl_ms: None,
        };
        let trigger = outbound_event();

        let decision = planner_with_hook(hook)?
            .evaluate(EnforcementPlanRequest {
                verdict: &verdict,
                trigger: &trigger,
            })
            .expect("deny verdict should be evaluated");

        assert_eq!(decision.outcome, EnforcementOutcome::Delegated);
        assert_eq!(decision.effective_action, Action::Deny);
        let body = server.join().expect("server thread should not panic")?;
        assert!(body.contains("\"requested_action\":\"deny\""));
        Ok(())
    }

    #[test]
    fn http_json_hook_preserves_unsupported_decision() -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let endpoint = endpoint_plan(listener.local_addr()?);
        let server = thread::spawn(move || -> Result<(), String> {
            let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
            let _ = read_request_body(&stream)?;
            write_response(
                &mut stream,
                r#"{"outcome":"unsupported","reason":"reset unavailable"}"#,
            )
        });
        let hook = HttpJsonL7MitmPolicyHook::new(
            &endpoint,
            1_000,
            4_096,
            L7MitmPolicyHookConnectionOptions::default(),
        )?;
        let verdict = Verdict {
            action: Action::Reset,
            scope: VerdictScope::Flow,
            reason: "blocked".to_string(),
            confidence: 100,
            ttl_ms: None,
        };
        let trigger = outbound_event();

        let decision = planner_with_hook(hook)?
            .evaluate(EnforcementPlanRequest {
                verdict: &verdict,
                trigger: &trigger,
            })
            .expect("reset verdict should be evaluated");

        assert_eq!(decision.outcome, EnforcementOutcome::Unsupported);
        assert_eq!(decision.effective_action, Action::Observe);
        assert!(decision.reason.contains("reset unavailable"));
        server.join().expect("server thread should not panic")?;
        Ok(())
    }

    #[test]
    fn http_json_hook_uses_typed_loopback_endpoint() -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let mut endpoint = endpoint_plan(listener.local_addr()?);
        endpoint.endpoint = "http://203.0.113.10:1/raw-url-must-not-be-used".to_string();
        endpoint.path_and_query = "/typed-hook?source=plan".to_string();
        let server = thread::spawn(move || -> Result<String, String> {
            let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
            let (head, _) = read_request(&stream)?;
            write_response(
                &mut stream,
                r#"{"outcome":"delegated","reason":"mapped loopback accepted"}"#,
            )?;
            Ok(head)
        });
        let hook = HttpJsonL7MitmPolicyHook::new(
            &endpoint,
            1_000,
            4_096,
            L7MitmPolicyHookConnectionOptions::default(),
        )?;
        let verdict = Verdict {
            action: Action::Deny,
            scope: VerdictScope::Flow,
            reason: "blocked".to_string(),
            confidence: 100,
            ttl_ms: None,
        };
        let trigger = outbound_event();

        let decision = planner_with_hook(hook)?
            .evaluate(EnforcementPlanRequest {
                verdict: &verdict,
                trigger: &trigger,
            })
            .expect("deny verdict should be evaluated");

        assert_eq!(decision.outcome, EnforcementOutcome::Delegated);
        let head = server.join().expect("server thread should not panic")?;
        assert!(head.starts_with("POST /typed-hook?source=plan HTTP/1.1\r\n"));
        assert!(head.contains(&format!("Host: {}\r\n", endpoint.authority)));
        Ok(())
    }

    #[test]
    fn http_json_hook_preserves_socket_mark_connection_option()
    -> Result<(), Box<dyn std::error::Error>> {
        let mark = NonZeroU32::new(0x5450_0102).expect("mark must be non-zero");
        let connection = L7MitmPolicyHookConnectionOptions::default().with_socket_mark(mark);
        let hook = HttpJsonL7MitmPolicyHook::new(
            &endpoint_plan("127.0.0.1:1".parse()?),
            1_000,
            4_096,
            connection,
        )?;

        assert_eq!(hook.connection, connection);
        Ok(())
    }

    #[test]
    fn http_json_response_supports_keep_alive_content_length()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let endpoint = endpoint_plan(listener.local_addr()?);
        let server = thread::spawn(move || -> Result<TcpStream, String> {
            let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
            let _ = read_request_body(&stream)?;
            write_response_with_connection(
                &mut stream,
                "keep-alive",
                r#"{"outcome":"delegated","reason":"keep alive accepted"}"#,
            )?;
            Ok(stream)
        });
        let hook = HttpJsonL7MitmPolicyHook::new(
            &endpoint,
            1_000,
            4_096,
            L7MitmPolicyHookConnectionOptions::default(),
        )?;
        let verdict = Verdict {
            action: Action::Deny,
            scope: VerdictScope::Flow,
            reason: "blocked".to_string(),
            confidence: 100,
            ttl_ms: None,
        };
        let trigger = outbound_event();

        let decision = planner_with_hook(hook)?
            .evaluate(EnforcementPlanRequest {
                verdict: &verdict,
                trigger: &trigger,
            })
            .expect("deny verdict should be evaluated");

        assert_eq!(decision.outcome, EnforcementOutcome::Delegated);
        let _server_stream = server.join().expect("server thread should not panic")?;
        Ok(())
    }

    #[test]
    fn http_json_response_limit_applies_to_body() -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let server = thread::spawn(move || -> Result<(), String> {
            let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
            write_response(
                &mut stream,
                r#"{"outcome":"delegated","reason":"oversized"}"#,
            )
        });
        let stream = TcpStream::connect(address)?;

        let error = read_hook_response(stream, 8, &test_deadline())
            .expect_err("body must exceed configured limit");

        assert!(matches!(
            error,
            L7MitmPolicyHookError::ResponseTooLarge { limit: 8 }
        ));
        server.join().expect("server thread should not panic")?;
        Ok(())
    }

    #[test]
    fn http_json_response_rejects_non_success_status() -> Result<(), Box<dyn std::error::Error>> {
        let response = HttpJsonHookHttpResponse {
            status: 503,
            body: Vec::new(),
        };

        let error = parse_hook_response(response).expect_err("non-2xx status must fail");

        assert!(matches!(
            error,
            L7MitmPolicyHookError::Status { status: 503 }
        ));
        Ok(())
    }

    #[test]
    fn http_json_response_rejects_invalid_json() {
        let response = HttpJsonHookHttpResponse {
            status: 200,
            body: b"bad".to_vec(),
        };

        let error = parse_hook_response(response).expect_err("invalid JSON must fail");

        assert!(matches!(error, L7MitmPolicyHookError::Deserialize(_)));
    }

    #[test]
    fn http_json_response_rejects_chunked_even_after_content_length() {
        let error = parse_response_head(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: gzip, chunked\r\n",
        )
        .expect_err("chunked response bodies must be rejected");

        assert!(matches!(error, L7MitmPolicyHookError::InvalidResponse(_)));
    }

    #[test]
    fn http_json_response_rejects_duplicate_content_length() {
        let error =
            parse_response_head(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n")
                .expect_err("duplicate content length must be rejected");

        assert!(matches!(error, L7MitmPolicyHookError::InvalidResponse(_)));
    }

    #[test]
    fn http_json_response_rejects_oversized_headers() -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        let server = thread::spawn(move || -> Result<(), String> {
            let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nX-Padding: {}\r\n",
                "a".repeat(MAX_RESPONSE_HEADER_BYTES)
            )
            .map_err(|error| error.to_string())
        });
        let stream = TcpStream::connect(address)?;

        let error = read_hook_response(stream, 4_096, &test_deadline())
            .expect_err("oversized headers must fail before body parsing");

        assert!(matches!(error, L7MitmPolicyHookError::InvalidResponse(_)));
        server.join().expect("server thread should not panic")?;
        Ok(())
    }

    fn planner_with_hook(
        hook: HttpJsonL7MitmPolicyHook,
    ) -> Result<ScopedEnforcementPlanner, enforcement::EnforcementError> {
        ScopedEnforcementPlanner::with_proxy_side_policy_hook(
            PlannerPolicy::compile(
                None,
                ProtectiveActionProfile::new([Action::Deny, Action::Reset])?,
            )?,
            ProxySideEnforcementSurface::L7Mitm,
            hook,
        )
    }

    fn endpoint_plan(address: SocketAddr) -> TransparentInterceptionMitmPolicyHookEndpointPlan {
        TransparentInterceptionMitmPolicyHookEndpointPlan {
            endpoint: format!("http://{address}/enforce"),
            address,
            authority: address.to_string(),
            path_and_query: "/enforce".to_string(),
        }
    }

    fn read_request(stream: &TcpStream) -> Result<(String, String), String> {
        let mut reader = BufReader::new(stream.try_clone().map_err(|error| error.to_string())?);
        let mut head = String::new();
        let mut content_length = None;
        loop {
            let mut line = String::new();
            reader
                .read_line(&mut line)
                .map_err(|error| error.to_string())?;
            if line == "\r\n" {
                break;
            }
            head.push_str(&line);
            if let Some(value) = line.strip_prefix("Content-Length:") {
                content_length = Some(
                    value
                        .trim()
                        .parse::<usize>()
                        .map_err(|error| error.to_string())?,
                );
            }
        }
        let mut body = vec![0_u8; content_length.ok_or("missing content length")?];
        reader
            .read_exact(&mut body)
            .map_err(|error| error.to_string())?;
        Ok((
            head,
            String::from_utf8(body).map_err(|error| error.to_string())?,
        ))
    }

    fn read_request_body(stream: &TcpStream) -> Result<String, String> {
        read_request(stream).map(|(_, body)| body)
    }

    fn write_response(stream: &mut TcpStream, body: &str) -> Result<(), String> {
        write_response_with_connection(stream, "close", body)
    }

    fn write_response_with_connection(
        stream: &mut TcpStream,
        connection: &str,
        body: &str,
    ) -> Result<(), String> {
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n{}",
            body.len(),
            connection,
            body
        )
        .map_err(|error| error.to_string())
    }

    fn test_deadline() -> HookDeadline {
        HookDeadline::after(Duration::from_secs(1))
    }

    fn outbound_event() -> EventEnvelope {
        EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1_700_000_000,
            },
            flow_context(),
            CaptureOrigin::from_source(CaptureSource::Replay),
            "test-config",
            EventKind::OpaqueStream(OpaqueStream {
                direction: Direction::Outbound,
                fingerprint: vec![1, 2, 3],
                reason: "test payload".to_string(),
            }),
        )
    }

    fn flow_context() -> FlowContext {
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
                    systemd_service: Some("app.service".to_string()),
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
            protocol: TransportProtocol::Tcp,
            start_monotonic_ns: 1,
            socket_cookie: None,
            attribution_confidence: 100,
        }
    }
}
