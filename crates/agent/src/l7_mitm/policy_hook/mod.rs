use std::{convert::TryFrom, io, num::NonZeroU32, time::Duration};

mod http;

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

use http::{
    HookDeadline, HttpJsonEndpoint, HttpJsonHookHttpResponse, read_hook_response,
    write_hook_request,
};

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
        parse_hook_response(response, request.verdict.action)
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

#[derive(Serialize)]
struct HttpJsonHookRequest<'a> {
    requested_action: Action,
    verdict: &'a Verdict,
    trigger: &'a EventEnvelope,
}

#[derive(Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
enum HttpJsonHookResponse {
    Delegated {
        executed_action: Action,
        reason: Option<String>,
    },
    Unsupported {
        reason: Option<String>,
    },
}

fn parse_hook_response(
    response: HttpJsonHookHttpResponse,
    requested_action: Action,
) -> Result<ProxySideEnforcementHookDecision, L7MitmPolicyHookError> {
    if !(200..300).contains(&response.status) {
        return Err(L7MitmPolicyHookError::Status {
            status: response.status,
        });
    }
    match serde_json::from_slice::<HttpJsonHookResponse>(&response.body)
        .map_err(L7MitmPolicyHookError::Deserialize)?
    {
        HttpJsonHookResponse::Delegated {
            executed_action,
            reason,
        } => {
            if executed_action != requested_action {
                return Err(L7MitmPolicyHookError::InvalidResponse(format!(
                    "delegated response executed_action {executed_action:?} did not match requested_action {requested_action:?}"
                )));
            }
            Ok(ProxySideEnforcementHookDecision::delegated(
                executed_action,
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

#[cfg(test)]
mod tests {
    use std::{
        io::{BufRead, BufReader, Read, Write},
        net::{SocketAddr, TcpListener, TcpStream},
        thread,
    };

    use enforcement::{
        EnforcementPlanRequest, EnforcementPlanner, PlannerPolicy, ProxySideEnforcementSurface,
        ScopedEnforcementPlanner,
    };
    use probe_core::{
        AddressPort, CaptureOrigin, CaptureSource, Direction, EnforcementExecutionEvidence,
        EnforcementOutcome, EventKind, FlowContext, FlowIdentity, OpaqueStream, ProcessContext,
        ProcessIdentity, ProtectiveActionProfile, Timestamp, TransportProtocol, VerdictScope,
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
                r#"{"outcome":"delegated","executed_action":"deny","reason":"local proxy accepted"}"#,
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

        assert_eq!(
            decision.outcome,
            EnforcementOutcome::Delegated,
            "{}",
            decision.reason
        );
        assert_eq!(decision.effective_action, Action::Deny);
        assert_eq!(
            decision.execution,
            Some(EnforcementExecutionEvidence::ProxySideHook {
                surface: ProxySideEnforcementSurface::L7Mitm,
                executed_action: Action::Deny,
                reason: "local proxy accepted".to_string(),
            })
        );
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
        assert_eq!(decision.execution, None);
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
                r#"{"outcome":"delegated","executed_action":"deny","reason":"mapped loopback accepted"}"#,
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

        assert_eq!(
            decision.outcome,
            EnforcementOutcome::Delegated,
            "{}",
            decision.reason
        );
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
                r#"{"outcome":"delegated","executed_action":"deny","reason":"keep alive accepted"}"#,
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
    fn http_json_hook_accepts_chunked_response_body() -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let endpoint = endpoint_plan(listener.local_addr()?);
        let server = thread::spawn(move || -> Result<(), String> {
            let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
            let _ = read_request_body(&stream)?;
            let first = "{\"outcome\":\"delegated\",\"executed_action\":\"deny\",\"reason\":\"";
            let second = r#"chunked accepted"}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x};part=one\r\n{}\r\n{:x}\r\n{}\r\n0\r\nX-Hook: done\r\n\r\n",
                first.len(),
                first,
                second.len(),
                second
            )
            .map_err(|error| error.to_string())
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

        assert_eq!(
            decision.outcome,
            EnforcementOutcome::Delegated,
            "{}",
            decision.reason
        );
        assert_eq!(decision.effective_action, Action::Deny);
        assert_eq!(
            decision.execution,
            Some(EnforcementExecutionEvidence::ProxySideHook {
                surface: ProxySideEnforcementSurface::L7Mitm,
                executed_action: Action::Deny,
                reason: "chunked accepted".to_string(),
            })
        );
        assert!(decision.reason.contains("chunked accepted"));
        server.join().expect("server thread should not panic")?;
        Ok(())
    }

    #[test]
    fn http_json_response_rejects_non_success_status() -> Result<(), Box<dyn std::error::Error>> {
        let response = HttpJsonHookHttpResponse {
            status: 503,
            body: Vec::new(),
        };

        let error =
            parse_hook_response(response, Action::Deny).expect_err("non-2xx status must fail");

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

        let error =
            parse_hook_response(response, Action::Deny).expect_err("invalid JSON must fail");

        assert!(matches!(error, L7MitmPolicyHookError::Deserialize(_)));
    }

    #[test]
    fn http_json_hook_fails_decision_when_executed_action_does_not_match()
    -> Result<(), Box<dyn std::error::Error>> {
        let decision = evaluate_hook_response(
            r#"{"outcome":"delegated","executed_action":"reset","reason":"wrong action"}"#,
        )?;

        assert_eq!(decision.outcome, EnforcementOutcome::Failed);
        assert_eq!(decision.effective_action, Action::Observe);
        assert_eq!(decision.execution, None);
        assert!(decision.reason.contains("executed_action Reset"));
        assert!(decision.reason.contains("requested_action Deny"));
        Ok(())
    }

    #[test]
    fn http_json_hook_fails_decision_when_executed_action_is_missing()
    -> Result<(), Box<dyn std::error::Error>> {
        let decision =
            evaluate_hook_response(r#"{"outcome":"delegated","reason":"missing action"}"#)?;

        assert_eq!(decision.outcome, EnforcementOutcome::Failed);
        assert_eq!(decision.effective_action, Action::Observe);
        assert_eq!(decision.execution, None);
        assert!(decision.reason.contains("response JSON failed"));
        assert!(decision.reason.contains("executed_action"));
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

    fn evaluate_hook_response(
        response_body: &'static str,
    ) -> Result<probe_core::EnforcementDecision, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let endpoint = endpoint_plan(listener.local_addr()?);
        let server = thread::spawn(move || -> Result<(), String> {
            let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
            let _ = read_request_body(&stream)?;
            write_response(&mut stream, response_body)
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
        server
            .join()
            .expect("server thread should not panic")
            .map_err(std::io::Error::other)?;
        Ok(decision)
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
