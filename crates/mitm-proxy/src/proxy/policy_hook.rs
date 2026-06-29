use std::{
    net::{TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
};

use probe_core::{Action, EventEnvelope, Verdict};
use serde::{Deserialize, Serialize};

use crate::{
    MitmProxyError,
    error::io_error,
    http::{read_http_message, write_json_response},
};

use super::{ACCEPT_IDLE_SLEEP, ProxyState, configure_stream};

pub(super) fn spawn_policy_hook_listener(
    listener: TcpListener,
    state: Arc<ProxyState>,
    shutdown: Arc<AtomicBool>,
) -> JoinHandle<Result<(), MitmProxyError>> {
    thread::spawn(move || accept_connections(listener, state, shutdown))
}

fn accept_connections(
    listener: TcpListener,
    state: Arc<ProxyState>,
    shutdown: Arc<AtomicBool>,
) -> Result<(), MitmProxyError> {
    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _peer)) => {
                let state = Arc::clone(&state);
                thread::spawn(move || {
                    if let Err(error) = handle_connection(stream, state) {
                        eprintln!("MITM proxy policy hook connection failed: {error}");
                    }
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_IDLE_SLEEP);
            }
            Err(source) => {
                return Err(io_error("accept MITM proxy policy hook connection")(source));
            }
        }
    }
    Ok(())
}

fn handle_connection(mut stream: TcpStream, state: Arc<ProxyState>) -> Result<(), MitmProxyError> {
    configure_stream(&stream, state.config.io_timeout)?;
    let request = match read_http_message(&mut stream, state.config.max_request_bytes) {
        Ok(Some(request)) => request,
        Ok(None) => return Ok(()),
        Err(error) => {
            write_json_response(&mut stream, 400, unsupported_response(error.to_string()))?;
            return Ok(());
        }
    };

    if request.method != "POST" || request.path != state.config.policy_hook_path {
        write_json_response(
            &mut stream,
            200,
            unsupported_response(format!(
                "expected POST {}, got {} {}",
                state.config.policy_hook_path, request.method, request.path
            )),
        )?;
        return Ok(());
    }

    let body = match serde_json::from_slice::<PolicyHookRequest>(&request.body) {
        Ok(body) => body,
        Err(error) => {
            write_json_response(&mut stream, 400, unsupported_response(error.to_string()))?;
            return Ok(());
        }
    };

    if body.verdict.action != body.requested_action {
        write_json_response(
            &mut stream,
            200,
            unsupported_response(format!(
                "verdict action {:?} did not match requested action {:?}",
                body.verdict.action, body.requested_action
            )),
        )?;
        return Ok(());
    }

    let Some(flow) = body.trigger.flow() else {
        write_json_response(
            &mut stream,
            200,
            unsupported_response("policy hook trigger did not contain a flow"),
        )?;
        return Ok(());
    };

    match body.requested_action {
        Action::Deny => {
            let reason = Some(body.verdict.reason);
            if state.registry.deny(&flow.id.0, reason.clone()) {
                write_json_response(&mut stream, 200, delegated_response(Action::Deny, reason))
            } else {
                write_json_response(
                    &mut stream,
                    200,
                    unsupported_response(format!(
                        "flow {} is not pending in MITM proxy",
                        flow.id.0
                    )),
                )
            }
        }
        action => write_json_response(
            &mut stream,
            200,
            unsupported_response(format!("MITM proxy does not support action {action:?}")),
        ),
    }
}

#[derive(Debug, Deserialize)]
struct PolicyHookRequest {
    requested_action: Action,
    verdict: Verdict,
    trigger: EventEnvelope,
}

#[derive(Debug, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
enum PolicyHookResponse {
    Delegated {
        executed_action: Action,
        reason: Option<String>,
    },
    Unsupported {
        reason: String,
    },
}

fn delegated_response(action: Action, reason: Option<String>) -> PolicyHookResponse {
    PolicyHookResponse::Delegated {
        executed_action: action,
        reason,
    }
}

fn unsupported_response(reason: impl Into<String>) -> PolicyHookResponse {
    PolicyHookResponse::Unsupported {
        reason: reason.into(),
    }
}
