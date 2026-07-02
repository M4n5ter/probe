use probe_core::{Direction, EventEnvelope, EventKind};

use crate::admin::EventTailRecord;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrafficRow {
    pub(crate) sequence: u64,
    pub(crate) process: String,
    pub(crate) event_type: String,
    pub(crate) direction: String,
    pub(crate) endpoint: String,
    pub(crate) summary: String,
}

impl TrafficRow {
    pub(super) fn from_record(record: EventTailRecord) -> Self {
        Self::from_event(record.sequence, &record.event)
    }

    fn from_event(sequence: u64, event: &EventEnvelope) -> Self {
        let flow = event.flow();
        Self {
            sequence,
            process: flow
                .map(|flow| format!("{} ({})", flow.process.name, flow.process.identity.pid))
                .unwrap_or_else(|| "provider".to_string()),
            event_type: event.kind().event_type().as_str().to_string(),
            direction: event
                .kind()
                .direction()
                .map(direction_label)
                .unwrap_or("-")
                .to_string(),
            endpoint: flow
                .map(|flow| format!("{}:{}", flow.remote.address, flow.remote.port))
                .unwrap_or_else(|| "-".to_string()),
            summary: summarize_event(event.kind()),
        }
    }
}

fn direction_label(direction: Direction) -> &'static str {
    match direction {
        Direction::Inbound => "in",
        Direction::Outbound => "out",
    }
}

fn summarize_event(kind: &EventKind) -> String {
    match kind {
        EventKind::ConnectionOpened => "connection opened".to_string(),
        EventKind::ConnectionClosed => "connection closed".to_string(),
        EventKind::HttpRequestHeaders(headers) => format!(
            "{} {}",
            headers.method.as_deref().unwrap_or("-"),
            headers.target.as_deref().unwrap_or("-")
        ),
        EventKind::HttpResponseHeaders(headers) => format!(
            "{} {}",
            headers
                .status
                .map(|status| status.to_string())
                .unwrap_or_else(|| "-".to_string()),
            headers.reason.as_deref().unwrap_or("")
        ),
        EventKind::HttpBodyChunk(chunk) => {
            format!("body {} bytes at {}", chunk.data.len(), chunk.offset)
        }
        EventKind::SseEvent(event) => {
            format!("sse {} bytes", event.data.len())
        }
        EventKind::WebSocketHandoff(handoff) => format!(
            "websocket {}",
            handoff.target.as_deref().unwrap_or("handoff")
        ),
        EventKind::WebSocketFrame(frame) => {
            format!("ws frame {:?} {} bytes", frame.opcode, frame.payload_len)
        }
        EventKind::WebSocketMessage(message) => {
            format!(
                "ws message {:?} {} bytes",
                message.opcode, message.payload_len
            )
        }
        EventKind::OpaqueStream(stream) => stream.reason.clone(),
        EventKind::CaptureLoss(loss) => {
            format!("capture loss {} events: {}", loss.lost_events, loss.reason)
        }
        EventKind::Gap(gap) => gap.reason.clone(),
        EventKind::ProtocolError(error) => error.reason.clone(),
        EventKind::PolicyAlert(alert) => alert.message.clone(),
        EventKind::PolicyVerdict(verdict) => {
            format!("verdict {:?}: {}", verdict.action, verdict.reason)
        }
        EventKind::PolicyRuntimeError(error) => error.reason.clone(),
        EventKind::EnforcementDecision(decision) => {
            format!("{:?}: {}", decision.outcome, decision.reason)
        }
        EventKind::L7MitmAudit(audit) => audit
            .reason()
            .map(str::to_string)
            .unwrap_or_else(|| format!("{:?}", audit.phase())),
    }
}

#[cfg(test)]
mod tests {
    use probe_core::{
        AddressPort, CaptureOrigin, CaptureSource, FlowContext, FlowIdentity, HttpHeaders,
        ProcessContext, ProcessIdentity, Timestamp, TransportProtocol,
    };

    use super::*;

    #[test]
    fn traffic_row_does_not_retain_raw_argv() {
        let event = EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            flow_with_raw_argv(),
            CaptureOrigin::from_source(CaptureSource::Replay),
            "test",
            EventKind::HttpRequestHeaders(HttpHeaders {
                direction: Direction::Outbound,
                stream_sequence: 1,
                method: Some("GET".to_string()),
                target: Some("/health".to_string()),
                status: None,
                reason: None,
                version: "HTTP/1.1".to_string(),
                headers: Vec::new(),
            }),
        );

        let row = TrafficRow::from_event(7, &event);

        assert_eq!(row.sequence, 7);
        assert_eq!(row.process, "curl (42)");
        assert_eq!(row.summary, "GET /health");
        assert!(!format!("{row:?}").contains("--secret-token"));
    }

    fn flow_with_raw_argv() -> FlowContext {
        let process = ProcessContext {
            identity: ProcessIdentity {
                pid: 42,
                tgid: 42,
                start_time_ticks: 7,
                boot_id: "boot".to_string(),
                exe_path: "/usr/bin/curl".to_string(),
                cmdline_hash: "hash".to_string(),
                uid: 1000,
                gid: 1000,
                cgroup: None,
                systemd_service: None,
                container_id: None,
                runtime_hint: None,
            },
            name: "curl".to_string(),
            cmdline: vec!["curl".to_string(), "--secret-token".to_string()],
        };
        let local = AddressPort {
            address: "127.0.0.1".to_string(),
            port: 50_000,
        };
        let remote = AddressPort {
            address: "127.0.0.1".to_string(),
            port: 80,
        };
        FlowContext {
            id: FlowIdentity::stable(
                &process.identity,
                &local,
                &remote,
                TransportProtocol::Tcp,
                1,
                None,
            ),
            process,
            local,
            remote,
            protocol: TransportProtocol::Tcp,
            start_monotonic_ns: 1,
            socket_cookie: None,
            attribution_confidence: 100,
        }
    }
}
