use std::collections::BTreeMap;

use probe_core::{Direction, WebSocketHandoff, WebSocketMessageOpcode, WebSocketOpcode};

use super::text::{bytes_detail, direction_label, fit_preview_lines, hex_or_dash};
use super::{event_ref::TrafficEventRef, rows::TrafficRow};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WebSocketSessionRow {
    pub(crate) sequence: u64,
    pub(crate) process: String,
    pub(crate) capture_path: &'static str,
    pub(crate) target: String,
    pub(crate) direction: String,
    pub(crate) endpoint: String,
    pub(crate) frames: usize,
    pub(crate) messages: usize,
    pub(crate) payload_bytes: u64,
    pub(crate) summary: String,
    handoff: Option<WebSocketHandoff>,
    frame_events: Vec<WebSocketFrameEvent>,
    message_events: Vec<WebSocketMessageEvent>,
    raw_sequences: Vec<u64>,
    latest_sequence: u64,
    identity: WebSocketSessionIdentity,
}

impl WebSocketSessionRow {
    pub(crate) fn identity(&self) -> WebSocketSessionIdentity {
        self.identity.clone()
    }

    pub(crate) fn matches_identity(&self, identity: &WebSocketSessionIdentity) -> bool {
        &self.identity == identity
    }

    pub(crate) fn order_sequence(&self) -> u64 {
        self.latest_sequence
    }

    pub(crate) fn detail_lines(&self) -> Vec<String> {
        let mut lines = vec![
            format!("Sequence: {}", self.sequence),
            "View: WebSocket session".to_string(),
            format!("Process: {}", self.process),
            format!("Capture path: {}", self.capture_path),
            format!("Direction: {}", self.direction),
            format!("Remote: {}", self.endpoint),
            format!("Target: {}", self.target),
            format!("Summary: {}", self.summary),
        ];
        lines.extend(self.handoff_detail_lines());
        lines.extend(self.message_detail_lines());
        lines.extend(self.frame_detail_lines());
        lines.push(format!(
            "Raw event sequences: {}",
            self.raw_sequences
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ));
        lines
    }

    pub(crate) fn preview_lines(&self, max_lines: usize) -> Vec<String> {
        let lines = vec![
            format!("Sequence: {}", self.sequence),
            "View: WebSocket session".to_string(),
            format!("Process: {}", self.process),
            format!("Remote: {}", self.endpoint),
            format!("Target: {}", self.target),
            format!("Frames: {}", self.frames),
            format!("Messages: {}", self.messages),
            format!("Message payload: {} bytes", self.payload_bytes),
            "Open detail for handoff, frames, messages, and payloads".to_string(),
        ];
        fit_preview_lines(lines, max_lines)
    }

    pub(crate) fn detail_fetch_sequences(&self) -> Vec<u64> {
        self.message_events
            .iter()
            .filter(|message| message.payload.is_none())
            .map(|message| message.sequence)
            .collect()
    }

    fn handoff_detail_lines(&self) -> Vec<String> {
        let mut lines = vec!["Handoff".to_string()];
        match &self.handoff {
            Some(handoff) => {
                lines.push(format!(
                    "  Direction: {}",
                    direction_label(handoff.direction)
                ));
                lines.push(format!("  Stream: {}", handoff.stream_sequence));
                lines.push(format!(
                    "  Target: {}",
                    handoff.target.as_deref().unwrap_or("-")
                ));
                lines.push(format!(
                    "  Subprotocol: {}",
                    handoff.subprotocol.as_deref().unwrap_or("-")
                ));
                lines.push(format!(
                    "  Extensions: {}",
                    if handoff.extensions.is_empty() {
                        "-".to_string()
                    } else {
                        handoff.extensions.join(", ")
                    }
                ));
            }
            None => lines.push("  Handoff was not observed in current window".to_string()),
        }
        lines
    }

    fn message_detail_lines(&self) -> Vec<String> {
        let mut lines = vec![format!("Messages: {}", self.message_events.len())];
        if self.message_events.is_empty() {
            lines.push("  -".to_string());
            return lines;
        }
        for message in &self.message_events {
            lines.push(format!(
                "  #{} {} {} bytes frames {}..{} direction {}",
                message.message_sequence,
                message_opcode_label(message.opcode),
                message.payload_len,
                message.first_frame_sequence,
                message.final_frame_sequence,
                direction_label(message.direction)
            ));
            lines.push(format!(
                "    Payload: {}",
                message
                    .payload
                    .as_deref()
                    .map(bytes_detail)
                    .unwrap_or_else(|| "open raw event detail".to_string())
            ));
            lines.push(format!(
                "    Fingerprint: {}",
                hex_or_dash(&message.payload_fingerprint)
            ));
        }
        lines
    }

    fn frame_detail_lines(&self) -> Vec<String> {
        let mut lines = vec![format!("Frames: {}", self.frame_events.len())];
        if self.frame_events.is_empty() {
            lines.push("  -".to_string());
            return lines;
        }
        for frame in &self.frame_events {
            lines.push(format!(
                "  #{} {} fin={} payload={} masked={} direction={} fingerprint={}",
                frame.frame_sequence,
                frame_opcode_label(frame.opcode),
                frame.fin,
                frame.payload_len,
                frame.masked,
                direction_label(frame.direction),
                hex_or_dash(&frame.payload_fingerprint)
            ));
        }
        lines
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct WebSocketSessionIdentity {
    flow_id: String,
    stream_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WebSocketFrameEvent {
    direction: Direction,
    frame_sequence: u64,
    fin: bool,
    opcode: WebSocketOpcode,
    payload_len: u64,
    masked: bool,
    payload_fingerprint: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WebSocketMessageEvent {
    sequence: u64,
    direction: Direction,
    message_sequence: u64,
    first_frame_sequence: u64,
    final_frame_sequence: u64,
    opcode: WebSocketMessageOpcode,
    payload_len: u64,
    payload: Option<Vec<u8>>,
    payload_fingerprint: Vec<u8>,
}

#[derive(Debug, Clone)]
struct WebSocketSessionBuilder {
    identity: WebSocketSessionIdentity,
    first_sequence: u64,
    process: String,
    capture_path: &'static str,
    endpoint: String,
    handoff: Option<WebSocketHandoff>,
    frame_events: Vec<WebSocketFrameEvent>,
    message_events: Vec<WebSocketMessageEvent>,
    raw_sequences: Vec<u64>,
    latest_sequence: u64,
}

impl WebSocketSessionBuilder {
    fn new(identity: WebSocketSessionIdentity, row: &TrafficRow) -> Self {
        Self {
            identity,
            first_sequence: row.sequence,
            process: row.process.clone(),
            capture_path: row.capture_path,
            endpoint: row.endpoint.clone(),
            handoff: None,
            frame_events: Vec::new(),
            message_events: Vec::new(),
            raw_sequences: Vec::new(),
            latest_sequence: row.sequence,
        }
    }

    fn observe(&mut self, row: &TrafficRow, event: TrafficEventRef<'_>) {
        self.first_sequence = self.first_sequence.min(row.sequence);
        self.latest_sequence = self.latest_sequence.max(row.sequence);
        self.raw_sequences.push(row.sequence);
        if let Some(handoff) = event.websocket_handoff() {
            self.handoff = Some(handoff.clone());
        } else if let Some(frame) = event.websocket_frame() {
            self.frame_events.push(WebSocketFrameEvent {
                direction: frame.direction,
                frame_sequence: frame.frame_sequence,
                fin: frame.fin,
                opcode: frame.opcode,
                payload_len: frame.payload_len,
                masked: frame.masked,
                payload_fingerprint: frame.payload_fingerprint.clone(),
            });
        } else if let Some(message) = event.websocket_message() {
            self.message_events.push(WebSocketMessageEvent {
                sequence: row.sequence,
                direction: message.direction,
                message_sequence: message.message_sequence,
                first_frame_sequence: message.first_frame_sequence,
                final_frame_sequence: message.final_frame_sequence,
                opcode: message.opcode,
                payload_len: message.payload_len,
                payload: message.payload.map(<[u8]>::to_vec),
                payload_fingerprint: message.payload_fingerprint.to_vec(),
            });
        }
    }

    fn into_row(mut self) -> WebSocketSessionRow {
        self.raw_sequences.sort_unstable();
        self.raw_sequences.dedup();
        self.frame_events.sort_by_key(|frame| frame.frame_sequence);
        self.message_events
            .sort_by_key(|message| message.message_sequence);
        let target = self
            .handoff
            .as_ref()
            .and_then(|handoff| handoff.target.clone())
            .unwrap_or_else(|| "-".to_string());
        let direction = self
            .handoff
            .as_ref()
            .map(|handoff| direction_label(handoff.direction).to_string())
            .or_else(|| {
                self.message_events
                    .first()
                    .map(|message| direction_label(message.direction).to_string())
            })
            .or_else(|| {
                self.frame_events
                    .first()
                    .map(|frame| direction_label(frame.direction).to_string())
            })
            .unwrap_or_else(|| "-".to_string());
        let payload_bytes = self
            .message_events
            .iter()
            .map(|message| message.payload_len)
            .sum::<u64>();
        let frames = self.frame_events.len();
        let messages = self.message_events.len();
        let summary = format!("{target} ({frames} frames, {messages} messages, {payload_bytes} B)");
        WebSocketSessionRow {
            sequence: self.first_sequence,
            process: self.process,
            capture_path: self.capture_path,
            target,
            direction,
            endpoint: self.endpoint,
            frames,
            messages,
            payload_bytes,
            summary,
            handoff: self.handoff,
            frame_events: self.frame_events,
            message_events: self.message_events,
            raw_sequences: self.raw_sequences,
            latest_sequence: self.latest_sequence,
            identity: self.identity,
        }
    }
}

pub(super) fn build_websocket_session_rows(rows: &[TrafficRow]) -> Vec<WebSocketSessionRow> {
    let mut sessions = BTreeMap::<WebSocketSessionIdentity, WebSocketSessionBuilder>::new();
    let mut ordered_rows = rows.iter().collect::<Vec<_>>();
    ordered_rows.sort_by_key(|row| row.sequence);
    for row in ordered_rows {
        let Some(event) = row.event_ref() else {
            continue;
        };
        let Some(key) = websocket_session_key(event) else {
            continue;
        };
        sessions
            .entry(key.clone())
            .or_insert_with(|| WebSocketSessionBuilder::new(key, row))
            .observe(row, event);
    }
    let mut rows = sessions
        .into_values()
        .map(WebSocketSessionBuilder::into_row)
        .collect::<Vec<_>>();
    rows.sort_by_key(|row| std::cmp::Reverse(row.order_sequence()));
    rows
}

fn websocket_session_key(event: TrafficEventRef<'_>) -> Option<WebSocketSessionIdentity> {
    let flow_id = event.flow()?.id.0.clone();
    let stream_sequence = event
        .websocket_handoff()
        .map(|handoff| handoff.stream_sequence)
        .or_else(|| event.websocket_frame().map(|frame| frame.stream_sequence))
        .or_else(|| {
            event
                .websocket_message()
                .map(|message| message.stream_sequence)
        })?;
    Some(WebSocketSessionIdentity {
        flow_id,
        stream_sequence,
    })
}

fn message_opcode_label(opcode: WebSocketMessageOpcode) -> &'static str {
    match opcode {
        WebSocketMessageOpcode::Text => "text",
        WebSocketMessageOpcode::Binary => "binary",
    }
}

fn frame_opcode_label(opcode: WebSocketOpcode) -> String {
    match opcode {
        WebSocketOpcode::Continuation => "continuation".to_string(),
        WebSocketOpcode::Text => "text".to_string(),
        WebSocketOpcode::Binary => "binary".to_string(),
        WebSocketOpcode::Close => "close".to_string(),
        WebSocketOpcode::Ping => "ping".to_string(),
        WebSocketOpcode::Pong => "pong".to_string(),
        WebSocketOpcode::Other { code } => format!("other({code})"),
    }
}

#[cfg(test)]
mod tests {
    use probe_core::{
        AddressPort, CaptureOrigin, CaptureSource, EventEnvelope, EventKind, FlowContext,
        FlowIdentity, ProcessContext, ProcessIdentity, Timestamp, TransportProtocol,
        WebSocketFrame, WebSocketMessage,
    };

    use super::*;

    #[test]
    fn groups_websocket_handoff_frames_and_messages_into_session() {
        let rows = vec![
            TrafficRow::from_event(
                1,
                event(EventKind::WebSocketHandoff(WebSocketHandoff {
                    direction: Direction::Outbound,
                    stream_sequence: 3,
                    target: Some("/ws".to_string()),
                    subprotocol: Some("chat".to_string()),
                    extensions: vec!["permessage-deflate".to_string()],
                })),
            ),
            TrafficRow::from_event(
                2,
                event(EventKind::WebSocketFrame(WebSocketFrame {
                    direction: Direction::Outbound,
                    stream_sequence: 3,
                    frame_sequence: 1,
                    fin: true,
                    rsv1: false,
                    rsv2: false,
                    rsv3: false,
                    opcode: WebSocketOpcode::Text,
                    payload_len: 5,
                    masked: true,
                    payload_fingerprint: vec![0xaa],
                })),
            ),
            TrafficRow::from_event(
                3,
                event(EventKind::WebSocketMessage(WebSocketMessage {
                    direction: Direction::Outbound,
                    stream_sequence: 3,
                    message_sequence: 1,
                    first_frame_sequence: 1,
                    final_frame_sequence: 1,
                    opcode: WebSocketMessageOpcode::Text,
                    payload_len: 5,
                    payload: b"hello".to_vec().into(),
                    payload_fingerprint: vec![0xbb],
                })),
            ),
        ];

        let sessions = build_websocket_session_rows(&rows);

        let [session] = sessions.as_slice() else {
            panic!("expected one websocket session: {sessions:?}");
        };
        assert_eq!(session.sequence, 1);
        assert_eq!(session.target, "/ws");
        assert_eq!(session.frames, 1);
        assert_eq!(session.messages, 1);
        assert_eq!(session.payload_bytes, 5);
        assert_eq!(session.summary, "/ws (1 frames, 1 messages, 5 B)");
        let details = session.detail_lines();
        assert!(details.iter().any(|line| line == "  Subprotocol: chat"));
        assert!(details.iter().any(|line| line == "    Payload: hello"));
        assert!(
            details
                .iter()
                .any(|line| line.contains("#1 text fin=true payload=5"))
        );
    }

    #[test]
    fn orders_sessions_newest_first_by_latest_observed_sequence() {
        let rows = vec![
            TrafficRow::from_event(
                1,
                event_with_flow_id(
                    "z-late-flow",
                    EventKind::WebSocketHandoff(WebSocketHandoff {
                        direction: Direction::Outbound,
                        stream_sequence: 1,
                        target: Some("/late".to_string()),
                        subprotocol: None,
                        extensions: Vec::new(),
                    }),
                ),
            ),
            TrafficRow::from_event(
                10,
                event_with_flow_id(
                    "a-early-flow",
                    EventKind::WebSocketHandoff(WebSocketHandoff {
                        direction: Direction::Outbound,
                        stream_sequence: 1,
                        target: Some("/early".to_string()),
                        subprotocol: None,
                        extensions: Vec::new(),
                    }),
                ),
            ),
            TrafficRow::from_event(
                20,
                event_with_flow_id(
                    "z-late-flow",
                    EventKind::WebSocketMessage(WebSocketMessage {
                        direction: Direction::Outbound,
                        stream_sequence: 1,
                        message_sequence: 1,
                        first_frame_sequence: 1,
                        final_frame_sequence: 1,
                        opcode: WebSocketMessageOpcode::Text,
                        payload_len: 4,
                        payload: b"late".to_vec().into(),
                        payload_fingerprint: vec![0xcc],
                    }),
                ),
            ),
        ];

        let sessions = build_websocket_session_rows(&rows);

        assert_eq!(
            sessions
                .iter()
                .map(|session| session.target.as_str())
                .collect::<Vec<_>>(),
            vec!["/late", "/early"]
        );
    }

    fn event(kind: EventKind) -> EventEnvelope {
        event_with_flow_id("flow-a", kind)
    }

    fn event_with_flow_id(flow_id: &str, kind: EventKind) -> EventEnvelope {
        let mut flow = flow();
        flow.id = FlowIdentity(flow_id.to_string());
        EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            flow,
            CaptureOrigin::from_source(CaptureSource::Replay),
            "test",
            kind,
        )
    }

    fn flow() -> FlowContext {
        let process = ProcessIdentity {
            pid: 7,
            tgid: 7,
            start_time_ticks: 1,
            boot_id: "boot".to_string(),
            exe_path: "/usr/bin/backend".to_string(),
            cmdline_hash: "hash".to_string(),
            uid: 0,
            gid: 0,
            cgroup: None,
            systemd_service: None,
            container_id: None,
            runtime_hint: None,
        };
        let local = AddressPort {
            address: "127.0.0.1".to_string(),
            port: 50_000,
        };
        let remote = AddressPort {
            address: "127.0.0.1".to_string(),
            port: 8080,
        };
        FlowContext {
            id: FlowIdentity::stable(&process, &local, &remote, TransportProtocol::Tcp, 1, None),
            process: ProcessContext {
                identity: process,
                name: "backend".to_string(),
                cmdline: vec!["backend".to_string()],
            },
            local,
            remote,
            protocol: TransportProtocol::Tcp,
            start_monotonic_ns: 1,
            socket_cookie: None,
            attribution_confidence: 100,
        }
    }
}
