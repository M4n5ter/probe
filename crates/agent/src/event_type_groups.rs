use probe_core::EventType;

static PARSED_APPLICATION_EVENT_TYPES: [EventType; 7] = [
    EventType::HttpRequestHeaders,
    EventType::HttpResponseHeaders,
    EventType::HttpBodyChunk,
    EventType::SseEvent,
    EventType::WebSocketHandoff,
    EventType::WebSocketFrame,
    EventType::WebSocketMessage,
];

static HTTP_EVENT_TYPES: [EventType; 4] = [
    EventType::HttpRequestHeaders,
    EventType::HttpResponseHeaders,
    EventType::HttpBodyChunk,
    EventType::SseEvent,
];

static WEBSOCKET_EVENT_TYPES: [EventType; 3] = [
    EventType::WebSocketHandoff,
    EventType::WebSocketFrame,
    EventType::WebSocketMessage,
];

static SECURITY_EVENT_TYPES: [EventType; 5] = [
    EventType::PolicyAlert,
    EventType::PolicyVerdict,
    EventType::PolicyRuntimeError,
    EventType::EnforcementDecision,
    EventType::L7MitmAudit,
];

static DIAGNOSTIC_EVENT_TYPES: [EventType; 3] = [
    EventType::CaptureLoss,
    EventType::Gap,
    EventType::ProtocolError,
];

pub(crate) fn parsed_application() -> &'static [EventType] {
    &PARSED_APPLICATION_EVENT_TYPES
}

pub(crate) fn http() -> &'static [EventType] {
    &HTTP_EVENT_TYPES
}

pub(crate) fn websocket() -> &'static [EventType] {
    &WEBSOCKET_EVENT_TYPES
}

pub(crate) fn security() -> &'static [EventType] {
    &SECURITY_EVENT_TYPES
}

pub(crate) fn diagnostics() -> &'static [EventType] {
    &DIAGNOSTIC_EVENT_TYPES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsed_application_events_are_http_sse_and_websocket() {
        assert_eq!(
            parsed_application(),
            &[
                EventType::HttpRequestHeaders,
                EventType::HttpResponseHeaders,
                EventType::HttpBodyChunk,
                EventType::SseEvent,
                EventType::WebSocketHandoff,
                EventType::WebSocketFrame,
                EventType::WebSocketMessage,
            ]
        );
    }

    #[test]
    fn http_events_include_sse() {
        assert_eq!(
            http(),
            &[
                EventType::HttpRequestHeaders,
                EventType::HttpResponseHeaders,
                EventType::HttpBodyChunk,
                EventType::SseEvent,
            ]
        );
    }

    #[test]
    fn websocket_events_cover_handoff_frames_and_messages() {
        assert_eq!(
            websocket(),
            &[
                EventType::WebSocketHandoff,
                EventType::WebSocketFrame,
                EventType::WebSocketMessage,
            ]
        );
    }

    #[test]
    fn security_events_cover_policy_and_mitm_audit() {
        assert_eq!(
            security(),
            &[
                EventType::PolicyAlert,
                EventType::PolicyVerdict,
                EventType::PolicyRuntimeError,
                EventType::EnforcementDecision,
                EventType::L7MitmAudit,
            ]
        );
    }

    #[test]
    fn diagnostic_events_are_degraded_capture_and_parser_events() {
        assert_eq!(
            diagnostics(),
            &[
                EventType::CaptureLoss,
                EventType::Gap,
                EventType::ProtocolError,
            ]
        );
    }
}
