use std::{
    fs::OpenOptions,
    io::{self, Write},
    path::Path,
};

use capture::{CaptureEvent, CapturedBytes, EnforcementEvidencePropagation};
use probe_core::{
    AddressPort, CaptureOrigin, CaptureProviderKind, CaptureSource, Direction, EnforcementEvidence,
    EventEnvelope, FlowContext, FlowIdentity, ProcessContext, ProcessIdentity, Timestamp,
    TransportProtocol,
};

pub const FLOW_ID: &str = "mitm_bridge:e2e-flow";
pub const REQUEST_TARGET: &str = "/mitm-bridge/e2e";
pub const POLICY_HOOK_METHOD: &str = "POST";
pub const POLICY_HOOK_PATH: &str = "/mitm-policy-hook";
pub const POLICY_HOOK_CONTENT_TYPE: &str = "application/json";
pub const POLICY_HOOK_ACCEPT: &str = "application/json";
pub const POLICY_HOOK_RESPONSE_REASON: &str = "e2e MITM policy hook delegated deny";
pub const REQUEST_BYTES: &[u8] =
    b"GET /mitm-bridge/e2e HTTP/1.1\r\nHost: mitm-bridge.e2e.test\r\n\r\n";

pub fn create_empty_capture_event_feed(path: &Path) -> Result<(), io::Error> {
    OpenOptions::new().write(true).create_new(true).open(path)?;
    Ok(())
}

pub fn append_capture_event_feed(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut content = String::new();
    for event in capture_events() {
        content.push_str(&serde_json::to_string(&event)?);
        content.push('\n');
    }
    let mut file = OpenOptions::new().append(true).open(path)?;
    file.write_all(content.as_bytes())?;
    file.flush()?;
    Ok(())
}

pub fn is_ingress_bytes(event: &CaptureEvent) -> bool {
    matches!(
        event,
        CaptureEvent::Bytes(bytes)
            if bytes.origin.source() == CaptureSource::L7MitmPlaintext
                && bytes.origin.provider() == CaptureProviderKind::Interception
                && bytes.flow.id.0 == FLOW_ID
                && bytes.bytes.as_ref() == REQUEST_BYTES
    )
}

pub fn is_flow(envelope: &EventEnvelope) -> bool {
    envelope.origin().source() == CaptureSource::L7MitmPlaintext
        && envelope.origin().provider() == CaptureProviderKind::Interception
        && envelope.flow().is_some_and(|flow| flow.id.0 == FLOW_ID)
}

fn capture_events() -> [CaptureEvent; 3] {
    let flow = flow();
    [
        CaptureEvent::ConnectionOpened {
            timestamp: timestamp(1),
            flow: flow.clone(),
            origin: origin(),
        },
        CaptureEvent::Bytes(CapturedBytes {
            timestamp: timestamp(2),
            flow: flow.clone(),
            origin: origin(),
            direction: Direction::Outbound,
            stream_offset: 0,
            bytes: REQUEST_BYTES.to_vec().into(),
            attribution_confidence: 100,
            degraded: false,
            degradation_reason: None,
            enforcement_evidence: EnforcementEvidence::default(),
            enforcement_evidence_propagation: EnforcementEvidencePropagation::Event,
        }),
        CaptureEvent::ConnectionClosed {
            timestamp: timestamp(3),
            flow,
            origin: origin(),
        },
    ]
}

fn flow() -> FlowContext {
    let process = ProcessContext {
        identity: ProcessIdentity {
            pid: 44_001,
            tgid: 44_001,
            start_time_ticks: 90_001,
            boot_id: "e2e-boot".to_string(),
            exe_path: "/usr/bin/traffic-probe-e2e-mitm-bridge".to_string(),
            cmdline_hash: "mitm-bridge-cmdline-hash".to_string(),
            uid: 1000,
            gid: 1000,
            cgroup: None,
            systemd_service: None,
            container_id: None,
            runtime_hint: None,
        },
        name: "traffic-probe-e2e-mitm-bridge".to_string(),
        cmdline: vec!["traffic-probe-e2e-mitm-bridge".to_string()],
    };
    FlowContext {
        id: FlowIdentity(FLOW_ID.to_string()),
        process,
        local: AddressPort {
            address: "127.0.0.1".to_string(),
            port: 51_801,
        },
        remote: AddressPort {
            address: "127.0.0.1".to_string(),
            port: 443,
        },
        protocol: TransportProtocol::Tcp,
        start_monotonic_ns: 1,
        socket_cookie: Some(918_001),
        attribution_confidence: 100,
    }
}

fn origin() -> CaptureOrigin {
    CaptureOrigin::from_source(CaptureSource::L7MitmPlaintext)
}

fn timestamp(monotonic_ns: u64) -> Timestamp {
    Timestamp {
        monotonic_ns,
        wall_time_unix_ns: i64::try_from(monotonic_ns).unwrap_or(i64::MAX),
    }
}
