use std::net::{IpAddr, Ipv4Addr};

use capture::{
    CaptureError, CaptureEvent, LibsslResolvedFlow, LibsslUprobeFlowLookup,
    LibsslUprobeFlowResolver,
};
use probe_core::{
    CaptureProviderKind, CaptureSource, Direction, ProcessContext, ProcessIdentity, TcpConnection,
    TcpEndpoint,
};

pub(crate) const DIRECT_LOOPBACK_FLOW_CONFIDENCE: u8 = 90;

pub(crate) struct DirectLoopbackFlowResolver {
    fixture_pid: u32,
    start_time_ticks: u64,
    listen_port: u16,
}

impl DirectLoopbackFlowResolver {
    pub(crate) fn new(fixture_pid: u32, start_time_ticks: u64, listen_port: u16) -> Self {
        Self {
            fixture_pid,
            start_time_ticks,
            listen_port,
        }
    }

    fn process(&self, lookup: &LibsslUprobeFlowLookup) -> ProcessContext {
        ProcessContext {
            identity: ProcessIdentity {
                pid: self.fixture_pid,
                tgid: lookup.tgid,
                start_time_ticks: self.start_time_ticks,
                boot_id: "e2e".to_string(),
                exe_path: "traffic-probe-e2e-fixture".to_string(),
                cmdline_hash: "e2e".to_string(),
                uid: 0,
                gid: 0,
                cgroup: None,
                systemd_service: None,
                container_id: None,
                runtime_hint: None,
            },
            name: "traffic-probe-e2e-fixture".to_string(),
            cmdline: vec!["traffic-probe-e2e-fixture".to_string()],
        }
    }

    fn connection(&self, direction: Direction, ssl_pointer: u64) -> TcpConnection {
        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let client = TcpEndpoint::new(
            loopback,
            synthetic_client_port(synthetic_flow_seed(ssl_pointer), self.listen_port),
        );
        let server = TcpEndpoint::new(loopback, self.listen_port);
        match direction {
            Direction::Outbound => TcpConnection::new(client, server),
            Direction::Inbound => TcpConnection::new(server, client),
        }
    }
}

impl LibsslUprobeFlowResolver for DirectLoopbackFlowResolver {
    fn resolve_libssl_uprobe_flow(
        &mut self,
        lookup: LibsslUprobeFlowLookup,
    ) -> Result<Option<LibsslResolvedFlow>, CaptureError> {
        if lookup.fd.is_none() {
            return Err(CaptureError::provider(
                "e2e_tls_plaintext_provider",
                "expected libssl uprobe sample to include the socket fd",
            ));
        }
        let direction = lookup.direction;
        Ok(Some(LibsslResolvedFlow {
            process: self.process(&lookup),
            confidence: DIRECT_LOOPBACK_FLOW_CONFIDENCE,
            connection: self.connection(direction, lookup.ssl_pointer),
            socket_cookie: None,
            start_monotonic_ns: synthetic_flow_start(lookup.ssl_pointer),
        }))
    }
}

fn synthetic_flow_start(ssl_pointer: u64) -> u64 {
    synthetic_flow_seed(ssl_pointer).max(1)
}

fn synthetic_client_port(seed: u64, listen_port: u16) -> u16 {
    let port = 10_000 + (seed % 50_000) as u16;
    if port == listen_port { 60_000 } else { port }
}

fn synthetic_flow_seed(ssl_pointer: u64) -> u64 {
    let mut value = ssl_pointer;
    value ^= value >> 33;
    value = value.wrapping_mul(0xff51_afd7_ed55_8ccd);
    value ^= value >> 33;
    value = value.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    value ^ (value >> 33)
}

pub(crate) fn is_expected_tls_plaintext_request_bytes(
    event: &CaptureEvent,
    listen_port: u16,
) -> bool {
    let CaptureEvent::Bytes(bytes) = event else {
        return false;
    };
    bytes.origin.source() == CaptureSource::LibsslUprobe
        && bytes.origin.provider() == CaptureProviderKind::Plaintext
        && bytes.direction == Direction::Outbound
        && bytes.flow.remote.port == listen_port
        && bytes.flow.attribution_confidence == DIRECT_LOOPBACK_FLOW_CONFIDENCE
        && bytes
            .bytes
            .as_ref()
            .windows("POST /traffic-probe-e2e/0".len())
            .any(|window| window == b"POST /traffic-probe-e2e/0")
}

pub(crate) fn provider_event_summary(events: &[CaptureEvent], listen_port: u16) -> String {
    let summaries = events
        .iter()
        .filter_map(|event| event_summary(event, listen_port))
        .take(16)
        .collect::<Vec<_>>();
    if !summaries.is_empty() {
        return summaries.join("; ");
    }
    let unrelated = events
        .iter()
        .filter_map(unrelated_event_summary)
        .take(16)
        .collect::<Vec<_>>();
    if unrelated.is_empty() {
        format!("no TLS plaintext provider events near port {listen_port}")
    } else {
        format!(
            "no TLS plaintext provider events near port {listen_port}; unrelated events: {}",
            unrelated.join("; ")
        )
    }
}

fn event_summary(event: &CaptureEvent, listen_port: u16) -> Option<String> {
    match event {
        CaptureEvent::Bytes(bytes)
            if bytes.flow.local.port == listen_port || bytes.flow.remote.port == listen_port =>
        {
            Some(format!(
                "bytes source={:?} provider={:?} direction={:?} local={}:{} remote={}:{} confidence={} len={} degraded={}",
                bytes.origin.source(),
                bytes.origin.provider(),
                bytes.direction,
                bytes.flow.local.address,
                bytes.flow.local.port,
                bytes.flow.remote.address,
                bytes.flow.remote.port,
                bytes.flow.attribution_confidence,
                bytes.bytes.len(),
                bytes.degraded
            ))
        }
        CaptureEvent::Gap(gap)
            if gap.flow.local.port == listen_port || gap.flow.remote.port == listen_port =>
        {
            Some(format!(
                "gap source={:?} provider={:?} direction={:?} local={}:{} remote={}:{} confidence={} reason={}",
                gap.origin.source(),
                gap.origin.provider(),
                gap.gap.direction,
                gap.flow.local.address,
                gap.flow.local.port,
                gap.flow.remote.address,
                gap.flow.remote.port,
                gap.flow.attribution_confidence,
                gap.gap.reason
            ))
        }
        _ => None,
    }
}

fn unrelated_event_summary(event: &CaptureEvent) -> Option<String> {
    match event {
        CaptureEvent::Bytes(bytes) if bytes.origin.source() == CaptureSource::LibsslUprobe => {
            Some(format!(
                "bytes pid={} command={} direction={:?} confidence={} len={} degraded={} reason={}",
                bytes.flow.process.identity.pid,
                bytes.flow.process.name,
                bytes.direction,
                bytes.flow.attribution_confidence,
                bytes.bytes.len(),
                bytes.degraded,
                bytes.degradation_reason.as_deref().unwrap_or("")
            ))
        }
        CaptureEvent::Gap(gap) if gap.origin.source() == CaptureSource::LibsslUprobe => {
            Some(format!(
                "gap pid={} command={} direction={:?} confidence={} reason={}",
                gap.flow.process.identity.pid,
                gap.flow.process.name,
                gap.gap.direction,
                gap.flow.attribution_confidence,
                gap.gap.reason
            ))
        }
        _ => None,
    }
}
