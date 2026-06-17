use probe_core::{
    AddressPort, Direction, EventId, FlowContext, FlowIdentity, Gap, ProcessContext,
    ProcessIdentity, TcpConnection, Timestamp, TransportProtocol,
};

use crate::{CaptureError, PlaintextChunk, PlaintextEvent, PlaintextGap, PlaintextSource};

use super::record::LibsslUprobePlaintextSample;

const LIBSSL_UPROBE_FLOW_ATTRIBUTION_REASON: &str =
    "libssl uprobe fd-to-flow attribution is best-effort without strong socket ownership proof";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibsslUprobeFlowLookup {
    pub tgid: u32,
    pub thread_pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub command: String,
    pub ssl_pointer: u64,
    pub fd: Option<i32>,
    pub direction: Direction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibsslResolvedFlow {
    pub process: ProcessContext,
    pub confidence: u8,
    pub connection: TcpConnection,
    pub socket_cookie: Option<u64>,
    pub start_monotonic_ns: u64,
}

pub trait LibsslUprobeFlowResolver {
    fn resolve_libssl_uprobe_flow(
        &mut self,
        lookup: LibsslUprobeFlowLookup,
    ) -> Result<Option<LibsslResolvedFlow>, CaptureError>;
}

pub(super) fn libssl_plaintext_events_from_sample(
    sample: &LibsslUprobePlaintextSample,
    timestamp: Timestamp,
    resolver: &mut dyn LibsslUprobeFlowResolver,
) -> Result<Vec<PlaintextEvent>, CaptureError> {
    let resolved = resolver.resolve_libssl_uprobe_flow(LibsslUprobeFlowLookup {
        tgid: sample.tgid,
        thread_pid: sample.pid,
        uid: sample.uid,
        gid: sample.gid,
        command: sample.command_lossy(),
        ssl_pointer: sample.ssl_pointer,
        fd: sample.fd,
        direction: sample.direction,
    })?;
    let Some(flow) = resolved else {
        return Ok(unresolved_plaintext_events(sample, timestamp));
    };
    Ok(resolved_plaintext_events(
        sample,
        timestamp,
        flow_from_resolved(flow),
    ))
}

fn resolved_plaintext_events(
    sample: &LibsslUprobePlaintextSample,
    timestamp: Timestamp,
    flow: FlowContext,
) -> Vec<PlaintextEvent> {
    let mut events = Vec::new();
    if !sample.read_failed && !sample.captured_bytes.is_empty() {
        let mut chunk = PlaintextChunk::new(
            timestamp,
            flow.clone(),
            sample.direction,
            sample.captured_bytes.as_ref(),
        )
        .with_stream_offset(sample.stream_offset);
        chunk = chunk.with_degradation(resolved_bytes_degradation_reason(sample));
        events.push(PlaintextEvent::bytes(PlaintextSource::LibsslUprobe, chunk));
    }
    if should_emit_gap(sample) {
        events.push(PlaintextEvent::gap(
            PlaintextSource::LibsslUprobe,
            PlaintextGap::new(timestamp, flow, gap_from_sample(sample, gap_start(sample))),
        ));
    }
    events
}

fn unresolved_plaintext_events(
    sample: &LibsslUprobePlaintextSample,
    timestamp: Timestamp,
) -> Vec<PlaintextEvent> {
    let flow = unresolved_flow(sample, timestamp);
    let mut events = Vec::new();
    if !sample.read_failed && !sample.captured_bytes.is_empty() {
        let chunk = PlaintextChunk::new(
            timestamp,
            flow.clone(),
            sample.direction,
            sample.captured_bytes.as_ref(),
        )
        .with_stream_offset(sample.stream_offset)
        .with_degradation(unresolved_bytes_degradation_reason(sample));
        events.push(PlaintextEvent::bytes(PlaintextSource::LibsslUprobe, chunk));
    }
    if should_emit_gap(sample) {
        events.push(PlaintextEvent::gap(
            PlaintextSource::LibsslUprobe,
            PlaintextGap::new(
                timestamp,
                flow,
                Gap {
                    direction: sample.direction,
                    expected_offset: gap_start(sample),
                    next_offset: known_end_offset(sample),
                    reason: unresolved_gap_reason(sample),
                },
            ),
        ));
    }
    events
}

fn gap_from_sample(sample: &LibsslUprobePlaintextSample, expected_offset: u64) -> Gap {
    Gap {
        direction: sample.direction,
        expected_offset,
        next_offset: known_end_offset(sample),
        reason: degradation_reason(sample).unwrap_or_else(|| {
            "libssl uprobe plaintext sample is missing bytes for an unknown reason".to_string()
        }),
    }
}

fn should_emit_gap(sample: &LibsslUprobePlaintextSample) -> bool {
    sample.read_failed || missing_plaintext_bytes(sample)
}

fn gap_start(sample: &LibsslUprobePlaintextSample) -> u64 {
    if sample.read_failed {
        return sample.stream_offset;
    }
    sample
        .stream_offset
        .saturating_add(sample.captured_bytes.len() as u64)
}

fn known_end_offset(sample: &LibsslUprobePlaintextSample) -> Option<u64> {
    if sample.original_len == 0 {
        None
    } else {
        Some(
            sample
                .stream_offset
                .saturating_add(u64::from(sample.original_len)),
        )
    }
}

fn degradation_reason(sample: &LibsslUprobePlaintextSample) -> Option<String> {
    if sample.read_failed {
        return Some("libssl uprobe could not read the plaintext buffer".to_string());
    }
    if missing_plaintext_bytes(sample) {
        return Some(format!(
            "libssl uprobe plaintext sample truncated: captured {} of {} byte(s)",
            sample.captured_bytes.len(),
            sample.original_len
        ));
    }
    if sample.truncated {
        return Some("libssl uprobe reported a truncated plaintext sample".to_string());
    }
    None
}

fn resolved_bytes_degradation_reason(sample: &LibsslUprobePlaintextSample) -> String {
    match degradation_reason(sample) {
        Some(reason) => format!("{LIBSSL_UPROBE_FLOW_ATTRIBUTION_REASON}; {reason}"),
        None => LIBSSL_UPROBE_FLOW_ATTRIBUTION_REASON.to_string(),
    }
}

fn unresolved_bytes_degradation_reason(sample: &LibsslUprobePlaintextSample) -> String {
    match degradation_reason(sample) {
        Some(reason) => format!("{}; {reason}", unresolved_flow_reason(sample)),
        None => unresolved_flow_reason(sample),
    }
}

fn unresolved_gap_reason(sample: &LibsslUprobePlaintextSample) -> String {
    match degradation_reason(sample) {
        Some(reason) => format!("{}; {reason}", unresolved_flow_reason(sample)),
        None => unresolved_flow_reason(sample),
    }
}

fn unresolved_flow_reason(sample: &LibsslUprobePlaintextSample) -> String {
    format!(
        "libssl uprobe plaintext sample could not be resolved to a TCP flow; tgid={}, thread_pid={}, fd={:?}",
        sample.tgid, sample.pid, sample.fd
    )
}

fn missing_plaintext_bytes(sample: &LibsslUprobePlaintextSample) -> bool {
    sample.captured_bytes.len() < sample.original_len as usize
}

fn unresolved_flow(sample: &LibsslUprobePlaintextSample, timestamp: Timestamp) -> FlowContext {
    let process = process_context_from_sample(sample);
    let local = unknown_endpoint();
    let remote = unknown_endpoint();
    let start_monotonic_ns = 0;
    let id = unresolved_flow_id(
        sample,
        &process,
        &local,
        &remote,
        start_monotonic_ns,
        timestamp.monotonic_ns,
    );
    FlowContext {
        id,
        process,
        local,
        remote,
        protocol: TransportProtocol::Tcp,
        start_monotonic_ns,
        socket_cookie: None,
        attribution_confidence: 0,
    }
}

fn unresolved_flow_id(
    sample: &LibsslUprobePlaintextSample,
    process: &ProcessContext,
    local: &AddressPort,
    remote: &AddressPort,
    start_monotonic_ns: u64,
    sample_monotonic_ns: u64,
) -> FlowIdentity {
    FlowIdentity(
        EventId::stable([
            b"libssl-unresolved-flow".as_slice(),
            process.identity.stable_key().as_bytes(),
            local.address.as_bytes(),
            &local.port.to_be_bytes(),
            remote.address.as_bytes(),
            &remote.port.to_be_bytes(),
            b"tcp".as_slice(),
            &start_monotonic_ns.to_be_bytes(),
            &sample_monotonic_ns.to_be_bytes(),
            &sample.ssl_pointer.to_be_bytes(),
        ])
        .0,
    )
}

pub(in crate::tls::plaintext) fn is_unresolved_libssl_flow(flow: &FlowContext) -> bool {
    flow.attribution_confidence == 0
        && flow.local.port == 0
        && flow.remote.port == 0
        && flow.local.address == "0.0.0.0"
        && flow.remote.address == "0.0.0.0"
}

pub(in crate::tls::plaintext) fn flow_from_resolved(resolved: LibsslResolvedFlow) -> FlowContext {
    let local = AddressPort::from(resolved.connection.local);
    let remote = AddressPort::from(resolved.connection.remote);
    FlowContext {
        id: FlowIdentity::stable(
            &resolved.process.identity,
            &local,
            &remote,
            TransportProtocol::Tcp,
            resolved.start_monotonic_ns,
            resolved.socket_cookie,
        ),
        process: resolved.process,
        local,
        remote,
        protocol: TransportProtocol::Tcp,
        start_monotonic_ns: resolved.start_monotonic_ns,
        socket_cookie: resolved.socket_cookie,
        attribution_confidence: resolved.confidence,
    }
}

fn process_context_from_sample(sample: &LibsslUprobePlaintextSample) -> ProcessContext {
    let name = sample.command_lossy();
    let name = if name.is_empty() {
        "unknown".to_string()
    } else {
        name
    };
    ProcessContext {
        identity: ProcessIdentity {
            pid: sample.tgid,
            tgid: sample.tgid,
            start_time_ticks: 0,
            boot_id: String::new(),
            exe_path: String::new(),
            cmdline_hash: String::new(),
            uid: sample.uid,
            gid: sample.gid,
            cgroup: None,
            systemd_service: None,
            container_id: None,
            runtime_hint: None,
        },
        name: name.clone(),
        cmdline: vec![name],
    }
}

fn unknown_endpoint() -> AddressPort {
    AddressPort {
        address: "0.0.0.0".to_string(),
        port: 0,
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use bytes::Bytes;
    use probe_core::CaptureSource;

    use crate::{CaptureEvent, CaptureProviderKind, CapturedGap};

    use super::*;

    #[test]
    fn resolved_sample_becomes_libssl_plaintext_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let sample = plaintext_sample(b"GET /", 5, false, false, Some(7));
        let resolved = demo_resolved_flow();
        let flow = flow_from_resolved(resolved.clone());
        let mut resolver = StaticFlowResolver {
            resolved: Some(resolved),
            last_lookup: None,
        };

        let events = libssl_plaintext_events_from_sample(&sample, demo_timestamp(), &mut resolver)?;

        assert_eq!(events.len(), 1);
        let CaptureEvent::Bytes(bytes) = CaptureEvent::from(events[0].clone()) else {
            panic!("expected bytes event");
        };
        assert_eq!(bytes.timestamp, demo_timestamp());
        assert_eq!(bytes.flow, flow);
        assert_eq!(bytes.origin.source(), CaptureSource::LibsslUprobe);
        assert_eq!(bytes.origin.provider(), CaptureProviderKind::Plaintext);
        assert_eq!(bytes.direction, Direction::Outbound);
        assert_eq!(bytes.stream_offset, 100);
        assert_eq!(bytes.bytes.as_ref(), b"GET /");
        assert!(bytes.degraded);
        assert_eq!(
            bytes.degradation_reason.as_deref(),
            Some(LIBSSL_UPROBE_FLOW_ATTRIBUTION_REASON)
        );
        Ok(())
    }

    #[test]
    fn read_failed_sample_emits_gap_without_plaintext_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let sample = plaintext_sample(b"", 5, false, true, Some(7));
        let mut resolver = StaticFlowResolver {
            resolved: Some(demo_resolved_flow()),
            last_lookup: None,
        };

        let events = libssl_plaintext_events_from_sample(&sample, demo_timestamp(), &mut resolver)?;

        assert_eq!(events.len(), 1);
        let CaptureEvent::Gap(CapturedGap { gap, .. }) = CaptureEvent::from(events[0].clone())
        else {
            panic!("expected read failure gap");
        };
        assert_eq!(gap.expected_offset, 100);
        assert_eq!(gap.next_offset, Some(105));
        assert_eq!(
            gap.reason,
            "libssl uprobe could not read the plaintext buffer"
        );
        Ok(())
    }

    #[test]
    fn truncated_flag_without_missing_bytes_degrades_chunk_without_gap()
    -> Result<(), Box<dyn std::error::Error>> {
        let sample = plaintext_sample(b"GET /", 5, true, false, Some(7));
        let mut resolver = StaticFlowResolver {
            resolved: Some(demo_resolved_flow()),
            last_lookup: None,
        };

        let events = libssl_plaintext_events_from_sample(&sample, demo_timestamp(), &mut resolver)?;

        assert_eq!(events.len(), 1);
        let CaptureEvent::Bytes(bytes) = CaptureEvent::from(events[0].clone()) else {
            panic!("expected degraded bytes event");
        };
        assert!(bytes.degraded);
        assert_eq!(
            bytes.degradation_reason.as_deref(),
            Some(
                expected_bytes_degradation_reason(
                    "libssl uprobe reported a truncated plaintext sample"
                )
                .as_str()
            )
        );
        Ok(())
    }

    #[test]
    fn truncated_sample_emits_degraded_chunk_and_gap() -> Result<(), Box<dyn std::error::Error>> {
        let sample = plaintext_sample(b"GET /", 9, true, false, Some(7));
        let mut resolver = StaticFlowResolver {
            resolved: Some(demo_resolved_flow()),
            last_lookup: None,
        };

        let events = libssl_plaintext_events_from_sample(&sample, demo_timestamp(), &mut resolver)?;

        assert_eq!(events.len(), 2);
        let CaptureEvent::Bytes(bytes) = CaptureEvent::from(events[0].clone()) else {
            panic!("expected bytes event");
        };
        assert!(bytes.degraded);
        assert_eq!(
            bytes.degradation_reason.as_deref(),
            Some(
                expected_bytes_degradation_reason(
                    "libssl uprobe plaintext sample truncated: captured 5 of 9 byte(s)"
                )
                .as_str()
            )
        );
        let CaptureEvent::Gap(CapturedGap { gap, origin, .. }) =
            CaptureEvent::from(events[1].clone())
        else {
            panic!("expected gap event");
        };
        assert_eq!(origin.source(), CaptureSource::LibsslUprobe);
        assert_eq!(origin.provider(), CaptureProviderKind::Plaintext);
        assert_eq!(gap.direction, Direction::Outbound);
        assert_eq!(gap.expected_offset, 105);
        assert_eq!(gap.next_offset, Some(109));
        Ok(())
    }

    #[test]
    fn unresolved_sample_emits_degraded_bytes_with_unknown_flow()
    -> Result<(), Box<dyn std::error::Error>> {
        let sample = plaintext_sample(b"GET /", 5, false, false, None);
        let mut resolver = StaticFlowResolver {
            resolved: None,
            last_lookup: None,
        };

        let events = libssl_plaintext_events_from_sample(&sample, demo_timestamp(), &mut resolver)?;

        assert_eq!(events.len(), 1);
        let CaptureEvent::Bytes(bytes) = CaptureEvent::from(events[0].clone()) else {
            panic!("expected unresolved plaintext bytes");
        };
        assert_eq!(bytes.timestamp, demo_timestamp());
        assert_eq!(bytes.flow.process.identity.pid, 22);
        assert_eq!(bytes.flow.process.name, "curl");
        assert_eq!(bytes.flow.attribution_confidence, 0);
        assert_eq!(bytes.flow.local.port, 0);
        assert_eq!(bytes.flow.remote.port, 0);
        assert_eq!(bytes.flow.socket_cookie, None);
        assert_eq!(bytes.origin.source(), CaptureSource::LibsslUprobe);
        assert_eq!(bytes.origin.provider(), CaptureProviderKind::Plaintext);
        assert_eq!(bytes.direction, Direction::Outbound);
        assert_eq!(bytes.stream_offset, 100);
        assert_eq!(bytes.bytes.as_ref(), b"GET /");
        assert!(bytes.degraded);
        assert!(bytes.degradation_reason.as_deref().is_some_and(|reason| {
            reason.contains("libssl uprobe plaintext sample could not be resolved")
        }));
        assert!(
            !bytes
                .degradation_reason
                .as_deref()
                .unwrap_or_default()
                .contains("0xfeed")
        );
        Ok(())
    }

    #[test]
    fn unresolved_samples_on_same_ssl_pointer_do_not_share_flow_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut first_resolver = StaticFlowResolver {
            resolved: None,
            last_lookup: None,
        };
        let mut second_resolver = StaticFlowResolver {
            resolved: None,
            last_lookup: None,
        };

        let first = libssl_plaintext_events_from_sample(
            &plaintext_sample(b"GET /", 5, false, false, Some(7)),
            Timestamp {
                monotonic_ns: 10,
                wall_time_unix_ns: 100,
            },
            &mut first_resolver,
        )?;
        let second = libssl_plaintext_events_from_sample(
            &plaintext_sample(b" HTTP", 5, false, false, Some(7)),
            Timestamp {
                monotonic_ns: 11,
                wall_time_unix_ns: 101,
            },
            &mut second_resolver,
        )?;

        let first_flow = bytes_flow(&first[0]);
        let second_flow = bytes_flow(&second[0]);
        assert_ne!(first_flow.id, second_flow.id);
        assert_eq!(first_flow.socket_cookie, None);
        assert_eq!(second_flow.socket_cookie, None);
        Ok(())
    }

    #[test]
    fn unresolved_read_failed_sample_emits_gap_without_plaintext_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let sample = plaintext_sample(b"", 5, false, true, None);
        let mut resolver = StaticFlowResolver {
            resolved: None,
            last_lookup: None,
        };

        let events = libssl_plaintext_events_from_sample(&sample, demo_timestamp(), &mut resolver)?;

        assert_eq!(events.len(), 1);
        let CaptureEvent::Gap(CapturedGap {
            timestamp,
            flow,
            origin,
            gap,
            ..
        }) = CaptureEvent::from(events[0].clone())
        else {
            panic!("expected unresolved flow gap");
        };
        assert_eq!(timestamp, demo_timestamp());
        assert_eq!(flow.process.identity.pid, 22);
        assert_eq!(flow.process.name, "curl");
        assert_eq!(flow.attribution_confidence, 0);
        assert_eq!(origin.source(), CaptureSource::LibsslUprobe);
        assert_eq!(origin.provider(), CaptureProviderKind::Plaintext);
        assert_eq!(gap.expected_offset, 100);
        assert_eq!(gap.next_offset, Some(105));
        assert!(
            gap.reason
                .contains("libssl uprobe plaintext sample could not be resolved")
        );
        assert!(
            gap.reason
                .contains("libssl uprobe could not read the plaintext buffer")
        );
        assert!(!gap.reason.contains("0xfeed"));
        Ok(())
    }

    #[test]
    fn resolved_samples_on_same_connection_keep_flow_identity_across_timestamps()
    -> Result<(), Box<dyn std::error::Error>> {
        let resolved = demo_resolved_flow();
        let mut first_resolver = StaticFlowResolver {
            resolved: Some(resolved.clone()),
            last_lookup: None,
        };
        let mut second_resolver = StaticFlowResolver {
            resolved: Some(resolved),
            last_lookup: None,
        };

        let first = libssl_plaintext_events_from_sample(
            &plaintext_sample(b"GET /", 5, false, false, Some(7)),
            Timestamp {
                monotonic_ns: 10,
                wall_time_unix_ns: 100,
            },
            &mut first_resolver,
        )?;
        let second = libssl_plaintext_events_from_sample(
            &plaintext_sample(b" HTTP", 5, false, false, Some(7)),
            Timestamp {
                monotonic_ns: 11,
                wall_time_unix_ns: 101,
            },
            &mut second_resolver,
        )?;

        let first_flow = bytes_flow(&first[0]);
        let second_flow = bytes_flow(&second[0]);
        assert_eq!(first_flow.id, second_flow.id);
        assert_eq!(first_flow.start_monotonic_ns, 1);
        assert_eq!(second_flow.start_monotonic_ns, 1);
        assert_eq!(first_flow.socket_cookie, Some(4242));
        assert_eq!(second_flow.socket_cookie, Some(4242));
        Ok(())
    }

    #[test]
    fn sample_lookup_includes_process_ssl_fd_and_direction()
    -> Result<(), Box<dyn std::error::Error>> {
        let sample = plaintext_sample(b"GET /", 5, false, false, Some(7));
        let mut resolver = StaticFlowResolver {
            resolved: Some(demo_resolved_flow()),
            last_lookup: None,
        };

        let _ = libssl_plaintext_events_from_sample(&sample, demo_timestamp(), &mut resolver)?;

        assert_eq!(resolver.last_lookup, Some(lookup_for_sample(&sample)));
        Ok(())
    }

    fn plaintext_sample(
        captured_bytes: &[u8],
        original_len: u32,
        truncated: bool,
        read_failed: bool,
        fd: Option<i32>,
    ) -> LibsslUprobePlaintextSample {
        LibsslUprobePlaintextSample {
            pid: 11,
            tgid: 22,
            uid: 33,
            gid: 44,
            command: nul_padded_command("curl"),
            ssl_pointer: 0xfeed,
            fd,
            direction: Direction::Outbound,
            stream_offset: 100,
            original_len,
            captured_bytes: Bytes::copy_from_slice(captured_bytes),
            truncated,
            read_failed,
        }
    }

    fn expected_bytes_degradation_reason(sample_reason: &str) -> String {
        format!("{LIBSSL_UPROBE_FLOW_ATTRIBUTION_REASON}; {sample_reason}")
    }

    fn lookup_for_sample(sample: &LibsslUprobePlaintextSample) -> LibsslUprobeFlowLookup {
        LibsslUprobeFlowLookup {
            tgid: sample.tgid,
            thread_pid: sample.pid,
            uid: sample.uid,
            gid: sample.gid,
            command: sample.command_lossy(),
            ssl_pointer: sample.ssl_pointer,
            fd: sample.fd,
            direction: sample.direction,
        }
    }

    fn demo_timestamp() -> Timestamp {
        Timestamp {
            monotonic_ns: 1,
            wall_time_unix_ns: 2,
        }
    }

    fn demo_resolved_flow() -> LibsslResolvedFlow {
        let process = ProcessIdentity {
            pid: 22,
            tgid: 22,
            start_time_ticks: 1,
            boot_id: "boot".to_string(),
            exe_path: "/usr/bin/curl".to_string(),
            cmdline_hash: "hash".to_string(),
            uid: 33,
            gid: 44,
            cgroup: None,
            systemd_service: None,
            container_id: None,
            runtime_hint: None,
        };
        LibsslResolvedFlow {
            process: ProcessContext {
                identity: process,
                name: "curl".to_string(),
                cmdline: vec!["curl".to_string()],
            },
            confidence: 90,
            connection: TcpConnection::new(
                probe_core::TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 50_000),
                probe_core::TcpEndpoint::new(Ipv4Addr::new(127, 0, 0, 1).into(), 443),
            ),
            socket_cookie: Some(4242),
            start_monotonic_ns: 1,
        }
    }

    fn bytes_flow(event: &PlaintextEvent) -> FlowContext {
        let CaptureEvent::Bytes(bytes) = CaptureEvent::from(event.clone()) else {
            panic!("expected bytes event");
        };
        bytes.flow
    }

    fn nul_padded_command(command: &str) -> [u8; 16] {
        let mut bytes = [0; 16];
        for (target, source) in bytes.iter_mut().zip(command.as_bytes()) {
            *target = *source;
        }
        bytes
    }

    struct StaticFlowResolver {
        resolved: Option<LibsslResolvedFlow>,
        last_lookup: Option<LibsslUprobeFlowLookup>,
    }

    impl LibsslUprobeFlowResolver for StaticFlowResolver {
        fn resolve_libssl_uprobe_flow(
            &mut self,
            lookup: LibsslUprobeFlowLookup,
        ) -> Result<Option<LibsslResolvedFlow>, CaptureError> {
            self.last_lookup = Some(lookup);
            Ok(self.resolved.clone())
        }
    }
}
