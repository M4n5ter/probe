use std::{
    collections::VecDeque,
    time::{SystemTime, UNIX_EPOCH},
};

use probe_core::{CapabilityKind, CapabilityState, CaptureSource, Timestamp};

use crate::{CaptureError, CaptureEvent, CaptureProvider, CaptureProviderKind, PlaintextEvent};

use super::{
    bridge::{LibsslUprobeFlowResolver, libssl_plaintext_events_from_sample},
    record::LibsslUprobePlaintextSample,
};

pub(in crate::tls::plaintext) trait LibsslUprobePlaintextSampleSource {
    fn next_tls_plaintext_sample(
        &mut self,
    ) -> Result<Option<LibsslUprobePlaintextSample>, CaptureError>;
}

pub(in crate::tls::plaintext) struct LibsslUprobePlaintextProvider {
    source: Box<dyn LibsslUprobePlaintextSampleSource>,
    resolver: Box<dyn LibsslUprobeFlowResolver>,
    pending_events: VecDeque<PlaintextEvent>,
    clock: LibsslUprobePlaintextClock,
}

impl LibsslUprobePlaintextProvider {
    pub(in crate::tls::plaintext) fn new(
        source: Box<dyn LibsslUprobePlaintextSampleSource>,
        resolver: Box<dyn LibsslUprobeFlowResolver>,
    ) -> Self {
        Self {
            source,
            resolver,
            pending_events: VecDeque::new(),
            clock: LibsslUprobePlaintextClock::default(),
        }
    }

    fn next_event(&mut self) -> Result<Option<CaptureEvent>, CaptureError> {
        loop {
            if let Some(event) = self.pending_events.pop_front() {
                return Ok(Some(CaptureEvent::from(event)));
            }
            let Some(sample) = self.source.next_tls_plaintext_sample()? else {
                return Ok(None);
            };
            let events = libssl_plaintext_events_from_sample(
                &sample,
                self.clock.next_timestamp(),
                self.resolver.as_mut(),
            )?;
            self.pending_events.extend(events);
        }
    }
}

impl CaptureProvider for LibsslUprobePlaintextProvider {
    fn name(&self) -> &'static str {
        "libssl_uprobe_plaintext"
    }

    fn kind(&self) -> CaptureProviderKind {
        CaptureProviderKind::Plaintext
    }

    fn source(&self) -> CaptureSource {
        CaptureSource::LibsslUprobe
    }

    fn capabilities(&self) -> Vec<CapabilityState> {
        vec![CapabilityState::degraded(
            CapabilityKind::LibsslUprobe,
            "libssl uprobe plaintext provider consumes supplied samples; uprobe attachment is not wired here",
        )]
    }

    fn next(&mut self) -> Result<Option<CaptureEvent>, CaptureError> {
        self.next_event()
    }
}

#[derive(Default)]
struct LibsslUprobePlaintextClock {
    monotonic_sequence: u64,
}

impl LibsslUprobePlaintextClock {
    fn next_timestamp(&mut self) -> Timestamp {
        self.monotonic_sequence = self.monotonic_sequence.saturating_add(1);
        Timestamp {
            monotonic_ns: self.monotonic_sequence,
            wall_time_unix_ns: current_wall_time_unix_ns(),
        }
    }
}

fn current_wall_time_unix_ns() -> i64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    nanos.min(i64::MAX as u128) as i64
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use ebpf_abi::{
        EBPF_TLS_DIRECTION_OUTBOUND, EBPF_TLS_PLAINTEXT_FD_VALID, EBPF_TLS_PLAINTEXT_SAMPLE_BYTES,
        EbpfTlsPlaintextEvent, EbpfTlsPlaintextObservation,
    };
    use probe_core::{
        CaptureSource, Direction, ProcessContext, ProcessIdentity, TcpConnection, TcpEndpoint,
    };

    use crate::CaptureProviderKind;

    use super::{
        super::bridge::{LibsslResolvedFlow, LibsslUprobeFlowLookup, LibsslUprobeFlowResolver},
        *,
    };

    #[test]
    fn provider_decodes_tls_plaintext_source_samples() -> Result<(), Box<dyn std::error::Error>> {
        let event = sample_event();
        let resolver = Box::new(StaticFlowResolver {
            expected: LibsslUprobeFlowLookup {
                tgid: 22,
                thread_pid: 11,
                ssl_pointer: 0xfeed,
                fd: Some(7),
                direction: Direction::Outbound,
            },
            resolved: Some(demo_resolved_flow()),
            seen: false,
        });
        let mut provider = LibsslUprobePlaintextProvider::new(
            Box::new(VecTlsPlaintextSource::new([event])),
            resolver,
        );

        let Some(crate::CaptureEvent::Bytes(bytes)) = provider.next()? else {
            panic!("expected provider to emit plaintext bytes");
        };

        assert_eq!(provider.name(), "libssl_uprobe_plaintext");
        assert_eq!(provider.source(), CaptureSource::LibsslUprobe);
        assert_eq!(bytes.source, CaptureSource::LibsslUprobe);
        assert_eq!(bytes.provider, CaptureProviderKind::Plaintext);
        assert_eq!(bytes.stream_offset, 100);
        assert_eq!(bytes.bytes.as_ref(), b"GET /");
        assert!(provider.next()?.is_none());
        Ok(())
    }

    fn sample_event() -> EbpfTlsPlaintextEvent {
        let mut payload = [0; EBPF_TLS_PLAINTEXT_SAMPLE_BYTES];
        payload[..5].copy_from_slice(b"GET /");
        EbpfTlsPlaintextEvent::libssl_plaintext_sampled(
            11,
            22,
            33,
            44,
            nul_padded_command("curl"),
            EbpfTlsPlaintextObservation::new(
                0xfeed,
                7,
                EBPF_TLS_DIRECTION_OUTBOUND,
                100,
                5,
                5,
                payload,
            ),
            EBPF_TLS_PLAINTEXT_FD_VALID,
        )
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
                TcpEndpoint::new("127.0.0.1".parse().expect("valid local address"), 50_000),
                TcpEndpoint::new("127.0.0.1".parse().expect("valid remote address"), 443),
            ),
            start_monotonic_ns: 1,
        }
    }

    fn nul_padded_command(command: &str) -> [u8; 16] {
        let mut bytes = [0; 16];
        for (target, source) in bytes.iter_mut().zip(command.as_bytes()) {
            *target = *source;
        }
        bytes
    }

    struct StaticFlowResolver {
        expected: LibsslUprobeFlowLookup,
        resolved: Option<LibsslResolvedFlow>,
        seen: bool,
    }

    impl LibsslUprobeFlowResolver for StaticFlowResolver {
        fn resolve_libssl_uprobe_flow(
            &mut self,
            lookup: LibsslUprobeFlowLookup,
        ) -> Result<Option<LibsslResolvedFlow>, CaptureError> {
            assert_eq!(lookup, self.expected);
            self.seen = true;
            Ok(self.resolved.clone())
        }
    }

    struct VecTlsPlaintextSource {
        samples: VecDeque<LibsslUprobePlaintextSample>,
    }

    impl VecTlsPlaintextSource {
        fn new(events: impl IntoIterator<Item = EbpfTlsPlaintextEvent>) -> Self {
            Self {
                samples: events
                    .into_iter()
                    .map(|event| {
                        LibsslUprobePlaintextSample::from_ebpf_event(&event)
                            .expect("test event must normalize")
                    })
                    .collect(),
            }
        }
    }

    impl LibsslUprobePlaintextSampleSource for VecTlsPlaintextSource {
        fn next_tls_plaintext_sample(
            &mut self,
        ) -> Result<Option<LibsslUprobePlaintextSample>, CaptureError> {
            Ok(self.samples.pop_front())
        }
    }
}
