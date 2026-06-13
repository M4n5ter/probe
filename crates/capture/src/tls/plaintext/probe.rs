use std::{collections::BTreeSet, path::PathBuf};

use aya::{
    Ebpf, EbpfError,
    maps::{MapData, RingBuf},
    programs::{ProbeKind, ProgramError, UProbe},
};
use ebpf_abi::{EBPF_EVENTS_MAP_NAME, EbpfEventDecodeError, decode_tls_plaintext_event};
use ebpf_object::{
    EbpfObjectArtifact, EbpfObjectProbe, EbpfObjectProbeReport, EbpfPreflightedObject,
};
use thiserror::Error;

use crate::{
    CaptureError,
    tls::{
        LibsslMappedLibrary, LibsslUprobeAttachKind, LibsslUprobeAttachPlan,
        LibsslUprobeAttachPoint, LibsslUprobeSymbolFailure,
        discovery::verify_current_mapped_library_identity,
    },
};

use super::{provider::LibsslUprobePlaintextSampleSource, record::LibsslUprobePlaintextSample};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibsslUprobePlaintextProbeConfig {
    pub object_path: PathBuf,
    pub attach_plan: LibsslUprobeAttachPlan,
}

impl LibsslUprobePlaintextProbeConfig {
    pub fn new(object_path: impl Into<PathBuf>, attach_plan: LibsslUprobeAttachPlan) -> Self {
        Self {
            object_path: object_path.into(),
            attach_plan,
        }
    }
}

#[derive(Debug, Error)]
pub(in crate::tls::plaintext) enum LibsslUprobePlaintextProbeError {
    #[error("eBPF TLS plaintext object preflight failed: {summary}")]
    ObjectPreflight {
        summary: String,
        report: Box<EbpfObjectProbeReport>,
    },
    #[error("libssl uprobe attach plan has no attachable probes")]
    EmptyAttachPlan,
    #[error("libssl uprobe target pid {pid} cannot be represented as a Linux pid_t")]
    InvalidTargetPid { pid: u32 },
    #[error("failed to load eBPF TLS plaintext object with aya: {source}")]
    Load { source: Box<EbpfError> },
    #[error("eBPF TLS plaintext object is missing program {name}")]
    MissingProgram { name: &'static str },
    #[error("failed to {action} eBPF TLS plaintext program {name}: {source}")]
    Program {
        name: &'static str,
        action: &'static str,
        source: Box<ProgramError>,
    },
    #[error("eBPF TLS plaintext program {name} has {actual} kind, expected {expected:?}")]
    ProgramKind {
        name: &'static str,
        actual: &'static str,
        expected: LibsslUprobeAttachKind,
    },
    #[error(
        "failed to attach eBPF TLS plaintext program {program_name} to {library_symbol} for pid {pid} at {target_path}: {source}"
    )]
    Attach {
        program_name: &'static str,
        library_symbol: &'static str,
        pid: u32,
        target_path: PathBuf,
        source: Box<ProgramError>,
    },
    #[error("libssl uprobe attach target for pid {pid} is no longer valid: {source}")]
    AttachTarget {
        pid: u32,
        source: Box<LibsslUprobeSymbolFailure>,
    },
    #[error("eBPF TLS plaintext object is missing map {name}")]
    MissingMap { name: &'static str },
    #[error("failed to open eBPF TLS plaintext ring buffer map {name}: {source}")]
    Map {
        name: &'static str,
        source: Box<aya::maps::MapError>,
    },
    #[error("failed to decode eBPF TLS plaintext event: {error:?}")]
    Decode { error: EbpfEventDecodeError },
    #[error("failed to normalize eBPF TLS plaintext sample: {reason}")]
    Sample { reason: String },
}

pub(in crate::tls::plaintext) struct LibsslUprobePlaintextProbe {
    _ebpf: Ebpf,
    events: RingBuf<MapData>,
}

impl LibsslUprobePlaintextProbe {
    pub(in crate::tls::plaintext) fn load(
        config: LibsslUprobePlaintextProbeConfig,
    ) -> Result<Self, LibsslUprobePlaintextProbeError> {
        let attach_requests = attach_requests_from_plan(&config.attach_plan)?;
        let object = EbpfObjectProbe::preflight(
            &EbpfObjectArtifact::TlsPlaintext.probe_config(config.object_path),
        )
        .map_err(|report| LibsslUprobePlaintextProbeError::ObjectPreflight {
            summary: report.summary(),
            report,
        })?;
        Self::load_preflighted(object, &attach_requests)
    }

    fn load_preflighted(
        object: EbpfPreflightedObject,
        attach_requests: &[LibsslUprobeAttachRequest],
    ) -> Result<Self, LibsslUprobePlaintextProbeError> {
        let mut ebpf =
            Ebpf::load(object.bytes()).map_err(|source| LibsslUprobePlaintextProbeError::Load {
                source: Box::new(source),
            })?;
        attach_uprobes(&mut ebpf, attach_requests)?;
        let events = open_events_ringbuf(&mut ebpf)?;
        Ok(Self {
            _ebpf: ebpf,
            events,
        })
    }

    fn next_sample(
        &mut self,
    ) -> Result<Option<LibsslUprobePlaintextSample>, LibsslUprobePlaintextProbeError> {
        let Some(item) = self.events.next() else {
            return Ok(None);
        };
        plaintext_sample_from_ringbuf_record(&item).map(Some)
    }
}

impl LibsslUprobePlaintextSampleSource for LibsslUprobePlaintextProbe {
    fn next_tls_plaintext_sample(
        &mut self,
    ) -> Result<Option<LibsslUprobePlaintextSample>, CaptureError> {
        self.next_sample()
            .map_err(|error| CaptureError::provider("libssl_uprobe_plaintext", error.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LibsslUprobeAttachRequest {
    program_name: &'static str,
    library_symbol: &'static str,
    library: LibsslMappedLibrary,
    pid: i32,
    raw_pid: u32,
    offset: u64,
    kind: LibsslUprobeAttachKind,
}

fn attach_requests_from_plan(
    plan: &LibsslUprobeAttachPlan,
) -> Result<Vec<LibsslUprobeAttachRequest>, LibsslUprobePlaintextProbeError> {
    let mut requests = Vec::new();
    for target in &plan.targets {
        let pid = i32::try_from(target.pid)
            .map_err(|_| LibsslUprobePlaintextProbeError::InvalidTargetPid { pid: target.pid })?;
        for recipe in &target.recipes {
            requests.extend(recipe.attach_points().into_iter().map(|point| {
                attach_request_from_point(point, target.library.clone(), pid, target.pid)
            }));
        }
    }
    if requests.is_empty() {
        return Err(LibsslUprobePlaintextProbeError::EmptyAttachPlan);
    }
    Ok(requests)
}

fn attach_request_from_point(
    point: LibsslUprobeAttachPoint,
    library: LibsslMappedLibrary,
    pid: i32,
    raw_pid: u32,
) -> LibsslUprobeAttachRequest {
    LibsslUprobeAttachRequest {
        program_name: point.program_name,
        library_symbol: point.library_symbol,
        library,
        pid,
        raw_pid,
        offset: point.offset,
        kind: point.kind,
    }
}

fn attach_uprobes(
    ebpf: &mut Ebpf,
    requests: &[LibsslUprobeAttachRequest],
) -> Result<(), LibsslUprobePlaintextProbeError> {
    let mut loaded_programs = BTreeSet::new();
    let mut verified_libraries = BTreeSet::new();
    for request in requests {
        if verified_libraries.insert((request.raw_pid, request.library.clone())) {
            verify_current_mapped_library_identity(&request.library).map_err(|source| {
                LibsslUprobePlaintextProbeError::AttachTarget {
                    pid: request.raw_pid,
                    source: Box::new(source),
                }
            })?;
        }
        let program = ebpf.program_mut(request.program_name).ok_or(
            LibsslUprobePlaintextProbeError::MissingProgram {
                name: request.program_name,
            },
        )?;
        let program: &mut UProbe =
            program
                .try_into()
                .map_err(|source| LibsslUprobePlaintextProbeError::Program {
                    name: request.program_name,
                    action: "cast",
                    source: Box::new(source),
                })?;
        if !uprobe_kind_matches_attach_kind(program.kind(), request.kind) {
            return Err(LibsslUprobePlaintextProbeError::ProgramKind {
                name: request.program_name,
                actual: probe_kind_label(program.kind()),
                expected: request.kind,
            });
        }
        if loaded_programs.insert(request.program_name) {
            program
                .load()
                .map_err(|source| LibsslUprobePlaintextProbeError::Program {
                    name: request.program_name,
                    action: "load",
                    source: Box::new(source),
                })?;
        }
        program
            .attach(
                Some(request.library_symbol),
                request.offset,
                &request.library.read_path,
                Some(request.pid),
            )
            .map_err(|source| LibsslUprobePlaintextProbeError::Attach {
                program_name: request.program_name,
                library_symbol: request.library_symbol,
                pid: request.raw_pid,
                target_path: request.library.read_path.clone(),
                source: Box::new(source),
            })?;
    }
    Ok(())
}

fn uprobe_kind_matches_attach_kind(actual: ProbeKind, expected: LibsslUprobeAttachKind) -> bool {
    matches!(
        (actual, expected),
        (ProbeKind::UProbe, LibsslUprobeAttachKind::Entry)
            | (ProbeKind::URetProbe, LibsslUprobeAttachKind::Return)
    )
}

fn probe_kind_label(kind: ProbeKind) -> &'static str {
    match kind {
        ProbeKind::KProbe => "kprobe",
        ProbeKind::KRetProbe => "kretprobe",
        ProbeKind::UProbe => "uprobe",
        ProbeKind::URetProbe => "uretprobe",
    }
}

fn open_events_ringbuf(
    ebpf: &mut Ebpf,
) -> Result<RingBuf<MapData>, LibsslUprobePlaintextProbeError> {
    let map =
        ebpf.take_map(EBPF_EVENTS_MAP_NAME)
            .ok_or(LibsslUprobePlaintextProbeError::MissingMap {
                name: EBPF_EVENTS_MAP_NAME,
            })?;
    RingBuf::try_from(map).map_err(|source| LibsslUprobePlaintextProbeError::Map {
        name: EBPF_EVENTS_MAP_NAME,
        source: Box::new(source),
    })
}

fn plaintext_sample_from_ringbuf_record(
    bytes: &[u8],
) -> Result<LibsslUprobePlaintextSample, LibsslUprobePlaintextProbeError> {
    let event = decode_tls_plaintext_event(bytes)
        .map_err(|error| LibsslUprobePlaintextProbeError::Decode { error })?;
    LibsslUprobePlaintextSample::from_ebpf_event(&event).map_err(|error| {
        LibsslUprobePlaintextProbeError::Sample {
            reason: error.to_string(),
        }
    })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use ebpf_abi::{
        EBPF_TLS_DIRECTION_OUTBOUND, EBPF_TLS_PLAINTEXT_EVENT_BYTES, EBPF_TLS_PLAINTEXT_FD_VALID,
        EBPF_TLS_PLAINTEXT_SAMPLE_BYTES, EbpfTlsPlaintextEvent, EbpfTlsPlaintextObservation,
        encode_tls_plaintext_event,
    };
    use tempfile::tempdir;

    use crate::{
        LibsslExecutableMapping, LibsslLibraryKind, LibsslMappedFileIdentity, LibsslMappedLibrary,
        LibsslUprobeSymbol, LibsslUprobeTarget, LibsslUprobeTargetDiscoveryReport,
    };

    use super::*;

    #[test]
    fn attach_requests_preserve_plan_pid_path_symbol_and_kind()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan =
            LibsslUprobeAttachPlan::from_discovery_report(LibsslUprobeTargetDiscoveryReport {
                pid: 42,
                targets: vec![LibsslUprobeTarget {
                    pid: 42,
                    library: mapped_library("/usr/lib/libssl.so.3"),
                    library_kind: LibsslLibraryKind::OpenSslLike,
                    executable_mappings: vec![LibsslExecutableMapping {
                        start_address: 0x1000,
                        end_address: 0x2000,
                        file_offset: 0,
                    }],
                    symbols: vec![LibsslUprobeSymbol::SslRead],
                }],
                degraded_reasons: Vec::new(),
            });

        let requests = attach_requests_from_plan(&plan)?;

        assert_eq!(
            requests,
            vec![
                LibsslUprobeAttachRequest {
                    program_name: LibsslUprobeSymbol::SslRead.entry_program_name(),
                    library_symbol: "SSL_read",
                    library: mapped_library("/usr/lib/libssl.so.3"),
                    pid: 42,
                    raw_pid: 42,
                    offset: 0,
                    kind: LibsslUprobeAttachKind::Entry,
                },
                LibsslUprobeAttachRequest {
                    program_name: LibsslUprobeSymbol::SslRead
                        .return_program_name()
                        .expect("SSL_read should have a return probe"),
                    library_symbol: "SSL_read",
                    library: mapped_library("/usr/lib/libssl.so.3"),
                    pid: 42,
                    raw_pid: 42,
                    offset: 0,
                    kind: LibsslUprobeAttachKind::Return,
                },
            ]
        );
        Ok(())
    }

    #[test]
    fn attach_requests_reject_empty_plan() {
        let error = attach_requests_from_plan(&LibsslUprobeAttachPlan {
            targets: Vec::new(),
            degraded_reasons: Vec::new(),
        })
        .expect_err("empty plan must not load a TLS uprobe probe");

        assert!(matches!(
            error,
            LibsslUprobePlaintextProbeError::EmptyAttachPlan
        ));
    }

    #[test]
    fn attach_requests_reject_pid_that_cannot_fit_pid_t() {
        let plan =
            LibsslUprobeAttachPlan::from_discovery_report(LibsslUprobeTargetDiscoveryReport {
                pid: i32::MAX as u32 + 1,
                targets: vec![LibsslUprobeTarget {
                    pid: i32::MAX as u32 + 1,
                    library: mapped_library("/usr/lib/libssl.so.3"),
                    library_kind: LibsslLibraryKind::OpenSslLike,
                    executable_mappings: Vec::new(),
                    symbols: vec![LibsslUprobeSymbol::SslRead],
                }],
                degraded_reasons: Vec::new(),
            });

        let error = attach_requests_from_plan(&plan)
            .expect_err("pid outside pid_t range must fail before aya attach");

        assert!(matches!(
            error,
            LibsslUprobePlaintextProbeError::InvalidTargetPid { pid }
                if pid == i32::MAX as u32 + 1
        ));
    }

    #[test]
    fn attach_kind_matches_aya_uprobe_kind() {
        assert!(uprobe_kind_matches_attach_kind(
            ProbeKind::UProbe,
            LibsslUprobeAttachKind::Entry
        ));
        assert!(uprobe_kind_matches_attach_kind(
            ProbeKind::URetProbe,
            LibsslUprobeAttachKind::Return
        ));
        assert!(!uprobe_kind_matches_attach_kind(
            ProbeKind::UProbe,
            LibsslUprobeAttachKind::Return
        ));
        assert!(!uprobe_kind_matches_attach_kind(
            ProbeKind::URetProbe,
            LibsslUprobeAttachKind::Entry
        ));
    }

    #[test]
    fn ringbuf_record_decodes_to_plaintext_sample() -> Result<(), Box<dyn std::error::Error>> {
        let bytes = encode_tls_plaintext_event(&sample_event());

        let sample = plaintext_sample_from_ringbuf_record(&bytes)?;

        assert_eq!(bytes.len(), EBPF_TLS_PLAINTEXT_EVENT_BYTES);
        assert_eq!(sample.tgid, 22);
        assert_eq!(sample.fd, Some(7));
        assert_eq!(sample.stream_offset, 100);
        assert_eq!(sample.captured_bytes.as_ref(), b"GET /");
        Ok(())
    }

    #[test]
    fn probe_load_fails_before_aya_for_missing_object() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let config = LibsslUprobePlaintextProbeConfig::new(
            temp.path().join("missing.o"),
            LibsslUprobeAttachPlan::from_discovery_report(LibsslUprobeTargetDiscoveryReport {
                pid: 42,
                targets: vec![LibsslUprobeTarget {
                    pid: 42,
                    library: mapped_library("/usr/lib/libssl.so.3"),
                    library_kind: LibsslLibraryKind::OpenSslLike,
                    executable_mappings: Vec::new(),
                    symbols: vec![LibsslUprobeSymbol::SslRead],
                }],
                degraded_reasons: Vec::new(),
            }),
        );

        let error = match LibsslUprobePlaintextProbe::load(config) {
            Ok(_) => panic!("missing object must fail in object preflight"),
            Err(error) => error,
        };

        let LibsslUprobePlaintextProbeError::ObjectPreflight { report, .. } = error else {
            panic!("expected object preflight error");
        };
        assert!(report.summary().contains("missing.o"));
        Ok(())
    }

    fn mapped_library(path: &str) -> LibsslMappedLibrary {
        let mapped_path = PathBuf::from(path);
        LibsslMappedLibrary {
            read_path: Path::new("/proc/42/root").join(path.trim_start_matches('/')),
            mapped_path,
            identity: LibsslMappedFileIdentity {
                device_major: 8,
                device_minor: 1,
                inode: 100,
            },
            deleted: false,
        }
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

    fn nul_padded_command(command: &str) -> [u8; 16] {
        let mut bytes = [0; 16];
        for (target, source) in bytes.iter_mut().zip(command.as_bytes()) {
            *target = *source;
        }
        bytes
    }
}
