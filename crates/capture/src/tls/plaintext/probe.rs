use std::path::PathBuf;

use aya::{
    Ebpf, EbpfError,
    maps::{MapData, RingBuf},
};
use ebpf_abi::{EBPF_EVENTS_MAP_NAME, EbpfEventDecodeError, decode_tls_plaintext_event};
use ebpf_object::{
    EbpfObjectArtifact, EbpfObjectProbe, EbpfObjectProbeReport, EbpfPreflightedObject,
};
use thiserror::Error;

use crate::{CaptureError, tls::LibsslUprobeAttachPlan};

use super::{
    attach::{
        AttachFailurePolicy, LibsslUprobeAttachError, LibsslUprobeAttachRecipeRequest,
        LibsslUprobeAttachSession, attach_recipes_from_plan,
    },
    provider::LibsslUprobePlaintextSampleSource,
    record::LibsslUprobePlaintextSample,
};

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
    #[error("failed to load eBPF TLS plaintext object with aya: {source}")]
    Load { source: Box<EbpfError> },
    #[error("{source}")]
    Attach {
        #[from]
        source: LibsslUprobeAttachError,
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
    ebpf: Ebpf,
    attach_session: LibsslUprobeAttachSession,
    events: RingBuf<MapData>,
}

pub(in crate::tls::plaintext) enum LibsslUprobePlaintextProbeLoad {
    Enabled(Box<LibsslUprobePlaintextProbe>),
    Disabled { reason: String },
}

impl LibsslUprobePlaintextProbe {
    pub(in crate::tls::plaintext) fn load(
        config: LibsslUprobePlaintextProbeConfig,
    ) -> Result<Self, LibsslUprobePlaintextProbeError> {
        let attach_recipes = attach_recipes_from_plan(&config.attach_plan)?;
        let object = EbpfObjectProbe::preflight(
            &EbpfObjectArtifact::TlsPlaintext.probe_config(config.object_path),
        )
        .map_err(|report| LibsslUprobePlaintextProbeError::ObjectPreflight {
            summary: report.summary(),
            report,
        })?;
        Self::load_preflighted(object, &attach_recipes)
    }

    pub(in crate::tls::plaintext) fn load_best_effort(
        config: LibsslUprobePlaintextProbeConfig,
    ) -> Result<LibsslUprobePlaintextProbeLoad, LibsslUprobePlaintextProbeError> {
        let attach_recipes = attach_recipes_from_plan(&config.attach_plan)?;
        let object = EbpfObjectProbe::preflight(
            &EbpfObjectArtifact::TlsPlaintext.probe_config(config.object_path),
        )
        .map_err(|report| LibsslUprobePlaintextProbeError::ObjectPreflight {
            summary: report.summary(),
            report,
        })?;
        Self::load_preflighted_best_effort(object, &attach_recipes)
    }

    fn load_preflighted(
        object: EbpfPreflightedObject,
        attach_recipes: &[LibsslUprobeAttachRecipeRequest],
    ) -> Result<Self, LibsslUprobePlaintextProbeError> {
        let mut ebpf =
            Ebpf::load(object.bytes()).map_err(|source| LibsslUprobePlaintextProbeError::Load {
                source: Box::new(source),
            })?;
        let mut attach_session = LibsslUprobeAttachSession::default();
        attach_session.attach_uprobes(&mut ebpf, attach_recipes, AttachFailurePolicy::Strict)?;
        let events = open_events_ringbuf_or_detach(&mut ebpf, &mut attach_session)?;
        Ok(Self {
            ebpf,
            attach_session,
            events,
        })
    }

    fn load_preflighted_best_effort(
        object: EbpfPreflightedObject,
        attach_recipes: &[LibsslUprobeAttachRecipeRequest],
    ) -> Result<LibsslUprobePlaintextProbeLoad, LibsslUprobePlaintextProbeError> {
        let mut ebpf =
            Ebpf::load(object.bytes()).map_err(|source| LibsslUprobePlaintextProbeError::Load {
                source: Box::new(source),
            })?;
        let mut attach_session = LibsslUprobeAttachSession::default();
        let attach_summary = attach_session.attach_uprobes(
            &mut ebpf,
            attach_recipes,
            AttachFailurePolicy::BestEffort,
        )?;
        if !attach_summary.has_committed_targets() {
            attach_session.detach_all_best_effort(&mut ebpf)?;
            return Ok(LibsslUprobePlaintextProbeLoad::Disabled {
                reason: attach_summary.unresolvable_plaintext_reason(),
            });
        }
        let events = open_events_ringbuf_or_detach(&mut ebpf, &mut attach_session)?;
        Ok(LibsslUprobePlaintextProbeLoad::Enabled(Box::new(Self {
            ebpf,
            attach_session,
            events,
        })))
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

impl Drop for LibsslUprobePlaintextProbe {
    fn drop(&mut self) {
        let _ = self.attach_session.detach_all_best_effort(&mut self.ebpf);
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

fn open_events_ringbuf_or_detach(
    ebpf: &mut Ebpf,
    attach_session: &mut LibsslUprobeAttachSession,
) -> Result<RingBuf<MapData>, LibsslUprobePlaintextProbeError> {
    match open_events_ringbuf(ebpf) {
        Ok(events) => Ok(events),
        Err(error) => {
            let _ = attach_session.detach_all_best_effort(ebpf);
            Err(error)
        }
    }
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
    use std::path::{Path, PathBuf};

    use ebpf_abi::{
        EBPF_TLS_DIRECTION_OUTBOUND, EBPF_TLS_PLAINTEXT_EVENT_BYTES, EBPF_TLS_PLAINTEXT_FD_VALID,
        EBPF_TLS_PLAINTEXT_SAMPLE_BYTES, EbpfTlsPlaintextEvent, EbpfTlsPlaintextObservation,
        encode_tls_plaintext_event,
    };
    use probe_core::ProcessGeneration;
    use tempfile::tempdir;

    use crate::{
        LibsslLibraryKind, LibsslMappedFileIdentity, LibsslMappedLibrary, LibsslUprobeSymbol,
        LibsslUprobeTarget, LibsslUprobeTargetDiscoveryReport, tls::LibsslUprobeProcessVerifier,
    };

    use super::*;

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
            LibsslUprobeAttachPlan::from_discovery_report(discovery_report(
                42,
                vec![LibsslUprobeTarget {
                    library: mapped_library("/usr/lib/libssl.so.3"),
                    library_kind: LibsslLibraryKind::OpenSslLike,
                    executable_mappings: Vec::new(),
                    symbols: vec![LibsslUprobeSymbol::SslRead],
                }],
            )),
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

    fn discovery_report(
        pid: u32,
        targets: Vec<LibsslUprobeTarget>,
    ) -> LibsslUprobeTargetDiscoveryReport {
        LibsslUprobeTargetDiscoveryReport::new(
            process_generation(pid),
            process_verifier(),
            targets,
            Vec::new(),
        )
    }

    fn process_generation(pid: u32) -> ProcessGeneration {
        ProcessGeneration {
            pid,
            start_time_ticks: u64::from(pid) * 100,
        }
    }

    fn process_verifier() -> LibsslUprobeProcessVerifier {
        LibsslUprobeProcessVerifier::new("/proc")
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
