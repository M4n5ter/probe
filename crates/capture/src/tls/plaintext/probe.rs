use std::{collections::BTreeSet, path::PathBuf};

use aya::{
    Ebpf, EbpfError,
    maps::{MapData, RingBuf},
    programs::{ProbeKind, ProgramError, UProbe, uprobe::UProbeLinkId},
};
use ebpf_abi::{EBPF_EVENTS_MAP_NAME, EbpfEventDecodeError, decode_tls_plaintext_event};
use ebpf_object::{
    EbpfObjectArtifact, EbpfObjectProbe, EbpfObjectProbeReport, EbpfPreflightedObject,
};
use probe_core::ProcessGeneration;
use thiserror::Error;

use crate::{
    CaptureError,
    tls::{
        LibsslMappedLibrary, LibsslUprobeAttachKind, LibsslUprobeAttachPlan,
        LibsslUprobeAttachPoint, LibsslUprobeProcessGenerationFailure, LibsslUprobeProcessVerifier,
        LibsslUprobeSymbolFailure, LibsslUprobeSymbolRole,
        discovery::{verify_current_mapped_library_identity, verify_current_process_generation},
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
    #[error("failed to rollback eBPF TLS plaintext attach for program {program_name}: {source}")]
    RollbackAttach {
        program_name: &'static str,
        source: Box<ProgramError>,
    },
    #[error("libssl uprobe attach target for pid {pid} is no longer valid: {source}")]
    AttachTarget {
        pid: u32,
        source: Box<LibsslUprobeSymbolFailure>,
    },
    #[error("libssl uprobe attach target process for pid {pid} is no longer valid: {source}")]
    AttachProcess {
        pid: u32,
        source: Box<LibsslUprobeProcessGenerationFailure>,
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
        attach_uprobes(&mut ebpf, attach_recipes, AttachFailurePolicy::Strict)?;
        let events = open_events_ringbuf(&mut ebpf)?;
        Ok(Self {
            _ebpf: ebpf,
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
        let attach_summary =
            attach_uprobes(&mut ebpf, attach_recipes, AttachFailurePolicy::BestEffort)?;
        if !attach_summary.has_resolvable_plaintext_recipe() {
            return Ok(LibsslUprobePlaintextProbeLoad::Disabled {
                reason: attach_summary.unresolvable_plaintext_reason(),
            });
        }
        let events = open_events_ringbuf(&mut ebpf)?;
        Ok(LibsslUprobePlaintextProbeLoad::Enabled(Box::new(Self {
            _ebpf: ebpf,
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

impl LibsslUprobePlaintextSampleSource for LibsslUprobePlaintextProbe {
    fn next_tls_plaintext_sample(
        &mut self,
    ) -> Result<Option<LibsslUprobePlaintextSample>, CaptureError> {
        self.next_sample()
            .map_err(|error| CaptureError::provider("libssl_uprobe_plaintext", error.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LibsslUprobeAttachRecipeRequest {
    library: LibsslMappedLibrary,
    process: ProcessGeneration,
    process_verifier: LibsslUprobeProcessVerifier,
    semantic: LibsslUprobeSymbolRole,
    pid: i32,
    attach_points: Vec<LibsslUprobeAttachPointRequest>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LibsslUprobeAttachPointRequest {
    program_name: &'static str,
    library_symbol: &'static str,
    offset: u64,
    kind: LibsslUprobeAttachKind,
}

struct AttachedLibsslUprobe {
    program_name: &'static str,
    link_id: UProbeLinkId,
}

fn attach_recipes_from_plan(
    plan: &LibsslUprobeAttachPlan,
) -> Result<Vec<LibsslUprobeAttachRecipeRequest>, LibsslUprobePlaintextProbeError> {
    let mut requests = Vec::new();
    for process in plan.processes() {
        let pid = attachable_pid(process.pid())?;
        for target in process.targets() {
            for recipe in &target.recipes {
                requests.push(attach_recipe_request_from_plan(
                    target.library.clone(),
                    process.process(),
                    process.process_verifier().clone(),
                    recipe.semantic(),
                    pid,
                    recipe
                        .attach_points()
                        .into_iter()
                        .map(attach_point_request_from_plan)
                        .collect(),
                ));
            }
        }
    }
    if requests.is_empty() {
        return Err(LibsslUprobePlaintextProbeError::EmptyAttachPlan);
    }
    Ok(requests)
}

fn attachable_pid(pid: u32) -> Result<i32, LibsslUprobePlaintextProbeError> {
    if pid == 0 {
        return Err(LibsslUprobePlaintextProbeError::InvalidTargetPid { pid });
    }
    i32::try_from(pid).map_err(|_| LibsslUprobePlaintextProbeError::InvalidTargetPid { pid })
}

fn attach_recipe_request_from_plan(
    library: LibsslMappedLibrary,
    process: ProcessGeneration,
    process_verifier: LibsslUprobeProcessVerifier,
    semantic: LibsslUprobeSymbolRole,
    pid: i32,
    attach_points: Vec<LibsslUprobeAttachPointRequest>,
) -> LibsslUprobeAttachRecipeRequest {
    LibsslUprobeAttachRecipeRequest {
        library,
        process,
        process_verifier,
        semantic,
        pid,
        attach_points,
    }
}

fn attach_point_request_from_plan(
    point: LibsslUprobeAttachPoint,
) -> LibsslUprobeAttachPointRequest {
    LibsslUprobeAttachPointRequest {
        program_name: point.program_name,
        library_symbol: point.library_symbol,
        offset: point.offset,
        kind: point.kind,
    }
}

fn attach_uprobes(
    ebpf: &mut Ebpf,
    recipes: &[LibsslUprobeAttachRecipeRequest],
    policy: AttachFailurePolicy,
) -> Result<LibsslUprobeAttachSummary, LibsslUprobePlaintextProbeError> {
    let mut loaded_programs = BTreeSet::new();
    let mut attach_summary = LibsslUprobeAttachSummary::from_recipes(recipes);
    for (recipe_index, recipe) in recipes.iter().enumerate() {
        if let Err(error) = attach_recipe_uprobes(ebpf, &mut loaded_programs, recipe) {
            match policy {
                AttachFailurePolicy::Strict => return Err(error),
                AttachFailurePolicy::BestEffort if error.is_best_effort_attach_failure() => {
                    attach_summary.record_failure(&error);
                }
                AttachFailurePolicy::BestEffort => return Err(error),
            }
        } else {
            attach_summary.record_recipe_attached(recipe_index);
        }
    }
    Ok(attach_summary)
}

impl LibsslUprobePlaintextProbeError {
    fn is_best_effort_attach_failure(&self) -> bool {
        matches!(
            self,
            Self::Attach { .. } | Self::AttachTarget { .. } | Self::AttachProcess { .. }
        )
    }
}

fn attach_recipe_uprobes(
    ebpf: &mut Ebpf,
    loaded_programs: &mut BTreeSet<&'static str>,
    recipe: &LibsslUprobeAttachRecipeRequest,
) -> Result<(), LibsslUprobePlaintextProbeError> {
    attach_target_is_current(recipe)?;

    let mut attached = Vec::new();
    for point in &recipe.attach_points {
        if let Err(error) =
            attach_single_uprobe(ebpf, loaded_programs, recipe, point, &mut attached)
        {
            rollback_attached_uprobes(ebpf, attached)?;
            return Err(error);
        }
    }
    Ok(())
}

fn attach_single_uprobe(
    ebpf: &mut Ebpf,
    loaded_programs: &mut BTreeSet<&'static str>,
    recipe: &LibsslUprobeAttachRecipeRequest,
    point: &LibsslUprobeAttachPointRequest,
    attached: &mut Vec<AttachedLibsslUprobe>,
) -> Result<(), LibsslUprobePlaintextProbeError> {
    let program = uprobe_program_mut(ebpf, point.program_name)?;
    if !uprobe_kind_matches_attach_kind(program.kind(), point.kind) {
        return Err(LibsslUprobePlaintextProbeError::ProgramKind {
            name: point.program_name,
            actual: probe_kind_label(program.kind()),
            expected: point.kind,
        });
    }
    if loaded_programs.insert(point.program_name) {
        program
            .load()
            .map_err(|source| LibsslUprobePlaintextProbeError::Program {
                name: point.program_name,
                action: "load",
                source: Box::new(source),
            })?;
    }
    let link_id = program
        .attach(
            Some(point.library_symbol),
            point.offset,
            &recipe.library.read_path,
            Some(recipe.pid),
        )
        .map_err(|source| LibsslUprobePlaintextProbeError::Attach {
            program_name: point.program_name,
            library_symbol: point.library_symbol,
            pid: recipe.process.pid,
            target_path: recipe.library.read_path.clone(),
            source: Box::new(source),
        })?;
    attached.push(AttachedLibsslUprobe {
        program_name: point.program_name,
        link_id,
    });
    Ok(())
}

fn rollback_attached_uprobes(
    ebpf: &mut Ebpf,
    attached: Vec<AttachedLibsslUprobe>,
) -> Result<(), LibsslUprobePlaintextProbeError> {
    for attached in attached.into_iter().rev() {
        uprobe_program_mut(ebpf, attached.program_name)?
            .detach(attached.link_id)
            .map_err(|source| LibsslUprobePlaintextProbeError::RollbackAttach {
                program_name: attached.program_name,
                source: Box::new(source),
            })?;
    }
    Ok(())
}

fn uprobe_program_mut<'a>(
    ebpf: &'a mut Ebpf,
    program_name: &'static str,
) -> Result<&'a mut UProbe, LibsslUprobePlaintextProbeError> {
    let program = ebpf
        .program_mut(program_name)
        .ok_or(LibsslUprobePlaintextProbeError::MissingProgram { name: program_name })?;
    program
        .try_into()
        .map_err(|source| LibsslUprobePlaintextProbeError::Program {
            name: program_name,
            action: "cast",
            source: Box::new(source),
        })
}

fn attach_target_is_current(
    recipe: &LibsslUprobeAttachRecipeRequest,
) -> Result<(), LibsslUprobePlaintextProbeError> {
    if let Err(source) = verify_current_process_generation(recipe.process, &recipe.process_verifier)
    {
        return Err(LibsslUprobePlaintextProbeError::AttachProcess {
            pid: recipe.process.pid,
            source: Box::new(source),
        });
    }
    if let Err(source) = verify_current_mapped_library_identity(&recipe.library) {
        return Err(LibsslUprobePlaintextProbeError::AttachTarget {
            pid: recipe.process.pid,
            source: Box::new(source),
        });
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

struct LibsslUprobeAttachSummary {
    recipes: Vec<LibsslUprobeRecipeAttachProgress>,
    first_failure_reason: Option<String>,
    failure_count: usize,
}

impl LibsslUprobeAttachSummary {
    fn from_recipes(recipes: &[LibsslUprobeAttachRecipeRequest]) -> Self {
        let recipes = recipes
            .iter()
            .map(|recipe| LibsslUprobeRecipeAttachProgress {
                target: LibsslUprobeAttachTargetKey {
                    process: recipe.process,
                    library: recipe.library.clone(),
                },
                semantic: recipe.semantic,
                complete: false,
            })
            .collect();
        Self {
            recipes,
            first_failure_reason: None,
            failure_count: 0,
        }
    }

    fn record_recipe_attached(&mut self, recipe_index: usize) {
        if let Some(recipe) = self.recipes.get_mut(recipe_index) {
            recipe.complete = true;
        }
    }

    fn record_failure(&mut self, error: &LibsslUprobePlaintextProbeError) {
        self.failure_count = self.failure_count.saturating_add(1);
        self.first_failure_reason
            .get_or_insert_with(|| error.to_string());
    }

    fn has_resolvable_plaintext_recipe(&self) -> bool {
        self.recipes.iter().any(|recipe| {
            recipe.complete
                && matches!(recipe.semantic, LibsslUprobeSymbolRole::Plaintext { .. })
                && self.has_complete_fd_association_for(&recipe.target)
        })
    }

    fn has_complete_fd_association_for(&self, target: &LibsslUprobeAttachTargetKey) -> bool {
        self.recipes.iter().any(|recipe| {
            recipe.complete
                && recipe.target == *target
                && recipe.semantic == LibsslUprobeSymbolRole::FdAssociation
        })
    }

    fn unresolvable_plaintext_reason(&self) -> String {
        if self
            .recipes
            .iter()
            .any(|recipe| matches!(recipe.semantic, LibsslUprobeSymbolRole::Plaintext { .. }))
        {
            let mut reason = "libssl uprobe best-effort attach did not complete any same-target fd association plus plaintext recipe set".to_string();
            if let Some(first_failure_reason) = &self.first_failure_reason {
                reason.push_str("; first attach failure: ");
                reason.push_str(first_failure_reason);
                if self.failure_count > 1 {
                    reason.push_str(&format!(
                        "; additional attach failures: {}",
                        self.failure_count - 1
                    ));
                }
            }
            reason
        } else {
            "libssl uprobe attach plan did not contain a plaintext recipe".to_string()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LibsslUprobeAttachTargetKey {
    process: ProcessGeneration,
    library: LibsslMappedLibrary,
}

struct LibsslUprobeRecipeAttachProgress {
    target: LibsslUprobeAttachTargetKey,
    semantic: LibsslUprobeSymbolRole,
    complete: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttachFailurePolicy {
    Strict,
    BestEffort,
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
    use std::path::{Path, PathBuf};

    use ebpf_abi::{
        EBPF_TLS_DIRECTION_OUTBOUND, EBPF_TLS_PLAINTEXT_EVENT_BYTES, EBPF_TLS_PLAINTEXT_FD_VALID,
        EBPF_TLS_PLAINTEXT_SAMPLE_BYTES, EbpfTlsPlaintextEvent, EbpfTlsPlaintextObservation,
        encode_tls_plaintext_event,
    };
    use probe_core::Direction;
    use tempfile::tempdir;

    use crate::{
        LibsslExecutableMapping, LibsslLibraryKind, LibsslMappedFileIdentity, LibsslMappedLibrary,
        LibsslUprobeSymbol, LibsslUprobeTarget, LibsslUprobeTargetDiscoveryReport,
    };

    use super::*;

    #[test]
    fn attach_recipes_preserve_plan_pid_path_symbol_and_kind()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = LibsslUprobeAttachPlan::from_discovery_report(discovery_report(
            42,
            vec![LibsslUprobeTarget {
                library: mapped_library("/usr/lib/libssl.so.3"),
                library_kind: LibsslLibraryKind::OpenSslLike,
                executable_mappings: vec![LibsslExecutableMapping {
                    start_address: 0x1000,
                    end_address: 0x2000,
                    file_offset: 0,
                }],
                symbols: vec![LibsslUprobeSymbol::SslRead],
            }],
        ));

        let recipes = attach_recipes_from_plan(&plan)?;

        assert_eq!(
            recipes,
            vec![LibsslUprobeAttachRecipeRequest {
                library: mapped_library("/usr/lib/libssl.so.3"),
                process: process_generation(42),
                process_verifier: process_verifier(),
                semantic: LibsslUprobeSymbolRole::Plaintext {
                    direction: Direction::Inbound,
                },
                pid: 42,
                attach_points: vec![
                    LibsslUprobeAttachPointRequest {
                        program_name: LibsslUprobeSymbol::SslRead.entry_program_name(),
                        library_symbol: "SSL_read",
                        offset: 0,
                        kind: LibsslUprobeAttachKind::Entry,
                    },
                    LibsslUprobeAttachPointRequest {
                        program_name: LibsslUprobeSymbol::SslRead
                            .return_program_name()
                            .expect("SSL_read should have a return probe"),
                        library_symbol: "SSL_read",
                        offset: 0,
                        kind: LibsslUprobeAttachKind::Return,
                    },
                ],
            }]
        );
        Ok(())
    }

    #[test]
    fn attach_summary_requires_same_target_fd_association_and_plaintext()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = LibsslUprobeAttachPlan::from_discovery_report(discovery_report(
            42,
            vec![LibsslUprobeTarget {
                library: mapped_library("/usr/lib/libssl.so.3"),
                library_kind: LibsslLibraryKind::OpenSslLike,
                executable_mappings: Vec::new(),
                symbols: vec![LibsslUprobeSymbol::SslSetFd, LibsslUprobeSymbol::SslRead],
            }],
        ));
        let recipes = attach_recipes_from_plan(&plan)?;
        let lifecycle_recipe = recipes
            .iter()
            .position(|recipe| recipe.semantic == LibsslUprobeSymbolRole::FdAssociation)
            .expect("fixture should include lifecycle recipe");
        let plaintext_recipe = recipes
            .iter()
            .position(|recipe| matches!(recipe.semantic, LibsslUprobeSymbolRole::Plaintext { .. }))
            .expect("fixture should include plaintext recipe");
        let mut summary = LibsslUprobeAttachSummary::from_recipes(&recipes);

        summary.record_recipe_attached(lifecycle_recipe);
        assert!(!summary.has_resolvable_plaintext_recipe());

        summary.record_recipe_attached(plaintext_recipe);
        assert!(summary.has_resolvable_plaintext_recipe());
        Ok(())
    }

    #[test]
    fn attach_summary_rejects_plaintext_without_fd_association()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = LibsslUprobeAttachPlan::from_discovery_report(discovery_report(
            42,
            vec![LibsslUprobeTarget {
                library: mapped_library("/usr/lib/libssl.so.3"),
                library_kind: LibsslLibraryKind::OpenSslLike,
                executable_mappings: Vec::new(),
                symbols: vec![LibsslUprobeSymbol::SslRead],
            }],
        ));
        let recipes = attach_recipes_from_plan(&plan)?;
        let plaintext_recipe = recipes
            .iter()
            .position(|recipe| matches!(recipe.semantic, LibsslUprobeSymbolRole::Plaintext { .. }))
            .expect("fixture should include plaintext recipe");
        let mut summary = LibsslUprobeAttachSummary::from_recipes(&recipes);

        summary.record_recipe_attached(plaintext_recipe);

        assert!(!summary.has_resolvable_plaintext_recipe());
        assert!(
            summary
                .unresolvable_plaintext_reason()
                .contains("same-target fd association plus plaintext recipe set")
        );
        Ok(())
    }

    #[test]
    fn attach_summary_disabled_reason_preserves_first_attach_failure()
    -> Result<(), Box<dyn std::error::Error>> {
        let plan = LibsslUprobeAttachPlan::from_discovery_report(discovery_report(
            42,
            vec![LibsslUprobeTarget {
                library: mapped_library("/usr/lib/libssl.so.3"),
                library_kind: LibsslLibraryKind::OpenSslLike,
                executable_mappings: Vec::new(),
                symbols: vec![LibsslUprobeSymbol::SslRead],
            }],
        ));
        let recipes = attach_recipes_from_plan(&plan)?;
        let mut summary = LibsslUprobeAttachSummary::from_recipes(&recipes);

        summary.record_failure(&LibsslUprobePlaintextProbeError::AttachProcess {
            pid: 42,
            source: Box::new(LibsslUprobeProcessGenerationFailure::Changed {
                path: PathBuf::from("/proc/42/stat"),
                expected_start_time_ticks: 7,
                actual_start_time_ticks: 8,
            }),
        });

        let reason = summary.unresolvable_plaintext_reason();
        assert!(reason.contains("did not complete any same-target fd association"));
        assert!(reason.contains("first attach failure"));
        assert!(reason.contains("process stat /proc/42/stat no longer matches expected starttime"));
        Ok(())
    }

    #[test]
    fn attach_recipes_reject_empty_plan() {
        let error = attach_recipes_from_plan(&LibsslUprobeAttachPlan::from_discovery_reports([]))
            .expect_err("empty plan must not load a TLS uprobe probe");

        assert!(matches!(
            error,
            LibsslUprobePlaintextProbeError::EmptyAttachPlan
        ));
    }

    #[test]
    fn attach_recipes_reject_pid_that_cannot_fit_pid_t() {
        let plan = LibsslUprobeAttachPlan::from_discovery_report(discovery_report(
            i32::MAX as u32 + 1,
            vec![LibsslUprobeTarget {
                library: mapped_library("/usr/lib/libssl.so.3"),
                library_kind: LibsslLibraryKind::OpenSslLike,
                executable_mappings: Vec::new(),
                symbols: vec![LibsslUprobeSymbol::SslRead],
            }],
        ));

        let error = attach_recipes_from_plan(&plan)
            .expect_err("pid outside pid_t range must fail before aya attach");

        assert!(matches!(
            error,
            LibsslUprobePlaintextProbeError::InvalidTargetPid { pid }
                if pid == i32::MAX as u32 + 1
        ));
    }

    #[test]
    fn attach_recipes_reject_pid_zero() {
        let plan = LibsslUprobeAttachPlan::from_discovery_report(discovery_report(
            0,
            vec![LibsslUprobeTarget {
                library: mapped_library("/usr/lib/libssl.so.3"),
                library_kind: LibsslLibraryKind::OpenSslLike,
                executable_mappings: Vec::new(),
                symbols: vec![LibsslUprobeSymbol::SslRead],
            }],
        ));

        let error =
            attach_recipes_from_plan(&plan).expect_err("pid zero must not reach aya attach");

        assert!(matches!(
            error,
            LibsslUprobePlaintextProbeError::InvalidTargetPid { pid: 0 }
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
