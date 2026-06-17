use std::path::PathBuf;

use aya::{
    Ebpf, EbpfError,
    maps::{HashMap as AyaHashMap, MapData, PerCpuArray, RingBuf},
};
use ebpf_abi::{
    EBPF_EVENTS_MAP_NAME, EBPF_TLS_OUTPUT_LOSSES_MAP_NAME, EBPF_TLS_STATE_EPOCH_KEY,
    EBPF_TLS_STATE_EPOCHS_MAP_NAME, EbpfEventDecodeError, decode_tls_plaintext_event,
};
use ebpf_object::{
    EbpfObjectArtifact, EbpfObjectProbe, EbpfObjectProbeReport, EbpfPreflightedObject,
};
use thiserror::Error;

use crate::{
    CaptureError,
    tls::{
        LibsslUprobeAttachPlan, LibsslUprobeAttachState, LibsslUprobeAttachTargetId,
        LibsslUprobeAttachTargetSnapshot, LibsslUprobeReconcileReport,
    },
};

use super::{
    attach::{
        AttachFailurePolicy, LibsslUprobeAttachError, LibsslUprobeAttachRecipeRequest,
        LibsslUprobeAttachSession, LibsslUprobeAttachSummary, LibsslUprobeAttachWork,
        best_effort_attach_work_from_plan, strict_attach_work_from_plan,
    },
    provider::LibsslUprobePlaintextSampleSource,
    record::LibsslUprobePlaintextSample,
};

pub const MAX_LIBSSL_RECONCILE_TARGET_SNAPSHOTS_PER_BUCKET: usize = 64;

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
    #[error("failed to access eBPF TLS plaintext map {name}: {source}")]
    Map {
        name: &'static str,
        source: Box<aya::maps::MapError>,
    },
    #[error("failed to decode eBPF TLS plaintext event: {error:?}")]
    Decode { error: EbpfEventDecodeError },
    #[error("failed to normalize eBPF TLS plaintext sample: {reason}")]
    Sample { reason: String },
    #[error("eBPF TLS plaintext reconcile did not produce a ready target: {reason}")]
    UnresolvableAttach { reason: String },
    #[error("eBPF TLS plaintext state epoch is exhausted")]
    StateEpochExhausted,
    #[error("eBPF TLS plaintext provider is disabled after reconcile failure: {reason}")]
    Poisoned { reason: String },
}

pub(in crate::tls::plaintext) struct LibsslUprobePlaintextProbe {
    ebpf: Ebpf,
    attach_session: LibsslUprobeAttachSession,
    events: RingBuf<MapData>,
    output_losses: OutputLossMap,
    state_epoch_fence: TlsStateEpochFence,
    poisoned_reason: Option<String>,
}

pub(in crate::tls::plaintext) enum LibsslUprobePlaintextProbeLoad {
    Enabled(Box<LibsslUprobePlaintextProbe>),
    Disabled { reason: String },
}

impl LibsslUprobePlaintextProbe {
    pub(in crate::tls::plaintext) fn load(
        config: LibsslUprobePlaintextProbeConfig,
    ) -> Result<Self, LibsslUprobePlaintextProbeError> {
        let attach_plan = config.attach_plan;
        let attach_work = strict_attach_work_from_plan(&attach_plan)?;
        let object = EbpfObjectProbe::preflight(
            &EbpfObjectArtifact::TlsPlaintext.probe_config(config.object_path),
        )
        .map_err(|report| LibsslUprobePlaintextProbeError::ObjectPreflight {
            summary: report.summary(),
            report,
        })?;
        Self::load_preflighted(object, attach_work.as_recipes())
    }

    pub(in crate::tls::plaintext) fn load_best_effort(
        config: LibsslUprobePlaintextProbeConfig,
    ) -> Result<LibsslUprobePlaintextProbeLoad, LibsslUprobePlaintextProbeError> {
        let attach_plan = config.attach_plan;
        let attach_work = best_effort_attach_work_from_plan(&attach_plan)?;
        let object = EbpfObjectProbe::preflight(
            &EbpfObjectArtifact::TlsPlaintext.probe_config(config.object_path),
        )
        .map_err(|report| LibsslUprobePlaintextProbeError::ObjectPreflight {
            summary: report.summary(),
            report,
        })?;
        Self::load_preflighted_best_effort(object, &attach_work)
    }

    fn load_preflighted(
        object: EbpfPreflightedObject,
        attach_recipes: &[LibsslUprobeAttachRecipeRequest],
    ) -> Result<Self, LibsslUprobePlaintextProbeError> {
        let mut ebpf =
            Ebpf::load(object.bytes()).map_err(|source| LibsslUprobePlaintextProbeError::Load {
                source: Box::new(source),
            })?;
        let mut state_epoch_fence = TlsStateEpochFence::default();
        enable_tls_state_epoch(&mut ebpf, &mut state_epoch_fence)?;
        let mut attach_session = LibsslUprobeAttachSession::default();
        attach_session.attach_uprobes(&mut ebpf, attach_recipes, AttachFailurePolicy::Strict)?;
        let (events, output_losses) =
            open_output_maps_or_detach(&mut ebpf, &mut attach_session, &mut state_epoch_fence)?;
        Ok(Self {
            ebpf,
            attach_session,
            events,
            output_losses,
            state_epoch_fence,
            poisoned_reason: None,
        })
    }

    fn load_preflighted_best_effort(
        object: EbpfPreflightedObject,
        attach_work: &LibsslUprobeAttachWork,
    ) -> Result<LibsslUprobePlaintextProbeLoad, LibsslUprobePlaintextProbeError> {
        let mut ebpf =
            Ebpf::load(object.bytes()).map_err(|source| LibsslUprobePlaintextProbeError::Load {
                source: Box::new(source),
            })?;
        let mut state_epoch_fence = TlsStateEpochFence::default();
        let mut attach_session = LibsslUprobeAttachSession::default();
        if attach_work.is_empty() {
            let (events, output_losses) =
                open_output_maps_or_detach(&mut ebpf, &mut attach_session, &mut state_epoch_fence)?;
            return Ok(LibsslUprobePlaintextProbeLoad::Enabled(Box::new(Self {
                ebpf,
                attach_session,
                events,
                output_losses,
                state_epoch_fence,
                poisoned_reason: None,
            })));
        }
        enable_tls_state_epoch(&mut ebpf, &mut state_epoch_fence)?;
        let attach_summary = attach_session.attach_uprobes(
            &mut ebpf,
            attach_work.as_recipes(),
            AttachFailurePolicy::BestEffort,
        )?;
        if !attach_summary.has_committed_targets() {
            attach_session.detach_all_best_effort(&mut ebpf)?;
            return Ok(LibsslUprobePlaintextProbeLoad::Disabled {
                reason: attach_summary.unresolvable_plaintext_reason(),
            });
        }
        let (events, output_losses) =
            open_output_maps_or_detach(&mut ebpf, &mut attach_session, &mut state_epoch_fence)?;
        Ok(LibsslUprobePlaintextProbeLoad::Enabled(Box::new(Self {
            ebpf,
            attach_session,
            events,
            output_losses,
            state_epoch_fence,
            poisoned_reason: None,
        })))
    }

    fn reconcile_best_effort(
        &mut self,
        next_plan: LibsslUprobeAttachPlan,
    ) -> Result<LibsslUprobePlaintextReconcile, LibsslUprobePlaintextProbeError> {
        self.ensure_not_poisoned()?;
        let report = self.current_attach_state().reconcile(&next_plan);
        let attach_work = best_effort_attach_work_from_plan(&report.attach_plan)?;
        match self.execute_reconcile_report(report, &attach_work) {
            Ok(result) => Ok(result),
            Err(error) => Err(self.poison_after_reconcile_error(error)),
        }
    }

    fn execute_reconcile_report(
        &mut self,
        report: LibsslUprobeReconcileReport,
        attach_work: &LibsslUprobeAttachWork,
    ) -> Result<LibsslUprobePlaintextReconcile, LibsslUprobePlaintextProbeError> {
        let attach_recipes = attach_work.as_recipes();
        let detached_target_ids = report.stale_targets.to_vec();
        let detached_targets = reconcile_target_bucket(detached_target_ids.iter().cloned());
        let epoch_plan = TlsStateEpochReconcilePlan::new(
            &report,
            attach_recipes,
            self.state_epoch_fence.is_enabled(),
        );
        if epoch_plan.disable_before_detach {
            self.disable_tls_state_epoch()?;
        }
        self.attach_session
            .detach_targets_best_effort(&mut self.ebpf, detached_target_ids.iter().cloned())?;
        if epoch_plan.enable_before_attach {
            self.enable_tls_state_epoch()?;
        }

        let mut attached_count = 0;
        let mut attached_targets = LibsslUprobeReconcileTargetBucket::default();
        let mut attach_summary = None;
        if !attach_recipes.is_empty() {
            let summary = self.attach_session.attach_uprobes(
                &mut self.ebpf,
                attach_recipes,
                AttachFailurePolicy::BestEffort,
            )?;
            let committed_targets = summary.committed_targets().collect::<Vec<_>>();
            attached_count = committed_targets.len();
            attached_targets = reconcile_target_bucket(committed_targets);
            attach_summary = Some(summary);
        }
        let active_target_ids = self.attach_session.attached_targets().collect::<Vec<_>>();
        let active_count = active_target_ids.len();
        let active_targets = reconcile_target_bucket(active_target_ids);
        if let Some(reason) = attach_summary.as_ref().and_then(|summary| {
            unresolvable_reconcile_attach_reason(summary, attached_count, active_count)
        }) {
            return Err(LibsslUprobePlaintextProbeError::UnresolvableAttach { reason });
        }

        Ok(LibsslUprobePlaintextReconcile {
            attached_targets,
            detached_targets,
            active_targets,
        })
    }

    fn next_sample(
        &mut self,
    ) -> Result<Option<LibsslUprobePlaintextSample>, LibsslUprobePlaintextProbeError> {
        self.ensure_not_poisoned()?;
        let Some(item) = self.events.next() else {
            return Ok(None);
        };
        plaintext_sample_from_ringbuf_record(&item).map(Some)
    }

    fn output_loss_count(&mut self) -> Result<u64, LibsslUprobePlaintextProbeError> {
        let values = self.output_losses.get(&0, 0).map_err(|source| {
            LibsslUprobePlaintextProbeError::Map {
                name: EBPF_TLS_OUTPUT_LOSSES_MAP_NAME,
                source: Box::new(source),
            }
        })?;
        Ok(values
            .iter()
            .copied()
            .fold(0u64, |total, value| total.saturating_add(value)))
    }

    fn current_attach_state(&self) -> LibsslUprobeAttachState {
        LibsslUprobeAttachState::from_targets(self.attach_session.attached_targets())
    }

    fn enable_tls_state_epoch(&mut self) -> Result<(), LibsslUprobePlaintextProbeError> {
        enable_tls_state_epoch(&mut self.ebpf, &mut self.state_epoch_fence)
    }

    fn disable_tls_state_epoch(&mut self) -> Result<(), LibsslUprobePlaintextProbeError> {
        disable_tls_state_epoch(&mut self.ebpf, &mut self.state_epoch_fence)
    }

    fn ensure_not_poisoned(&self) -> Result<(), LibsslUprobePlaintextProbeError> {
        match &self.poisoned_reason {
            Some(reason) => Err(LibsslUprobePlaintextProbeError::Poisoned {
                reason: reason.clone(),
            }),
            None => Ok(()),
        }
    }

    fn poison_after_reconcile_error(
        &mut self,
        error: LibsslUprobePlaintextProbeError,
    ) -> LibsslUprobePlaintextProbeError {
        let mut reason = format!("dynamic libssl uprobe reconcile failed: {error}");
        if let Err(cleanup_error) = self.disable_tls_state_epoch() {
            reason.push_str("; TLS state epoch disable also failed: ");
            reason.push_str(&cleanup_error.to_string());
        }
        if let Err(cleanup_error) = self.attach_session.detach_all_best_effort(&mut self.ebpf) {
            reason.push_str("; best-effort cleanup also failed: ");
            reason.push_str(&cleanup_error.to_string());
        }
        self.poisoned_reason = Some(reason.clone());
        LibsslUprobePlaintextProbeError::Poisoned { reason }
    }
}

#[derive(Default)]
struct TlsStateEpochFence {
    next_epoch: u64,
    enabled: bool,
}

impl TlsStateEpochFence {
    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn next_epoch(&mut self) -> Result<u64, LibsslUprobePlaintextProbeError> {
        self.next_epoch = self
            .next_epoch
            .checked_add(1)
            .ok_or(LibsslUprobePlaintextProbeError::StateEpochExhausted)?;
        Ok(self.next_epoch)
    }

    fn mark_enabled(&mut self) {
        self.enabled = true;
    }

    fn mark_disabled(&mut self) {
        self.enabled = false;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TlsStateEpochReconcilePlan {
    disable_before_detach: bool,
    enable_before_attach: bool,
}

impl TlsStateEpochReconcilePlan {
    fn new(
        report: &LibsslUprobeReconcileReport,
        attach_recipes: &[LibsslUprobeAttachRecipeRequest],
        epoch_enabled: bool,
    ) -> Self {
        let has_stale_targets = !report.stale_targets.is_empty();
        let has_remaining_targets = reconcile_needs_enabled_state_epoch(report, attach_recipes);
        Self {
            disable_before_detach: has_stale_targets,
            enable_before_attach: has_remaining_targets && (has_stale_targets || !epoch_enabled),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibsslUprobePlaintextReconcile {
    pub attached_targets: LibsslUprobeReconcileTargetBucket,
    pub detached_targets: LibsslUprobeReconcileTargetBucket,
    pub active_targets: LibsslUprobeReconcileTargetBucket,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LibsslUprobeReconcileTargetBucket {
    total_count: usize,
    targets: Vec<LibsslUprobeAttachTargetSnapshot>,
}

impl LibsslUprobeReconcileTargetBucket {
    pub fn new(targets: impl IntoIterator<Item = LibsslUprobeAttachTargetSnapshot>) -> Self {
        let mut total_count = 0;
        let mut snapshots = Vec::new();
        for target in targets {
            total_count += 1;
            if snapshots.len() < MAX_LIBSSL_RECONCILE_TARGET_SNAPSHOTS_PER_BUCKET {
                snapshots.push(target);
            }
        }
        Self {
            total_count,
            targets: snapshots,
        }
    }

    pub fn total_count(&self) -> usize {
        self.total_count
    }

    pub fn targets(&self) -> &[LibsslUprobeAttachTargetSnapshot] {
        &self.targets
    }

    pub fn into_targets(self) -> Vec<LibsslUprobeAttachTargetSnapshot> {
        self.targets
    }

    pub fn omitted_count(&self) -> usize {
        self.total_count - self.targets.len()
    }
}

impl LibsslUprobePlaintextReconcile {
    pub fn attached_target_count(&self) -> usize {
        self.attached_targets.total_count()
    }

    pub fn detached_target_count(&self) -> usize {
        self.detached_targets.total_count()
    }

    pub fn active_target_count(&self) -> usize {
        self.active_targets.total_count()
    }
}

impl Drop for LibsslUprobePlaintextProbe {
    fn drop(&mut self) {
        let _ = self.disable_tls_state_epoch();
        let _ = self.attach_session.detach_all_best_effort(&mut self.ebpf);
    }
}

fn unresolvable_reconcile_attach_reason(
    attach_summary: &LibsslUprobeAttachSummary,
    attached_targets: usize,
    active_targets: usize,
) -> Option<String> {
    if attached_targets == 0 && active_targets == 0 {
        Some(attach_summary.unresolvable_plaintext_reason())
    } else {
        None
    }
}

fn reconcile_target_bucket(
    targets: impl IntoIterator<Item = LibsslUprobeAttachTargetId>,
) -> LibsslUprobeReconcileTargetBucket {
    LibsslUprobeReconcileTargetBucket::new(
        targets
            .into_iter()
            .map(LibsslUprobeAttachTargetSnapshot::from),
    )
}

impl LibsslUprobePlaintextSampleSource for LibsslUprobePlaintextProbe {
    fn reconcile_libssl_uprobes(
        &mut self,
        next_plan: LibsslUprobeAttachPlan,
    ) -> Result<LibsslUprobePlaintextReconcile, CaptureError> {
        self.reconcile_best_effort(next_plan)
            .map_err(|error| CaptureError::provider("libssl_uprobe_plaintext", error.to_string()))
    }

    fn next_tls_plaintext_sample(
        &mut self,
    ) -> Result<Option<LibsslUprobePlaintextSample>, CaptureError> {
        self.next_sample()
            .map_err(|error| CaptureError::provider("libssl_uprobe_plaintext", error.to_string()))
    }

    fn tls_plaintext_output_loss_count(&mut self) -> Result<u64, CaptureError> {
        self.output_loss_count()
            .map_err(|error| CaptureError::provider("libssl_uprobe_plaintext", error.to_string()))
    }
}

type OutputLossMap = PerCpuArray<MapData, u64>;

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

fn open_output_loss_map(ebpf: &mut Ebpf) -> Result<OutputLossMap, LibsslUprobePlaintextProbeError> {
    let map = ebpf.take_map(EBPF_TLS_OUTPUT_LOSSES_MAP_NAME).ok_or(
        LibsslUprobePlaintextProbeError::MissingMap {
            name: EBPF_TLS_OUTPUT_LOSSES_MAP_NAME,
        },
    )?;
    OutputLossMap::try_from(map).map_err(|source| LibsslUprobePlaintextProbeError::Map {
        name: EBPF_TLS_OUTPUT_LOSSES_MAP_NAME,
        source: Box::new(source),
    })
}

fn reconcile_needs_enabled_state_epoch(
    report: &LibsslUprobeReconcileReport,
    attach_recipes: &[LibsslUprobeAttachRecipeRequest],
) -> bool {
    !report.retained_targets.is_empty() || !attach_recipes.is_empty()
}

fn enable_tls_state_epoch(
    ebpf: &mut Ebpf,
    fence: &mut TlsStateEpochFence,
) -> Result<(), LibsslUprobePlaintextProbeError> {
    if fence.is_enabled() {
        return Ok(());
    }
    let epoch = fence.next_epoch()?;
    write_tls_state_epoch(ebpf, epoch)?;
    fence.mark_enabled();
    Ok(())
}

fn disable_tls_state_epoch(
    ebpf: &mut Ebpf,
    fence: &mut TlsStateEpochFence,
) -> Result<(), LibsslUprobePlaintextProbeError> {
    if !fence.is_enabled() {
        return Ok(());
    }
    write_tls_state_epoch(ebpf, 0)?;
    fence.mark_disabled();
    Ok(())
}

fn write_tls_state_epoch(
    ebpf: &mut Ebpf,
    epoch: u64,
) -> Result<(), LibsslUprobePlaintextProbeError> {
    let map = ebpf.map_mut(EBPF_TLS_STATE_EPOCHS_MAP_NAME).ok_or(
        LibsslUprobePlaintextProbeError::MissingMap {
            name: EBPF_TLS_STATE_EPOCHS_MAP_NAME,
        },
    )?;
    let mut state_epochs = AyaHashMap::<_, u32, u64>::try_from(map).map_err(|source| {
        LibsslUprobePlaintextProbeError::Map {
            name: EBPF_TLS_STATE_EPOCHS_MAP_NAME,
            source: Box::new(source),
        }
    })?;
    state_epochs
        .insert(EBPF_TLS_STATE_EPOCH_KEY, epoch, 0)
        .map_err(|source| LibsslUprobePlaintextProbeError::Map {
            name: EBPF_TLS_STATE_EPOCHS_MAP_NAME,
            source: Box::new(source),
        })?;
    Ok(())
}

fn open_output_maps_or_detach(
    ebpf: &mut Ebpf,
    attach_session: &mut LibsslUprobeAttachSession,
    state_epoch_fence: &mut TlsStateEpochFence,
) -> Result<(RingBuf<MapData>, OutputLossMap), LibsslUprobePlaintextProbeError> {
    let events = match open_events_ringbuf(ebpf) {
        Ok(events) => events,
        Err(error) => {
            let _ = disable_tls_state_epoch(ebpf, state_epoch_fence);
            let _ = attach_session.detach_all_best_effort(ebpf);
            return Err(error);
        }
    };
    match open_output_loss_map(ebpf) {
        Ok(output_losses) => Ok((events, output_losses)),
        Err(error) => {
            let _ = disable_tls_state_epoch(ebpf, state_epoch_fence);
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

    #[test]
    fn reconcile_attach_requires_committed_or_active_targets()
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
        let attach_work = best_effort_attach_work_from_plan(&plan)?;
        let summary = LibsslUprobeAttachSummary::from_recipes(attach_work.as_recipes());

        let reason = unresolvable_reconcile_attach_reason(&summary, 0, 0)
            .expect("uncommitted reconcile with no active targets must be unresolvable");

        assert!(reason.contains("did not commit any ready target"));
        assert!(unresolvable_reconcile_attach_reason(&summary, 0, 1).is_none());
        assert!(unresolvable_reconcile_attach_reason(&summary, 1, 1).is_none());
        Ok(())
    }

    #[test]
    fn reconcile_epoch_plan_leaves_retained_targets_on_current_epoch()
    -> Result<(), Box<dyn std::error::Error>> {
        let current_plan = attachable_plan(42, "/usr/lib/libssl-current.so.3");
        let current = LibsslUprobeAttachState::from_targets(current_plan.target_ids());
        let report = current.reconcile(&attachable_plan(42, "/usr/lib/libssl-current.so.3"));
        let plan = TlsStateEpochReconcilePlan::new(&report, &[], true);

        assert_eq!(
            plan,
            TlsStateEpochReconcilePlan {
                disable_before_detach: false,
                enable_before_attach: false,
            }
        );
        Ok(())
    }

    #[test]
    fn reconcile_epoch_plan_enables_empty_sidecar_before_new_attach()
    -> Result<(), Box<dyn std::error::Error>> {
        let current = LibsslUprobeAttachState::default();
        let next_plan = attachable_plan(42, "/usr/lib/libssl-new.so.3");
        let report = current.reconcile(&next_plan);
        let attach_work = best_effort_attach_work_from_plan(&report.attach_plan)?;
        let plan = TlsStateEpochReconcilePlan::new(&report, attach_work.as_recipes(), false);

        assert_eq!(
            plan,
            TlsStateEpochReconcilePlan {
                disable_before_detach: false,
                enable_before_attach: true,
            }
        );

        Ok(())
    }

    #[test]
    fn reconcile_epoch_plan_closes_state_when_no_target_remains()
    -> Result<(), Box<dyn std::error::Error>> {
        let current_plan = attachable_plan(42, "/usr/lib/libssl-old.so.3");
        let current = LibsslUprobeAttachState::from_targets(current_plan.target_ids());
        let empty_plan = LibsslUprobeAttachPlan::from_discovery_reports([]);
        let report = current.reconcile(&empty_plan);
        let plan = TlsStateEpochReconcilePlan::new(&report, &[], true);

        assert_eq!(
            plan,
            TlsStateEpochReconcilePlan {
                disable_before_detach: true,
                enable_before_attach: false,
            }
        );
        Ok(())
    }

    #[test]
    fn reconcile_epoch_plan_reopens_state_after_stale_before_new_attach()
    -> Result<(), Box<dyn std::error::Error>> {
        let current_plan = attachable_plan(42, "/usr/lib/libssl-old.so.3");
        let current = LibsslUprobeAttachState::from_targets(current_plan.target_ids());
        let next_plan = attachable_plan(43, "/usr/lib/libssl-new.so.3");
        let report = current.reconcile(&next_plan);
        let attach_work = best_effort_attach_work_from_plan(&report.attach_plan)?;
        let plan = TlsStateEpochReconcilePlan::new(&report, attach_work.as_recipes(), true);

        assert_eq!(
            plan,
            TlsStateEpochReconcilePlan {
                disable_before_detach: true,
                enable_before_attach: true,
            }
        );
        Ok(())
    }

    #[test]
    fn state_epoch_fence_advances_single_global_epoch_without_reusing_overflow() {
        let mut fence = TlsStateEpochFence::default();

        assert_eq!(fence.next_epoch().expect("epoch 1"), 1);
        fence.mark_enabled();
        assert!(fence.is_enabled());
        fence.mark_disabled();
        assert!(!fence.is_enabled());
        assert_eq!(fence.next_epoch().expect("epoch 2"), 2);

        let mut exhausted = TlsStateEpochFence {
            next_epoch: u64::MAX,
            enabled: false,
        };
        assert!(matches!(
            exhausted.next_epoch(),
            Err(LibsslUprobePlaintextProbeError::StateEpochExhausted)
        ));
    }

    fn attachable_plan(pid: u32, path: &str) -> LibsslUprobeAttachPlan {
        LibsslUprobeAttachPlan::from_discovery_report(discovery_report(
            pid,
            vec![LibsslUprobeTarget {
                library: mapped_library(path),
                library_kind: LibsslLibraryKind::OpenSslLike,
                executable_mappings: Vec::new(),
                symbols: vec![LibsslUprobeSymbol::SslSetFd, LibsslUprobeSymbol::SslRead],
            }],
        ))
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
