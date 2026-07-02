use probe_config::{
    AgentConfig, CaptureSelection, CompressionCodecName, ConnectionEnforcementBackendConfig,
    TransparentInterceptionStrategyConfig,
};
use probe_core::{EnforcementMode, Selector};

use super::{
    app::TuiTab,
    wire::{
        capture_selection_name, compression_codec_name, connection_backend_name,
        enforcement_mode_name, exporter_transport_name, interception_strategy_name,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FieldId {
    CaptureSelection,
    CaptureDeepObserveProcess,
    ExportWorkerEnabled,
    ExporterCodec(usize),
    IngressRetentionMaxRecords,
    ExportRetentionMaxRecords,
    EnforcementMode,
    ConnectionBackend,
    InterceptionStrategy,
    EnforcementProcessScope,
    InterceptionProcessScope,
    TlsPlaintextEnabled,
    TlsPlaintextProcessScope,
}

impl FieldId {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::CaptureSelection => "Capture backend",
            Self::CaptureDeepObserveProcess => "Observe selected process",
            Self::ExportWorkerEnabled => "Export worker",
            Self::ExporterCodec(_) => "Exporter codec",
            Self::IngressRetentionMaxRecords => "Ingress record limit",
            Self::ExportRetentionMaxRecords => "Export record limit",
            Self::EnforcementMode => "Enforcement mode",
            Self::ConnectionBackend => "Connection backend",
            Self::InterceptionStrategy => "Transparent interception",
            Self::EnforcementProcessScope => "Enforce selected process",
            Self::InterceptionProcessScope => "Intercept selected process",
            Self::TlsPlaintextEnabled => "TLS plaintext hooks",
            Self::TlsPlaintextProcessScope => "TLS selected process",
        }
    }

    pub(crate) fn action_hint(self) -> &'static str {
        match self {
            Self::CaptureSelection
            | Self::ExporterCodec(_)
            | Self::IngressRetentionMaxRecords
            | Self::ExportRetentionMaxRecords
            | Self::EnforcementMode
            | Self::ConnectionBackend
            | Self::InterceptionStrategy => "cycle value",
            Self::ExportWorkerEnabled | Self::TlsPlaintextEnabled => "toggle",
            Self::CaptureDeepObserveProcess
            | Self::EnforcementProcessScope
            | Self::InterceptionProcessScope
            | Self::TlsPlaintextProcessScope => "apply selected process",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FieldApplyOutcome {
    Unchanged,
    Changed(&'static str),
    MissingProcessSelector,
}

pub(crate) fn fields_for_tab(tab: TuiTab, config: &AgentConfig) -> Vec<FieldId> {
    match tab {
        TuiTab::Overview | TuiTab::Traffic | TuiTab::Processes => Vec::new(),
        TuiTab::Capture => vec![
            FieldId::CaptureSelection,
            FieldId::CaptureDeepObserveProcess,
        ],
        TuiTab::Export => {
            let mut fields = vec![FieldId::ExportWorkerEnabled];
            fields.extend(
                config
                    .exporters
                    .iter()
                    .enumerate()
                    .map(|(index, _)| FieldId::ExporterCodec(index)),
            );
            fields
        }
        TuiTab::Storage => vec![
            FieldId::IngressRetentionMaxRecords,
            FieldId::ExportRetentionMaxRecords,
        ],
        TuiTab::Enforcement => vec![
            FieldId::EnforcementMode,
            FieldId::ConnectionBackend,
            FieldId::InterceptionStrategy,
            FieldId::EnforcementProcessScope,
            FieldId::InterceptionProcessScope,
        ],
        TuiTab::Tls => vec![
            FieldId::TlsPlaintextEnabled,
            FieldId::TlsPlaintextProcessScope,
        ],
    }
}

pub(crate) fn field_value(
    config: &AgentConfig,
    field: FieldId,
    selected_process_name: Option<&str>,
) -> String {
    match field {
        FieldId::CaptureSelection => capture_selection_name(config.capture.selection).to_string(),
        FieldId::CaptureDeepObserveProcess => selector_state(
            config.capture.deep_observe_selector.is_some(),
            selected_process_name,
        ),
        FieldId::ExportWorkerEnabled => bool_state(config.export.worker.enabled),
        FieldId::ExporterCodec(index) => config
            .exporters
            .get(index)
            .map(|exporter| {
                format!(
                    "{} -> {} ({})",
                    exporter.id,
                    compression_codec_name(exporter.codec),
                    exporter_transport_name(&exporter.transport)
                )
            })
            .unwrap_or_else(|| "missing exporter".to_string()),
        FieldId::IngressRetentionMaxRecords => {
            retention_records_state(config.storage.retention.ingress.max_records)
        }
        FieldId::ExportRetentionMaxRecords => {
            retention_records_state(config.storage.retention.export.max_records)
        }
        FieldId::EnforcementMode => enforcement_mode_name(config.enforcement.mode).to_string(),
        FieldId::ConnectionBackend => {
            connection_backend_name(config.enforcement.backend).to_string()
        }
        FieldId::InterceptionStrategy => {
            interception_strategy_name(config.enforcement.interception.strategy).to_string()
        }
        FieldId::EnforcementProcessScope => {
            selector_state(config.enforcement.selector.is_some(), selected_process_name)
        }
        FieldId::InterceptionProcessScope => selector_state(
            config.enforcement.interception.selector.is_some(),
            selected_process_name,
        ),
        FieldId::TlsPlaintextEnabled => bool_state(config.tls.plaintext.instrumentation.enabled),
        FieldId::TlsPlaintextProcessScope => selector_state(
            config.tls.plaintext.instrumentation.selector.is_some(),
            selected_process_name,
        ),
    }
}

pub(crate) fn apply_field(
    config: &mut AgentConfig,
    field: FieldId,
    direction: isize,
    selected_process_selector: Option<Selector>,
) -> FieldApplyOutcome {
    match field {
        FieldId::CaptureSelection => {
            config.capture.selection = cycle_capture_selection(config.capture.selection, direction);
            FieldApplyOutcome::Changed("Capture backend changed")
        }
        FieldId::CaptureDeepObserveProcess => {
            apply_process_selector(selected_process_selector, |selector| {
                config.capture.deep_observe_selector = Some(selector);
                "Capture process selector updated"
            })
        }
        FieldId::ExportWorkerEnabled => {
            config.export.worker.enabled = !config.export.worker.enabled;
            FieldApplyOutcome::Changed("Export worker toggled")
        }
        FieldId::ExporterCodec(index) => {
            let Some(exporter) = config.exporters.get_mut(index) else {
                return FieldApplyOutcome::Unchanged;
            };
            exporter.codec = cycle_codec(exporter.codec, direction);
            FieldApplyOutcome::Changed("Exporter codec changed")
        }
        FieldId::IngressRetentionMaxRecords => {
            config.storage.retention.ingress.max_records =
                cycle_retention_records(config.storage.retention.ingress.max_records, direction);
            FieldApplyOutcome::Changed("Ingress record limit changed")
        }
        FieldId::ExportRetentionMaxRecords => {
            config.storage.retention.export.max_records =
                cycle_retention_records(config.storage.retention.export.max_records, direction);
            FieldApplyOutcome::Changed("Export record limit changed")
        }
        FieldId::EnforcementMode => {
            config.enforcement.mode = cycle_enforcement_mode(config.enforcement.mode, direction);
            FieldApplyOutcome::Changed("Enforcement mode changed")
        }
        FieldId::ConnectionBackend => {
            config.enforcement.backend = cycle_connection_backend(config.enforcement.backend);
            FieldApplyOutcome::Changed("Connection enforcement backend changed")
        }
        FieldId::InterceptionStrategy => {
            config.enforcement.interception.strategy =
                cycle_interception_strategy(config.enforcement.interception.strategy, direction);
            FieldApplyOutcome::Changed("Transparent interception strategy changed")
        }
        FieldId::EnforcementProcessScope => {
            apply_process_selector(selected_process_selector, |selector| {
                config.enforcement.selector = Some(selector);
                "Enforcement process selector updated"
            })
        }
        FieldId::InterceptionProcessScope => {
            apply_process_selector(selected_process_selector, |selector| {
                config.enforcement.interception.selector = Some(selector);
                "Interception process selector updated"
            })
        }
        FieldId::TlsPlaintextEnabled => {
            let enabled = &mut config.tls.plaintext.instrumentation.enabled;
            *enabled = !*enabled;
            FieldApplyOutcome::Changed("TLS plaintext hooks toggled")
        }
        FieldId::TlsPlaintextProcessScope => {
            apply_process_selector(selected_process_selector, |selector| {
                config.tls.plaintext.instrumentation.enabled = true;
                config.tls.plaintext.instrumentation.selector = Some(selector);
                "TLS plaintext process selector updated"
            })
        }
    }
}

fn apply_process_selector(
    selector: Option<Selector>,
    apply: impl FnOnce(Selector) -> &'static str,
) -> FieldApplyOutcome {
    match selector {
        Some(selector) => FieldApplyOutcome::Changed(apply(selector)),
        None => FieldApplyOutcome::MissingProcessSelector,
    }
}

fn bool_state(value: bool) -> String {
    if value {
        "enabled".to_string()
    } else {
        "disabled".to_string()
    }
}

fn retention_records_state(value: Option<u64>) -> String {
    match value {
        Some(records) => format!("{records} records"),
        None => "no record limit".to_string(),
    }
}

fn selector_state(has_selector: bool, process: Option<&str>) -> String {
    match (has_selector, process) {
        (true, Some(process)) => format!("configured; selected process: {process}"),
        (true, None) => "configured".to_string(),
        (false, Some(process)) => format!("not configured; selected process: {process}"),
        (false, None) => "not configured".to_string(),
    }
}

fn cycle_capture_selection(value: CaptureSelection, direction: isize) -> CaptureSelection {
    const VALUES: [CaptureSelection; 6] = [
        CaptureSelection::Auto,
        CaptureSelection::Ebpf,
        CaptureSelection::Libpcap,
        CaptureSelection::PlaintextFeed,
        CaptureSelection::CaptureEventFeed,
        CaptureSelection::Replay,
    ];
    VALUES[cycle_index(
        VALUES
            .iter()
            .position(|item| *item == value)
            .unwrap_or_default(),
        VALUES.len(),
        direction,
    )]
}

fn cycle_codec(value: CompressionCodecName, direction: isize) -> CompressionCodecName {
    const VALUES: [CompressionCodecName; 4] = [
        CompressionCodecName::None,
        CompressionCodecName::Zstd,
        CompressionCodecName::Gzip,
        CompressionCodecName::Deflate,
    ];
    VALUES[cycle_index(
        VALUES
            .iter()
            .position(|item| *item == value)
            .unwrap_or_default(),
        VALUES.len(),
        direction,
    )]
}

fn cycle_retention_records(value: Option<u64>, direction: isize) -> Option<u64> {
    const VALUES: [Option<u64>; 5] = [
        None,
        Some(10_000),
        Some(100_000),
        Some(1_000_000),
        Some(10_000_000),
    ];
    let index = VALUES
        .iter()
        .position(|item| *item == value)
        .unwrap_or_else(|| nearest_retention_index(value, direction, &VALUES));
    VALUES[cycle_index(index, VALUES.len(), direction)]
}

fn nearest_retention_index(value: Option<u64>, direction: isize, values: &[Option<u64>]) -> usize {
    let Some(records) = value else {
        return 0;
    };
    if direction >= 0 {
        values
            .iter()
            .position(|candidate| candidate.is_some_and(|candidate| candidate > records))
            .map_or(values.len().saturating_sub(1), |index| {
                index.saturating_sub(1)
            })
    } else {
        values
            .iter()
            .position(|candidate| candidate.is_some_and(|candidate| candidate >= records))
            .unwrap_or(0)
    }
}

fn cycle_enforcement_mode(value: EnforcementMode, direction: isize) -> EnforcementMode {
    const VALUES: [EnforcementMode; 4] = [
        EnforcementMode::Disabled,
        EnforcementMode::AuditOnly,
        EnforcementMode::DryRun,
        EnforcementMode::Enforce,
    ];
    VALUES[cycle_index(
        VALUES
            .iter()
            .position(|item| *item == value)
            .unwrap_or_default(),
        VALUES.len(),
        direction,
    )]
}

fn cycle_connection_backend(
    value: ConnectionEnforcementBackendConfig,
) -> ConnectionEnforcementBackendConfig {
    match value {
        ConnectionEnforcementBackendConfig::None => {
            ConnectionEnforcementBackendConfig::LinuxSocketDestroy
        }
        ConnectionEnforcementBackendConfig::LinuxSocketDestroy => {
            ConnectionEnforcementBackendConfig::None
        }
    }
}

fn cycle_interception_strategy(
    value: TransparentInterceptionStrategyConfig,
    direction: isize,
) -> TransparentInterceptionStrategyConfig {
    const VALUES: [TransparentInterceptionStrategyConfig; 5] = [
        TransparentInterceptionStrategyConfig::None,
        TransparentInterceptionStrategyConfig::InboundTproxy,
        TransparentInterceptionStrategyConfig::OutboundTransparentProxy,
        TransparentInterceptionStrategyConfig::InboundTproxyMitm,
        TransparentInterceptionStrategyConfig::OutboundTransparentMitm,
    ];
    VALUES[cycle_index(
        VALUES
            .iter()
            .position(|item| *item == value)
            .unwrap_or_default(),
        VALUES.len(),
        direction,
    )]
}

fn cycle_index(index: usize, len: usize, direction: isize) -> usize {
    if len == 0 {
        return 0;
    }
    (index as isize + direction).rem_euclid(len as isize) as usize
}

#[cfg(test)]
#[test]
fn retention_record_cycle_handles_unbounded_presets_and_custom_values() {
    assert_eq!(cycle_retention_records(None, 1), Some(10_000));
    assert_eq!(cycle_retention_records(Some(10_000), -1), None);
    assert_eq!(cycle_retention_records(Some(50_000), 1), Some(100_000));
    assert_eq!(cycle_retention_records(Some(50_000), -1), Some(10_000));
    assert_eq!(cycle_retention_records(Some(20_000_000), 1), None);
    assert_eq!(
        cycle_retention_records(Some(20_000_000), -1),
        Some(10_000_000)
    );
}
