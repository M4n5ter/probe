use std::{collections::BTreeMap, path::PathBuf};

use probe_config::{
    AgentConfig, CaptureSelection, CompressionCodecName, ConnectionEnforcementBackendConfig,
    ExporterConfig, ExporterTransportConfig, ExporterWorkerConfig,
    TransparentInterceptionStrategyConfig, default_admin_socket_path, default_export_file_path,
    default_export_unix_http_socket_path,
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
    AdminEnabled,
    AdminSocketPath,
    AdminPrometheusEnabled,
    ExportWorkerEnabled,
    AddDefaultExporter,
    ExporterTransport(usize),
    ExporterCodec(usize),
    ExporterWebhookEndpoint(usize),
    ExporterFilePath(usize),
    ExporterUnixSocketPath(usize),
    ExporterUnixHttpEndpoint(usize),
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
            Self::AdminEnabled => "Admin socket",
            Self::AdminSocketPath => "Admin socket path",
            Self::AdminPrometheusEnabled => "Prometheus listener",
            Self::ExportWorkerEnabled => "Export worker",
            Self::AddDefaultExporter => "Add exporter",
            Self::ExporterTransport(_) => "Exporter transport",
            Self::ExporterCodec(_) => "Exporter codec",
            Self::ExporterWebhookEndpoint(_) => "Webhook endpoint",
            Self::ExporterFilePath(_) => "File path",
            Self::ExporterUnixSocketPath(_) => "Unix socket path",
            Self::ExporterUnixHttpEndpoint(_) => "Unix HTTP endpoint",
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
            | Self::ExporterTransport(_)
            | Self::ExporterCodec(_)
            | Self::IngressRetentionMaxRecords
            | Self::ExportRetentionMaxRecords
            | Self::EnforcementMode
            | Self::ConnectionBackend
            | Self::InterceptionStrategy => "cycle value",
            Self::ExportWorkerEnabled | Self::TlsPlaintextEnabled => "toggle",
            Self::AdminEnabled | Self::AdminPrometheusEnabled => "toggle",
            Self::ExporterWebhookEndpoint(_)
            | Self::ExporterFilePath(_)
            | Self::ExporterUnixSocketPath(_)
            | Self::ExporterUnixHttpEndpoint(_)
            | Self::AdminSocketPath => "edit text",
            Self::AddDefaultExporter => "add exporter",
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
        TuiTab::Runtime => vec![
            FieldId::AdminEnabled,
            FieldId::AdminSocketPath,
            FieldId::AdminPrometheusEnabled,
        ],
        TuiTab::Capture => vec![
            FieldId::CaptureSelection,
            FieldId::CaptureDeepObserveProcess,
        ],
        TuiTab::Export => {
            let mut fields = vec![FieldId::ExportWorkerEnabled];
            if config.exporters.is_empty() {
                fields.push(FieldId::AddDefaultExporter);
                return fields;
            }
            for (index, exporter) in config.exporters.iter().enumerate() {
                fields.push(FieldId::ExporterTransport(index));
                fields.extend(exporter_target_fields(index, &exporter.transport));
                fields.push(FieldId::ExporterCodec(index));
            }
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
        FieldId::AdminEnabled => bool_state(config.admin.enabled),
        FieldId::AdminSocketPath => config.admin.socket_path.display().to_string(),
        FieldId::AdminPrometheusEnabled => bool_state(config.admin.prometheus.enabled),
        FieldId::ExportWorkerEnabled => bool_state(config.export.worker.enabled),
        FieldId::AddDefaultExporter => {
            format!(
                "{} -> file {}",
                DEFAULT_EXPORTER_ID,
                default_export_file_path().display()
            )
        }
        FieldId::ExporterTransport(index) => config
            .exporters
            .get(index)
            .map(|exporter| {
                format!(
                    "{} -> {}",
                    exporter.id,
                    exporter_transport_name(&exporter.transport)
                )
            })
            .unwrap_or_else(|| "missing exporter".to_string()),
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
        FieldId::ExporterWebhookEndpoint(index) => config
            .exporters
            .get(index)
            .and_then(|exporter| match &exporter.transport {
                ExporterTransportConfig::Webhook { endpoint, .. } => {
                    Some(exporter_text_state(&exporter.id, endpoint))
                }
                _ => None,
            })
            .unwrap_or_else(|| "missing webhook exporter".to_string()),
        FieldId::ExporterFilePath(index) => config
            .exporters
            .get(index)
            .and_then(|exporter| match &exporter.transport {
                ExporterTransportConfig::File { path } => Some(exporter_text_state(
                    &exporter.id,
                    &path.display().to_string(),
                )),
                _ => None,
            })
            .unwrap_or_else(|| "missing file exporter".to_string()),
        FieldId::ExporterUnixSocketPath(index) => config
            .exporters
            .get(index)
            .and_then(|exporter| match &exporter.transport {
                ExporterTransportConfig::UnixHttp { socket_path, .. } => Some(exporter_text_state(
                    &exporter.id,
                    &socket_path.display().to_string(),
                )),
                _ => None,
            })
            .unwrap_or_else(|| "missing unix_http exporter".to_string()),
        FieldId::ExporterUnixHttpEndpoint(index) => config
            .exporters
            .get(index)
            .and_then(|exporter| match &exporter.transport {
                ExporterTransportConfig::UnixHttp { endpoint, .. } => {
                    Some(exporter_text_state(&exporter.id, endpoint))
                }
                _ => None,
            })
            .unwrap_or_else(|| "missing unix_http exporter".to_string()),
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
        FieldId::AdminEnabled => {
            config.admin.enabled = !config.admin.enabled;
            if !config.admin.enabled {
                config.admin.prometheus.enabled = false;
            }
            if config.admin.enabled && config.admin.socket_path.as_os_str().is_empty() {
                config.admin.socket_path = default_admin_socket_path();
            }
            FieldApplyOutcome::Changed("Admin socket toggled")
        }
        FieldId::AdminSocketPath => FieldApplyOutcome::Unchanged,
        FieldId::AdminPrometheusEnabled => {
            config.admin.prometheus.enabled = !config.admin.prometheus.enabled;
            if config.admin.prometheus.enabled {
                config.admin.enabled = true;
                if config.admin.socket_path.as_os_str().is_empty() {
                    config.admin.socket_path = default_admin_socket_path();
                }
            }
            FieldApplyOutcome::Changed("Prometheus listener toggled")
        }
        FieldId::ExportWorkerEnabled => {
            config.export.worker.enabled = !config.export.worker.enabled;
            FieldApplyOutcome::Changed("Export worker toggled")
        }
        FieldId::AddDefaultExporter => {
            if !config.exporters.is_empty() {
                return FieldApplyOutcome::Unchanged;
            }
            config.exporters.push(default_exporter());
            FieldApplyOutcome::Changed("Default exporter added")
        }
        FieldId::ExporterTransport(index) => {
            let Some(exporter) = config.exporters.get_mut(index) else {
                return FieldApplyOutcome::Unchanged;
            };
            exporter.transport = cycle_exporter_transport(&exporter.transport, direction);
            FieldApplyOutcome::Changed("Exporter transport changed")
        }
        FieldId::ExporterCodec(index) => {
            let Some(exporter) = config.exporters.get_mut(index) else {
                return FieldApplyOutcome::Unchanged;
            };
            exporter.codec = cycle_codec(exporter.codec, direction);
            FieldApplyOutcome::Changed("Exporter codec changed")
        }
        FieldId::ExporterWebhookEndpoint(_)
        | FieldId::ExporterFilePath(_)
        | FieldId::ExporterUnixSocketPath(_)
        | FieldId::ExporterUnixHttpEndpoint(_) => FieldApplyOutcome::Unchanged,
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

pub(crate) fn editable_text_value(config: &AgentConfig, field: FieldId) -> Option<String> {
    match field {
        FieldId::ExporterWebhookEndpoint(index) => {
            config
                .exporters
                .get(index)
                .and_then(|exporter| match &exporter.transport {
                    ExporterTransportConfig::Webhook { endpoint, .. } => Some(endpoint.clone()),
                    _ => None,
                })
        }
        FieldId::ExporterFilePath(index) => {
            config
                .exporters
                .get(index)
                .and_then(|exporter| match &exporter.transport {
                    ExporterTransportConfig::File { path } => Some(path.display().to_string()),
                    _ => None,
                })
        }
        FieldId::ExporterUnixSocketPath(index) => {
            config
                .exporters
                .get(index)
                .and_then(|exporter| match &exporter.transport {
                    ExporterTransportConfig::UnixHttp { socket_path, .. } => {
                        Some(socket_path.display().to_string())
                    }
                    _ => None,
                })
        }
        FieldId::ExporterUnixHttpEndpoint(index) => {
            config
                .exporters
                .get(index)
                .and_then(|exporter| match &exporter.transport {
                    ExporterTransportConfig::UnixHttp { endpoint, .. } => Some(endpoint.clone()),
                    _ => None,
                })
        }
        FieldId::AdminSocketPath => Some(config.admin.socket_path.display().to_string()),
        _ => None,
    }
}

pub(crate) fn apply_text_field(
    config: &mut AgentConfig,
    field: FieldId,
    value: String,
) -> FieldApplyOutcome {
    let value = value.trim().to_string();
    match field {
        FieldId::ExporterWebhookEndpoint(index) => {
            let Some(exporter) = config.exporters.get_mut(index) else {
                return FieldApplyOutcome::Unchanged;
            };
            let ExporterTransportConfig::Webhook { endpoint, .. } = &mut exporter.transport else {
                return FieldApplyOutcome::Unchanged;
            };
            *endpoint = value;
            FieldApplyOutcome::Changed("Webhook endpoint changed")
        }
        FieldId::ExporterFilePath(index) => {
            let Some(exporter) = config.exporters.get_mut(index) else {
                return FieldApplyOutcome::Unchanged;
            };
            let ExporterTransportConfig::File { path } = &mut exporter.transport else {
                return FieldApplyOutcome::Unchanged;
            };
            *path = PathBuf::from(value);
            FieldApplyOutcome::Changed("File exporter path changed")
        }
        FieldId::ExporterUnixSocketPath(index) => {
            let Some(exporter) = config.exporters.get_mut(index) else {
                return FieldApplyOutcome::Unchanged;
            };
            let ExporterTransportConfig::UnixHttp { socket_path, .. } = &mut exporter.transport
            else {
                return FieldApplyOutcome::Unchanged;
            };
            *socket_path = PathBuf::from(value);
            FieldApplyOutcome::Changed("Unix HTTP socket path changed")
        }
        FieldId::ExporterUnixHttpEndpoint(index) => {
            let Some(exporter) = config.exporters.get_mut(index) else {
                return FieldApplyOutcome::Unchanged;
            };
            let ExporterTransportConfig::UnixHttp { endpoint, .. } = &mut exporter.transport else {
                return FieldApplyOutcome::Unchanged;
            };
            *endpoint = value;
            FieldApplyOutcome::Changed("Unix HTTP endpoint changed")
        }
        FieldId::AdminSocketPath => {
            config.admin.socket_path = PathBuf::from(value);
            FieldApplyOutcome::Changed("Admin socket path changed")
        }
        _ => FieldApplyOutcome::Unchanged,
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

fn exporter_target_fields(index: usize, transport: &ExporterTransportConfig) -> Vec<FieldId> {
    match transport {
        ExporterTransportConfig::Webhook { .. } => vec![FieldId::ExporterWebhookEndpoint(index)],
        ExporterTransportConfig::File { .. } => vec![FieldId::ExporterFilePath(index)],
        ExporterTransportConfig::UnixHttp { .. } => vec![
            FieldId::ExporterUnixSocketPath(index),
            FieldId::ExporterUnixHttpEndpoint(index),
        ],
    }
}

fn exporter_text_state(exporter_id: &str, value: &str) -> String {
    if value.is_empty() {
        format!("{exporter_id} -> not configured")
    } else {
        format!("{exporter_id} -> {value}")
    }
}

fn retention_records_state(value: Option<u64>) -> String {
    match value {
        Some(records) => format!("{records} records"),
        None => "no record limit".to_string(),
    }
}

const DEFAULT_EXPORTER_ID: &str = "default";
const DEFAULT_WEBHOOK_ENDPOINT: &str = "http://127.0.0.1:8080/events";
const DEFAULT_UNIX_HTTP_ENDPOINT: &str = "/events";

fn default_exporter() -> ExporterConfig {
    ExporterConfig {
        id: DEFAULT_EXPORTER_ID.to_string(),
        transport: default_file_transport(),
        codec: CompressionCodecName::Zstd,
        worker: ExporterWorkerConfig::default(),
    }
}

fn default_webhook_transport() -> ExporterTransportConfig {
    ExporterTransportConfig::Webhook {
        endpoint: DEFAULT_WEBHOOK_ENDPOINT.to_string(),
        headers: BTreeMap::new(),
        tls: Default::default(),
    }
}

fn default_file_transport() -> ExporterTransportConfig {
    ExporterTransportConfig::File {
        path: default_export_file_path(),
    }
}

fn default_unix_http_transport() -> ExporterTransportConfig {
    ExporterTransportConfig::UnixHttp {
        socket_path: default_export_unix_http_socket_path(),
        endpoint: DEFAULT_UNIX_HTTP_ENDPOINT.to_string(),
        headers: BTreeMap::new(),
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

fn cycle_exporter_transport(
    value: &ExporterTransportConfig,
    direction: isize,
) -> ExporterTransportConfig {
    const VALUES: [ExporterTransportKind; 3] = [
        ExporterTransportKind::Webhook,
        ExporterTransportKind::File,
        ExporterTransportKind::UnixHttp,
    ];
    let current = exporter_transport_kind(value);
    match VALUES[cycle_index(
        VALUES
            .iter()
            .position(|item| *item == current)
            .unwrap_or_default(),
        VALUES.len(),
        direction,
    )] {
        ExporterTransportKind::Webhook => default_webhook_transport(),
        ExporterTransportKind::File => default_file_transport(),
        ExporterTransportKind::UnixHttp => default_unix_http_transport(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExporterTransportKind {
    Webhook,
    File,
    UnixHttp,
}

fn exporter_transport_kind(value: &ExporterTransportConfig) -> ExporterTransportKind {
    match value {
        ExporterTransportConfig::Webhook { .. } => ExporterTransportKind::Webhook,
        ExporterTransportConfig::File { .. } => ExporterTransportKind::File,
        ExporterTransportConfig::UnixHttp { .. } => ExporterTransportKind::UnixHttp,
    }
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

#[cfg(test)]
#[test]
fn disabling_admin_also_disables_prometheus_listener() {
    let mut config = AgentConfig::default();
    config.admin.enabled = true;
    config.admin.prometheus.enabled = true;

    let outcome = apply_field(&mut config, FieldId::AdminEnabled, 1, None);

    assert_eq!(outcome, FieldApplyOutcome::Changed("Admin socket toggled"));
    assert!(!config.admin.enabled);
    assert!(!config.admin.prometheus.enabled);
}
