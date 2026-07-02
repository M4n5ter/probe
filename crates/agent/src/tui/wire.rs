use probe_config::{
    CaptureSelection, CompressionCodecName, ConnectionEnforcementBackendConfig,
    ExporterTransportConfig, LiveCaptureBackend, TransparentInterceptionStrategyConfig,
};
use probe_core::EnforcementMode;

pub(crate) fn capture_selection_name(value: CaptureSelection) -> &'static str {
    match value {
        CaptureSelection::Auto => "auto",
        CaptureSelection::Ebpf => "ebpf",
        CaptureSelection::Libpcap => "libpcap",
        CaptureSelection::PlaintextFeed => "plaintext_feed",
        CaptureSelection::CaptureEventFeed => "capture_event_feed",
        CaptureSelection::Replay => "replay",
    }
}

pub(crate) fn live_capture_backend_name(value: LiveCaptureBackend) -> &'static str {
    match value {
        LiveCaptureBackend::Ebpf => "ebpf",
        LiveCaptureBackend::Libpcap => "libpcap",
    }
}

pub(crate) fn compression_codec_name(value: CompressionCodecName) -> &'static str {
    match value {
        CompressionCodecName::None => "none",
        CompressionCodecName::Zstd => "zstd",
        CompressionCodecName::Gzip => "gzip",
        CompressionCodecName::Deflate => "deflate",
    }
}

pub(crate) fn exporter_transport_name(value: &ExporterTransportConfig) -> &'static str {
    match value {
        ExporterTransportConfig::Webhook { .. } => "webhook",
        ExporterTransportConfig::File { .. } => "file",
        ExporterTransportConfig::UnixHttp { .. } => "unix_http",
    }
}

pub(crate) fn enforcement_mode_name(value: EnforcementMode) -> &'static str {
    match value {
        EnforcementMode::Disabled => "disabled",
        EnforcementMode::AuditOnly => "audit_only",
        EnforcementMode::DryRun => "dry_run",
        EnforcementMode::Enforce => "enforce",
    }
}

pub(crate) fn connection_backend_name(value: ConnectionEnforcementBackendConfig) -> &'static str {
    match value {
        ConnectionEnforcementBackendConfig::None => "none",
        ConnectionEnforcementBackendConfig::LinuxSocketDestroy => "linux_socket_destroy",
    }
}

pub(crate) fn interception_strategy_name(
    value: TransparentInterceptionStrategyConfig,
) -> &'static str {
    match value {
        TransparentInterceptionStrategyConfig::None => "none",
        TransparentInterceptionStrategyConfig::InboundTproxy => "inbound_tproxy",
        TransparentInterceptionStrategyConfig::OutboundTransparentProxy => {
            "outbound_transparent_proxy"
        }
        TransparentInterceptionStrategyConfig::InboundTproxyMitm => "inbound_tproxy_mitm",
        TransparentInterceptionStrategyConfig::OutboundTransparentMitm => {
            "outbound_transparent_mitm"
        }
    }
}
