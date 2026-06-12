use probe_config::{AgentConfig, CaptureBackend, CaptureSelection};
use probe_core::{CapabilityKind, RuntimeMode};
use runtime::{CaptureProviderBuilder, ProviderRegistry, RuntimePlan};

use super::fixture::capture_provider;

#[test]
fn websocket_parser_capabilities_are_supported() -> Result<(), Box<dyn std::error::Error>> {
    let registry = ProviderRegistry::with_default_platform(vec![capture_provider(
        CaptureBackend::Replay,
        CaptureProviderBuilder::Replay,
        RuntimeMode::Available,
    )]);
    let mut config = AgentConfig::default();
    config.capture.selection = CaptureSelection::Replay;

    let plan = RuntimePlan::build(config, &registry)?;

    assert_eq!(
        plan.capabilities.mode(CapabilityKind::WebSocketHandoff),
        RuntimeMode::Available
    );
    assert_eq!(
        plan.capabilities.mode(CapabilityKind::WebSocketFrame),
        RuntimeMode::Available
    );
    Ok(())
}
