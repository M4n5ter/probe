use probe_config::{AgentConfig, CaptureBackend, CaptureSelection};
use probe_core::{CapabilityKind, RuntimeMode};
use runtime::{CaptureProviderBuilder, ProviderRegistry, RuntimePlan};

use super::fixture::capture_provider;

#[test]
fn ingress_journal_recovery_is_degraded_until_parser_checkpoints_are_durable()
-> Result<(), Box<dyn std::error::Error>> {
    let registry = ProviderRegistry::with_default_platform(vec![capture_provider(
        CaptureBackend::Replay,
        CaptureProviderBuilder::Replay,
        RuntimeMode::Available,
    )]);
    let mut config = AgentConfig::default();
    config.capture.selection = CaptureSelection::Replay;

    let plan = RuntimePlan::build(config, &registry)?;

    assert_eq!(
        plan.capabilities.mode(CapabilityKind::IngressJournal),
        RuntimeMode::Degraded
    );
    assert_eq!(
        plan.capabilities.mode(CapabilityKind::DurableSpool),
        RuntimeMode::Degraded
    );
    let durable_spool = plan
        .capabilities
        .states()
        .iter()
        .find(|state| state.kind == CapabilityKind::DurableSpool)
        .expect("durable spool capability should be reported");
    assert!(
        durable_spool
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("at-least-once"))
    );
    let ingress_journal = plan
        .capabilities
        .states()
        .iter()
        .find(|state| state.kind == CapabilityKind::IngressJournal)
        .expect("ingress journal capability should be reported");
    assert!(
        ingress_journal
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("parser checkpoints"))
    );
    Ok(())
}
