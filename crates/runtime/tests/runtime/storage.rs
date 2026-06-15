use probe_config::{AgentConfig, CaptureBackend, CaptureSelection};
use probe_core::{CapabilityKind, RuntimeMode};
use runtime::{CaptureProviderBuilder, IngressRetentionPlan, ProviderRegistry, RuntimePlan};

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

#[test]
fn storage_plan_normalizes_ingress_retention() -> Result<(), Box<dyn std::error::Error>> {
    let registry = ProviderRegistry::new(vec![], super::fixture::test_platform_capabilities());
    let mut config = AgentConfig::default();
    config.storage.retention.ingress.max_age_ms = Some(120_000);
    config.storage.retention.ingress.sweep_interval_ms = 5_000;
    config.storage.retention.ingress.prune_batch_limit = 128;

    let plan = RuntimePlan::build(config, &registry)?;

    assert_eq!(
        plan.storage.retention.ingress,
        IngressRetentionPlan {
            max_age_ms: Some(120_000),
            sweep_interval_ms: std::num::NonZeroU64::new(5_000)
                .expect("positive ingress retention sweep interval"),
            prune_batch_limit: std::num::NonZeroU64::new(128)
                .expect("positive ingress retention prune limit"),
        }
    );
    Ok(())
}
