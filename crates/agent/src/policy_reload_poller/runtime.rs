use std::{convert::Infallible, time::Duration};

use pipeline::PipelinePolicySet;
use probe_config::has_enabled_remote_policy_bundle_source;
use runtime::RuntimePlan;
use tracing::{info, warn};

use crate::{
    periodic_worker::{PeriodicWorkerHandle, spawn_delayed_async_periodic_worker},
    policy_reload::{PolicyReloadGate, reload_policies},
    runtime_plan::RuntimePlanHandle,
    runtime_reload::RuntimeReloadGate,
};

pub(crate) type PolicyReloadPollerHandle = PeriodicWorkerHandle;

pub(crate) fn spawn_poller(
    plan: RuntimePlanHandle,
    policy_set: PipelinePolicySet,
    gate: PolicyReloadGate,
    config_apply_gate: RuntimeReloadGate,
) -> Option<PolicyReloadPollerHandle> {
    let initial_plan = plan.snapshot();
    if !initial_plan.config.policy_reload.poll_remote_bundles
        || !has_enabled_remote_policy_bundle_source(&initial_plan.config.policies)
    {
        return None;
    }
    let interval = Duration::from_millis(initial_plan.config.policy_reload.remote_poll_interval_ms);
    drop(initial_plan);
    let inner = spawn_delayed_async_periodic_worker("remote policy reload", interval, move || {
        let plan = plan.clone();
        let policy_set = policy_set.clone();
        let gate = gate.clone();
        let config_apply_gate = config_apply_gate.clone();
        async move {
            let _config_apply_guard = config_apply_gate.lock().await;
            let plan = plan.snapshot();
            reload_remote_policies_once(&plan, &policy_set, &gate).await;
            Ok::<(), Infallible>(())
        }
    });
    Some(inner)
}

async fn reload_remote_policies_once(
    plan: &RuntimePlan,
    policy_set: &PipelinePolicySet,
    gate: &PolicyReloadGate,
) {
    match reload_policies(plan, policy_set, gate).await {
        Ok(summary) => {
            info!(
                loaded_count = summary.loaded_count,
                active_set_updated = summary.active_set_updated,
                "reloaded policy bundles after remote poll"
            );
        }
        Err(error) => {
            warn!("failed to reload policy bundles after remote poll: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };

    use capture::ReplayProvider;
    use parsers::Http1ParserFactory;
    use pipeline::{CapturePipeline, PipelinePolicySet};
    use probe_config::{
        AgentConfig, CaptureBackend, CaptureSelection, CompressionCodecName, ExporterConfig,
        MIN_POLICY_RELOAD_REMOTE_POLL_INTERVAL_MS, PolicyConfig, PolicyReloadConfig,
        PolicySourceConfig,
    };
    use probe_core::{
        AddressPort, CapabilityState, Direction, EventEnvelope, EventKind, FlowContext,
        FlowIdentity, ProcessContext, ProcessIdentity, SpoolPayloadSchema, Timestamp,
        TransportProtocol,
    };
    use runtime::{CaptureProviderBuilder, CaptureProviderDescriptor, ProviderRegistry};
    use storage::FjallSpool;
    use wiremock::{
        Mock, MockServer, Request, ResponseTemplate,
        matchers::{method, path},
    };

    use crate::{
        configured_policy::{
            PolicySourceLoadContext, load_configured_pipeline_policies_with_context,
        },
        policy_reload::ReloadablePolicySet,
    };

    use super::*;

    #[tokio::test]
    async fn poller_reloads_remote_policy_bundle_after_interval()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = MockServer::start().await;
        let remote_document = Arc::new(Mutex::new(remote_policy_bundle_document("old", "old")));
        let response_document = Arc::clone(&remote_document);
        Mock::given(method("GET"))
            .and(path("/policies/guard"))
            .respond_with(move |_: &Request| {
                ResponseTemplate::new(200).set_body_string(
                    response_document
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .clone(),
                )
            })
            .mount(&server)
            .await;
        let temp = tempfile::tempdir()?;
        let spool_path = temp.path().join("spool");
        let config = remote_policy_config(
            spool_path.clone(),
            format!("{}/policies/guard", server.uri()),
        );
        let plan = Arc::new(runtime_plan_from_config(config.clone())?);
        let loaded = load_configured_pipeline_policies_with_context(
            &config,
            PolicySourceLoadContext::default(),
        )
        .await?;
        let reloadable_policy_set = ReloadablePolicySet::from_loaded(loaded);
        let reload_gate = reloadable_policy_set.reload_gate();
        let policy_set = reloadable_policy_set.policy_set();
        let spool = FjallSpool::open(&spool_path)?;
        run_policy_request(&spool, policy_set.clone(), "/before", 1)?;
        assert!(
            policy_alert_messages(&spool)?
                .iter()
                .any(|message| message == "old /before")
        );

        *remote_document
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            remote_policy_bundle_document("new", "new");
        let poller = spawn_poller(
            RuntimePlanHandle::new(Arc::clone(&plan)),
            policy_set.clone(),
            reload_gate,
            RuntimeReloadGate::default(),
        )
        .expect("remote policy poller should start");

        wait_until_policy_message(&spool, policy_set, "new ").await?;

        poller.stop().await;
        Ok(())
    }

    #[tokio::test]
    async fn poller_keeps_active_policy_set_when_remote_bundle_is_unchanged()
    -> Result<(), Box<dyn std::error::Error>> {
        let server = MockServer::start().await;
        let remote_document = remote_policy_bundle_document_with_counter("counter");
        Mock::given(method("GET"))
            .and(path("/policies/guard"))
            .respond_with(ResponseTemplate::new(200).set_body_string(remote_document))
            .mount(&server)
            .await;
        let temp = tempfile::tempdir()?;
        let spool_path = temp.path().join("spool");
        let config = remote_policy_config(
            spool_path.clone(),
            format!("{}/policies/guard", server.uri()),
        );
        let plan = Arc::new(runtime_plan_from_config(config.clone())?);
        let loaded = load_configured_pipeline_policies_with_context(
            &config,
            PolicySourceLoadContext::default(),
        )
        .await?;
        let reloadable_policy_set = ReloadablePolicySet::from_loaded(loaded);
        let reload_gate = reloadable_policy_set.reload_gate();
        let policy_set = reloadable_policy_set.policy_set();
        let spool = FjallSpool::open(&spool_path)?;
        run_policy_request(&spool, policy_set.clone(), "/before", 1)?;
        assert!(
            policy_alert_messages(&spool)?
                .iter()
                .any(|message| message == "counter 1")
        );

        let poller = spawn_poller(
            RuntimePlanHandle::new(Arc::clone(&plan)),
            policy_set.clone(),
            reload_gate,
            RuntimeReloadGate::default(),
        )
        .expect("remote policy poller should start");
        wait_until_remote_requests(&server, 2).await?;
        run_policy_request(&spool, policy_set, "/after", 2)?;

        poller.stop().await;
        assert!(
            policy_alert_messages(&spool)?
                .iter()
                .any(|message| message == "counter 2"),
            "unchanged remote policy poll must not replace the active Lua VM"
        );
        Ok(())
    }

    async fn wait_until_policy_message(
        spool: &FjallSpool,
        policy_set: PipelinePolicySet,
        prefix: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut attempt = 0;
        loop {
            attempt += 1;
            run_policy_request(
                spool,
                policy_set.clone(),
                &format!("/after-{attempt}"),
                attempt + 10,
            )?;
            if policy_alert_messages(spool)?
                .iter()
                .any(|message| message.starts_with(prefix))
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("timed out waiting for remote policy reload poller".into());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn wait_until_remote_requests(
        server: &MockServer,
        expected_count: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let requests = server.received_requests().await.unwrap_or_default();
            if requests.len() >= expected_count {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "timed out waiting for {expected_count} remote policy requests"
                )
                .into());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn remote_policy_config(storage_path: PathBuf, endpoint: String) -> AgentConfig {
        AgentConfig {
            capture: probe_config::CaptureConfig {
                selection: CaptureSelection::Replay,
                ..Default::default()
            },
            storage: probe_config::StorageConfig {
                path: storage_path,
                ..Default::default()
            },
            exporters: vec![ExporterConfig {
                id: "primary".to_string(),
                transport: probe_config::ExporterTransportConfig::Webhook {
                    endpoint: "https://collector.example/batches".to_string(),
                    headers: Default::default(),
                    tls: Default::default(),
                },
                codec: CompressionCodecName::None,
                worker: Default::default(),
            }],
            policies: vec![PolicyConfig {
                id: "guard".to_string(),
                source: PolicySourceConfig::RemoteBundle {
                    endpoint,
                    max_body_bytes: None,
                },
                enabled: true,
                selector: None,
                ..PolicyConfig::default()
            }],
            policy_reload: PolicyReloadConfig {
                poll_remote_bundles: true,
                remote_poll_interval_ms: MIN_POLICY_RELOAD_REMOTE_POLL_INTERVAL_MS,
                ..PolicyReloadConfig::default()
            },
            ..AgentConfig::default()
        }
    }

    fn runtime_plan_from_config(config: AgentConfig) -> Result<RuntimePlan, runtime::RuntimeError> {
        let registry = ProviderRegistry::new(
            vec![CaptureProviderDescriptor::available(
                CaptureBackend::Replay,
                CaptureProviderBuilder::Replay,
            )],
            Vec::<CapabilityState>::new(),
        );
        RuntimePlan::build(config, &registry)
    }

    fn run_policy_request(
        spool: &FjallSpool,
        policy_set: PipelinePolicySet,
        target: &str,
        timestamp: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut parser_factory = Http1ParserFactory::default();
        let mut provider = ReplayProvider::new(
            demo_flow(),
            Direction::Outbound,
            format!("GET {target} HTTP/1.1\r\nHost: test\r\n\r\n").into_bytes(),
            Timestamp {
                monotonic_ns: timestamp,
                wall_time_unix_ns: timestamp as i64,
            },
        );
        let mut pipeline = CapturePipeline::new(spool, &mut parser_factory, policy_set, "test");
        pipeline.run_provider(&mut provider)?;
        Ok(())
    }

    fn policy_alert_messages(
        spool: &FjallSpool,
    ) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let mut messages = Vec::new();
        for stored in spool.read_export_batch("sink", 256)? {
            if stored.payload.schema() != &SpoolPayloadSchema::EventEnvelopeSubjectOriginJson {
                continue;
            }
            let envelope: EventEnvelope = serde_json::from_slice(stored.payload.bytes())?;
            if let EventKind::PolicyAlert(alert) = envelope.kind() {
                messages.push(alert.message.clone());
            }
        }
        Ok(messages)
    }

    fn demo_flow() -> FlowContext {
        let process = ProcessIdentity {
            pid: 1,
            tgid: 1,
            start_time_ticks: 1,
            boot_id: "boot".to_string(),
            exe_path: "replay".to_string(),
            cmdline_hash: "hash".to_string(),
            uid: 0,
            gid: 0,
            cgroup: None,
            systemd_service: None,
            container_id: None,
            runtime_hint: None,
        };
        let local = AddressPort {
            address: "127.0.0.1".to_string(),
            port: 50_000,
        };
        let remote = AddressPort {
            address: "127.0.0.1".to_string(),
            port: 80,
        };
        FlowContext {
            id: FlowIdentity::stable(&process, &local, &remote, TransportProtocol::Tcp, 1, None),
            process: ProcessContext {
                identity: process,
                name: "replay".to_string(),
                cmdline: vec!["replay".to_string()],
            },
            local,
            remote,
            protocol: TransportProtocol::Tcp,
            start_monotonic_ns: 1,
            socket_cookie: None,
            attribution_confidence: 0,
        }
    }

    fn remote_policy_bundle_document(version: &str, alert_prefix: &str) -> String {
        format!(
            r#"
source = '''
function on_http_request_headers(event)
  return probe.emit_alert("{alert_prefix} " .. event.kind.target)
end
'''

[manifest]
id = "guard"
version = "{version}"
hooks = ["on_http_request_headers"]
"#
        )
    }

    fn remote_policy_bundle_document_with_counter(version: &str) -> String {
        format!(
            r#"
source = '''
local seen = 0

function on_http_request_headers(_)
  seen = seen + 1
  return probe.emit_alert("{version} " .. tostring(seen))
end
'''

[manifest]
id = "guard"
version = "{version}"
hooks = ["on_http_request_headers"]
"#
        )
    }
}
