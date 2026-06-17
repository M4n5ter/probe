use std::sync::Arc;

use pipeline::PipelinePolicySet;
use probe_config::AgentConfig;
use tokio::sync::Mutex;

use crate::configured_policy::{
    ConfiguredPolicyError, ConfiguredPolicySource, load_configured_pipeline_policies,
};

#[derive(Clone)]
pub(crate) struct PolicyReloadGate {
    inner: Arc<Mutex<()>>,
}

impl Default for PolicyReloadGate {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(())),
        }
    }
}

pub(super) struct PolicyReloadSummary {
    pub loaded_count: u64,
    pub policies: Vec<ConfiguredPolicySource>,
}

pub(super) async fn reload_policies(
    config: &AgentConfig,
    policy_set: &PipelinePolicySet,
    gate: &PolicyReloadGate,
) -> Result<PolicyReloadSummary, ConfiguredPolicyError> {
    let _reload_guard = gate.inner.lock().await;
    let loaded = load_configured_pipeline_policies(config)?;
    let loaded_count = loaded.policies.len() as u64;
    let policies = loaded.sources;
    policy_set.replace(loaded.policies);
    Ok(PolicyReloadSummary {
        loaded_count,
        policies,
    })
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };

    use capture::ReplayProvider;
    use parsers::Http1ParserFactory;
    use pipeline::{CapturePipeline, PipelinePolicySet};
    use probe_config::{
        AgentConfig, CaptureBackend, CaptureSelection, ExporterConfig, PolicyConfig,
    };
    use probe_core::{
        AddressPort, CapabilityState, Direction, EventEnvelope, EventKind, FlowContext,
        FlowIdentity, ProcessContext, ProcessIdentity, SpoolPayloadSchema, Timestamp,
        TransportProtocol,
    };
    use runtime::{
        CaptureProviderBuilder, CaptureProviderDescriptor, ProviderRegistry, RuntimePlan,
    };
    use serde_json::json;
    use storage::FjallSpool;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixStream,
    };

    use super::super::server::{AdminRuntimeState, AdminServerConfig, spawn_admin_server};
    use crate::configured_policy::load_configured_pipeline_policies;

    #[tokio::test]
    async fn admin_reload_policies_swaps_active_pipeline_policy_set()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("admin-policy-reload")?;
        let socket_path = temp.join("admin.sock");
        let spool_path = temp.join("spool");
        let policy_path = temp.join("guard.bundle");
        write_policy_bundle(&policy_path, "old", "old")?;
        let mut config = config_with_storage_path(spool_path.clone());
        config.policies.push(PolicyConfig {
            id: "guard".to_string(),
            path: policy_path.clone(),
            ..PolicyConfig::default()
        });
        let spool = Arc::new(FjallSpool::open(&spool_path)?);
        let policy_set = load_configured_pipeline_policies(&config)?.into_policy_set();
        run_policy_request(spool.as_ref(), policy_set.clone(), "/before", 1)?;
        let plan = Arc::new(runtime_plan_from_config(config)?);
        let server = spawn_admin_server(
            Arc::clone(&plan),
            Arc::clone(&spool),
            AdminServerConfig {
                socket_path: socket_path.clone(),
            },
            AdminRuntimeState {
                policy_set: policy_set.clone(),
                ..AdminRuntimeState::default()
            },
        )?;
        write_policy_bundle(&policy_path, "new", "new")?;

        let response =
            send_admin_request(&socket_path, json!({ "command": "reload_policies" })).await?;

        assert_eq!(response["kind"], json!("policy_reload"));
        assert_eq!(response["loaded_count"], json!(1));
        assert_eq!(response["policies"][0]["id"], json!("guard"));
        run_policy_request(spool.as_ref(), policy_set, "/after", 2)?;
        assert_eq!(
            policy_alert_messages(spool.as_ref())?,
            vec!["old /before", "new /after"]
        );
        server.stop().await;
        drop(spool);
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[tokio::test]
    async fn admin_reload_policies_keeps_active_set_when_new_bundle_is_invalid()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("admin-policy-reload-invalid")?;
        let socket_path = temp.join("admin.sock");
        let spool_path = temp.join("spool");
        let policy_path = temp.join("guard.bundle");
        write_policy_bundle(&policy_path, "old", "old")?;
        let mut config = config_with_storage_path(spool_path.clone());
        config.policies.push(PolicyConfig {
            id: "guard".to_string(),
            path: policy_path.clone(),
            ..PolicyConfig::default()
        });
        let spool = Arc::new(FjallSpool::open(&spool_path)?);
        let policy_set = load_configured_pipeline_policies(&config)?.into_policy_set();
        let plan = Arc::new(runtime_plan_from_config(config)?);
        let server = spawn_admin_server(
            Arc::clone(&plan),
            Arc::clone(&spool),
            AdminServerConfig {
                socket_path: socket_path.clone(),
            },
            AdminRuntimeState {
                policy_set: policy_set.clone(),
                ..AdminRuntimeState::default()
            },
        )?;
        fs::write(
            policy_path.join("main.lua"),
            "function on_http_request_headers(",
        )?;

        let response =
            send_admin_request(&socket_path, json!({ "command": "reload_policies" })).await?;

        assert_eq!(response["kind"], json!("error"));
        assert!(
            response["message"]
                .as_str()
                .is_some_and(|message| message.contains("failed to reload policies"))
        );
        run_policy_request(spool.as_ref(), policy_set, "/after-error", 1)?;
        assert_eq!(
            policy_alert_messages(spool.as_ref())?,
            vec!["old /after-error"]
        );
        server.stop().await;
        drop(spool);
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    async fn send_admin_request(
        path: &Path,
        request: serde_json::Value,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let mut stream = UnixStream::connect(path).await?;
        let mut request_bytes = serde_json::to_vec(&request)?;
        request_bytes.push(b'\n');
        stream.write_all(&request_bytes).await?;
        read_admin_response(&mut stream).await
    }

    async fn read_admin_response(
        stream: &mut UnixStream,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let mut response = Vec::new();
        loop {
            let mut byte = [0_u8; 1];
            let read = stream.read(&mut byte).await?;
            if read == 0 || byte[0] == b'\n' {
                break;
            }
            response.push(byte[0]);
        }
        Ok(serde_json::from_slice(&response)?)
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

    fn config_with_storage_path(storage_path: PathBuf) -> AgentConfig {
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
                transport: probe_config::ExporterTransport::Webhook,
                endpoint: "https://collector.example/batches".to_string(),
                codec: probe_config::CompressionCodecName::None,
                headers: BTreeMap::new(),
                tls: Default::default(),
                worker: Default::default(),
            }],
            ..AgentConfig::default()
        }
    }

    fn write_policy_bundle(
        path: &Path,
        version: &str,
        alert_prefix: &str,
    ) -> Result<(), std::io::Error> {
        fs::create_dir_all(path)?;
        fs::write(
            path.join("manifest.toml"),
            format!(
                r#"id = "guard"
version = "{version}"
hooks = ["on_http_request_headers"]
"#
            ),
        )?;
        fs::write(
            path.join("main.lua"),
            format!(
                r#"
function on_http_request_headers(event)
  return probe.emit_alert("{alert_prefix} " .. event.kind.target)
end
"#
            ),
        )
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
        for stored in spool.read_export_batch("sink", 64)? {
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

    fn test_dir(name: &str) -> Result<PathBuf, std::io::Error> {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("sssa-{name}-{unique}"));
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
        fs::create_dir_all(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        Ok(path)
    }
}
