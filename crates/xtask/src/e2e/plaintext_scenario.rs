use std::{
    fs,
    path::{Path, PathBuf},
};

use probe_config::{AgentConfig, CaptureSelection, PolicyConfig};

pub(crate) const PLAINTEXT_FEED_EVENT_COUNT: usize = 3;
pub(crate) const PLAINTEXT_FEED_EXPORT_EVENT_COUNT: usize = 4;

pub(crate) struct PlaintextFeedScenario {
    agent_id: &'static str,
    config_version: &'static str,
    policy_id: &'static str,
    policy_version: &'static str,
    connection_id: &'static str,
    request: PlaintextHttpRequest,
    policy: PlaintextPolicy,
    flow: PlaintextFlow,
}

impl PlaintextFeedScenario {
    pub(crate) fn new(
        ids: PlaintextScenarioIds,
        request: PlaintextHttpRequest,
        policy: PlaintextPolicy,
    ) -> Self {
        Self {
            agent_id: ids.agent_id,
            config_version: ids.config_version,
            policy_id: ids.policy_id,
            policy_version: ids.policy_version,
            connection_id: ids.connection_id,
            request,
            policy,
            flow: PlaintextFlow::default(),
        }
    }

    pub(crate) fn with_flow(mut self, flow: PlaintextFlow) -> Self {
        self.flow = flow;
        self
    }

    pub(crate) fn write_feed(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let connection = self.connection_json();
        let request_bytes = self.request_bytes();
        let records = [
            serde_json::json!({
                "type": "connection_opened",
                "timestamp": feed_timestamp(1),
                "connection": connection.clone(),
            }),
            serde_json::json!({
                "type": "bytes",
                "timestamp": feed_timestamp(2),
                "connection": connection.clone(),
                "direction": "outbound",
                "stream_offset": 0,
                "bytes": request_bytes,
            }),
            serde_json::json!({
                "type": "connection_closed",
                "timestamp": feed_timestamp(3),
                "connection": connection,
            }),
        ];
        let mut content = String::new();
        for record in records {
            content.push_str(&serde_json::to_string(&record)?);
            content.push('\n');
        }
        fs::write(path, content)?;
        Ok(())
    }

    pub(crate) fn write_policy_bundle(&self, path: &Path) -> Result<(), std::io::Error> {
        fs::create_dir_all(path)?;
        fs::write(
            path.join("manifest.toml"),
            format!(
                r#"
id = "{}"
version = "{}"
hooks = ["on_http_request_headers"]
"#,
                self.policy_id, self.policy_version
            ),
        )?;
        fs::write(
            path.join("main.lua"),
            format!(
                r#"
function on_http_request_headers(event)
  return probe.emit_alert("{}" .. event.kind.target)
end
"#,
                self.policy.alert_prefix
            ),
        )
    }

    pub(crate) fn agent_config(
        &self,
        feed_path: PathBuf,
        policy_path: PathBuf,
        spool_path: PathBuf,
    ) -> AgentConfig {
        let mut config = AgentConfig {
            agent_id: self.agent_id.to_string(),
            config_version: self.config_version.to_string(),
            ..AgentConfig::default()
        };
        config.capture.selection = CaptureSelection::PlaintextFeed;
        config.capture.plaintext_feed.path = Some(feed_path);
        config.storage.path = spool_path;
        config.policies.push(PolicyConfig {
            id: self.policy_id.to_string(),
            path: policy_path,
            enabled: true,
            selector: None,
        });
        config
    }

    pub(crate) fn expected_flow_id(&self) -> String {
        format!("external_plaintext_feed:{}", self.connection_id)
    }

    pub(crate) fn request_bytes(&self) -> Vec<u8> {
        format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\n\r\n",
            self.request.target, self.request.host
        )
        .into_bytes()
    }

    pub(crate) fn request_target(&self) -> &str {
        self.request.target
    }

    pub(crate) fn expected_policy_alert_message(&self) -> String {
        format!("{}{}", self.policy.alert_prefix, self.request.target)
    }

    pub(crate) fn expected_policy_version(&self) -> String {
        format!("{}@{}", self.policy_id, self.policy_version)
    }

    fn connection_json(&self) -> serde_json::Value {
        serde_json::json!({
            "connection_id": self.connection_id,
            "local": {
                "address": "127.0.0.1",
                "port": self.flow.local_port,
            },
            "remote": {
                "address": "127.0.0.1",
                "port": self.flow.remote_port,
            },
            "protocol": "tcp",
            "start_monotonic_ns": 1,
            "socket_cookie": self.flow.socket_cookie,
            "attribution_confidence": 100,
            "process": {
                "pid": self.flow.process.pid,
                "tgid": self.flow.process.pid,
                "start_time_ticks": self.flow.process.start_time_ticks,
                "boot_id": "boot",
                "exe_path": self.flow.process.exe_path,
                "cmdline_hash": self.flow.process.cmdline_hash,
                "uid": 1000,
                "gid": 1000,
                "name": self.flow.process.name,
                "cmdline": [self.flow.process.name],
            },
        })
    }
}

pub(crate) struct PlaintextScenarioIds {
    agent_id: &'static str,
    config_version: &'static str,
    policy_id: &'static str,
    policy_version: &'static str,
    connection_id: &'static str,
}

impl PlaintextScenarioIds {
    pub(crate) fn new(
        agent_id: &'static str,
        config_version: &'static str,
        policy_id: &'static str,
        policy_version: &'static str,
        connection_id: &'static str,
    ) -> Self {
        Self {
            agent_id,
            config_version,
            policy_id,
            policy_version,
            connection_id,
        }
    }
}

pub(crate) struct PlaintextFlow {
    local_port: u16,
    remote_port: u16,
    socket_cookie: u64,
    process: PlaintextProcess,
}

impl PlaintextFlow {
    pub(crate) fn new(
        local_port: u16,
        remote_port: u16,
        socket_cookie: u64,
        process: PlaintextProcess,
    ) -> Self {
        Self {
            local_port,
            remote_port,
            socket_cookie,
            process,
        }
    }
}

impl Default for PlaintextFlow {
    fn default() -> Self {
        Self {
            local_port: 50_000,
            remote_port: 80,
            socket_cookie: 99,
            process: PlaintextProcess::default(),
        }
    }
}

pub(crate) struct PlaintextProcess {
    pid: u32,
    start_time_ticks: u64,
    name: &'static str,
    exe_path: &'static str,
    cmdline_hash: &'static str,
}

impl PlaintextProcess {
    pub(crate) fn new(
        pid: u32,
        start_time_ticks: u64,
        name: &'static str,
        exe_path: &'static str,
        cmdline_hash: &'static str,
    ) -> Self {
        Self {
            pid,
            start_time_ticks,
            name,
            exe_path,
            cmdline_hash,
        }
    }
}

impl Default for PlaintextProcess {
    fn default() -> Self {
        Self {
            pid: 123,
            start_time_ticks: 456,
            name: "sssa-e2e",
            exe_path: "/usr/bin/sssa-e2e",
            cmdline_hash: "hash",
        }
    }
}

pub(crate) struct PlaintextHttpRequest {
    target: &'static str,
    host: &'static str,
}

impl PlaintextHttpRequest {
    pub(crate) fn get(target: &'static str, host: &'static str) -> Self {
        Self { target, host }
    }
}

pub(crate) struct PlaintextPolicy {
    alert_prefix: &'static str,
}

impl PlaintextPolicy {
    pub(crate) fn alerting(alert_prefix: &'static str) -> Self {
        Self { alert_prefix }
    }
}

fn feed_timestamp(monotonic_ns: u64) -> serde_json::Value {
    serde_json::json!({
        "monotonic_ns": monotonic_ns,
        "wall_time_unix_ns": i64::try_from(monotonic_ns).unwrap_or(i64::MAX),
    })
}
