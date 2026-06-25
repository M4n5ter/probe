use std::{
    fs,
    path::{Path, PathBuf},
};

use probe_config::{AgentConfig, CaptureSelection, PolicyConfig, PolicySourceConfig};
use probe_core::{CaptureProviderKind, CaptureSource, Direction, EventEnvelope};

pub(crate) const PLAINTEXT_FEED_EVENT_COUNT: usize = 3;
pub(crate) const PLAINTEXT_FEED_EXPORT_EVENT_COUNT: usize = 4;

pub(crate) struct PlaintextFeedCase {
    agent_id: &'static str,
    config_version: &'static str,
    connection_id: &'static str,
    flow: PlaintextFlow,
}

impl PlaintextFeedCase {
    pub(crate) fn new(
        agent_id: &'static str,
        config_version: &'static str,
        connection_id: &'static str,
        flow: PlaintextFlow,
    ) -> Self {
        Self {
            agent_id,
            config_version,
            connection_id,
            flow,
        }
    }

    pub(crate) fn write_feed_records(
        &self,
        path: &Path,
        records: impl IntoIterator<Item = PlaintextFeedRecord>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        fs::write(path, self.feed_records_jsonl(records)?)?;
        Ok(())
    }

    pub(crate) fn feed_records_jsonl(
        &self,
        records: impl IntoIterator<Item = PlaintextFeedRecord>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let connection = self.connection_json();
        let mut content = String::new();
        for (index, record) in records.into_iter().enumerate() {
            let monotonic_ns = u64::try_from(index)
                .unwrap_or(u64::MAX - 1)
                .saturating_add(1);
            let record = self.feed_record_json(&connection, monotonic_ns, record);
            content.push_str(&serde_json::to_string(&record)?);
            content.push('\n');
        }
        Ok(content)
    }

    pub(crate) fn agent_config_with_policy(
        &self,
        feed_path: PathBuf,
        policy_path: PathBuf,
        spool_path: PathBuf,
        policy_id: impl Into<String>,
    ) -> AgentConfig {
        self.agent_config_with_policy_source(
            feed_path,
            PolicySourceConfig::LocalDirectory { path: policy_path },
            spool_path,
            policy_id,
        )
    }

    pub(crate) fn agent_config_with_policy_source(
        &self,
        feed_path: PathBuf,
        policy_source: PolicySourceConfig,
        spool_path: PathBuf,
        policy_id: impl Into<String>,
    ) -> AgentConfig {
        let mut config = self.agent_config(feed_path, spool_path);
        config.policies.push(PolicyConfig {
            id: policy_id.into(),
            source: policy_source,
            enabled: true,
            selector: None,
        });
        config
    }

    pub(crate) fn agent_config(&self, feed_path: PathBuf, spool_path: PathBuf) -> AgentConfig {
        let mut config = AgentConfig {
            agent_id: self.agent_id.to_string(),
            config_version: self.config_version.to_string(),
            ..AgentConfig::default()
        };
        config.capture.selection = CaptureSelection::PlaintextFeed;
        config.capture.plaintext_feed.path = Some(feed_path);
        config.storage.path = spool_path;
        config
    }

    pub(crate) fn expected_flow_id(&self) -> String {
        format!("external_plaintext_feed:{}", self.connection_id)
    }

    pub(crate) fn matches_export_flow(&self, envelope: &EventEnvelope) -> bool {
        envelope.origin().source() == CaptureSource::ExternalPlaintextFeed
            && envelope.origin().provider() == CaptureProviderKind::Plaintext
            && envelope
                .flow()
                .is_some_and(|flow| flow.id.0 == self.expected_flow_id())
    }

    fn feed_record_json(
        &self,
        connection: &serde_json::Value,
        monotonic_ns: u64,
        record: PlaintextFeedRecord,
    ) -> serde_json::Value {
        match record {
            PlaintextFeedRecord::ConnectionOpened => serde_json::json!({
                "type": "connection_opened",
                "timestamp": feed_timestamp(monotonic_ns),
                "connection": connection,
            }),
            PlaintextFeedRecord::Bytes {
                direction,
                stream_offset,
                bytes,
            } => serde_json::json!({
                "type": "bytes",
                "timestamp": feed_timestamp(monotonic_ns),
                "connection": connection,
                "direction": direction,
                "stream_offset": stream_offset,
                "bytes": bytes,
            }),
            PlaintextFeedRecord::Gap {
                direction,
                expected_offset,
                next_offset,
                reason,
            } => serde_json::json!({
                "type": "gap",
                "timestamp": feed_timestamp(monotonic_ns),
                "connection": connection,
                "direction": direction,
                "expected_offset": expected_offset,
                "next_offset": next_offset,
                "reason": reason,
            }),
            PlaintextFeedRecord::ConnectionClosed => serde_json::json!({
                "type": "connection_closed",
                "timestamp": feed_timestamp(monotonic_ns),
                "connection": connection,
            }),
        }
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

pub(crate) struct PlaintextFeedScenario {
    feed: PlaintextFeedCase,
    policy_id: &'static str,
    policy_version: &'static str,
    request: PlaintextHttpRequest,
    policy: PlaintextPolicy,
}

impl PlaintextFeedScenario {
    pub(crate) fn new(
        ids: PlaintextScenarioIds,
        request: PlaintextHttpRequest,
        policy: PlaintextPolicy,
    ) -> Self {
        let policy_id = ids.policy_id;
        let policy_version = ids.policy_version;
        Self {
            feed: PlaintextFeedCase::new(
                ids.agent_id,
                ids.config_version,
                ids.connection_id,
                PlaintextFlow::default(),
            ),
            policy_id,
            policy_version,
            request,
            policy,
        }
    }

    pub(crate) fn with_flow(mut self, flow: PlaintextFlow) -> Self {
        self.feed.flow = flow;
        self
    }

    pub(crate) fn write_feed(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let request_bytes = self.request_bytes();
        self.write_feed_records(
            path,
            [
                PlaintextFeedRecord::connection_opened(),
                PlaintextFeedRecord::bytes(Direction::Outbound, 0, request_bytes),
                PlaintextFeedRecord::connection_closed(),
            ],
        )
    }

    pub(crate) fn write_feed_records(
        &self,
        path: &Path,
        records: impl IntoIterator<Item = PlaintextFeedRecord>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.feed.write_feed_records(path, records)
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
        self.agent_config_with_policy_source(
            feed_path,
            PolicySourceConfig::LocalDirectory { path: policy_path },
            spool_path,
        )
    }

    pub(crate) fn agent_config_with_policy_source(
        &self,
        feed_path: PathBuf,
        policy_source: PolicySourceConfig,
        spool_path: PathBuf,
    ) -> AgentConfig {
        self.feed.agent_config_with_policy_source(
            feed_path,
            policy_source,
            spool_path,
            self.policy_id,
        )
    }

    pub(crate) fn expected_flow_id(&self) -> String {
        self.feed.expected_flow_id()
    }

    pub(crate) fn feed_case(&self) -> &PlaintextFeedCase {
        &self.feed
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
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PlaintextFeedRecord {
    ConnectionOpened,
    Bytes {
        direction: Direction,
        stream_offset: u64,
        bytes: Vec<u8>,
    },
    Gap {
        direction: Direction,
        expected_offset: u64,
        next_offset: Option<u64>,
        reason: &'static str,
    },
    ConnectionClosed,
}

impl PlaintextFeedRecord {
    pub(crate) fn connection_opened() -> Self {
        Self::ConnectionOpened
    }

    pub(crate) fn bytes(direction: Direction, stream_offset: u64, bytes: Vec<u8>) -> Self {
        Self::Bytes {
            direction,
            stream_offset,
            bytes,
        }
    }

    pub(crate) fn gap(
        direction: Direction,
        expected_offset: u64,
        next_offset: Option<u64>,
        reason: &'static str,
    ) -> Self {
        Self::Gap {
            direction,
            expected_offset,
            next_offset,
            reason,
        }
    }

    pub(crate) fn connection_closed() -> Self {
        Self::ConnectionClosed
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
