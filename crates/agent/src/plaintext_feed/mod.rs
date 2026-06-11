use std::{
    fs::File,
    io::{self, BufRead, BufReader},
    path::Path,
};

use capture::{
    CaptureError, CaptureEvent, CaptureProvider, CaptureProviderKind, PlaintextChunk,
    PlaintextConnection, PlaintextFeedEvent, PlaintextGap,
};
use probe_core::{
    AddressPort, CapabilityKind, CapabilityState, CaptureSource, Direction, FlowContext,
    FlowIdentity, Gap, ProcessContext, ProcessIdentity, Timestamp, TransportProtocol,
};
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

const MAX_PLAINTEXT_FEED_LINE_BYTES: usize = 16 * 1024 * 1024;
const PROVIDER_NAME: &str = "plaintext_feed_jsonl";

#[derive(Debug, Error)]
pub enum PlaintextFeedLoadError {
    #[error("failed to open plaintext feed {path}: {source}")]
    OpenFile {
        path: String,
        source: std::io::Error,
    },
}

pub fn load_plaintext_feed_provider(
    path: &Path,
) -> Result<JsonLinesPlaintextFeedProvider<BufReader<File>>, PlaintextFeedLoadError> {
    let file = File::open(path).map_err(|source| PlaintextFeedLoadError::OpenFile {
        path: path.display().to_string(),
        source,
    })?;
    Ok(JsonLinesPlaintextFeedProvider::new(
        BufReader::new(file),
        path.display().to_string(),
    ))
}

#[derive(Debug)]
pub struct JsonLinesPlaintextFeedProvider<R> {
    reader: R,
    path: String,
    line_number: usize,
    line_buffer: String,
}

impl<R> JsonLinesPlaintextFeedProvider<R>
where
    R: BufRead,
{
    fn new(reader: R, path: impl Into<String>) -> Self {
        Self {
            reader,
            path: path.into(),
            line_number: 0,
            line_buffer: String::new(),
        }
    }

    fn read_next_event(&mut self) -> Result<Option<PlaintextFeedEvent>, PlaintextFeedReadError> {
        loop {
            self.line_buffer.clear();
            let bytes_read = read_bounded_line(
                &mut self.reader,
                &mut self.line_buffer,
                MAX_PLAINTEXT_FEED_LINE_BYTES,
            )
            .map_err(|source| PlaintextFeedReadError::ReadLine {
                path: self.path.clone(),
                line: self.line_number.saturating_add(1),
                source,
            })?;
            if bytes_read == 0 {
                return Ok(None);
            }
            self.line_number = self.line_number.saturating_add(1);
            if self.line_buffer.trim().is_empty() {
                continue;
            }
            let event = serde_json::from_str::<PlaintextFeedJsonEvent>(&self.line_buffer).map_err(
                |source| PlaintextFeedReadError::InvalidJsonLine {
                    path: self.path.clone(),
                    line: self.line_number,
                    source,
                },
            )?;
            return Ok(Some(event.into()));
        }
    }
}

impl<R> CaptureProvider for JsonLinesPlaintextFeedProvider<R>
where
    R: BufRead,
{
    fn name(&self) -> &'static str {
        PROVIDER_NAME
    }

    fn kind(&self) -> CaptureProviderKind {
        CaptureProviderKind::Plaintext
    }

    fn source(&self) -> CaptureSource {
        CaptureSource::ExternalPlaintextFeed
    }

    fn capabilities(&self) -> Vec<CapabilityState> {
        vec![CapabilityState::available(
            CapabilityKind::ExternalPlaintextFeed,
        )]
    }

    fn next(&mut self) -> Result<Option<CaptureEvent>, CaptureError> {
        self.read_next_event()
            .map(|event| event.map(CaptureEvent::from))
            .map_err(|error| CaptureError::provider(PROVIDER_NAME, error.to_string()))
    }
}

#[derive(Debug, Error)]
enum PlaintextFeedReadError {
    #[error("failed to read plaintext feed {path}:{line}: {source}")]
    ReadLine {
        path: String,
        line: usize,
        source: std::io::Error,
    },
    #[error("invalid plaintext feed {path}:{line}: {source}")]
    InvalidJsonLine {
        path: String,
        line: usize,
        source: serde_json::Error,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum PlaintextFeedJsonEvent {
    Bytes(PlaintextFeedJsonBytes),
    Gap(PlaintextFeedJsonGap),
    ConnectionOpened(PlaintextFeedJsonConnectionLifecycle),
    ConnectionClosed(PlaintextFeedJsonConnectionLifecycle),
}

impl From<PlaintextFeedJsonEvent> for PlaintextFeedEvent {
    fn from(value: PlaintextFeedJsonEvent) -> Self {
        match value {
            PlaintextFeedJsonEvent::Bytes(bytes) => Self::Bytes(bytes.into()),
            PlaintextFeedJsonEvent::Gap(gap) => Self::Gap(gap.into()),
            PlaintextFeedJsonEvent::ConnectionOpened(connection) => {
                Self::ConnectionOpened(connection.into())
            }
            PlaintextFeedJsonEvent::ConnectionClosed(connection) => {
                Self::ConnectionClosed(connection.into())
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlaintextFeedJsonBytes {
    timestamp: PlaintextFeedJsonTimestamp,
    connection: PlaintextFeedJsonConnection,
    direction: Direction,
    stream_offset: u64,
    bytes: Vec<u8>,
    #[serde(default)]
    degraded: bool,
    #[serde(default)]
    degradation_reason: Option<String>,
}

impl From<PlaintextFeedJsonBytes> for PlaintextChunk {
    fn from(value: PlaintextFeedJsonBytes) -> Self {
        let timestamp = Timestamp::from(value.timestamp);
        let flow = value.connection.into_flow_context();
        let mut chunk = PlaintextChunk::new(timestamp, flow.clone(), value.direction, value.bytes);
        chunk.stream_offset = value.stream_offset;
        chunk.attribution_confidence = flow.attribution_confidence;
        chunk.degraded = value.degraded;
        chunk.degradation_reason = value.degradation_reason;
        chunk
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlaintextFeedJsonGap {
    timestamp: PlaintextFeedJsonTimestamp,
    connection: PlaintextFeedJsonConnection,
    direction: Direction,
    expected_offset: u64,
    #[serde(default)]
    next_offset: Option<u64>,
    reason: String,
}

impl From<PlaintextFeedJsonGap> for PlaintextGap {
    fn from(value: PlaintextFeedJsonGap) -> Self {
        Self::new(
            value.timestamp.into(),
            value.connection.into_flow_context(),
            Gap {
                direction: value.direction,
                expected_offset: value.expected_offset,
                next_offset: value.next_offset,
                reason: value.reason,
            },
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlaintextFeedJsonConnectionLifecycle {
    timestamp: PlaintextFeedJsonTimestamp,
    connection: PlaintextFeedJsonConnection,
}

impl From<PlaintextFeedJsonConnectionLifecycle> for PlaintextConnection {
    fn from(value: PlaintextFeedJsonConnectionLifecycle) -> Self {
        Self::new(value.timestamp.into(), value.connection.into_flow_context())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlaintextFeedJsonConnection {
    connection_id: String,
    local: PlaintextFeedJsonEndpoint,
    remote: PlaintextFeedJsonEndpoint,
    protocol: PlaintextFeedJsonProtocol,
    start_monotonic_ns: u64,
    #[serde(default)]
    socket_cookie: Option<u64>,
    attribution_confidence: PlaintextFeedJsonConfidence,
    #[serde(default)]
    process: Option<PlaintextFeedJsonProcess>,
}

impl PlaintextFeedJsonConnection {
    fn into_flow_context(self) -> FlowContext {
        let attribution_confidence =
            normalize_confidence(self.attribution_confidence.get(), self.process.is_some());
        let process = self.process.map_or_else(
            || synthetic_external_process(&self.connection_id),
            |process| process.process_context(),
        );
        FlowContext {
            id: FlowIdentity(format!("external_plaintext_feed:{}", self.connection_id)),
            process,
            local: self.local.into(),
            remote: self.remote.into(),
            protocol: self.protocol.into(),
            start_monotonic_ns: self.start_monotonic_ns,
            socket_cookie: self.socket_cookie,
            attribution_confidence,
        }
    }
}

fn normalize_confidence(confidence: u8, has_process: bool) -> u8 {
    if has_process { confidence } else { 0 }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlaintextFeedJsonEndpoint {
    address: String,
    port: u16,
}

impl From<PlaintextFeedJsonEndpoint> for AddressPort {
    fn from(value: PlaintextFeedJsonEndpoint) -> Self {
        Self {
            address: value.address,
            port: value.port,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PlaintextFeedJsonProtocol {
    Tcp,
    Udp,
}

impl From<PlaintextFeedJsonProtocol> for TransportProtocol {
    fn from(value: PlaintextFeedJsonProtocol) -> Self {
        match value {
            PlaintextFeedJsonProtocol::Tcp => Self::Tcp,
            PlaintextFeedJsonProtocol::Udp => Self::Udp,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlaintextFeedJsonProcess {
    pid: u32,
    tgid: u32,
    start_time_ticks: u64,
    boot_id: String,
    exe_path: String,
    cmdline_hash: String,
    uid: u32,
    gid: u32,
    name: String,
    cmdline: Vec<String>,
    #[serde(default)]
    cgroup: Option<String>,
    #[serde(default)]
    systemd_service: Option<String>,
    #[serde(default)]
    container_id: Option<String>,
    #[serde(default)]
    runtime_hint: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
struct PlaintextFeedJsonConfidence(u8);

impl PlaintextFeedJsonConfidence {
    fn get(self) -> u8 {
        self.0
    }
}

impl<'de> Deserialize<'de> for PlaintextFeedJsonConfidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u8::deserialize(deserializer)?;
        if value <= 100 {
            Ok(Self(value))
        } else {
            Err(serde::de::Error::custom(
                "attribution_confidence must be in 0..=100",
            ))
        }
    }
}

impl PlaintextFeedJsonProcess {
    fn process_context(self) -> ProcessContext {
        ProcessContext {
            identity: ProcessIdentity {
                pid: self.pid,
                tgid: self.tgid,
                start_time_ticks: self.start_time_ticks,
                boot_id: self.boot_id,
                exe_path: self.exe_path,
                cmdline_hash: self.cmdline_hash,
                uid: self.uid,
                gid: self.gid,
                cgroup: self.cgroup,
                systemd_service: self.systemd_service,
                container_id: self.container_id,
                runtime_hint: self.runtime_hint,
            },
            name: self.name.clone(),
            cmdline: if self.cmdline.is_empty() {
                vec![self.name]
            } else {
                self.cmdline
            },
        }
    }
}

fn synthetic_external_process(connection_id: &str) -> ProcessContext {
    let name = "external_plaintext_unknown".to_string();
    ProcessContext {
        identity: ProcessIdentity {
            pid: 0,
            tgid: 0,
            start_time_ticks: 0,
            boot_id: "external_plaintext_feed".to_string(),
            exe_path: "external_plaintext_unknown".to_string(),
            cmdline_hash: format!("unknown:{connection_id}"),
            uid: 0,
            gid: 0,
            cgroup: None,
            systemd_service: None,
            container_id: None,
            runtime_hint: None,
        },
        name: name.clone(),
        cmdline: vec![name],
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlaintextFeedJsonTimestamp {
    monotonic_ns: u64,
    wall_time_unix_ns: i64,
}

impl From<PlaintextFeedJsonTimestamp> for Timestamp {
    fn from(value: PlaintextFeedJsonTimestamp) -> Self {
        Self {
            monotonic_ns: value.monotonic_ns,
            wall_time_unix_ns: i128::from(value.wall_time_unix_ns),
        }
    }
}

fn read_bounded_line<R>(reader: &mut R, output: &mut String, max_bytes: usize) -> io::Result<usize>
where
    R: BufRead,
{
    let mut bytes = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            break;
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |position| position + 1);
        if bytes.len().saturating_add(take) > max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("plaintext feed line exceeds {max_bytes} bytes"),
            ));
        }
        let line_ended = available[..take].ends_with(b"\n");
        bytes.extend_from_slice(&available[..take]);
        reader.consume(take);
        if line_ended {
            break;
        }
    }

    if bytes.is_empty() {
        return Ok(0);
    }

    let text = String::from_utf8(bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("plaintext feed line is not UTF-8: {error}"),
        )
    })?;
    output.push_str(&text);
    Ok(output.len())
}

#[cfg(test)]
mod tests {
    use std::{
        io::Cursor,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;

    #[test]
    fn reads_plaintext_feed_json_lines() -> Result<(), Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "sssa-plaintext-feed-{}-{}.jsonl",
            std::process::id(),
            timestamp_suffix()
        ));
        std::fs::write(&path, plaintext_feed_fixture())?;

        let mut provider = load_plaintext_feed_provider(&path)?;
        let event = provider
            .next()?
            .expect("fixture should yield one plaintext event");

        std::fs::remove_file(&path)?;
        let CaptureEvent::Bytes(chunk) = event else {
            panic!("expected plaintext bytes");
        };
        assert_eq!(chunk.timestamp.wall_time_unix_ns, 1);
        assert_eq!(chunk.flow.id.0, "external_plaintext_feed:fixture-conn");
        assert_eq!(chunk.flow.local.address, "127.0.0.1");
        assert_eq!(chunk.flow.local.port, 50000);
        assert_eq!(chunk.flow.remote.port, 443);
        assert_eq!(chunk.flow.attribution_confidence, 42);
        assert_eq!(chunk.stream_offset, 7);
        assert_eq!(chunk.bytes.as_ref(), b"GET /feed HTTP/1.1\r\n\r\n");
        assert_eq!(chunk.attribution_confidence, 42);
        assert!(chunk.degraded);
        assert_eq!(chunk.degradation_reason.as_deref(), Some("json feed test"));
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn rejects_unknown_json_fields() {
        let input = r#"
{"type":"bytes","timestamp":{"monotonic_ns":1,"wall_time_unix_ns":1},"connection":{"connection_id":"fixture-conn","local":{"address":"127.0.0.1","port":50000},"remote":{"address":"127.0.0.1","port":443},"protocol":"tcp","start_monotonic_ns":1,"attribution_confidence":42},"direction":"outbound","stream_offset":0,"bytes":[71],"unexpected":true}
"#;
        let mut provider = JsonLinesPlaintextFeedProvider::new(Cursor::new(input), "fixture");

        let error = provider
            .next()
            .expect_err("unknown JSON fields must fail closed");

        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn missing_process_forces_zero_attribution_confidence() -> Result<(), Box<dyn std::error::Error>>
    {
        let input = r#"
{"type":"bytes","timestamp":{"monotonic_ns":1,"wall_time_unix_ns":1},"connection":{"connection_id":"fixture-conn","local":{"address":"127.0.0.1","port":50000},"remote":{"address":"127.0.0.1","port":443},"protocol":"tcp","start_monotonic_ns":1,"attribution_confidence":100},"direction":"outbound","stream_offset":0,"bytes":[71]}
"#;
        let mut provider = JsonLinesPlaintextFeedProvider::new(Cursor::new(input), "fixture");

        let Some(CaptureEvent::Bytes(chunk)) = provider.next()? else {
            panic!("expected plaintext bytes");
        };

        assert_eq!(chunk.attribution_confidence, 0);
        assert_eq!(chunk.flow.attribution_confidence, 0);
        assert_eq!(chunk.flow.process.name, "external_plaintext_unknown");
        assert_eq!(chunk.flow.process.identity.uid, 0);
        Ok(())
    }

    #[test]
    fn rejects_attribution_confidence_above_one_hundred() {
        let input = r#"
{"type":"bytes","timestamp":{"monotonic_ns":1,"wall_time_unix_ns":1},"connection":{"connection_id":"fixture-conn","local":{"address":"127.0.0.1","port":50000},"remote":{"address":"127.0.0.1","port":443},"protocol":"tcp","start_monotonic_ns":1,"attribution_confidence":101},"direction":"outbound","stream_offset":0,"bytes":[71]}
"#;
        let mut provider = JsonLinesPlaintextFeedProvider::new(Cursor::new(input), "fixture");

        let error = provider
            .next()
            .expect_err("over-100 confidence must fail closed");

        assert!(error.to_string().contains("0..=100"));
    }

    #[test]
    fn rejects_lines_over_the_size_limit() {
        let input = "x".repeat(MAX_PLAINTEXT_FEED_LINE_BYTES + 1);
        let mut provider = JsonLinesPlaintextFeedProvider::new(Cursor::new(input), "fixture");

        let error = provider
            .next()
            .expect_err("oversized JSON lines must fail closed");

        assert!(error.to_string().contains("exceeds"));
    }

    fn plaintext_feed_fixture() -> &'static str {
        r#"
{"type":"bytes","timestamp":{"monotonic_ns":1,"wall_time_unix_ns":1},"connection":{"connection_id":"fixture-conn","local":{"address":"127.0.0.1","port":50000},"remote":{"address":"127.0.0.1","port":443},"protocol":"tcp","start_monotonic_ns":1,"socket_cookie":99,"attribution_confidence":42,"process":{"pid":123,"tgid":123,"start_time_ticks":456,"boot_id":"boot","exe_path":"/usr/bin/feed","cmdline_hash":"hash","uid":1000,"gid":1000,"name":"feed","cmdline":["feed"]}},"direction":"outbound","stream_offset":7,"bytes":[71,69,84,32,47,102,101,101,100,32,72,84,84,80,47,49,46,49,13,10,13,10],"degraded":true,"degradation_reason":"json feed test"}
"#
    }

    fn timestamp_suffix() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos())
    }
}
