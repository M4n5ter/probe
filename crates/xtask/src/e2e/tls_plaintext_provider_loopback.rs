use std::{
    fs,
    net::{IpAddr, Ipv4Addr},
    path::Path,
    process::{Child, ExitCode},
    thread,
    time::{Duration, Instant},
};

use capture::{
    CaptureError, CaptureEvent, CapturePoll, CaptureProvider, CaptureProviderKind,
    LibsslResolvedFlow, LibsslUprobeAttachPlan, LibsslUprobeFlowLookup, LibsslUprobeFlowResolver,
    LibsslUprobePlaintextProbeConfig, LibsslUprobePlaintextProvider, LibsslUprobeTargetDiscovery,
};
use probe_core::{
    CaptureSource, Direction, ProcessContext, ProcessIdentity, TcpConnection, TcpEndpoint,
};

use super::{
    harness::{ChildSupervisor, create_temp_root, e2e_error, ensure_e2e_packages_built},
    loopback::{
        Http1LoopbackFixtureConfig, spawn_tls_http1_loopback_fixture, start_http1_loopback_fixture,
        wait_for_http1_loopback_fixture_exit, wait_for_http1_loopback_fixture_ready,
    },
};

const REQUESTS: usize = 1;
const REQUEST_BODY_BYTES: usize = 48;
const RESPONSE_BODY_BYTES: usize = 24;
const WRITE_CHUNKS: usize = 1;
const POST_EXCHANGE_DELAY_MS: u64 = 500;
const PROVIDER_EVENT_TIMEOUT: Duration = Duration::from_secs(5);
const PROVIDER_POLL_INTERVAL: Duration = Duration::from_millis(10);
const DIRECT_FLOW_CONFIDENCE: u8 = 90;

pub(crate) fn run() -> ExitCode {
    match run_inner() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("e2e TLS plaintext provider loopback failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_inner() -> Result<(), Box<dyn std::error::Error>> {
    ensure_e2e_packages_built(["e2e-fixture"])?;
    let tls_object_path = crate::ebpf::ensure_tls_plaintext_artifact_ready().map_err(e2e_error)?;

    let root = create_temp_root("tls-plaintext-provider-loopback")?;
    match run_at(&root, &tls_object_path) {
        Ok(()) => {
            fs::remove_dir_all(&root)?;
            println!("e2e TLS plaintext provider loopback passed");
            Ok(())
        }
        Err(error) => {
            eprintln!("e2e artifacts retained at {}", root.display());
            Err(error)
        }
    }
}

fn run_at(root: &Path, tls_object_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(root)?;
    let fixture_ready_path = root.join("fixture.ready");
    let fixture_start_path = root.join("fixture.start");

    let supervisor = ChildSupervisor::new()?;
    let mut fixture = supervisor.watch(
        spawn_tls_http1_loopback_fixture(
            &fixture_ready_path,
            &fixture_start_path,
            fixture_config(),
        )?,
        "fixture",
    );
    let fixture_ready =
        wait_for_http1_loopback_fixture_ready(fixture.child_mut(), &fixture_ready_path)?;
    let report = LibsslUprobeTargetDiscovery::default().discover_for_pid(fixture_ready.pid)?;
    let process = report.process();
    let attach_plan = LibsslUprobeAttachPlan::from_discovery_report(report);
    let mut provider = LibsslUprobePlaintextProvider::open(
        LibsslUprobePlaintextProbeConfig::new(tls_object_path, attach_plan),
        Box::new(LoopbackFlowResolver {
            fixture_pid: fixture_ready.pid,
            start_time_ticks: process.start_time_ticks,
            listen_port: fixture_ready.listen_port,
        }),
    )?;

    start_http1_loopback_fixture(&fixture_start_path, &fixture_ready.start_nonce)?;
    let provider_result = wait_for_provider_plaintext_request(
        &mut provider,
        fixture.child_mut(),
        fixture_ready.listen_port,
    );
    let fixture_result = wait_for_http1_loopback_fixture_exit(fixture.child_mut());
    fixture.unwatch();
    merge_provider_results(provider_result, fixture_result)?;
    Ok(())
}

fn fixture_config() -> Http1LoopbackFixtureConfig {
    Http1LoopbackFixtureConfig {
        requests: REQUESTS,
        request_body_bytes: REQUEST_BODY_BYTES,
        response_body_bytes: RESPONSE_BODY_BYTES,
        write_chunks: WRITE_CHUNKS,
        connect_write_delay_ms: 0,
        post_exchange_delay_ms: POST_EXCHANGE_DELAY_MS,
    }
}

fn wait_for_provider_plaintext_request(
    provider: &mut LibsslUprobePlaintextProvider,
    fixture: &mut Child,
    listen_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + PROVIDER_EVENT_TIMEOUT;
    let mut observed = Vec::new();
    loop {
        match provider.poll_next()? {
            CapturePoll::Event(event) => {
                let event = *event;
                if is_expected_tls_plaintext_request_bytes(&event, listen_port) {
                    return Ok(());
                }
                observed.push(event);
            }
            CapturePoll::Progress => {}
            CapturePoll::Idle => {
                thread::sleep(PROVIDER_POLL_INTERVAL);
            }
            CapturePoll::Finished => {
                return Err(
                    e2e_error("TLS plaintext provider finished before request bytes").into(),
                );
            }
        }
        if let Some(status) = fixture.try_wait()?
            && Instant::now() >= deadline
        {
            return Err(e2e_error(format!(
                "fixture exited with {status} before TLS plaintext provider emitted request bytes; observed {}",
                provider_event_summary(&observed, listen_port)
            ))
            .into());
        }
        if Instant::now() >= deadline {
            return Err(e2e_error(format!(
                "timed out waiting for TLS plaintext provider request bytes; observed {}",
                provider_event_summary(&observed, listen_port)
            ))
            .into());
        }
    }
}

fn is_expected_tls_plaintext_request_bytes(event: &CaptureEvent, listen_port: u16) -> bool {
    let CaptureEvent::Bytes(bytes) = event else {
        return false;
    };
    bytes.source == CaptureSource::LibsslUprobe
        && bytes.provider == CaptureProviderKind::Plaintext
        && bytes.direction == Direction::Outbound
        && bytes.flow.remote.port == listen_port
        && bytes.flow.attribution_confidence == DIRECT_FLOW_CONFIDENCE
        && bytes
            .bytes
            .as_ref()
            .windows("POST /sssa-e2e/0".len())
            .any(|window| window == b"POST /sssa-e2e/0")
}

fn provider_event_summary(events: &[CaptureEvent], listen_port: u16) -> String {
    let summaries = events
        .iter()
        .filter_map(|event| event_summary(event, listen_port))
        .take(16)
        .collect::<Vec<_>>();
    if !summaries.is_empty() {
        return summaries.join("; ");
    }
    let unrelated = events
        .iter()
        .filter_map(unrelated_event_summary)
        .take(16)
        .collect::<Vec<_>>();
    if unrelated.is_empty() {
        format!("no TLS plaintext provider events near port {listen_port}")
    } else {
        format!(
            "no TLS plaintext provider events near port {listen_port}; unrelated events: {}",
            unrelated.join("; ")
        )
    }
}

fn event_summary(event: &CaptureEvent, listen_port: u16) -> Option<String> {
    match event {
        CaptureEvent::Bytes(bytes)
            if bytes.flow.local.port == listen_port || bytes.flow.remote.port == listen_port =>
        {
            Some(format!(
                "bytes source={:?} provider={:?} direction={:?} local={}:{} remote={}:{} confidence={} len={} degraded={}",
                bytes.source,
                bytes.provider,
                bytes.direction,
                bytes.flow.local.address,
                bytes.flow.local.port,
                bytes.flow.remote.address,
                bytes.flow.remote.port,
                bytes.flow.attribution_confidence,
                bytes.bytes.len(),
                bytes.degraded
            ))
        }
        CaptureEvent::Gap(gap)
            if gap.flow.local.port == listen_port || gap.flow.remote.port == listen_port =>
        {
            Some(format!(
                "gap source={:?} provider={:?} direction={:?} local={}:{} remote={}:{} confidence={} reason={}",
                gap.source,
                gap.provider,
                gap.gap.direction,
                gap.flow.local.address,
                gap.flow.local.port,
                gap.flow.remote.address,
                gap.flow.remote.port,
                gap.flow.attribution_confidence,
                gap.gap.reason
            ))
        }
        _ => None,
    }
}

fn unrelated_event_summary(event: &CaptureEvent) -> Option<String> {
    match event {
        CaptureEvent::Bytes(bytes) if bytes.source == CaptureSource::LibsslUprobe => Some(format!(
            "bytes pid={} command={} direction={:?} confidence={} len={} degraded={} reason={}",
            bytes.flow.process.identity.pid,
            bytes.flow.process.name,
            bytes.direction,
            bytes.flow.attribution_confidence,
            bytes.bytes.len(),
            bytes.degraded,
            bytes.degradation_reason.as_deref().unwrap_or("")
        )),
        CaptureEvent::Gap(gap) if gap.source == CaptureSource::LibsslUprobe => Some(format!(
            "gap pid={} command={} direction={:?} confidence={} reason={}",
            gap.flow.process.identity.pid,
            gap.flow.process.name,
            gap.gap.direction,
            gap.flow.attribution_confidence,
            gap.gap.reason
        )),
        _ => None,
    }
}

fn merge_provider_results(
    provider_result: Result<(), Box<dyn std::error::Error>>,
    fixture_result: Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let errors = [("provider", provider_result), ("fixture", fixture_result)]
        .into_iter()
        .filter_map(|(label, result)| result.err().map(|error| format!("{label} failed: {error}")))
        .collect::<Vec<_>>();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(e2e_error(errors.join("; ")).into())
    }
}

struct LoopbackFlowResolver {
    fixture_pid: u32,
    start_time_ticks: u64,
    listen_port: u16,
}

impl LibsslUprobeFlowResolver for LoopbackFlowResolver {
    fn resolve_libssl_uprobe_flow(
        &mut self,
        lookup: LibsslUprobeFlowLookup,
    ) -> Result<Option<LibsslResolvedFlow>, CaptureError> {
        if lookup.fd.is_none() {
            return Err(CaptureError::provider(
                "e2e_tls_plaintext_provider",
                "expected libssl uprobe sample to include the socket fd",
            ));
        }
        let direction = lookup.direction;
        Ok(Some(LibsslResolvedFlow {
            process: self.process(&lookup),
            confidence: DIRECT_FLOW_CONFIDENCE,
            connection: self.connection(direction),
            start_monotonic_ns: 1,
        }))
    }
}

impl LoopbackFlowResolver {
    fn process(&self, lookup: &LibsslUprobeFlowLookup) -> ProcessContext {
        ProcessContext {
            identity: ProcessIdentity {
                pid: self.fixture_pid,
                tgid: lookup.tgid,
                start_time_ticks: self.start_time_ticks,
                boot_id: "e2e".to_string(),
                exe_path: "sssa-e2e-fixture".to_string(),
                cmdline_hash: "e2e".to_string(),
                uid: 0,
                gid: 0,
                cgroup: None,
                systemd_service: None,
                container_id: None,
                runtime_hint: None,
            },
            name: "sssa-e2e-fixture".to_string(),
            cmdline: vec!["sssa-e2e-fixture".to_string()],
        }
    }

    fn connection(&self, direction: Direction) -> TcpConnection {
        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let client = TcpEndpoint::new(loopback, 40_000);
        let server = TcpEndpoint::new(loopback, self.listen_port);
        match direction {
            Direction::Outbound => TcpConnection::new(client, server),
            Direction::Inbound => TcpConnection::new(server, client),
        }
    }
}
