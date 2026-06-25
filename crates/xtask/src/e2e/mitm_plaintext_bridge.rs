use std::{
    collections::BTreeSet,
    env, fs,
    fs::OpenOptions,
    io::Write,
    net::TcpListener,
    path::Path,
    process::{Command, ExitCode},
};

use capture::{CaptureEvent, CapturedBytes, EnforcementEvidencePropagation};
use probe_config::{
    AgentConfig, CaptureSelection, PolicyConfig, TlsMaterialConfig, TlsMaterialKind,
    TransparentInterceptionMitmBackendConfig, TransparentInterceptionMitmPlaintextBridgeModeConfig,
    TransparentInterceptionProxyModeConfig, TransparentInterceptionStrategyConfig,
};
use probe_core::{
    AddressPort, CaptureOrigin, CaptureProviderKind, CaptureSource, Direction, EnforcementEvidence,
    EnforcementMode, EventEnvelope, EventKind, FlowContext, FlowIdentity, ProcessContext,
    ProcessIdentity, ProcessSelector, Selector, Timestamp, TrafficSelector, TransportProtocol,
};
use storage::{FjallSpool, StoredEvent};

use super::{
    harness::{
        ChildSupervisor, UnixSocketReadySignal, create_temp_root, decode_capture_event,
        decode_envelope, e2e_error, ensure_e2e_packages_built,
        reexec_current_case_in_fresh_network_namespace, stop_running_child, trusted_system_command,
        verify_fresh_network_namespace,
    },
    loopback::{
        Http1LoopbackFixtureConfig, PlainHttp1LoopbackFixtureConfig,
        assert_no_policy_runtime_errors, merge_labeled_run_results, spawn_agent,
        spawn_http1_loopback_fixture, start_http1_loopback_fixture, wait_for_agent_policy_progress,
        wait_for_agent_ready, wait_for_http1_loopback_fixture_exit,
        wait_for_http1_loopback_fixture_ready,
    },
};

const CASE_NAME: &str = "e2e-mitm-plaintext-bridge-live-sidecar";
const IN_NETNS_ENV: &str = "SSSA_PROBE_E2E_MITM_PLAINTEXT_BRIDGE_NETNS";
const AGENT_ID: &str = "e2e-mitm-bridge-agent";
const CONFIG_VERSION: &str = CASE_NAME;
const E2E_EXPORT_CURSOR_OWNER: &str = "e2e-mitm-bridge";
const INTERFACE: &str = "any";
const POLICY_ID: &str = "mitm-bridge-e2e-policy";
const POLICY_VERSION: &str = "e2e";
const EXPECTED_POLICY_VERSION: &str = "mitm-bridge-e2e-policy@e2e";
const POLICY_ALERT_PREFIX: &str = "mitm bridge policy observed ";
const REQUESTS: usize = 1;
const REQUEST_BODY_BYTES: usize = 64;
const RESPONSE_BODY_BYTES: usize = 32;
const WRITE_CHUNKS: usize = 2;
const BRIDGE_FLOW_ID: &str = "external_mitm_bridge:e2e-flow";
const BRIDGE_REQUEST_TARGET: &str = "/mitm-bridge/e2e";
const BRIDGE_REQUEST: &[u8] =
    b"GET /mitm-bridge/e2e HTTP/1.1\r\nHost: mitm-bridge.e2e.test\r\n\r\n";
const DEFAULT_INTERCEPT_PORT: u16 = 65_529;

pub(crate) fn run() -> ExitCode {
    match run_outer() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("e2e MITM plaintext bridge live sidecar failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_outer() -> Result<(), Box<dyn std::error::Error>> {
    if env::var_os(IN_NETNS_ENV).is_some() {
        require_root()?;
        verify_fresh_network_namespace(IN_NETNS_ENV)?;
        bring_loopback_up()?;
        return run_inner();
    }

    ensure_e2e_packages_built(["agent", "e2e-fixture"])?;
    require_root()?;
    reexec_current_case_in_fresh_network_namespace(
        IN_NETNS_ENV,
        CASE_NAME,
        "network-namespace MITM plaintext bridge e2e",
    )
}

fn run_inner() -> Result<(), Box<dyn std::error::Error>> {
    let root = create_temp_root("mitm-plaintext-bridge-live-sidecar")?;
    match run_at(&root) {
        Ok(()) => {
            fs::remove_dir_all(&root)?;
            println!("e2e MITM plaintext bridge live sidecar passed");
            Ok(())
        }
        Err(error) => {
            eprintln!("e2e artifacts retained at {}", root.display());
            Err(error)
        }
    }
}

fn run_at(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(root)?;
    let fixture_ready_path = root.join("fixture.ready");
    let fixture_start_path = root.join("fixture.start");
    let agent_ready_socket_path = root.join("agent.ready.sock");
    let admin_socket_path = root.join("admin.sock");
    let policy_path = root.join("mitm-bridge-e2e-policy.bundle");
    let bridge_feed_path = root.join("mitm-bridge-capture-events.jsonl");
    let config_path = root.join("agent.toml");
    let spool_path = root.join("spool");

    let mitm_backend = TcpListener::bind(("127.0.0.1", 0))?;
    let mitm_backend_addr = mitm_backend.local_addr()?;
    write_policy_bundle(&policy_path)?;
    create_empty_bridge_capture_event_feed(&bridge_feed_path)?;

    let supervisor = ChildSupervisor::new()?;
    let mut fixture = supervisor.watch(
        spawn_http1_loopback_fixture(&fixture_ready_path, &fixture_start_path, fixture_config())?,
        "fixture",
    );
    let fixture_ready =
        wait_for_http1_loopback_fixture_ready(fixture.child_mut(), &fixture_ready_path)?;
    let intercept_port =
        unused_intercept_port([mitm_backend_addr.port(), fixture_ready.listen_port]);
    write_agent_config(AgentConfigInputs {
        config_path: &config_path,
        policy_path: &policy_path,
        bridge_feed_path: &bridge_feed_path,
        spool_path: &spool_path,
        admin_socket_path: &admin_socket_path,
        capture_port: fixture_ready.listen_port,
        mitm_backend_target: mitm_backend_addr.to_string(),
        proxy_port: mitm_backend_addr.port(),
        intercept_port,
    })?;

    let mut ready_signal = UnixSocketReadySignal::bind(agent_ready_socket_path)?;
    let mut agent = supervisor.watch(spawn_agent(&config_path, &ready_signal)?, "agent");
    wait_for_agent_ready(agent.child_mut(), &mut ready_signal)?;
    start_http1_loopback_fixture(&fixture_start_path, &fixture_ready.start_nonce)?;
    let primary_progress_result = wait_for_agent_policy_progress(
        agent.child_mut(),
        &admin_socket_path,
        expected_libpcap_targets().len() as u64,
    );
    let append_bridge_result = match &primary_progress_result {
        Ok(()) => append_bridge_capture_event_feed(&bridge_feed_path),
        Err(_) => Ok(()),
    };
    let bridge_progress_result = match (&primary_progress_result, &append_bridge_result) {
        (Ok(()), Ok(())) => wait_for_agent_policy_progress(
            agent.child_mut(),
            &admin_socket_path,
            expected_policy_alert_messages().len() as u64,
        ),
        _ => Ok(()),
    };
    let fixture_result = wait_for_http1_loopback_fixture_exit(fixture.child_mut());
    fixture.unwatch();
    let agent_result = stop_running_child(agent.child_mut(), "agent");
    agent.unwatch();
    let spool_result = match (
        &fixture_result,
        &primary_progress_result,
        &append_bridge_result,
        &bridge_progress_result,
        &agent_result,
    ) {
        (Ok(()), Ok(()), Ok(()), Ok(()), Ok(())) => assert_spool_outputs(&spool_path),
        _ => Ok(()),
    };
    drop(mitm_backend);

    merge_labeled_run_results([
        ("fixture", fixture_result),
        ("agent primary policy progress", primary_progress_result),
        ("MITM bridge feed append", append_bridge_result),
        ("agent MITM bridge policy progress", bridge_progress_result),
        ("agent", agent_result),
        ("spool assertion", spool_result),
    ])
}

fn fixture_config() -> PlainHttp1LoopbackFixtureConfig {
    PlainHttp1LoopbackFixtureConfig {
        shared: Http1LoopbackFixtureConfig {
            listen_port: None,
            requests: REQUESTS,
            request_body_bytes: REQUEST_BODY_BYTES,
            response_body_bytes: RESPONSE_BODY_BYTES,
            write_chunks: WRITE_CHUNKS,
            connect_write_delay_ms: 0,
            post_exchange_delay_ms: 0,
        },
        accept_read_delay_ms: 0,
    }
}

struct AgentConfigInputs<'a> {
    config_path: &'a Path,
    policy_path: &'a Path,
    bridge_feed_path: &'a Path,
    spool_path: &'a Path,
    admin_socket_path: &'a Path,
    capture_port: u16,
    mitm_backend_target: String,
    proxy_port: u16,
    intercept_port: u16,
}

fn write_agent_config(inputs: AgentConfigInputs<'_>) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = AgentConfig {
        agent_id: AGENT_ID.to_string(),
        config_version: CONFIG_VERSION.to_string(),
        ..AgentConfig::default()
    };
    config.capture.selection = CaptureSelection::Libpcap;
    config.capture.libpcap.interface = Some(INTERFACE.to_string());
    config.capture.libpcap.bpf_filter = format!("tcp and port {}", inputs.capture_port);
    config.capture.libpcap.read_timeout_ms = 100;
    config.storage.path = inputs.spool_path.to_path_buf();
    config.export.worker.enabled = false;
    config.admin.enabled = true;
    config.admin.socket_path = inputs.admin_socket_path.to_path_buf();
    config.policies.push(PolicyConfig {
        id: POLICY_ID.to_string(),
        source: probe_config::PolicySourceConfig::LocalDirectory {
            path: inputs.policy_path.to_path_buf(),
        },
        enabled: true,
        selector: None,
    });
    config.enforcement.mode = EnforcementMode::Enforce;
    config.enforcement.interception.strategy =
        TransparentInterceptionStrategyConfig::InboundTproxyMitm;
    config.enforcement.interception.proxy.mode = TransparentInterceptionProxyModeConfig::External;
    config.enforcement.interception.proxy.listen_port = Some(inputs.proxy_port);
    config.enforcement.interception.selector = Some(Selector::term(
        ProcessSelector::default(),
        TrafficSelector {
            local_ports: vec![inputs.intercept_port],
            directions: vec![Direction::Inbound],
            ..TrafficSelector::default()
        },
    ));
    config.enforcement.interception.mitm.backend =
        TransparentInterceptionMitmBackendConfig::External;
    config
        .enforcement
        .interception
        .mitm
        .backend_readiness_probe
        .target = Some(inputs.mitm_backend_target);
    config.enforcement.interception.mitm.plaintext_bridge.mode =
        TransparentInterceptionMitmPlaintextBridgeModeConfig::CaptureEventFeed;
    config.enforcement.interception.mitm.plaintext_bridge.path =
        Some(inputs.bridge_feed_path.to_path_buf());
    config.enforcement.interception.mitm.plaintext_bridge.follow = Some(true);
    config.enforcement.interception.mitm.ca_certificate_ref = Some("mitm-ca".to_string());
    config.enforcement.interception.mitm.ca_private_key_ref = Some("mitm-ca-key".to_string());
    config.tls.materials = vec![
        TlsMaterialConfig {
            id: Some("mitm-ca".to_string()),
            kind: TlsMaterialKind::MitmCaCertificate,
            path: inputs.config_path.with_file_name("mitm-ca.pem"),
        },
        TlsMaterialConfig {
            id: Some("mitm-ca-key".to_string()),
            kind: TlsMaterialKind::MitmCaPrivateKey,
            path: inputs.config_path.with_file_name("mitm-ca.key"),
        },
    ];
    fs::write(inputs.config_path, toml::to_string(&config)?)?;
    Ok(())
}

fn write_policy_bundle(path: &Path) -> Result<(), std::io::Error> {
    fs::create_dir_all(path)?;
    fs::write(
        path.join("manifest.toml"),
        format!(
            r#"
id = "{POLICY_ID}"
version = "{POLICY_VERSION}"
hooks = ["on_http_request_headers"]
"#
        ),
    )?;
    fs::write(
        path.join("main.lua"),
        format!(
            r#"
function on_http_request_headers(event)
  return probe.emit_alert("{POLICY_ALERT_PREFIX}" .. event.kind.target)
end
"#,
        ),
    )
}

fn create_empty_bridge_capture_event_feed(path: &Path) -> Result<(), std::io::Error> {
    OpenOptions::new().write(true).create_new(true).open(path)?;
    Ok(())
}

fn append_bridge_capture_event_feed(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut content = String::new();
    for event in bridge_capture_events() {
        content.push_str(&serde_json::to_string(&event)?);
        content.push('\n');
    }
    let mut file = OpenOptions::new().append(true).open(path)?;
    file.write_all(content.as_bytes())?;
    file.flush()?;
    Ok(())
}

fn bridge_capture_events() -> [CaptureEvent; 3] {
    let flow = bridge_flow();
    [
        CaptureEvent::ConnectionOpened {
            timestamp: timestamp(1),
            flow: flow.clone(),
            origin: bridge_origin(),
        },
        CaptureEvent::Bytes(CapturedBytes {
            timestamp: timestamp(2),
            flow: flow.clone(),
            origin: bridge_origin(),
            direction: Direction::Outbound,
            stream_offset: 0,
            bytes: BRIDGE_REQUEST.to_vec().into(),
            attribution_confidence: 100,
            degraded: false,
            degradation_reason: None,
            enforcement_evidence: EnforcementEvidence::default(),
            enforcement_evidence_propagation: EnforcementEvidencePropagation::Event,
        }),
        CaptureEvent::ConnectionClosed {
            timestamp: timestamp(3),
            flow,
            origin: bridge_origin(),
        },
    ]
}

fn bridge_flow() -> FlowContext {
    let process = ProcessContext {
        identity: ProcessIdentity {
            pid: 44_001,
            tgid: 44_001,
            start_time_ticks: 90_001,
            boot_id: "e2e-boot".to_string(),
            exe_path: "/usr/bin/sssa-e2e-mitm-bridge".to_string(),
            cmdline_hash: "mitm-bridge-cmdline-hash".to_string(),
            uid: 1000,
            gid: 1000,
            cgroup: None,
            systemd_service: None,
            container_id: None,
            runtime_hint: None,
        },
        name: "sssa-e2e-mitm-bridge".to_string(),
        cmdline: vec!["sssa-e2e-mitm-bridge".to_string()],
    };
    FlowContext {
        id: FlowIdentity(BRIDGE_FLOW_ID.to_string()),
        process,
        local: AddressPort {
            address: "127.0.0.1".to_string(),
            port: 51_801,
        },
        remote: AddressPort {
            address: "127.0.0.1".to_string(),
            port: 443,
        },
        protocol: TransportProtocol::Tcp,
        start_monotonic_ns: 1,
        socket_cookie: Some(918_001),
        attribution_confidence: 100,
    }
}

fn bridge_origin() -> CaptureOrigin {
    CaptureOrigin::from_source(CaptureSource::ExternalPlaintextFeed)
}

fn timestamp(monotonic_ns: u64) -> Timestamp {
    Timestamp {
        monotonic_ns,
        wall_time_unix_ns: i64::try_from(monotonic_ns).unwrap_or(i64::MAX),
    }
}

fn assert_spool_outputs(spool_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let spool = FjallSpool::open(spool_path)?;
    let ingress = spool.read_ingress_batch_after(0, 512)?;
    if ingress.is_empty() {
        return Err(e2e_error("expected MITM bridge ingress records, got none").into());
    }
    assert_livestream_ingress(&ingress)?;

    let envelopes = spool
        .read_export_batch(E2E_EXPORT_CURSOR_OWNER, 512)?
        .iter()
        .map(decode_envelope)
        .collect::<Result<Vec<_>, _>>()?;
    assert_no_policy_runtime_errors(&envelopes)?;
    assert_expected_bridge_export(&envelopes)?;
    assert_expected_libpcap_export(&envelopes)?;
    assert_expected_libpcap_policy_alerts(&envelopes)?;

    println!(
        "e2e MITM plaintext bridge live sidecar observed {} ingress records and {} export records",
        ingress.len(),
        envelopes.len()
    );
    Ok(())
}

fn assert_livestream_ingress(events: &[StoredEvent]) -> Result<(), Box<dyn std::error::Error>> {
    let capture_events = events
        .iter()
        .map(decode_capture_event)
        .collect::<Result<Vec<_>, _>>()?;
    if !capture_events.iter().any(is_bridge_ingress_bytes) {
        return Err(e2e_error("missing MITM bridge capture-event feed ingress bytes").into());
    }
    if !capture_events.iter().any(|event| {
        matches!(
            event,
            CaptureEvent::Bytes(bytes)
                if bytes.origin.source() == CaptureSource::Libpcap
                    && bytes.origin.provider() == CaptureProviderKind::Libpcap
                    && bytes.degraded
        )
    }) {
        return Err(e2e_error("missing required libpcap primary ingress bytes").into());
    }
    Ok(())
}

fn is_bridge_ingress_bytes(event: &CaptureEvent) -> bool {
    matches!(
        event,
        CaptureEvent::Bytes(bytes)
            if bytes.origin.source() == CaptureSource::ExternalPlaintextFeed
                && bytes.origin.provider() == CaptureProviderKind::Plaintext
                && bytes.flow.id.0 == BRIDGE_FLOW_ID
                && bytes.bytes.as_ref() == BRIDGE_REQUEST
    )
}

fn assert_expected_bridge_export(
    envelopes: &[EventEnvelope],
) -> Result<(), Box<dyn std::error::Error>> {
    let request_found = envelopes.iter().any(|envelope| {
        is_bridge_flow(envelope)
            && matches!(
                envelope.kind(),
                EventKind::HttpRequestHeaders(headers)
                    if headers.method.as_deref() == Some("GET")
                        && headers.target.as_deref() == Some(BRIDGE_REQUEST_TARGET)
            )
    });
    if !request_found {
        return Err(e2e_error("missing MITM bridge parsed HTTP request").into());
    }

    let bridge_alert = expected_bridge_policy_alert_message();
    let alert_found = envelopes.iter().any(|envelope| {
        is_bridge_flow(envelope)
            && envelope.policy_version() == Some(EXPECTED_POLICY_VERSION)
            && matches!(
                envelope.kind(),
                EventKind::PolicyAlert(alert) if alert.message == bridge_alert
            )
    });
    if !alert_found {
        return Err(e2e_error("missing MITM bridge policy alert").into());
    }
    Ok(())
}

fn assert_expected_libpcap_export(
    envelopes: &[EventEnvelope],
) -> Result<(), Box<dyn std::error::Error>> {
    let observed = envelopes
        .iter()
        .filter_map(|envelope| match envelope.kind() {
            EventKind::HttpRequestHeaders(headers)
                if envelope.origin().source() == CaptureSource::Libpcap
                    && envelope.origin().provider() == CaptureProviderKind::Libpcap
                    && headers.direction == Direction::Outbound
                    && headers.method.as_deref() == Some("POST") =>
            {
                headers.target.clone()
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let expected = expected_libpcap_targets();
    if observed.is_superset(&expected) {
        return Ok(());
    }
    Err(e2e_error(format!(
        "missing libpcap primary HTTP request targets; expected at least {:?}, observed {:?}",
        expected, observed
    ))
    .into())
}

fn assert_expected_libpcap_policy_alerts(
    envelopes: &[EventEnvelope],
) -> Result<(), Box<dyn std::error::Error>> {
    let observed = envelopes
        .iter()
        .filter_map(|envelope| match envelope.kind() {
            EventKind::PolicyAlert(alert)
                if envelope.origin().source() == CaptureSource::Libpcap
                    && envelope.origin().provider() == CaptureProviderKind::Libpcap
                    && envelope.policy_version() == Some(EXPECTED_POLICY_VERSION) =>
            {
                Some(alert.message.clone())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let expected = expected_libpcap_targets()
        .into_iter()
        .map(expected_policy_alert_message)
        .collect::<BTreeSet<_>>();
    if observed.is_superset(&expected) {
        return Ok(());
    }
    Err(e2e_error(format!(
        "missing libpcap primary policy alerts; expected at least {:?}, observed {:?}",
        expected, observed
    ))
    .into())
}

fn is_bridge_flow(envelope: &EventEnvelope) -> bool {
    envelope.origin().source() == CaptureSource::ExternalPlaintextFeed
        && envelope.origin().provider() == CaptureProviderKind::Plaintext
        && envelope
            .flow()
            .is_some_and(|flow| flow.id.0 == BRIDGE_FLOW_ID)
}

fn expected_policy_alert_messages() -> BTreeSet<String> {
    expected_libpcap_targets()
        .into_iter()
        .map(expected_policy_alert_message)
        .chain([expected_bridge_policy_alert_message()])
        .collect()
}

fn expected_libpcap_targets() -> BTreeSet<String> {
    (0..REQUESTS)
        .map(|request| format!("/sssa-e2e/{request}"))
        .collect()
}

fn expected_policy_alert_message(target: String) -> String {
    format!("{POLICY_ALERT_PREFIX}{target}")
}

fn expected_bridge_policy_alert_message() -> String {
    format!("{POLICY_ALERT_PREFIX}{BRIDGE_REQUEST_TARGET}")
}

fn unused_intercept_port(used_ports: impl IntoIterator<Item = u16>) -> u16 {
    let used_ports = used_ports.into_iter().collect::<BTreeSet<_>>();
    for port in [DEFAULT_INTERCEPT_PORT, DEFAULT_INTERCEPT_PORT - 1] {
        if !used_ports.contains(&port) {
            return port;
        }
    }
    DEFAULT_INTERCEPT_PORT - 2
}

fn bring_loopback_up() -> Result<(), Box<dyn std::error::Error>> {
    ip(["link", "set", "lo", "up"])
}

fn ip(args: impl IntoIterator<Item = &'static str>) -> Result<(), Box<dyn std::error::Error>> {
    let command =
        trusted_system_command(["/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip", "/bin/ip"], "ip")?;
    let status = Command::new(command).args(args).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(e2e_error(format!("ip command exited with {status}")).into())
    }
}

fn require_root() -> Result<(), Box<dyn std::error::Error>> {
    if rustix::process::geteuid().as_raw() == 0 {
        Ok(())
    } else {
        Err(e2e_error("MITM plaintext bridge e2e must run as root").into())
    }
}
