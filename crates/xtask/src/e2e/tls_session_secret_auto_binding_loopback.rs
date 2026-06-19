use std::{
    collections::{BTreeSet, HashMap},
    fs,
    io::{Read, Write},
    net::{Ipv4Addr, Shutdown, TcpListener, TcpStream},
    path::Path,
    process::ExitCode,
    thread,
    time::Duration,
};

use capture::{
    CaptureEvent, CapturedBytes, EnforcementEvidencePropagation, Tls13ApplicationDataDecryptor,
    Tls13SessionSecretHandshakeObservationKind, Tls13SessionSecretHandshakeObserver,
    TlsSessionSecretStore,
};
use probe_config::{
    AgentConfig, CaptureSelection, PolicyConfig, TlsMaterialConfig, TlsMaterialKind,
};
use probe_core::{
    AddressPort, CaptureOrigin, CaptureProviderKind, CaptureSource, Direction, EventEnvelope,
    EventKind, FlowContext, FlowIdentity, ProcessContext, ProcessIdentity, Timestamp,
    TransportProtocol,
};
use storage::{FjallSpool, StoredEvent};

use super::{
    harness::{
        ChildSupervisor, UnixSocketReadySignal, create_temp_root, decode_capture_event,
        decode_envelope, e2e_error, ensure_e2e_packages_built, stop_running_child,
    },
    loopback::{
        assert_no_policy_runtime_errors, merge_labeled_run_results, spawn_agent,
        wait_for_agent_policy_progress, wait_for_agent_ready,
    },
};

const E2E_EXPORT_CURSOR_OWNER: &str = "e2e-tls-session-secret";
const INTERFACE: &str = "any";
const POLICY_ID: &str = "tls-session-secret-e2e-policy";
const POLICY_VERSION: &str = "e2e";
const SESSION_SECRET_ID: &str = "tls-session-secrets";
const EXPECTED_METHOD: &str = "GET";
const CLIENT_RANDOM_BYTES: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const SHA256_TRAFFIC_SECRET: &str =
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
const SYNTHETIC_APPLICATION_RECORD: &[u8] = &[
    0x17, 0x03, 0x03, 0x00, 0x35, 0x62, 0x4d, 0xb3, 0x1e, 0x84, 0x42, 0x03, 0xee, 0xd7, 0x0e, 0xd8,
    0x95, 0x90, 0x7c, 0x1d, 0xba, 0x83, 0xb7, 0x98, 0x3b, 0xed, 0x37, 0xe4, 0x48, 0xfe, 0xf6, 0x3e,
    0x37, 0xa1, 0x91, 0x8f, 0xb3, 0xd2, 0x3e, 0x8e, 0xc8, 0x69, 0x65, 0x62, 0xf3, 0x74, 0x4f, 0x95,
    0x45, 0x35, 0x57, 0xcf, 0xf5, 0xfe, 0xc8, 0x55, 0xa1, 0xfe,
];
const TLS13_VERSION: [u8; 2] = [0x03, 0x04];
const TLS_LEGACY_RECORD_VERSION: [u8; 2] = [0x03, 0x03];
const TLS_HANDSHAKE_CONTENT_TYPE: u8 = 0x16;
const TLS_CLIENT_HELLO: u8 = 0x01;
const TRAFFIC_DELAY: Duration = Duration::from_millis(25);

pub(crate) fn run() -> ExitCode {
    match run_inner() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("e2e TLS session-secret auto-binding loopback failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_inner() -> Result<(), Box<dyn std::error::Error>> {
    ensure_e2e_packages_built(["agent"])?;
    let root = create_temp_root("tls-session-secret-auto-binding-loopback")?;
    match run_at(&root) {
        Ok(()) => {
            fs::remove_dir_all(&root)?;
            println!("e2e TLS session-secret auto-binding loopback passed");
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
    let fixture = SyntheticTls13SessionSecretFixture;
    fixture.validate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let listen_port = listener.local_addr()?.port();
    let agent_ready_socket_path = root.join("agent.ready.sock");
    let admin_socket_path = root.join("admin.sock");
    let policy_path = root.join("tls-session-secret-e2e-policy.bundle");
    let config_path = root.join("agent.toml");
    let spool_path = root.join("spool");
    let session_secret_path = root.join("session-secrets.jsonl");

    let supervisor = ChildSupervisor::new()?;
    write_policy_bundle(&policy_path, fixture)?;
    write_session_secret_material(&session_secret_path, fixture)?;
    write_agent_config(
        &config_path,
        &policy_path,
        &spool_path,
        &admin_socket_path,
        &session_secret_path,
        listen_port,
    )?;

    let mut ready_signal = UnixSocketReadySignal::bind(agent_ready_socket_path)?;
    let mut agent = supervisor.watch(spawn_agent(&config_path, &ready_signal)?, "agent");
    wait_for_agent_ready(agent.child_mut(), &mut ready_signal)?;

    let traffic_result = run_synthetic_tls_traffic(listener, fixture);
    let progress_result = match &traffic_result {
        Ok(()) => wait_for_agent_policy_progress(agent.child_mut(), &admin_socket_path, 1),
        Err(_) => Ok(()),
    };
    let agent_result = stop_running_child(agent.child_mut(), "agent");
    agent.unwatch();
    let spool_result = match (&traffic_result, &agent_result) {
        (Ok(()), Ok(())) => assert_spool_outputs(&spool_path, fixture),
        _ => Ok(()),
    };

    merge_labeled_run_results([
        ("synthetic TLS traffic", traffic_result),
        ("agent policy progress", progress_result),
        ("agent", agent_result),
        ("spool assertion", spool_result),
    ])?;
    Ok(())
}

fn run_synthetic_tls_traffic(
    listener: TcpListener,
    fixture: SyntheticTls13SessionSecretFixture,
) -> Result<(), Box<dyn std::error::Error>> {
    let listen_addr = listener.local_addr()?;
    let server = thread::spawn(move || drain_server_connection(listener));
    let mut client = TcpStream::connect(listen_addr)?;
    client.set_nodelay(true)?;
    client.write_all(&fixture.client_hello_record())?;
    thread::sleep(TRAFFIC_DELAY);
    client.write_all(fixture.application_record())?;
    client.shutdown(Shutdown::Write)?;
    let server_result = server
        .join()
        .map_err(|_| e2e_error("synthetic TLS server thread panicked"))?;
    server_result?;
    Ok(())
}

fn drain_server_connection(listener: TcpListener) -> Result<(), std::io::Error> {
    let (mut stream, _) = listener.accept()?;
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes)?;
    Ok(())
}

fn write_policy_bundle(
    path: &Path,
    fixture: SyntheticTls13SessionSecretFixture,
) -> Result<(), std::io::Error> {
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
  local target = event.kind.target or ""
  if target == "{}" then
    return probe.emit_alert("tls session secret policy observed " .. target)
  end
end
"#,
            fixture.target()
        ),
    )
}

fn write_session_secret_material(
    path: &Path,
    fixture: SyntheticTls13SessionSecretFixture,
) -> Result<(), std::io::Error> {
    fs::write(path, fixture.session_secret_material_jsonl())
}

fn write_agent_config(
    path: &Path,
    policy_path: &Path,
    spool_path: &Path,
    admin_socket_path: &Path,
    session_secret_path: &Path,
    listen_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = AgentConfig {
        agent_id: "e2e-tls-session-secret-agent".to_string(),
        config_version: "e2e-tls-session-secret-auto-binding-loopback".to_string(),
        ..AgentConfig::default()
    };
    config.capture.selection = CaptureSelection::Libpcap;
    config.capture.libpcap.interface = Some(INTERFACE.to_string());
    config.capture.libpcap.bpf_filter = format!("tcp and port {listen_port}");
    config.capture.libpcap.read_timeout_ms = 100;
    config.storage.path = spool_path.to_path_buf();
    config.export.worker.enabled = false;
    config.admin.enabled = true;
    config.admin.socket_path = admin_socket_path.to_path_buf();
    config.tls.materials.push(TlsMaterialConfig {
        id: Some(SESSION_SECRET_ID.to_string()),
        kind: TlsMaterialKind::SessionSecretFile,
        path: session_secret_path.to_path_buf(),
    });
    config
        .tls
        .plaintext
        .decrypt_hints
        .session_secret_refs
        .push(SESSION_SECRET_ID.to_string());
    config.policies.push(PolicyConfig {
        id: POLICY_ID.to_string(),
        path: policy_path.to_path_buf(),
        enabled: true,
        selector: None,
    });
    fs::write(path, toml::to_string(&config)?)?;
    Ok(())
}

fn assert_spool_outputs(
    spool_path: &Path,
    fixture: SyntheticTls13SessionSecretFixture,
) -> Result<(), Box<dyn std::error::Error>> {
    let spool = FjallSpool::open(spool_path)?;
    let ingress = spool.read_ingress_batch_after(0, 256)?;
    if ingress.is_empty() {
        return Err(e2e_error("expected TLS session-secret ingress records, got none").into());
    }
    assert_ingress_contains_ciphertext_and_plaintext(&ingress, fixture)?;

    let envelopes = spool
        .read_export_batch(E2E_EXPORT_CURSOR_OWNER, 512)?
        .iter()
        .map(decode_envelope)
        .collect::<Result<Vec<_>, _>>()?;
    assert_no_policy_runtime_errors(&envelopes)?;
    assert_expected_request(&envelopes)?;
    assert_expected_policy_alert(&envelopes)?;

    println!(
        "e2e TLS session-secret auto-binding observed {} ingress records and {} export records",
        ingress.len(),
        envelopes.len()
    );
    Ok(())
}

fn assert_ingress_contains_ciphertext_and_plaintext(
    events: &[StoredEvent],
    fixture: SyntheticTls13SessionSecretFixture,
) -> Result<(), Box<dyn std::error::Error>> {
    let capture_events = events
        .iter()
        .map(decode_capture_event)
        .collect::<Result<Vec<_>, _>>()?;
    assert_libpcap_ciphertext_boundary(&capture_events, fixture)?;
    let has_tls_plaintext = capture_events
        .iter()
        .any(|event| is_expected_tls_session_secret_plaintext(event, fixture));
    if !has_tls_plaintext {
        return Err(e2e_error(format!(
            "missing decrypted TLS session-secret plaintext; observed {}",
            ingress_summary(&capture_events)
        ))
        .into());
    }
    Ok(())
}

fn assert_libpcap_ciphertext_boundary(
    events: &[CaptureEvent],
    fixture: SyntheticTls13SessionSecretFixture,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload_spans = outbound_libpcap_payload_spans(events);
    if payload_spans.is_empty() {
        return Err(e2e_error("missing live libpcap ciphertext ingress").into());
    }

    let client_hello = fixture.client_hello_record();
    if !payload_spans
        .iter()
        .any(|span| span.as_slice() == client_hello.as_slice())
    {
        return Err(e2e_error(format!(
            "missing pre-bind TLS ClientHello in live libpcap ingress; observed {}",
            ingress_summary(events)
        ))
        .into());
    }
    let unexpected = payload_spans
        .iter()
        .filter(|span| span.as_slice() != client_hello.as_slice())
        .map(Vec::len)
        .collect::<Vec<_>>();
    if !unexpected.is_empty() {
        return Err(e2e_error(format!(
            "unexpected outbound libpcap payload after TLS session-secret binding; non-ClientHello span lengths: {unexpected:?}",
        ))
        .into());
    }
    Ok(())
}

fn is_expected_tls_session_secret_plaintext(
    event: &CaptureEvent,
    fixture: SyntheticTls13SessionSecretFixture,
) -> bool {
    let CaptureEvent::Bytes(bytes) = event else {
        return false;
    };
    bytes.origin.source() == CaptureSource::TlsSessionSecret
        && bytes.origin.provider() == CaptureProviderKind::Plaintext
        && bytes.direction == Direction::Outbound
        && bytes.degraded
        && {
            let expected = fixture.expected_plaintext();
            bytes
                .bytes
                .as_ref()
                .windows(expected.len())
                .any(|window| window == expected.as_slice())
        }
}

fn assert_expected_request(envelopes: &[EventEnvelope]) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = SyntheticTls13SessionSecretFixture;
    let observed = envelopes
        .iter()
        .filter_map(|envelope| match envelope.kind() {
            EventKind::HttpRequestHeaders(headers)
                if envelope.origin().source() == CaptureSource::TlsSessionSecret
                    && envelope.origin().provider() == CaptureProviderKind::Plaintext
                    && envelope.degraded()
                    && headers.direction == Direction::Outbound
                    && headers.method.as_deref() == Some(EXPECTED_METHOD) =>
            {
                headers.target.clone()
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    if observed.contains(fixture.target()) {
        return Ok(());
    }

    Err(e2e_error(format!(
        "missing TLS session-secret HTTP request target {}; observed {observed:?}",
        fixture.target()
    ))
    .into())
}

fn assert_expected_policy_alert(
    envelopes: &[EventEnvelope],
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = SyntheticTls13SessionSecretFixture;
    let expected_policy_version = format!("{POLICY_ID}@{POLICY_VERSION}");
    let observed = envelopes
        .iter()
        .filter_map(|envelope| match envelope.kind() {
            EventKind::PolicyAlert(alert)
                if envelope.origin().source() == CaptureSource::TlsSessionSecret
                    && envelope.origin().provider() == CaptureProviderKind::Plaintext
                    && envelope.degraded()
                    && envelope.policy_version() == Some(expected_policy_version.as_str()) =>
            {
                Some(alert.message.clone())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let expected = fixture.policy_alert();
    if observed.contains(expected.as_str()) {
        return Ok(());
    }

    Err(e2e_error(format!(
        "missing TLS session-secret policy alert {expected}; observed {observed:?}"
    ))
    .into())
}

fn tls_handshake_record(handshake_type: u8, body: Vec<u8>) -> Vec<u8> {
    let mut handshake = vec![
        handshake_type,
        ((body.len() >> 16) & 0xff) as u8,
        ((body.len() >> 8) & 0xff) as u8,
        (body.len() & 0xff) as u8,
    ];
    handshake.extend_from_slice(&body);
    tls_record(
        TLS_HANDSHAKE_CONTENT_TYPE,
        TLS_LEGACY_RECORD_VERSION,
        handshake,
    )
}

fn tls_client_hello_body() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&CLIENT_RANDOM_BYTES);
    body.push(0);
    body.extend_from_slice(&2_u16.to_be_bytes());
    body.extend_from_slice(&TLS_AES_128_GCM_SHA256.to_be_bytes());
    body.extend_from_slice(&[1, 0]);
    let extensions = supported_versions_client_extension();
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    body
}

fn supported_versions_client_extension() -> Vec<u8> {
    vec![
        0x00,
        0x2b,
        0x00,
        0x03,
        0x02,
        TLS13_VERSION[0],
        TLS13_VERSION[1],
    ]
}

fn tls_record(content_type: u8, version: [u8; 2], payload: Vec<u8>) -> Vec<u8> {
    let mut record = vec![
        content_type,
        version[0],
        version[1],
        ((payload.len() >> 8) & 0xff) as u8,
        (payload.len() & 0xff) as u8,
    ];
    record.extend_from_slice(&payload);
    record
}

fn outbound_libpcap_payload_spans(events: &[CaptureEvent]) -> Vec<Vec<u8>> {
    let mut by_flow = HashMap::<&str, Vec<(u64, &[u8])>>::new();
    for event in events {
        let CaptureEvent::Bytes(bytes) = event else {
            continue;
        };
        if bytes.origin.source() == CaptureSource::Libpcap
            && bytes.origin.provider() == CaptureProviderKind::Libpcap
            && bytes.direction == Direction::Outbound
        {
            by_flow
                .entry(bytes.flow.id.0.as_str())
                .or_default()
                .push((bytes.stream_offset, bytes.bytes.as_ref()));
        }
    }

    by_flow
        .into_values()
        .flat_map(contiguous_payload_spans)
        .collect()
}

fn contiguous_payload_spans(mut chunks: Vec<(u64, &[u8])>) -> Vec<Vec<u8>> {
    chunks.sort_by_key(|(offset, _)| *offset);
    let mut spans = Vec::new();
    let mut current = Vec::new();
    let mut next_offset = None::<u64>;
    for (offset, bytes) in chunks {
        let end_offset = offset.saturating_add(bytes.len() as u64);
        match next_offset {
            None => {
                current.extend_from_slice(bytes);
                next_offset = Some(end_offset);
            }
            Some(next) if offset > next => {
                if !current.is_empty() {
                    spans.push(std::mem::take(&mut current));
                }
                current.extend_from_slice(bytes);
                next_offset = Some(end_offset);
            }
            Some(next) if offset < next => {
                let overlap = (next - offset) as usize;
                if overlap < bytes.len() {
                    current.extend_from_slice(&bytes[overlap..]);
                    next_offset = Some(end_offset);
                }
            }
            Some(_) => {
                current.extend_from_slice(bytes);
                next_offset = Some(end_offset);
            }
        }
    }
    if !current.is_empty() {
        spans.push(current);
    }
    spans
}

fn ingress_summary(events: &[CaptureEvent]) -> String {
    let summaries = events
        .iter()
        .filter_map(event_summary)
        .take(16)
        .collect::<Vec<_>>();
    if summaries.is_empty() {
        "no relevant ingress events".to_string()
    } else {
        summaries.join("; ")
    }
}

fn event_summary(event: &CaptureEvent) -> Option<String> {
    match event {
        CaptureEvent::Bytes(bytes)
            if matches!(
                bytes.origin.source(),
                CaptureSource::Libpcap | CaptureSource::TlsSessionSecret
            ) =>
        {
            Some(format!(
                "bytes source={:?} provider={:?} direction={:?} len={} degraded={}",
                bytes.origin.source(),
                bytes.origin.provider(),
                bytes.direction,
                bytes.bytes.len(),
                bytes.degraded
            ))
        }
        CaptureEvent::Gap(gap)
            if matches!(
                gap.origin.source(),
                CaptureSource::Libpcap | CaptureSource::TlsSessionSecret
            ) =>
        {
            Some(format!(
                "gap source={:?} provider={:?} direction={:?} reason={}",
                gap.origin.source(),
                gap.origin.provider(),
                gap.gap.direction,
                gap.gap.reason
            ))
        }
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SyntheticTls13SessionSecretFixture;

impl SyntheticTls13SessionSecretFixture {
    fn validate(self) -> Result<(), Box<dyn std::error::Error>> {
        let material = self.session_secret_material_jsonl();
        let store = TlsSessionSecretStore::parse(material.as_bytes())?;
        let record = store
            .records()
            .first()
            .ok_or_else(|| e2e_error("synthetic TLS fixture material is empty"))?;
        if record.client_random().as_bytes() != &CLIENT_RANDOM_BYTES {
            return Err(e2e_error("synthetic TLS fixture material client_random drifted").into());
        }
        self.validate_client_hello_random()?;
        let mut decryptor = Tls13ApplicationDataDecryptor::from_session_secret_record(record)?;
        let decrypted = decryptor.decrypt_next_record(self.application_record())?;
        let expected_plaintext = self.expected_plaintext();
        if !decrypted.content_type().is_application_data()
            || decrypted.plaintext() != expected_plaintext.as_slice()
        {
            return Err(e2e_error(
                "synthetic TLS fixture record does not match expected plaintext",
            )
            .into());
        }
        Ok(())
    }

    fn validate_client_hello_random(self) -> Result<(), Box<dyn std::error::Error>> {
        let mut observer = Tls13SessionSecretHandshakeObserver::new();
        let observations = observer.push_capture_event(&CaptureEvent::Bytes(self.client_hello()));
        let [observation] = observations.as_slice() else {
            return Err(e2e_error(
                "synthetic TLS fixture ClientHello did not produce exactly one observation",
            )
            .into());
        };
        let Tls13SessionSecretHandshakeObservationKind::ClientHello { client_random } =
            observation.kind()
        else {
            return Err(e2e_error(
                "synthetic TLS fixture did not produce a ClientHello observation",
            )
            .into());
        };
        if client_random.as_bytes() == &CLIENT_RANDOM_BYTES {
            Ok(())
        } else {
            Err(e2e_error("synthetic TLS fixture ClientHello client_random drifted").into())
        }
    }

    fn client_hello(self) -> CapturedBytes {
        CapturedBytes {
            timestamp: Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            flow: synthetic_flow(),
            origin: CaptureOrigin::from_source(CaptureSource::Libpcap),
            direction: Direction::Outbound,
            stream_offset: 0,
            bytes: self.client_hello_record().into(),
            attribution_confidence: 100,
            degraded: true,
            degradation_reason: Some("synthetic TLS fixture".to_string()),
            enforcement_evidence: Default::default(),
            enforcement_evidence_propagation: EnforcementEvidencePropagation::Event,
        }
    }

    fn session_secret_material_jsonl(self) -> String {
        let client_random = hex_encode(&CLIENT_RANDOM_BYTES);
        let cipher_suite = format!("0x{TLS_AES_128_GCM_SHA256:04x}");
        format!(
            r#"{{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"{client_random}","cipher_suite":"{cipher_suite}","secret":"{SHA256_TRAFFIC_SECRET}"}}
"#
        )
    }

    fn client_hello_record(self) -> Vec<u8> {
        tls_handshake_record(TLS_CLIENT_HELLO, tls_client_hello_body())
    }

    fn application_record(self) -> &'static [u8] {
        SYNTHETIC_APPLICATION_RECORD
    }

    fn expected_plaintext(self) -> Vec<u8> {
        format!(
            "{EXPECTED_METHOD} {} HTTP/1.1\r\nhost: e2e\r\n\r\n",
            self.target()
        )
        .into_bytes()
    }

    fn target(self) -> &'static str {
        "/tls13"
    }

    fn policy_alert(self) -> String {
        format!("tls session secret policy observed {}", self.target())
    }
}

fn synthetic_flow() -> FlowContext {
    let local = AddressPort {
        address: "127.0.0.1".to_string(),
        port: 40_000,
    };
    let remote = AddressPort {
        address: "127.0.0.1".to_string(),
        port: 443,
    };
    let process = ProcessIdentity {
        pid: 1,
        tgid: 1,
        start_time_ticks: 1,
        boot_id: "e2e".to_string(),
        exe_path: "synthetic-tls-fixture".to_string(),
        cmdline_hash: "synthetic".to_string(),
        uid: 0,
        gid: 0,
        cgroup: None,
        systemd_service: None,
        container_id: None,
        runtime_hint: None,
    };
    FlowContext {
        id: FlowIdentity::stable(&process, &local, &remote, TransportProtocol::Tcp, 1, None),
        process: ProcessContext {
            identity: process,
            name: "synthetic-tls-fixture".to_string(),
            cmdline: vec!["synthetic-tls-fixture".to_string()],
        },
        local,
        remote,
        protocol: TransportProtocol::Tcp,
        start_monotonic_ns: 1,
        socket_cookie: None,
        attribution_confidence: 100,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}
