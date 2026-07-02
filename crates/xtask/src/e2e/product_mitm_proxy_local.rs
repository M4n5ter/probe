use std::{
    collections::HashMap,
    fs,
    io::{Read, Write},
    net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, ExitCode, Stdio},
    sync::Arc,
    time::Duration,
};

use capture::CaptureEvent;
use probe_config::{AgentConfig, CaptureSelection};
use probe_core::{CaptureProviderKind, CaptureSource, Direction, EventEnvelope, EventKind};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, StreamOwned,
    pki_types::{CertificateDer, ServerName},
};
use storage::FjallSpool;

use super::harness::{
    ChildSupervisor, HttpSourceServer, TlsHttpSourceServer, TlsServerMaterial, debug_binary,
    decode_capture_event, decode_envelope, e2e_error, ensure_e2e_packages_built,
    run_agent_with_max_events, run_in_own_process_group, run_with_temp_root,
    wait_for_file_or_child_exit, write_tls_server_material,
};
use super::plaintext_assertions::has_header;

const AGENT_ID: &str = "e2e-product-mitm-proxy-local-agent";
const CONFIG_VERSION: &str = "e2e-product-mitm-proxy-local";
const E2E_EXPORT_CURSOR_OWNER: &str = "e2e-product-mitm-proxy-local";
const HOST: &str = "product-mitm-local.e2e.test";
const PLAIN_TARGET: &str = "/product-mitm-local/plain";
const TLS_TARGET: &str = "/product-mitm-local/tls";
const AUTO_PLAIN_HOST: &str = "plain.product-mitm-local.e2e.test";
const AUTO_TLS_HOST: &str = "tls.product-mitm-local.e2e.test";
const AUTO_PLAIN_TARGET: &str = "/product-mitm-local/auto/plain";
const AUTO_TLS_TARGET: &str = "/product-mitm-local/auto/tls";
const PLAIN_BODY: &str = "plain product MITM local response";
const TLS_BODY: &str = "tls product MITM local response";
const TEXT_PLAIN_CONTENT_TYPE: &str = "text/plain";
const AUTO_PLAINTEXT_CONTENT_TYPE: &str = "text/probe-auto-plain";
const AUTO_TLS_CONTENT_TYPE: &str = "text/probe-auto-tls";
const AUTO_PLAIN_BODY: &str = "auto plaintext product MITM response";
const AUTO_TLS_BODY: &str = "auto tls product MITM response";
const READY_TIMEOUT: Duration = Duration::from_secs(10);
const IO_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DownstreamMode {
    Plaintext,
    Tls,
}

struct ScenarioOutput {
    feed_events: usize,
    export_events: usize,
}

struct MitmCaMaterial {
    certificate_path: PathBuf,
    private_key_path: PathBuf,
    certificate_der: CertificateDer<'static>,
}

#[derive(Clone, Copy)]
struct HttpExpectation {
    label: &'static str,
    target: &'static str,
    response_content_type: &'static str,
    body: &'static str,
}

type ByteChunk<'a> = (u64, &'a [u8]);
type FeedStreams<'a> = HashMap<String, Vec<ByteChunk<'a>>>;
type HttpBodyStreamKey = (String, u64);
type HttpBodyStreams<'a> = HashMap<HttpBodyStreamKey, Vec<ByteChunk<'a>>>;

pub(crate) fn run() -> ExitCode {
    match run_inner() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("e2e product MITM proxy local failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_inner() -> Result<(), Box<dyn std::error::Error>> {
    ensure_e2e_packages_built(["agent", "mitm-proxy"])?;
    run_with_temp_root("product-mitm-proxy-local", run_at)?;
    println!("e2e product MITM proxy local passed");
    Ok(())
}

fn run_at(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(root)?;
    let plaintext = run_scenario(root, DownstreamMode::Plaintext)?;
    let tls = run_scenario(root, DownstreamMode::Tls)?;
    let auto = run_auto_upstream_tls_scenario(root)?;
    println!(
        "e2e product MITM proxy local observed plaintext feed={} export={}, tls feed={} export={}, auto mixed feed={} export={}",
        plaintext.feed_events,
        plaintext.export_events,
        tls.feed_events,
        tls.export_events,
        auto.feed_events,
        auto.export_events
    );
    Ok(())
}

fn run_scenario(
    root: &Path,
    mode: DownstreamMode,
) -> Result<ScenarioOutput, Box<dyn std::error::Error>> {
    let scenario_root = root.join(mode.directory_name());
    fs::create_dir_all(&scenario_root)?;
    let feed_path = scenario_root.join("mitm-feed.jsonl");
    let config_path = scenario_root.join("agent.toml");
    let spool_path = scenario_root.join("spool");
    let pid_file = scenario_root.join("mitm-proxy.pid");

    let upstream = HttpSourceServer::spawn(
        mode.target(),
        TEXT_PLAIN_CONTENT_TYPE,
        mode.body().to_string(),
    )?;
    let proxy_listen = SocketAddr::from((Ipv4Addr::LOCALHOST, unused_loopback_port()?));
    let mitm_ca = matches!(mode, DownstreamMode::Tls)
        .then(|| write_mitm_ca(&scenario_root))
        .transpose()?;

    let supervisor = ChildSupervisor::new()?;
    let mut proxy = supervisor.watch(
        spawn_product_proxy(
            proxy_listen,
            upstream.listen_port(),
            &feed_path,
            &pid_file,
            mitm_ca.as_ref(),
        )?,
        "product MITM proxy",
    );
    wait_for_file_or_child_exit(
        proxy.child_mut(),
        &pid_file,
        READY_TIMEOUT,
        "product MITM proxy pid",
    )?;
    let response = exercise_proxy(mode, proxy_listen, mitm_ca.as_ref())?;
    assert_http_response(mode, &response)?;
    let upstream_requests = upstream.finish()?;
    if upstream_requests != 1 {
        return Err(e2e_error(format!(
            "{} upstream observed {upstream_requests} request(s), expected one",
            mode.label()
        ))
        .into());
    }
    drop(proxy);

    let feed_events = read_feed_events(&feed_path)?;
    assert_proxy_feed(mode, &feed_events)?;
    write_agent_config(&config_path, &feed_path, &spool_path)?;
    run_agent_with_max_events(&config_path, feed_events.len())?;
    let export_events = assert_agent_spool(mode, &spool_path, feed_events.len())?;
    Ok(ScenarioOutput {
        feed_events: feed_events.len(),
        export_events,
    })
}

fn run_auto_upstream_tls_scenario(
    root: &Path,
) -> Result<ScenarioOutput, Box<dyn std::error::Error>> {
    let scenario_root = root.join("auto-upstream-tls");
    fs::create_dir_all(&scenario_root)?;
    let feed_path = scenario_root.join("mitm-feed.jsonl");
    let config_path = scenario_root.join("agent.toml");
    let spool_path = scenario_root.join("spool");
    let pid_file = scenario_root.join("mitm-proxy.pid");

    let plain = HttpSourceServer::spawn(
        AUTO_PLAIN_TARGET,
        AUTO_PLAINTEXT_CONTENT_TYPE,
        AUTO_PLAIN_BODY.to_string(),
    )?;
    let tls_material = write_tls_server_material(&scenario_root, AUTO_TLS_HOST)?;
    let tls = TlsHttpSourceServer::spawn(
        AUTO_TLS_TARGET,
        AUTO_TLS_CONTENT_TYPE,
        AUTO_TLS_BODY,
        &tls_material,
    )?;
    let proxy_listen = SocketAddr::from((Ipv4Addr::LOCALHOST, unused_loopback_port()?));
    let mitm_ca = write_mitm_ca(&scenario_root)?;

    let supervisor = ChildSupervisor::new()?;
    let mut proxy = supervisor.watch(
        spawn_auto_product_proxy(
            proxy_listen,
            &feed_path,
            &pid_file,
            &mitm_ca,
            &tls_material,
            plain.listen_port(),
            tls.listen_port(),
        )?,
        "product MITM proxy",
    );
    wait_for_file_or_child_exit(
        proxy.child_mut(),
        &pid_file,
        READY_TIMEOUT,
        "product MITM proxy pid",
    )?;

    let plain_response = send_plaintext_request(
        proxy_listen,
        &http_request_with_host(AUTO_PLAIN_TARGET, AUTO_PLAIN_HOST),
    )?;
    assert_http_response_bytes("auto plaintext", &plain_response, AUTO_PLAIN_BODY)?;
    let tls_response = send_tls_request_with_host(
        proxy_listen,
        mitm_ca.certificate_der.clone(),
        AUTO_TLS_HOST,
        &http_request_with_host(AUTO_TLS_TARGET, AUTO_TLS_HOST),
    )?;
    assert_http_response_bytes("auto TLS", &tls_response, AUTO_TLS_BODY)?;

    if plain.finish()? != 1 {
        return Err(
            e2e_error("auto plaintext upstream did not observe exactly one request").into(),
        );
    }
    tls.finish()?;
    drop(proxy);

    let feed_events = read_feed_events(&feed_path)?;
    let expectations = [
        HttpExpectation {
            label: "auto plaintext",
            target: AUTO_PLAIN_TARGET,
            response_content_type: AUTO_PLAINTEXT_CONTENT_TYPE,
            body: AUTO_PLAIN_BODY,
        },
        HttpExpectation {
            label: "auto TLS",
            target: AUTO_TLS_TARGET,
            response_content_type: AUTO_TLS_CONTENT_TYPE,
            body: AUTO_TLS_BODY,
        },
    ];
    assert_proxy_feed_expectations(&feed_events, &expectations)?;
    write_agent_config(&config_path, &feed_path, &spool_path)?;
    run_agent_with_max_events(&config_path, feed_events.len())?;
    let export_events = assert_agent_spool_expectations(
        "auto mixed",
        &spool_path,
        feed_events.len(),
        &expectations,
    )?;
    Ok(ScenarioOutput {
        feed_events: feed_events.len(),
        export_events,
    })
}

fn spawn_product_proxy(
    listen: SocketAddr,
    upstream_port: u16,
    feed_path: &Path,
    pid_file: &Path,
    mitm_ca: Option<&MitmCaMaterial>,
) -> Result<Child, Box<dyn std::error::Error>> {
    let mut command = Command::new(debug_binary("traffic-probe-mitm-proxy")?);
    let command = run_in_own_process_group(&mut command)
        .arg("--listen")
        .arg(listen.to_string())
        .arg("--feed")
        .arg(feed_path)
        .arg("--pid-file")
        .arg(pid_file)
        .arg("--upstream")
        .arg(SocketAddr::from((Ipv4Addr::LOCALHOST, upstream_port)).to_string())
        .arg("--request-direction")
        .arg("outbound")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if let Some(mitm_ca) = mitm_ca {
        command
            .arg("--tls-ca-certificate")
            .arg(&mitm_ca.certificate_path)
            .arg("--tls-ca-private-key")
            .arg(&mitm_ca.private_key_path)
            .arg("--tls-material-root")
            .arg(
                mitm_ca
                    .certificate_path
                    .parent()
                    .expect("MITM CA material has a parent"),
            );
    }
    Ok(command.spawn()?)
}

fn spawn_auto_product_proxy(
    listen: SocketAddr,
    feed_path: &Path,
    pid_file: &Path,
    mitm_ca: &MitmCaMaterial,
    upstream_tls: &TlsServerMaterial,
    plain_upstream_port: u16,
    tls_upstream_port: u16,
) -> Result<Child, Box<dyn std::error::Error>> {
    let mut command = Command::new(debug_binary("traffic-probe-mitm-proxy")?);
    let command = run_in_own_process_group(&mut command)
        .arg("--listen")
        .arg(listen.to_string())
        .arg("--feed")
        .arg(feed_path)
        .arg("--pid-file")
        .arg(pid_file)
        .arg("--request-direction")
        .arg("outbound")
        .arg("--upstream-tls-mode")
        .arg("auto")
        .arg("--upstream-route")
        .arg(format!("{AUTO_PLAIN_HOST}=127.0.0.1:{plain_upstream_port}"))
        .arg("--upstream-route")
        .arg(format!("{AUTO_TLS_HOST}=127.0.0.1:{tls_upstream_port}"))
        .arg("--tls-ca-certificate")
        .arg(&mitm_ca.certificate_path)
        .arg("--tls-ca-private-key")
        .arg(&mitm_ca.private_key_path)
        .arg("--tls-material-root")
        .arg(
            mitm_ca
                .certificate_path
                .parent()
                .expect("MITM CA material has a parent"),
        )
        .arg("--upstream-trust-anchor")
        .arg(&upstream_tls.certificate_path)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    Ok(command.spawn()?)
}

fn exercise_proxy(
    mode: DownstreamMode,
    proxy_listen: SocketAddr,
    mitm_ca: Option<&MitmCaMaterial>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let request = http_request(mode.target());
    match mode {
        DownstreamMode::Plaintext => send_plaintext_request(proxy_listen, &request),
        DownstreamMode::Tls => send_tls_request(
            proxy_listen,
            mitm_ca
                .ok_or_else(|| e2e_error("TLS scenario did not create MITM CA material"))?
                .certificate_der
                .clone(),
            &request,
        ),
    }
}

fn send_plaintext_request(
    proxy_listen: SocketAddr,
    request: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(proxy_listen)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    stream.write_all(request)?;
    stream.shutdown(Shutdown::Write)?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    Ok(response)
}

fn send_tls_request(
    proxy_listen: SocketAddr,
    trusted_certificate: CertificateDer<'static>,
    request: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    send_tls_request_with_host(proxy_listen, trusted_certificate, HOST, request)
}

fn send_tls_request_with_host(
    proxy_listen: SocketAddr,
    trusted_certificate: CertificateDer<'static>,
    server_name: &str,
    request: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut stream = tls_client_stream(proxy_listen, trusted_certificate, server_name)?;
    stream.write_all(request)?;
    stream.flush()?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    Ok(response)
}

fn tls_client_stream(
    proxy_listen: SocketAddr,
    trusted_certificate: CertificateDer<'static>,
    server_name: &str,
) -> Result<StreamOwned<ClientConnection, TcpStream>, Box<dyn std::error::Error>> {
    let mut roots = RootCertStore::empty();
    roots.add(trusted_certificate)?;
    let crypto_provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = ClientConfig::builder_with_provider(crypto_provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name = ServerName::try_from(server_name.to_string())?;
    let connection = ClientConnection::new(Arc::new(config), server_name)?;
    let stream = TcpStream::connect(proxy_listen)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    Ok(StreamOwned::new(connection, stream))
}

fn write_agent_config(
    path: &Path,
    feed_path: &Path,
    spool_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = AgentConfig {
        agent_id: AGENT_ID.to_string(),
        config_version: CONFIG_VERSION.to_string(),
        ..AgentConfig::default()
    };
    config.capture.selection = CaptureSelection::CaptureEventFeed;
    config.capture.capture_event_feed.path = Some(feed_path.to_path_buf());
    config.capture.capture_event_feed.follow = Some(false);
    config.storage.path = spool_path.to_path_buf();
    config.export.worker.enabled = false;
    fs::write(path, toml::to_string(&config)?)?;
    Ok(())
}

fn assert_proxy_feed(
    mode: DownstreamMode,
    events: &[CaptureEvent],
) -> Result<(), Box<dyn std::error::Error>> {
    assert_proxy_feed_expectations(events, &[mode.expectation()])
}

fn assert_proxy_feed_expectations(
    events: &[CaptureEvent],
    expectations: &[HttpExpectation],
) -> Result<(), Box<dyn std::error::Error>> {
    if events.len() < 4 {
        return Err(e2e_error(format!(
            "MITM proxy feed contained only {} event(s)",
            events.len()
        ))
        .into());
    }
    for expectation in expectations {
        if !l7_mitm_plaintext_stream_contains(
            events,
            Direction::Outbound,
            expectation.target.as_bytes(),
        ) {
            return Err(e2e_error(format!(
                "{} MITM proxy feed is missing outbound request plaintext",
                expectation.label
            ))
            .into());
        }
        if !l7_mitm_plaintext_stream_contains(
            events,
            Direction::Inbound,
            expectation.body.as_bytes(),
        ) {
            return Err(e2e_error(format!(
                "{} MITM proxy feed is missing inbound response plaintext",
                expectation.label
            ))
            .into());
        }
    }
    Ok(())
}

fn assert_agent_spool(
    mode: DownstreamMode,
    spool_path: &Path,
    expected_ingress_events: usize,
) -> Result<usize, Box<dyn std::error::Error>> {
    assert_agent_spool_expectations(
        mode.label(),
        spool_path,
        expected_ingress_events,
        &[mode.expectation()],
    )
}

fn assert_agent_spool_expectations(
    label: &str,
    spool_path: &Path,
    expected_ingress_events: usize,
    expectations: &[HttpExpectation],
) -> Result<usize, Box<dyn std::error::Error>> {
    let spool = FjallSpool::open(spool_path)?;
    let ingress = spool.read_ingress_batch_after(0, 128)?;
    if ingress.len() != expected_ingress_events {
        return Err(e2e_error(format!(
            "{label} agent stored {} ingress record(s), expected {expected_ingress_events}",
            ingress.len()
        ))
        .into());
    }
    let ingress_events = ingress
        .iter()
        .map(decode_capture_event)
        .collect::<Result<Vec<_>, _>>()?;
    assert_proxy_feed_expectations(&ingress_events, expectations)?;

    let envelopes = spool
        .read_export_batch(E2E_EXPORT_CURSOR_OWNER, 128)?
        .iter()
        .map(decode_envelope)
        .collect::<Result<Vec<_>, _>>()?;
    assert_parsed_http_expectations(label, &envelopes, expectations)?;
    Ok(envelopes.len())
}

fn assert_parsed_http_expectations(
    label: &str,
    envelopes: &[EventEnvelope],
    expectations: &[HttpExpectation],
) -> Result<(), Box<dyn std::error::Error>> {
    if !envelopes
        .iter()
        .all(|envelope| is_l7_mitm_origin(envelope.origin().source(), envelope.origin().provider()))
    {
        return Err(e2e_error(format!(
            "{label} agent export contained non-MITM plaintext origin"
        ))
        .into());
    }
    if envelopes
        .iter()
        .any(|envelope| matches!(envelope.kind(), EventKind::ProtocolError(_)))
    {
        return Err(e2e_error(format!("{label} agent export contained protocol error")).into());
    }
    for expectation in expectations {
        assert_parsed_http_expectation(envelopes, *expectation)?;
    }
    Ok(())
}

fn assert_parsed_http_expectation(
    envelopes: &[EventEnvelope],
    expectation: HttpExpectation,
) -> Result<(), Box<dyn std::error::Error>> {
    if !envelopes.iter().any(|envelope| {
        matches!(
            envelope.kind(),
            EventKind::HttpRequestHeaders(headers)
                if headers.direction == Direction::Outbound
                    && headers.method.as_deref() == Some("GET")
                    && headers.target.as_deref() == Some(expectation.target)
        )
    }) {
        return Err(e2e_error(format!(
            "{} agent export is missing parsed HTTP request headers",
            expectation.label
        ))
        .into());
    }
    if !envelopes.iter().any(|envelope| {
        matches!(
            envelope.kind(),
            EventKind::HttpResponseHeaders(headers)
                if headers.direction == Direction::Inbound
                    && headers.status == Some(200)
                    && has_header(
                        &headers.headers,
                        "content-type",
                        expectation.response_content_type
                    )
        )
    }) {
        return Err(e2e_error(format!(
            "{} agent export is missing parsed HTTP response headers",
            expectation.label
        ))
        .into());
    }
    if !http_body_stream_contains(envelopes, Direction::Inbound, expectation.body.as_bytes()) {
        return Err(e2e_error(format!(
            "{} agent export is missing parsed HTTP response body",
            expectation.label
        ))
        .into());
    }
    Ok(())
}

fn l7_mitm_plaintext_stream_contains(
    events: &[CaptureEvent],
    direction: Direction,
    expected: &[u8],
) -> bool {
    let mut streams: FeedStreams<'_> = HashMap::new();
    for event in events {
        let CaptureEvent::Bytes(bytes) = event else {
            continue;
        };
        if !is_l7_mitm_origin(bytes.origin.source(), bytes.origin.provider())
            || bytes.direction != direction
        {
            continue;
        }
        streams
            .entry(bytes.flow.id.0.clone())
            .or_default()
            .push((bytes.stream_offset, bytes.bytes.as_ref()));
    }
    streams
        .into_values()
        .any(|chunks| ordered_chunks_contain(chunks, expected))
}

fn http_body_stream_contains(
    envelopes: &[EventEnvelope],
    direction: Direction,
    expected: &[u8],
) -> bool {
    let mut streams: HttpBodyStreams<'_> = HashMap::new();
    for envelope in envelopes {
        let EventKind::HttpBodyChunk(chunk) = envelope.kind() else {
            continue;
        };
        if chunk.direction != direction {
            continue;
        }
        let Some(flow) = envelope.flow() else {
            continue;
        };
        streams
            .entry((flow.id.0.clone(), chunk.stream_sequence))
            .or_default()
            .push((chunk.offset, chunk.data.as_ref()));
    }
    streams
        .into_values()
        .any(|chunks| ordered_chunks_contain(chunks, expected))
}

fn ordered_chunks_contain(mut chunks: Vec<(u64, &[u8])>, expected: &[u8]) -> bool {
    if expected.is_empty() {
        return true;
    }
    chunks.sort_by_key(|(offset, _)| *offset);

    let mut assembled = Vec::new();
    let mut next_offset = None;
    for (offset, bytes) in chunks {
        let Some(end_offset) = offset.checked_add(bytes.len() as u64) else {
            assembled.clear();
            next_offset = None;
            continue;
        };

        match next_offset {
            Some(next) if offset == next => {
                assembled.extend_from_slice(bytes);
                next_offset = Some(end_offset);
            }
            Some(next) if offset < next => {
                let overlap = (next - offset) as usize;
                if overlap < bytes.len() {
                    assembled.extend_from_slice(&bytes[overlap..]);
                    next_offset = Some(end_offset);
                }
            }
            _ => {
                assembled.clear();
                assembled.extend_from_slice(bytes);
                next_offset = Some(end_offset);
            }
        }

        if contains_bytes(&assembled, expected) {
            return true;
        }
    }
    false
}

fn read_feed_events(path: &Path) -> Result<Vec<CaptureEvent>, Box<dyn std::error::Error>> {
    let source = fs::read_to_string(path)?;
    if source.is_empty() || !source.ends_with('\n') {
        return Err(e2e_error(format!(
            "MITM feed {} is empty or missing final newline",
            path.display()
        ))
        .into());
    }
    source
        .lines()
        .map(|line| Ok(serde_json::from_str::<CaptureEvent>(line)?))
        .collect()
}

fn write_mitm_ca(root: &Path) -> Result<MitmCaMaterial, Box<dyn std::error::Error>> {
    let signing_key = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Traffic Probe Local E2E MITM CA");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let certificate = params.self_signed(&signing_key)?;
    let certificate_path = root.join("mitm-ca.pem");
    let private_key_path = root.join("mitm-ca.key");
    write_private_file(&certificate_path, certificate.pem())?;
    write_private_file(&private_key_path, signing_key.serialize_pem())?;
    Ok(MitmCaMaterial {
        certificate_path,
        private_key_path,
        certificate_der: certificate.der().clone(),
    })
}

fn write_private_file(
    path: &Path,
    contents: impl AsRef<[u8]>,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(path, contents)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn assert_http_response(
    mode: DownstreamMode,
    response: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    assert_http_response_bytes(mode.label(), response, mode.body())
}

fn assert_http_response_bytes(
    label: &str,
    response: &[u8],
    body: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = String::from_utf8_lossy(response);
    if response.starts_with("HTTP/1.1 200 OK") && response.contains(body) {
        return Ok(());
    }
    Err(e2e_error(format!("{label} proxy response mismatch: {response:?}")).into())
}

fn http_request(target: &str) -> Vec<u8> {
    http_request_with_host(target, HOST)
}

fn http_request_with_host(target: &str, host: &str) -> Vec<u8> {
    format!("GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").into_bytes()
}

fn unused_loopback_port() -> Result<u16, Box<dyn std::error::Error>> {
    Ok(TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?
        .local_addr()?
        .port())
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn is_l7_mitm_origin(source: CaptureSource, provider: CaptureProviderKind) -> bool {
    source == CaptureSource::L7MitmPlaintext && provider == CaptureProviderKind::Interception
}

impl DownstreamMode {
    fn directory_name(self) -> &'static str {
        match self {
            Self::Plaintext => "plaintext",
            Self::Tls => "tls",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Plaintext => "plaintext",
            Self::Tls => "TLS",
        }
    }

    fn target(self) -> &'static str {
        match self {
            Self::Plaintext => PLAIN_TARGET,
            Self::Tls => TLS_TARGET,
        }
    }

    fn body(self) -> &'static str {
        match self {
            Self::Plaintext => PLAIN_BODY,
            Self::Tls => TLS_BODY,
        }
    }

    fn expectation(self) -> HttpExpectation {
        HttpExpectation {
            label: self.label(),
            target: self.target(),
            response_content_type: TEXT_PLAIN_CONTENT_TYPE,
            body: self.body(),
        }
    }
}

#[cfg(test)]
#[test]
fn ordered_chunks_contain_matches_across_chunk_boundaries() {
    assert!(ordered_chunks_contain(
        vec![(6, b"world".as_slice()), (0, b"hello ".as_slice())],
        b"lo world",
    ));
}

#[cfg(test)]
#[test]
fn ordered_chunks_contain_does_not_join_across_gaps() {
    assert!(!ordered_chunks_contain(
        vec![(0, b"hello ".as_slice()), (16, b"world".as_slice())],
        b"hello world",
    ));
}
