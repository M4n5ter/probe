use std::{
    fs,
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, ExitCode, Stdio},
    thread,
    time::{Duration, Instant},
};

use probe_config::{AgentConfig, CaptureSelection, PolicyConfig};
use probe_core::{Direction, ProcessSelector, Selector, TrafficSelector};

use super::{
    harness::{
        ChildSupervisor, UnixSocketReadySignal, create_temp_root, debug_binary, e2e_error,
        ensure_e2e_packages_built, publish_atomic_file, run_in_own_process_group,
        stop_running_child, trusted_system_command, wait_for_child_exit,
        wait_for_file_or_child_exit,
    },
    loopback::{
        merge_labeled_run_results, spawn_agent, wait_for_agent_policy_progress,
        wait_for_agent_ready,
    },
    tls_plaintext_assertions::{TlsPlaintextExpectations, assert_spool_outputs_for_pid},
    tls_plaintext_status::{
        wait_for_tls_plaintext_active_target_path_after_sequence,
        wait_for_tls_plaintext_no_active_target_after_sequence,
    },
};

const INTERFACE: &str = "any";
const POLICY_ID: &str = "tls-plaintext-e2e-policy";
const POLICY_VERSION: &str = "e2e";
const REQUESTS: usize = 2;
const REQUEST_BODY_BYTES: usize = 48;
const POST_WRITE_DELAY_MS: u64 = 500;
const FIXTURE_EXE_GLOB: &str = "**/sssa-e2e-dynssl-fixture";
const TLS_RECONCILE_INTERVAL_MS: u64 = 100;
const READY_TIMEOUT: Duration = Duration::from_secs(10);
const SERVER_READY_TIMEOUT: Duration = Duration::from_secs(10);
const DYNSSL_FIXTURE_TIMEOUT: Duration = Duration::from_secs(20);

pub(crate) fn run() -> ExitCode {
    match run_inner() {
        Ok(()) => {
            println!("e2e TLS plaintext dynamic library loopback passed");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("e2e TLS plaintext dynamic library loopback failed: {error}");
            ExitCode::FAILURE
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DynamicLibraryPaths {
    process_ready: PathBuf,
    phases: [DynSslPhasePaths; 2],
    agent_ready_socket: PathBuf,
    admin_socket: PathBuf,
    policy: PathBuf,
    config: PathBuf,
    spool: PathBuf,
    tls_server_cert: PathBuf,
    tls_server_key: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DynSslPhasePaths {
    libssl: PathBuf,
    load_start: PathBuf,
    library_ready: PathBuf,
    exchange_start: PathBuf,
}

impl DynamicLibraryPaths {
    fn new(root: &Path) -> Self {
        Self {
            process_ready: root.join("dynssl-process.ready"),
            phases: [
                DynSslPhasePaths {
                    libssl: root.join("libssl-sssa-e2e.so.3"),
                    load_start: root.join("dynssl-load.start"),
                    library_ready: root.join("dynssl-library.ready"),
                    exchange_start: root.join("dynssl-exchange.start"),
                },
                DynSslPhasePaths {
                    libssl: root.join("libssl-sssa-e2e-replacement.so.3"),
                    load_start: root.join("dynssl-replacement-load.start"),
                    library_ready: root.join("dynssl-replacement-library.ready"),
                    exchange_start: root.join("dynssl-replacement-exchange.start"),
                },
            ],
            agent_ready_socket: root.join("agent.ready.sock"),
            admin_socket: root.join("admin.sock"),
            policy: root.join("tls-plaintext-e2e-policy.bundle"),
            config: root.join("agent.toml"),
            spool: root.join("spool"),
            tls_server_cert: root.join("server.crt"),
            tls_server_key: root.join("server.key"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DynSslReady {
    pid: u32,
    start_nonce: String,
    libssl_path: Option<PathBuf>,
}

fn run_inner() -> Result<(), Box<dyn std::error::Error>> {
    ensure_e2e_packages_built(["agent", "e2e-dynssl-fixture"])?;
    let tls_object_path = crate::ebpf::ensure_tls_plaintext_artifact_ready().map_err(e2e_error)?;

    let root = create_temp_root("tls-plaintext-dynamic-library-loopback")?;
    let result = run_at(&root, &tls_object_path);
    match result {
        Ok(()) => {
            fs::remove_dir_all(&root)?;
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
    let paths = DynamicLibraryPaths::new(root);
    let listen_port = available_loopback_port()?;
    let server_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, listen_port));
    let expectations = TlsPlaintextExpectations::new(REQUESTS);

    write_policy_bundle(&paths.policy)?;
    write_agent_config(&paths, tls_object_path, listen_port)?;
    write_server_certificate(&paths.tls_server_cert, &paths.tls_server_key)?;
    for phase in &paths.phases {
        copy_libssl_for_mapping(&phase.libssl)?;
    }

    let supervisor = ChildSupervisor::new()?;
    let mut server = supervisor.watch(
        spawn_openssl_server(listen_port, &paths.tls_server_cert, &paths.tls_server_key)?,
        "openssl TLS server",
    );
    wait_for_server_ready(server.child_mut(), server_addr)?;

    let mut fixture = supervisor.watch(
        spawn_dynssl_fixture(&paths, server_addr, REQUEST_BODY_BYTES)?,
        "dynamic libssl fixture",
    );
    let process_ready = wait_for_dynssl_ready(fixture.child_mut(), &paths.process_ready)?;

    let mut ready_signal = UnixSocketReadySignal::bind(paths.agent_ready_socket.clone())?;
    let mut agent = supervisor.watch(spawn_agent(&paths.config, &ready_signal)?, "agent");
    wait_for_agent_ready(agent.child_mut(), &mut ready_signal)?;
    let empty_status = wait_for_tls_plaintext_no_active_target_after_sequence(
        agent.child_mut(),
        &paths.admin_socket,
        process_ready.pid,
        0,
    )?;

    let primary_phase = &paths.phases[0];
    let replacement_phase = &paths.phases[1];
    start_dynssl_phase(&primary_phase.load_start, &process_ready.start_nonce)?;
    let library_ready = wait_for_dynssl_ready(fixture.child_mut(), &primary_phase.library_ready)?;
    if library_ready.pid != process_ready.pid {
        return Err(e2e_error(format!(
            "dynamic libssl fixture changed pid from {} to {}",
            process_ready.pid, library_ready.pid
        ))
        .into());
    }
    let mapped_path = library_ready.libssl_path.as_ref().ok_or_else(|| {
        e2e_error(format!(
            "dynamic libssl ready file {} did not contain libssl_path",
            primary_phase.library_ready.display()
        ))
    })?;
    let primary_active_status = wait_for_tls_plaintext_active_target_path_after_sequence(
        agent.child_mut(),
        &paths.admin_socket,
        process_ready.pid,
        mapped_path,
        empty_status.sequence,
    )?;

    start_dynssl_phase(&primary_phase.exchange_start, &library_ready.start_nonce)?;
    wait_for_agent_policy_progress(agent.child_mut(), &paths.admin_socket, 1)?;

    start_dynssl_phase(&replacement_phase.load_start, &library_ready.start_nonce)?;
    let replacement_ready =
        wait_for_dynssl_ready(fixture.child_mut(), &replacement_phase.library_ready)?;
    if replacement_ready.pid != process_ready.pid {
        return Err(e2e_error(format!(
            "dynamic libssl fixture changed pid from {} to {} during replacement",
            process_ready.pid, replacement_ready.pid
        ))
        .into());
    }
    let replacement_mapped_path = replacement_ready.libssl_path.as_ref().ok_or_else(|| {
        e2e_error(format!(
            "dynamic libssl replacement ready file {} did not contain libssl_path",
            replacement_phase.library_ready.display()
        ))
    })?;
    if replacement_mapped_path == mapped_path {
        return Err(e2e_error(format!(
            "dynamic libssl replacement reused mapped path {}",
            replacement_mapped_path.display()
        ))
        .into());
    }
    let replacement_active_status = wait_for_tls_plaintext_active_target_path_after_sequence(
        agent.child_mut(),
        &paths.admin_socket,
        process_ready.pid,
        replacement_mapped_path,
        primary_active_status.sequence,
    )?;
    let primary_mapping_visible = proc_maps_contains_path(process_ready.pid, mapped_path)?;
    if primary_mapping_visible
        && !replacement_active_status.has_active_target_path(process_ready.pid, mapped_path)
    {
        return Err(e2e_error(format!(
            "dynamic libssl primary mapping {} remained visible after replacement, but admin status did not retain it as an active target",
            mapped_path.display()
        ))
        .into());
    }
    if !primary_mapping_visible
        && replacement_active_status.has_active_target_path(process_ready.pid, mapped_path)
    {
        return Err(e2e_error(format!(
            "dynamic libssl primary mapping {} disappeared after replacement, but admin status still retained it as an active target",
            mapped_path.display()
        ))
        .into());
    }

    start_dynssl_phase(
        &replacement_phase.exchange_start,
        &replacement_ready.start_nonce,
    )?;
    let fixture_result = wait_for_child_exit(
        fixture.child_mut(),
        DYNSSL_FIXTURE_TIMEOUT,
        "dynamic libssl fixture",
    );
    fixture.unwatch();
    let progress_result = match &fixture_result {
        Ok(()) => wait_for_agent_policy_progress(
            agent.child_mut(),
            &paths.admin_socket,
            expectations.policy_alert_count_for_runs(1),
        ),
        Err(_) => Ok(()),
    };
    let agent_result = stop_running_child(agent.child_mut(), "agent");
    agent.unwatch();
    let spool_result = match (&fixture_result, &agent_result) {
        (Ok(()), Ok(())) => {
            assert_spool_outputs_for_pid(&paths.spool, listen_port, expectations, process_ready.pid)
        }
        _ => Ok(()),
    };

    merge_labeled_run_results([
        ("dynamic libssl fixture", fixture_result),
        ("agent policy progress", progress_result),
        ("agent", agent_result),
        ("spool assertion", spool_result),
    ])?;

    Ok(())
}

fn spawn_dynssl_fixture(
    paths: &DynamicLibraryPaths,
    server_addr: SocketAddr,
    request_body_bytes: usize,
) -> Result<Child, Box<dyn std::error::Error>> {
    let mut command = Command::new(debug_binary("sssa-e2e-dynssl-fixture")?);
    let command = run_in_own_process_group(&mut command)
        .arg("--server-addr")
        .arg(server_addr.to_string())
        .arg("--process-ready-file")
        .arg(&paths.process_ready);
    for phase in &paths.phases {
        append_dynssl_phase_args(command, phase);
    }
    let child = command
        .arg("--request-index")
        .arg("0")
        .arg("--request-body-bytes")
        .arg(request_body_bytes.to_string())
        .arg("--post-write-delay-ms")
        .arg(POST_WRITE_DELAY_MS.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    Ok(child)
}

fn append_dynssl_phase_args(command: &mut Command, phase: &DynSslPhasePaths) {
    command
        .arg("--phase-libssl")
        .arg(&phase.libssl)
        .arg("--phase-load-start-file")
        .arg(&phase.load_start)
        .arg("--phase-library-ready-file")
        .arg(&phase.library_ready)
        .arg("--phase-exchange-start-file")
        .arg(&phase.exchange_start);
}

fn spawn_openssl_server(
    listen_port: u16,
    cert_path: &Path,
    key_path: &Path,
) -> Result<Child, Box<dyn std::error::Error>> {
    let mut command = Command::new(openssl_command()?);
    let child = run_in_own_process_group(&mut command)
        .args(["s_server", "-quiet", "-www", "-accept"])
        .arg(listen_port.to_string())
        .arg("-cert")
        .arg(cert_path)
        .arg("-key")
        .arg(key_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    Ok(child)
}

fn write_server_certificate(cert_path: &Path, key_path: &Path) -> Result<(), std::io::Error> {
    let status = Command::new(openssl_command()?)
        .args(["req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes"])
        .arg("-keyout")
        .arg(key_path)
        .arg("-out")
        .arg(cert_path)
        .args(["-days", "1", "-subj", "/CN=sssa-e2e-dynssl"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(e2e_error(format!(
            "openssl certificate generation exited with {status}"
        )))
    }
}

fn copy_libssl_for_mapping(target: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let source = resolve_libssl_so()?;
    fs::copy(&source, target)?;
    Ok(())
}

fn resolve_libssl_so() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let output = Command::new(ldconfig_command()?).arg("-p").output()?;
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(path) = stdout
            .lines()
            .filter(|line| line.contains("libssl.so.3"))
            .filter_map(|line| {
                line.rsplit_once("=>")
                    .map(|(_, path)| PathBuf::from(path.trim()))
            })
            .find(|path| path.is_file())
        {
            return Ok(path);
        }
    }
    [
        "/lib/x86_64-linux-gnu/libssl.so.3",
        "/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "/home/linuxbrew/.linuxbrew/opt/openssl@3/lib/libssl.so.3",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|path| path.is_file())
    .ok_or_else(|| e2e_error("failed to resolve libssl.so.3").into())
}

fn openssl_command() -> Result<PathBuf, std::io::Error> {
    trusted_system_command(["/usr/bin/openssl", "/bin/openssl"], "openssl")
}

fn ldconfig_command() -> Result<PathBuf, std::io::Error> {
    trusted_system_command(
        [
            "/usr/sbin/ldconfig",
            "/sbin/ldconfig",
            "/usr/bin/ldconfig",
            "/bin/ldconfig",
        ],
        "ldconfig",
    )
}

fn wait_for_server_ready(
    server: &mut Child,
    server_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + SERVER_READY_TIMEOUT;
    loop {
        if TcpStream::connect(server_addr).is_ok() {
            return Ok(());
        }
        if let Some(status) = server.try_wait()? {
            return Err(e2e_error(format!(
                "openssl TLS server exited with {status} before listening on {server_addr}"
            ))
            .into());
        }
        if Instant::now() >= deadline {
            return Err(e2e_error(format!(
                "timed out waiting for openssl TLS server on {server_addr}"
            ))
            .into());
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn wait_for_dynssl_ready(
    fixture: &mut Child,
    ready_path: &Path,
) -> Result<DynSslReady, Box<dyn std::error::Error>> {
    wait_for_file_or_child_exit(fixture, ready_path, READY_TIMEOUT, "dynamic libssl ready")?;
    parse_dynssl_ready(ready_path)
}

fn parse_dynssl_ready(path: &Path) -> Result<DynSslReady, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    let Some(pid) = ready_value(&content, "pid") else {
        return Err(e2e_error(format!(
            "dynamic libssl ready file {} did not contain pid",
            path.display()
        ))
        .into());
    };
    let Some(start_nonce) = ready_value(&content, "start_nonce") else {
        return Err(e2e_error(format!(
            "dynamic libssl ready file {} did not contain start_nonce",
            path.display()
        ))
        .into());
    };
    Ok(DynSslReady {
        pid: pid.parse::<u32>()?,
        start_nonce,
        libssl_path: ready_value(&content, "libssl_path").map(PathBuf::from),
    })
}

fn proc_maps_contains_path(pid: u32, mapped_path: &Path) -> Result<bool, std::io::Error> {
    let maps = fs::read_to_string(format!("/proc/{pid}/maps"))?;
    let mapped_path = mapped_path.to_string_lossy();
    Ok(maps
        .lines()
        .filter_map(proc_maps_pathname)
        .any(|pathname| pathname == mapped_path.as_ref()))
}

fn proc_maps_pathname(line: &str) -> Option<&str> {
    line.split_whitespace().nth(5)
}

fn start_dynssl_phase(start_path: &Path, start_nonce: &str) -> Result<(), std::io::Error> {
    publish_atomic_file(
        start_path,
        format!("start_nonce={start_nonce}\n").as_bytes(),
    )
}

fn ready_value(content: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    content
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .map(ToOwned::to_owned)
}

fn available_loopback_port() -> Result<u16, std::io::Error> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    Ok(listener.local_addr()?.port())
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
        r#"
function on_http_request_headers(event)
  local target = event.kind.target or ""
  if string.sub(target, 1, 10) == "/sssa-e2e/" then
    return probe.emit_alert("tls plaintext policy observed " .. target)
  end
end
"#,
    )
}

fn write_agent_config(
    paths: &DynamicLibraryPaths,
    tls_object_path: &Path,
    listen_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = AgentConfig {
        agent_id: "e2e-tls-plaintext-dynamic-library-agent".to_string(),
        config_version: "e2e-tls-plaintext-dynamic-library-loopback".to_string(),
        ..AgentConfig::default()
    };
    config.capture.selection = CaptureSelection::Libpcap;
    config.capture.libpcap.interface = Some(INTERFACE.to_string());
    config.capture.libpcap.bpf_filter = format!("tcp and port {listen_port}");
    config.capture.libpcap.read_timeout_ms = 100;
    config.tls.plaintext.instrumentation.enabled = true;
    config
        .tls
        .plaintext
        .instrumentation
        .libssl_uprobe_object_path = Some(tls_object_path.to_path_buf());
    config.tls.plaintext.instrumentation.reconcile_interval_ms = TLS_RECONCILE_INTERVAL_MS;
    config.tls.plaintext.instrumentation.selector = Some(Selector::term(
        ProcessSelector {
            exe_path_globs: vec![FIXTURE_EXE_GLOB.to_string()],
            ..ProcessSelector::default()
        },
        TrafficSelector {
            remote_ports: vec![listen_port],
            directions: vec![Direction::Outbound],
            ..TrafficSelector::default()
        },
    ));
    config.storage.path = paths.spool.clone();
    config.export.worker.enabled = false;
    config.admin.enabled = true;
    config.admin.socket_path = paths.admin_socket.clone();
    config.policies.push(PolicyConfig {
        id: POLICY_ID.to_string(),
        source: probe_config::PolicySourceConfig::LocalDirectory {
            path: paths.policy.clone(),
        },
        enabled: true,
        selector: None,
    });
    fs::write(&paths.config, toml::to_string(&config)?)?;
    Ok(())
}
