use std::{
    fs,
    path::Path,
    process::{Child, ExitCode},
    thread,
    time::{Duration, Instant},
};

use capture::{
    CapturePoll, CaptureProvider, LibsslUprobeAttachPlan, LibsslUprobePlaintextProbeConfig,
    LibsslUprobePlaintextProvider, LibsslUprobeTargetDiscovery,
};

use super::{
    harness::{ChildSupervisor, create_temp_root, e2e_error, ensure_e2e_packages_built},
    loopback::{
        Http1LoopbackFixtureConfig, spawn_tls_http1_loopback_fixture, start_http1_loopback_fixture,
        wait_for_http1_loopback_fixture_exit, wait_for_http1_loopback_fixture_ready,
    },
    tls_plaintext_harness::{
        DirectLoopbackFlowResolver, is_expected_tls_plaintext_request_bytes, provider_event_summary,
    },
};

const REQUESTS: usize = 1;
const REQUEST_BODY_BYTES: usize = 48;
const RESPONSE_BODY_BYTES: usize = 24;
const WRITE_CHUNKS: usize = 1;
const POST_EXCHANGE_DELAY_MS: u64 = 500;
const PROVIDER_EVENT_TIMEOUT: Duration = Duration::from_secs(5);
const PROVIDER_POLL_INTERVAL: Duration = Duration::from_millis(10);

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
        Box::new(DirectLoopbackFlowResolver::new(
            fixture_ready.pid,
            process.start_time_ticks,
            fixture_ready.listen_port,
        )),
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
        listen_port: None,
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
