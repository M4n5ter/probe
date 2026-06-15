use std::{
    net::{Ipv4Addr, SocketAddr, TcpStream},
    path::Path,
    process::{Command, ExitCode},
    thread,
    time::{Duration, Instant},
};

use capture::{
    EbpfProcessObservation, EbpfProcessObservationProbe, EbpfProcessObservationProbeConfig,
};
use ebpf_object::EbpfObjectArtifact;
use probe_core::TcpEndpoint;

use super::build::{EbpfBuildConfig, verify_named_ebpf_object_contract};

const INITIAL_DRAIN_DEADLINE: Duration = Duration::from_millis(250);
const INITIAL_DRAIN_LIMIT: usize = 256;
const OBSERVATION_DEADLINE: Duration = Duration::from_secs(2);
const TRIGGER_CONNECT_TIMEOUT: Duration = Duration::from_millis(250);

pub fn run_privileged_smoke() -> ExitCode {
    let config = EbpfBuildConfig::from_xtask_manifest_dir(env!("CARGO_MANIFEST_DIR"));
    if verify_named_ebpf_object_contract(
        &config.process_artifact_path,
        EbpfObjectArtifact::ProcessObservation.label(),
        EbpfObjectArtifact::ProcessObservation.strict_contract(),
    ) != ExitCode::SUCCESS
    {
        eprintln!(
            "missing or invalid process eBPF artifact; run `cargo run -p xtask -- check-ebpf` as the regular user first"
        );
        return ExitCode::FAILURE;
    }
    run_process_observation_privileged_smoke(&config)
}

fn run_process_observation_privileged_smoke(config: &EbpfBuildConfig) -> ExitCode {
    if current_uid().is_some_and(|uid| uid != "0") {
        eprintln!(
            "privileged eBPF smoke requires root or CAP_BPF/CAP_PERFMON; continuing so capability-based environments can pass"
        );
    }

    match observe_process_connect_tracepoint(&config.process_artifact_path) {
        Ok(()) => {
            println!(
                "verified privileged eBPF process observation smoke: {} loaded, attached, and observed connect tracepoint",
                config.process_artifact_path.display()
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("privileged eBPF process observation smoke failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn observe_process_connect_tracepoint(object_path: &Path) -> Result<(), String> {
    let mut probe =
        EbpfProcessObservationProbe::load(EbpfProcessObservationProbeConfig::new(object_path))
            .map_err(|error| error.to_string())?;
    drain_initial_observations(&mut probe)?;

    let expected_command = "sssa-smoke";
    let trigger_endpoint = SocketAddr::from((Ipv4Addr::LOCALHOST, 9));
    let expected_endpoint = TcpEndpoint::new(Ipv4Addr::LOCALHOST.into(), trigger_endpoint.port());
    thread::Builder::new()
        .name(expected_command.to_string())
        .spawn(move || {
            let _ = TcpStream::connect_timeout(&trigger_endpoint, TRIGGER_CONNECT_TIMEOUT);
        })
        .map_err(|error| format!("failed to spawn connect trigger thread: {error}"))?
        .join()
        .map_err(|_| "connect trigger thread panicked".to_string())?;

    let mut observed = Vec::new();
    let deadline = Instant::now() + OBSERVATION_DEADLINE;
    while Instant::now() < deadline {
        match probe
            .next_observation()
            .map_err(|error| error.to_string())?
        {
            Some(EbpfProcessObservation::Connect(observation))
                if observation.process.command_lossy() == expected_command
                    && observation.endpoint.remote_endpoint() == Some(expected_endpoint) =>
            {
                return Ok(());
            }
            Some(observation) => {
                observed.push(format_observation(observation));
            }
            None => thread::sleep(Duration::from_millis(10)),
        }
    }

    Err(format!(
        "did not observe connect tracepoint for command {expected_command}; observed={}",
        observed.join(";")
    ))
}

fn drain_initial_observations(probe: &mut EbpfProcessObservationProbe) -> Result<(), String> {
    let deadline = Instant::now() + INITIAL_DRAIN_DEADLINE;
    for _ in 0..INITIAL_DRAIN_LIMIT {
        if Instant::now() >= deadline {
            return Ok(());
        }
        if probe
            .next_observation()
            .map_err(|error| error.to_string())?
            .is_none()
        {
            return Ok(());
        }
    }
    Ok(())
}

fn format_observation(observation: EbpfProcessObservation) -> String {
    match observation {
        EbpfProcessObservation::Connect(observation) => format!(
            "pid={},tgid={},command={},endpoint={:?}",
            observation.process.pid,
            observation.process.tgid,
            observation.process.command_lossy(),
            observation.endpoint
        ),
        EbpfProcessObservation::Close(observation) => format!(
            "pid={},tgid={},command={},closed_fd={}",
            observation.process.pid,
            observation.process.tgid,
            observation.process.command_lossy(),
            observation.fd
        ),
    }
}

fn current_uid() -> Option<String> {
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|uid| !uid.is_empty())
}
