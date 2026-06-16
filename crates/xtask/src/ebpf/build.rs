use std::{
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
    time::SystemTime,
};

use ebpf_object::{EbpfObjectArtifact, EbpfObjectContract, EbpfObjectProbe, EbpfObjectProbeConfig};

const BPF_TARGET: &str = "bpfel-unknown-none";
const BPF_LINKER: &str = "bpf-linker";
const EBPF_MANIFEST: &str = "crates/ebpf-program/Cargo.toml";
const EBPF_TARGET_DIR: &str = "target/ebpf";
const EBPF_BUILD_STAMP: &str = "sssa-ebpf-build.stamp";
const EBPF_PROCESS_ARTIFACT: &str = "bpfel-unknown-none/release/ebpf-program";
const EBPF_TLS_PLAINTEXT_ARTIFACT: &str = "bpfel-unknown-none/release/ebpf-tls-plaintext";

pub fn run_build() -> ExitCode {
    let config = EbpfBuildConfig::from_xtask_manifest_dir(env!("CARGO_MANIFEST_DIR"));
    match BuildPrerequisites::detect().validate() {
        Ok(()) => build_ebpf_program(&config),
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

pub fn run_check() -> ExitCode {
    let config = EbpfBuildConfig::from_xtask_manifest_dir(env!("CARGO_MANIFEST_DIR"));
    match BuildPrerequisites::detect().validate() {
        Ok(()) => {}
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    }

    if check_ebpf_format(&config) != ExitCode::SUCCESS {
        return ExitCode::FAILURE;
    }
    if clippy_ebpf_program(&config) != ExitCode::SUCCESS {
        return ExitCode::FAILURE;
    }
    build_ebpf_program(&config)
}

pub(crate) fn ensure_process_artifact_ready() -> Result<PathBuf, String> {
    let config = EbpfBuildConfig::from_xtask_manifest_dir(env!("CARGO_MANIFEST_DIR"));
    ensure_named_ebpf_object_ready(
        &config.process_artifact_path,
        EbpfObjectArtifact::ProcessObservation.label(),
        EbpfObjectArtifact::ProcessObservation.strict_contract(),
        &config.build_stamp_path,
        &process_artifact_freshness_inputs(&config)?,
    )?;
    Ok(config.process_artifact_path)
}

pub(super) struct EbpfBuildConfig {
    pub(super) repo_root: PathBuf,
    manifest_path: PathBuf,
    target_dir: PathBuf,
    build_stamp_path: PathBuf,
    pub(super) process_artifact_path: PathBuf,
    tls_plaintext_artifact_path: PathBuf,
}

impl EbpfBuildConfig {
    pub(super) fn from_xtask_manifest_dir(manifest_dir: &str) -> Self {
        let repo_root = Path::new(manifest_dir)
            .ancestors()
            .nth(2)
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let manifest_path = repo_root.join(EBPF_MANIFEST);
        let target_dir = repo_root.join(EBPF_TARGET_DIR);
        let build_stamp_path = target_dir.join(EBPF_BUILD_STAMP);
        let process_artifact_path = target_dir.join(EBPF_PROCESS_ARTIFACT);
        let tls_plaintext_artifact_path = target_dir.join(EBPF_TLS_PLAINTEXT_ARTIFACT);
        Self {
            repo_root,
            manifest_path,
            target_dir,
            build_stamp_path,
            process_artifact_path,
            tls_plaintext_artifact_path,
        }
    }
}

struct BuildPrerequisites {
    nightly_cargo: bool,
    nightly_rust_src: bool,
    bpf_target: bool,
    bpf_linker: bool,
}

impl BuildPrerequisites {
    fn detect() -> Self {
        let nightly_cargo = command_succeeds("cargo", ["+nightly", "--version"]);
        Self {
            nightly_cargo,
            nightly_rust_src: nightly_cargo
                && output_contains(
                    "rustup",
                    ["component", "list", "--toolchain", "nightly", "--installed"],
                    "rust-src",
                ),
            bpf_target: nightly_cargo
                && output_contains("rustc", ["+nightly", "--print", "target-list"], BPF_TARGET),
            bpf_linker: command_succeeds(BPF_LINKER, ["--version"]),
        }
    }

    fn validate(&self) -> Result<(), String> {
        if !self.nightly_cargo {
            return Err("missing nightly toolchain; install it with `rustup toolchain install nightly --component rust-src`".to_string());
        }
        if !self.nightly_rust_src {
            return Err("missing nightly rust-src component; install it with `rustup component add rust-src --toolchain nightly`".to_string());
        }
        if !self.bpf_target {
            return Err(format!(
                "nightly rustc does not report target {BPF_TARGET}; update the nightly toolchain"
            ));
        }
        if !self.bpf_linker {
            return Err(format!(
                "missing {BPF_LINKER}; install the latest stable release before running eBPF builds"
            ));
        }
        Ok(())
    }
}

fn build_ebpf_program(config: &EbpfBuildConfig) -> ExitCode {
    let mut command = Command::new("cargo");
    command
        .arg("+nightly")
        .arg("build")
        .arg("--manifest-path")
        .arg(&config.manifest_path)
        .arg("--locked")
        .arg("--target-dir")
        .arg(&config.target_dir)
        .arg("--target")
        .arg(BPF_TARGET)
        .arg("-Z")
        .arg("build-std=core")
        .arg("--release")
        .current_dir(&config.repo_root)
        .env("CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER", BPF_LINKER)
        .env("RUSTFLAGS", "-C debuginfo=2 -C link-arg=--btf");

    match command.status() {
        Ok(status) if status.success() => {
            let result = verify_ebpf_object_contracts(config);
            if result == ExitCode::SUCCESS {
                write_build_stamp(config)
            } else {
                result
            }
        }
        Ok(_) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("failed to run eBPF cargo build: {error}");
            ExitCode::FAILURE
        }
    }
}

fn check_ebpf_format(config: &EbpfBuildConfig) -> ExitCode {
    let mut command = Command::new("cargo");
    command
        .arg("+nightly")
        .arg("fmt")
        .arg("--manifest-path")
        .arg(&config.manifest_path)
        .arg("--")
        .arg("--check")
        .current_dir(&config.repo_root);

    run_named_command("eBPF cargo fmt", &mut command)
}

fn clippy_ebpf_program(config: &EbpfBuildConfig) -> ExitCode {
    let mut command = ebpf_target_cargo_command(config, "clippy");
    command.arg("--").arg("-D").arg("warnings");

    run_named_command("eBPF cargo clippy", &mut command)
}

fn ebpf_target_cargo_command(config: &EbpfBuildConfig, subcommand: &str) -> Command {
    let mut command = Command::new("cargo");
    command
        .arg("+nightly")
        .arg(subcommand)
        .arg("--manifest-path")
        .arg(&config.manifest_path)
        .arg("--locked")
        .arg("--target-dir")
        .arg(&config.target_dir)
        .arg("--target")
        .arg(BPF_TARGET)
        .arg("-Z")
        .arg("build-std=core")
        .arg("--release")
        .current_dir(&config.repo_root)
        .env("CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER", BPF_LINKER)
        .env("RUSTFLAGS", "-C debuginfo=2 -C link-arg=--btf");
    command
}

fn run_named_command(name: &str, command: &mut Command) -> ExitCode {
    match command.status() {
        Ok(status) if status.success() => ExitCode::SUCCESS,
        Ok(_) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("failed to run {name}: {error}");
            ExitCode::FAILURE
        }
    }
}

fn verify_ebpf_object_contracts(config: &EbpfBuildConfig) -> ExitCode {
    for (artifact, path) in [
        (
            EbpfObjectArtifact::ProcessObservation,
            config.process_artifact_path.as_path(),
        ),
        (
            EbpfObjectArtifact::TlsPlaintext,
            config.tls_plaintext_artifact_path.as_path(),
        ),
    ] {
        if verify_named_ebpf_object_contract(path, artifact.label(), artifact.strict_contract())
            != ExitCode::SUCCESS
        {
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}

pub(super) fn verify_named_ebpf_object_contract(
    path: &Path,
    label: &str,
    contract: EbpfObjectContract,
) -> ExitCode {
    match ensure_named_ebpf_object_contract(path, label, contract) {
        Ok(summary) => {
            println!("verified built eBPF object {label} contract: {summary}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn ensure_named_ebpf_object_ready(
    path: &Path,
    label: &str,
    contract: EbpfObjectContract,
    build_stamp_path: &Path,
    freshness_inputs: &[PathBuf],
) -> Result<(), String> {
    ensure_named_ebpf_object_contract(path, label, contract)?;
    ensure_build_stamp_fresh(build_stamp_path, freshness_inputs)
}

fn ensure_named_ebpf_object_contract(
    path: &Path,
    label: &str,
    contract: EbpfObjectContract,
) -> Result<String, String> {
    let report = EbpfObjectProbe::probe(&EbpfObjectProbeConfig::with_contract(path, contract));
    if !report.preflight_available() {
        let failed_stage = if report.object_available() {
            "contract"
        } else {
            "object"
        };
        return Err(format!(
            "eBPF object failed {label} {failed_stage} preflight: {}; run `cargo run -p xtask --locked -- ebpf-build`",
            report.summary()
        ));
    }
    Ok(report.summary())
}

fn process_artifact_freshness_inputs(config: &EbpfBuildConfig) -> Result<Vec<PathBuf>, String> {
    let mut inputs = vec![
        config.repo_root.join("Cargo.lock"),
        config.manifest_path.clone(),
        config.repo_root.join("crates/ebpf-program/Cargo.lock"),
        config.repo_root.join("crates/ebpf-abi/Cargo.toml"),
    ];
    collect_rust_inputs(
        &config.repo_root.join("crates/ebpf-program/src"),
        &mut inputs,
    )?;
    collect_rust_inputs(&config.repo_root.join("crates/ebpf-abi/src"), &mut inputs)?;
    Ok(inputs)
}

fn collect_rust_inputs(dir: &Path, inputs: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = fs::read_dir(dir)
        .map_err(|source| format!("failed to read eBPF input dir {}: {source}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|source| {
            format!(
                "failed to read eBPF input dir entry under {}: {source}",
                dir.display()
            )
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|source| {
            format!(
                "failed to read eBPF input file type {}: {source}",
                path.display()
            )
        })?;
        if file_type.is_dir() {
            collect_rust_inputs(&path, inputs)?;
        } else if path.extension() == Some(OsStr::new("rs")) {
            inputs.push(path);
        }
    }
    Ok(())
}

fn ensure_build_stamp_fresh(build_stamp_path: &Path, inputs: &[PathBuf]) -> Result<(), String> {
    let stamp_mtime = modified_time(build_stamp_path).map_err(|source| {
        format!("{source}; run `cargo run -p xtask --locked -- ebpf-build` before privileged e2e")
    })?;
    let Some((newest_input, newest_input_mtime)) = newest_input(inputs)? else {
        return Ok(());
    };
    if newest_input_mtime <= stamp_mtime {
        return Ok(());
    }

    Err(format!(
        "eBPF build stamp {} is older than input {}; run `cargo run -p xtask --locked -- ebpf-build`",
        build_stamp_path.display(),
        newest_input.display()
    ))
}

fn newest_input(inputs: &[PathBuf]) -> Result<Option<(PathBuf, SystemTime)>, String> {
    let mut newest = None;
    for input in inputs {
        let input_mtime = modified_time(input)?;
        if newest
            .as_ref()
            .map(|(_, newest_mtime)| input_mtime > *newest_mtime)
            .unwrap_or(true)
        {
            newest = Some((input.clone(), input_mtime));
        }
    }
    Ok(newest)
}

fn modified_time(path: &Path) -> Result<SystemTime, String> {
    fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .map_err(|source| {
            format!(
                "failed to read modified time for {}: {source}",
                path.display()
            )
        })
}

fn write_build_stamp(config: &EbpfBuildConfig) -> ExitCode {
    if let Err(error) = fs::create_dir_all(&config.target_dir) {
        eprintln!(
            "failed to create eBPF target dir {}: {error}",
            config.target_dir.display()
        );
        return ExitCode::FAILURE;
    }
    match fs::write(&config.build_stamp_path, b"ok\n") {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "failed to write eBPF build stamp {}: {error}",
                config.build_stamp_path.display()
            );
            ExitCode::FAILURE
        }
    }
}

fn command_succeeds<const N: usize>(program: &str, args: [&str; N]) -> bool {
    Command::new(program)
        .args(args.iter().map(OsStr::new))
        .status()
        .is_ok_and(|status| status.success())
}

fn output_contains<const N: usize>(program: &str, args: [&str; N], needle: &str) -> bool {
    Command::new(program)
        .args(args.iter().map(OsStr::new))
        .output()
        .ok()
        .filter(|output| output.status.success())
        .is_some_and(|output| String::from_utf8_lossy(&output.stdout).contains(needle))
}
