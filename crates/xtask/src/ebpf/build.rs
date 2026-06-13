use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

use ebpf_object::{EbpfObjectArtifact, EbpfObjectContract, EbpfObjectProbe, EbpfObjectProbeConfig};

const BPF_TARGET: &str = "bpfel-unknown-none";
const BPF_LINKER: &str = "bpf-linker";
const EBPF_MANIFEST: &str = "crates/ebpf-program/Cargo.toml";
const EBPF_TARGET_DIR: &str = "target/ebpf";
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

struct EbpfBuildConfig {
    repo_root: PathBuf,
    manifest_path: PathBuf,
    target_dir: PathBuf,
    process_artifact_path: PathBuf,
    tls_plaintext_artifact_path: PathBuf,
}

impl EbpfBuildConfig {
    fn from_xtask_manifest_dir(manifest_dir: &str) -> Self {
        let repo_root = Path::new(manifest_dir)
            .ancestors()
            .nth(2)
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let manifest_path = repo_root.join(EBPF_MANIFEST);
        let target_dir = repo_root.join(EBPF_TARGET_DIR);
        let process_artifact_path = target_dir.join(EBPF_PROCESS_ARTIFACT);
        let tls_plaintext_artifact_path = target_dir.join(EBPF_TLS_PLAINTEXT_ARTIFACT);
        Self {
            repo_root,
            manifest_path,
            target_dir,
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
        Ok(status) if status.success() => verify_ebpf_object_contracts(config),
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

fn verify_named_ebpf_object_contract(
    path: &Path,
    label: &str,
    contract: EbpfObjectContract,
) -> ExitCode {
    let report = EbpfObjectProbe::probe(&EbpfObjectProbeConfig::with_contract(path, contract));
    if !report.preflight_available() {
        let failed_stage = if report.object_available() {
            "contract"
        } else {
            "object"
        };
        eprintln!(
            "built eBPF object failed {label} {failed_stage} preflight: {}",
            report.summary()
        );
        return ExitCode::FAILURE;
    }
    println!(
        "verified built eBPF object {label} contract: {}",
        report.summary()
    );
    ExitCode::SUCCESS
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
