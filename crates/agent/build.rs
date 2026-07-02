use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

use ebpf_object::{EbpfObjectArtifact, EbpfObjectProbe};

const PROCESS_OBSERVATION_SOURCE_ENV: &str = "PROBE_PROCESS_OBSERVATION_OBJECT_SOURCE";
const TLS_UPROBE_SOURCE_ENV: &str = "PROBE_TLS_UPROBE_OBJECT_SOURCE";
const OUT_PROCESS_OBSERVATION_OBJECT: &str = "ebpf-process-observation";
const OUT_TLS_UPROBE_OBJECT: &str = "ebpf-tls-plaintext";
const BPF_TARGET: &str = "bpfel-unknown-none";
const BPF_LINKER: &str = "bpf-linker";
const EBPF_TARGET_DIR: &str = "target/ebpf";
const EBPF_PROCESS_OBSERVATION_OBJECT: &str = "bpfel-unknown-none/release/ebpf-program";
const EBPF_TLS_UPROBE_OBJECT: &str = "bpfel-unknown-none/release/ebpf-tls-plaintext";

fn main() {
    println!("cargo:rerun-if-env-changed={PROCESS_OBSERVATION_SOURCE_ENV}");
    println!("cargo:rerun-if-env-changed={TLS_UPROBE_SOURCE_ENV}");
    print_ebpf_rerun_inputs();

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set"));
    let sources = resolve_ebpf_object_sources();
    embed_ebpf_object(
        EbpfObjectArtifact::ProcessObservation,
        &sources.process_observation,
        &out_dir.join(OUT_PROCESS_OBSERVATION_OBJECT),
    );
    embed_ebpf_object(
        EbpfObjectArtifact::TlsPlaintext,
        &sources.tls_plaintext,
        &out_dir.join(OUT_TLS_UPROBE_OBJECT),
    );
}

struct EbpfObjectSources {
    process_observation: PathBuf,
    tls_plaintext: PathBuf,
}

fn resolve_ebpf_object_sources() -> EbpfObjectSources {
    let process_observation = configured_source(PROCESS_OBSERVATION_SOURCE_ENV);
    let tls_plaintext = configured_source(TLS_UPROBE_SOURCE_ENV);
    if process_observation.is_none() || tls_plaintext.is_none() {
        build_first_party_ebpf_artifacts();
    }
    EbpfObjectSources {
        process_observation: process_observation.unwrap_or_else(default_process_observation_source),
        tls_plaintext: tls_plaintext.unwrap_or_else(default_tls_uprobe_source),
    }
}

fn configured_source(env_name: &str) -> Option<PathBuf> {
    env::var_os(env_name)
        .filter(|value| !value.is_empty())
        .map(|value| {
            let source = PathBuf::from(value);
            println!("cargo:rerun-if-changed={}", source.display());
            source
        })
}

fn default_process_observation_source() -> PathBuf {
    default_ebpf_source(default_process_observation_path(), "process observation")
}

fn default_tls_uprobe_source() -> PathBuf {
    default_ebpf_source(default_tls_uprobe_path(), "TLS uprobe")
}

fn default_ebpf_source(path: PathBuf, label: &str) -> PathBuf {
    if !path.exists() {
        panic!(
            "default {label} object {} was not produced by the eBPF build",
            path.display()
        );
    }
    path
}

fn default_process_observation_path() -> PathBuf {
    repo_root()
        .join(EBPF_TARGET_DIR)
        .join(EBPF_PROCESS_OBSERVATION_OBJECT)
}

fn default_tls_uprobe_path() -> PathBuf {
    repo_root()
        .join(EBPF_TARGET_DIR)
        .join(EBPF_TLS_UPROBE_OBJECT)
}

fn build_first_party_ebpf_artifacts() {
    let repo_root = repo_root();
    let manifest_path = repo_root.join("crates/ebpf-program/Cargo.toml");
    let target_dir = repo_root.join(EBPF_TARGET_DIR);
    let mut command = Command::new("cargo");
    command
        .arg("+nightly")
        .arg("build")
        .arg("--manifest-path")
        .arg(&manifest_path)
        .arg("--locked")
        .arg("--target-dir")
        .arg(&target_dir)
        .arg("--target")
        .arg(BPF_TARGET)
        .arg("-Z")
        .arg("build-std=core")
        .arg("--release")
        .current_dir(&repo_root)
        .env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("RUSTC")
        .env_remove("RUSTC_WRAPPER")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env_remove("CARGO_BUILD_RUSTC")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env("CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER", BPF_LINKER)
        .env("RUSTFLAGS", "-C debuginfo=2 -C link-arg=--btf");
    let status = command
        .status()
        .unwrap_or_else(|error| {
            panic!(
                "failed to run first-party eBPF build for embedded objects: {error}; install nightly rust-src and {BPF_LINKER}"
            )
        });
    if !status.success() {
        panic!(
            "first-party eBPF build failed with {status}; install nightly rust-src and {BPF_LINKER}"
        );
    }
}

fn embed_ebpf_object(artifact: EbpfObjectArtifact, source: &Path, out_path: &Path) {
    let preflight =
        EbpfObjectProbe::preflight(&artifact.probe_config(source)).unwrap_or_else(|report| {
            panic!(
                "failed to embed {} eBPF object {}: {}",
                artifact.label(),
                source.display(),
                report.summary()
            )
        });
    fs::write(out_path, preflight.bytes()).unwrap_or_else(|error| {
        panic!(
            "failed to write embedded {} eBPF object {}: {error}",
            artifact.label(),
            out_path.display()
        )
    });
}

fn print_ebpf_rerun_inputs() {
    let repo_root = repo_root();
    println!(
        "cargo:rerun-if-changed={}",
        repo_root.join("Cargo.lock").display()
    );
    let ebpf_root = repo_root.join("crates/ebpf-program");
    println!(
        "cargo:rerun-if-changed={}",
        ebpf_root.join("Cargo.toml").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        ebpf_root.join("Cargo.lock").display()
    );
    let ebpf_abi_root = repo_root.join("crates/ebpf-abi");
    println!(
        "cargo:rerun-if-changed={}",
        ebpf_abi_root.join("Cargo.toml").display()
    );
    print_rerun_inputs_under(&ebpf_root.join("src"));
    print_rerun_inputs_under(&ebpf_abi_root.join("src"));
}

fn print_rerun_inputs_under(path: &Path) {
    println!("cargo:rerun-if-changed={}", path.display());
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if path.is_dir() {
            print_rerun_inputs_under(&path);
        } else {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("agent crate should live under <repo>/crates/agent")
        .to_path_buf()
}
