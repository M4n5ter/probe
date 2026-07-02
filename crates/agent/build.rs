use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

use ebpf_object::{EbpfObjectArtifact, EbpfObjectProbe};

const TLS_UPROBE_SOURCE_ENV: &str = "PROBE_TLS_UPROBE_OBJECT_SOURCE";
const OUT_TLS_UPROBE_OBJECT: &str = "ebpf-tls-plaintext";
const BPF_TARGET: &str = "bpfel-unknown-none";
const BPF_LINKER: &str = "bpf-linker";
const EBPF_TARGET_DIR: &str = "target/ebpf";
const EBPF_TLS_UPROBE_OBJECT: &str = "bpfel-unknown-none/release/ebpf-tls-plaintext";

fn main() {
    println!("cargo:rerun-if-env-changed={TLS_UPROBE_SOURCE_ENV}");
    print_ebpf_rerun_inputs();

    let out_path = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set"))
        .join(OUT_TLS_UPROBE_OBJECT);
    embed_tls_uprobe_object(&tls_uprobe_source(), &out_path);
}

fn configured_source() -> Option<PathBuf> {
    env::var_os(TLS_UPROBE_SOURCE_ENV)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn tls_uprobe_source() -> PathBuf {
    match configured_source() {
        Some(source) => {
            println!("cargo:rerun-if-changed={}", source.display());
            source
        }
        None => default_tls_uprobe_source(),
    }
}

fn default_tls_uprobe_source() -> PathBuf {
    let path = default_tls_uprobe_path();
    build_first_party_ebpf_artifacts();
    if !path.exists() {
        panic!(
            "default TLS uprobe object {} was not produced by the eBPF build",
            path.display()
        );
    }
    path
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
                "failed to run first-party eBPF build for TLS uprobe embedding: {error}; install nightly rust-src and {BPF_LINKER}"
            )
        });
    if !status.success() {
        panic!(
            "first-party eBPF build failed with {status}; install nightly rust-src and {BPF_LINKER}"
        );
    }
}

fn embed_tls_uprobe_object(source: &Path, out_path: &Path) {
    let preflight =
        EbpfObjectProbe::preflight(&EbpfObjectArtifact::TlsPlaintext.probe_config(source))
            .unwrap_or_else(|report| {
                panic!(
                    "failed to embed TLS uprobe object {}: {}",
                    source.display(),
                    report.summary()
                )
            });
    fs::write(out_path, preflight.bytes()).unwrap_or_else(|error| {
        panic!(
            "failed to write embedded TLS uprobe object {}: {error}",
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
