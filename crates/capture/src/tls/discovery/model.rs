use std::path::PathBuf;

use ebpf_abi::{EbpfTlsDirection, EbpfTlsLibsslSymbol, EbpfTlsUprobeRole};
use probe_core::{Direction, ProcessGeneration};
use thiserror::Error;

pub type LibsslUprobeSymbol = EbpfTlsLibsslSymbol;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibsslUprobeTargetDiscoveryReport {
    process: ProcessGeneration,
    targets: Vec<LibsslUprobeTarget>,
    degraded_reasons: Vec<LibsslUprobeDegradationReason>,
    process_verifier: LibsslUprobeProcessVerifier,
}

impl LibsslUprobeTargetDiscoveryReport {
    pub(in crate::tls) fn new(
        process: ProcessGeneration,
        process_verifier: LibsslUprobeProcessVerifier,
        targets: Vec<LibsslUprobeTarget>,
        degraded_reasons: Vec<LibsslUprobeDegradationReason>,
    ) -> Self {
        Self {
            process,
            targets,
            degraded_reasons,
            process_verifier,
        }
    }

    pub fn process(&self) -> ProcessGeneration {
        self.process
    }

    pub fn targets(&self) -> &[LibsslUprobeTarget] {
        &self.targets
    }

    pub fn degraded_reasons(&self) -> &[LibsslUprobeDegradationReason] {
        &self.degraded_reasons
    }

    pub(in crate::tls) fn into_attach_parts(
        self,
    ) -> (
        ProcessGeneration,
        LibsslUprobeProcessVerifier,
        Vec<LibsslUprobeTarget>,
        Vec<LibsslUprobeDegradationReason>,
    ) {
        (
            self.process,
            self.process_verifier,
            self.targets,
            self.degraded_reasons,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::tls) struct LibsslUprobeProcessVerifier {
    proc_root: PathBuf,
}

impl LibsslUprobeProcessVerifier {
    pub(in crate::tls) fn new(proc_root: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: proc_root.into(),
        }
    }

    pub(in crate::tls) fn stat_path(&self, pid: u32) -> PathBuf {
        self.proc_root.join(pid.to_string()).join("stat")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibsslUprobeTarget {
    pub library: LibsslMappedLibrary,
    pub library_kind: LibsslLibraryKind,
    pub executable_mappings: Vec<LibsslExecutableMapping>,
    pub symbols: Vec<LibsslUprobeSymbol>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LibsslMappedLibrary {
    pub mapped_path: PathBuf,
    pub read_path: PathBuf,
    pub identity: LibsslMappedFileIdentity,
    pub deleted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LibsslMappedFileIdentity {
    pub device_major: u32,
    pub device_minor: u32,
    pub inode: u64,
}

impl std::fmt::Display for LibsslMappedFileIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "device {:02x}:{:02x} inode {}",
            self.device_major, self.device_minor, self.inode
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibsslExecutableMapping {
    pub start_address: u64,
    pub end_address: u64,
    pub file_offset: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LibsslLibraryKind {
    OpenSslLike,
    BoringSslLike,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LibsslUprobeSymbolRole {
    Plaintext { direction: Direction },
    FdAssociation,
    StateReset,
    StateCleanup,
}

impl LibsslUprobeSymbolRole {
    pub(crate) fn from_ebpf_role(role: EbpfTlsUprobeRole) -> Self {
        match role {
            EbpfTlsUprobeRole::Plaintext { direction } => Self::Plaintext {
                direction: direction_from_ebpf_contract(direction),
            },
            EbpfTlsUprobeRole::FdAssociation => Self::FdAssociation,
            EbpfTlsUprobeRole::StateReset => Self::StateReset,
            EbpfTlsUprobeRole::StateCleanup => Self::StateCleanup,
        }
    }
}

fn direction_from_ebpf_contract(direction: EbpfTlsDirection) -> Direction {
    match direction {
        EbpfTlsDirection::Inbound => Direction::Inbound,
        EbpfTlsDirection::Outbound => Direction::Outbound,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LibsslUprobeDegradationReason {
    #[error(
        "TLS library mapping {mapped_path} for pid {pid} is deleted; refusing to plan uprobes against a possibly replaced path"
    )]
    DeletedMapping { pid: u32, mapped_path: PathBuf },
    #[error("TLS library {mapped_path} has no supported SSL_read/write plaintext symbols")]
    UnsupportedSymbols { mapped_path: PathBuf },
    #[error("failed to resolve symbols for TLS library {mapped_path}: {reason}")]
    SymbolResolutionFailed {
        mapped_path: PathBuf,
        reason: LibsslUprobeSymbolFailure,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LibsslUprobeSymbolFailure {
    #[error("failed to inspect TLS library {path}: {reason}")]
    InspectLibrary { path: PathBuf, reason: String },
    #[error("TLS library {path} is not a regular file")]
    NotRegular { path: PathBuf },
    #[error("TLS library {path} is too large: {size} bytes exceeds {limit} bytes")]
    TooLarge {
        path: PathBuf,
        size: u64,
        limit: u64,
    },
    #[error(
        "TLS library {read_path} no longer matches mapped file {mapped_path}: expected {expected_identity}, got {actual_identity}"
    )]
    MappedLibraryChanged {
        mapped_path: PathBuf,
        read_path: PathBuf,
        expected_identity: LibsslMappedFileIdentity,
        actual_identity: LibsslMappedFileIdentity,
    },
    #[error("failed to read TLS library {path}: {reason}")]
    ReadLibrary { path: PathBuf, reason: String },
    #[error("failed to parse TLS library {path}: {reason}")]
    ParseLibrary { path: PathBuf, reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LibsslUprobeProcessGenerationFailure {
    #[error("failed to read process stat {path}: {reason}")]
    ReadStat { path: PathBuf, reason: String },
    #[error("invalid process stat {path}: {reason}")]
    InvalidStat { path: PathBuf, reason: String },
    #[error(
        "process stat {path} no longer matches expected starttime: expected {expected_start_time_ticks}, got {actual_start_time_ticks}"
    )]
    Changed {
        path: PathBuf,
        expected_start_time_ticks: u64,
        actual_start_time_ticks: u64,
    },
}

#[derive(Debug, Error)]
pub enum LibsslUprobeDiscoveryError {
    #[error("failed to read proc maps for pid {pid} at {path}: {source}")]
    ReadMaps {
        pid: u32,
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid proc maps line {line_number} for pid {pid}: {reason}")]
    InvalidMaps {
        pid: u32,
        line_number: usize,
        reason: String,
    },
    #[error("failed to verify process generation for pid {pid}: {reason}")]
    ProcessGeneration {
        pid: u32,
        reason: LibsslUprobeProcessGenerationFailure,
    },
}
