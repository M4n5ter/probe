use std::path::PathBuf;

use aya::programs::ProgramError;
use thiserror::Error;

use crate::tls::{
    LibsslUprobeAttachKind, LibsslUprobeProcessGenerationFailure, LibsslUprobeSymbolFailure,
};

#[derive(Debug, Error)]
pub(in crate::tls::plaintext) enum LibsslUprobeAttachError {
    #[error("libssl uprobe attach plan has no attachable probes")]
    EmptyAttachPlan,
    #[error("libssl uprobe attach startup was cancelled")]
    StartupCancelled,
    #[error("libssl uprobe target pid {pid} cannot be represented as a Linux pid_t")]
    InvalidTargetPid { pid: u32 },
    #[error("eBPF TLS plaintext object is missing program {name}")]
    MissingProgram { name: &'static str },
    #[error("failed to {action} eBPF TLS plaintext program {name}: {source}")]
    Program {
        name: &'static str,
        action: &'static str,
        source: Box<ProgramError>,
    },
    #[error("eBPF TLS plaintext program {name} has {actual} kind, expected {expected:?}")]
    ProgramKind {
        name: &'static str,
        actual: &'static str,
        expected: LibsslUprobeAttachKind,
    },
    #[error(
        "failed to attach eBPF TLS plaintext program {program_name} to {library_symbol} for pid {pid} at {target_path}: {source}"
    )]
    Attach {
        program_name: &'static str,
        library_symbol: &'static str,
        pid: u32,
        target_path: PathBuf,
        source: Box<ProgramError>,
    },
    #[error("failed to rollback eBPF TLS plaintext attach for program {program_name}: {source}")]
    RollbackAttach {
        program_name: &'static str,
        source: Box<ProgramError>,
    },
    #[error(
        "failed to detach eBPF TLS plaintext program {program_name} from pid {pid} at {target_path}: {source}"
    )]
    Detach {
        program_name: &'static str,
        pid: u32,
        target_path: PathBuf,
        source: Box<ProgramError>,
    },
    #[error("libssl uprobe attach target for pid {pid} is no longer valid: {source}")]
    AttachTarget {
        pid: u32,
        source: Box<LibsslUprobeSymbolFailure>,
    },
    #[error("libssl uprobe attach target process for pid {pid} is no longer valid: {source}")]
    AttachProcess {
        pid: u32,
        source: Box<LibsslUprobeProcessGenerationFailure>,
    },
    #[error("unsafe partial libssl uprobe attach for pid {pid} at {target_path}: {reason}")]
    UnsafePartialTarget {
        pid: u32,
        target_path: PathBuf,
        reason: &'static str,
    },
}
