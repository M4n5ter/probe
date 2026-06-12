use std::path::PathBuf;

use thiserror::Error;

pub(super) const SUPPORTED_LIBSSL_SYMBOLS: [LibsslUprobeSymbol; 4] = [
    LibsslUprobeSymbol::SslRead,
    LibsslUprobeSymbol::SslWrite,
    LibsslUprobeSymbol::SslReadEx,
    LibsslUprobeSymbol::SslWriteEx,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibsslUprobeTargetDiscoveryReport {
    pub pid: u32,
    pub targets: Vec<LibsslUprobeTarget>,
    pub degraded_reasons: Vec<LibsslUprobeDegradationReason>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibsslUprobeTarget {
    pub pid: u32,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LibsslUprobeSymbol {
    SslRead,
    SslWrite,
    SslReadEx,
    SslWriteEx,
}

impl LibsslUprobeSymbol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SslRead => "SSL_read",
            Self::SslWrite => "SSL_write",
            Self::SslReadEx => "SSL_read_ex",
            Self::SslWriteEx => "SSL_write_ex",
        }
    }

    pub(super) fn from_name(name: &str) -> Option<Self> {
        let stable_name = name.split('@').next().unwrap_or(name);
        SUPPORTED_LIBSSL_SYMBOLS
            .into_iter()
            .find(|symbol| symbol.as_str() == stable_name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LibsslUprobeDegradationReason {
    #[error(
        "TLS library mapping {mapped_path} for pid {pid} is deleted; refusing to plan uprobes against a possibly replaced path"
    )]
    DeletedMapping { pid: u32, mapped_path: PathBuf },
    #[error("TLS library {mapped_path} has no supported SSL_read/write symbols")]
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
}
