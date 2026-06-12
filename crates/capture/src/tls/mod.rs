mod attach_plan;

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Path, PathBuf},
};

#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;

use object::{Object, ObjectSymbol};
use thiserror::Error;

pub use attach_plan::{
    LibsslUprobeAttachKind, LibsslUprobeAttachPlan, LibsslUprobeAttachProbe,
    LibsslUprobeAttachRecipe, LibsslUprobeAttachTarget,
};

const PROC_ROOT: &str = "/proc";
const DELETED_MAPPING_SUFFIX: &str = " (deleted)";
const MAX_LIBSSL_OBJECT_BYTES: u64 = 128 * 1024 * 1024;
const SUPPORTED_LIBSSL_SYMBOLS: [LibsslUprobeSymbol; 4] = [
    LibsslUprobeSymbol::SslRead,
    LibsslUprobeSymbol::SslWrite,
    LibsslUprobeSymbol::SslReadEx,
    LibsslUprobeSymbol::SslWriteEx,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibsslUprobeTargetDiscovery {
    proc_root: PathBuf,
}

impl LibsslUprobeTargetDiscovery {
    pub fn new() -> Self {
        Self {
            proc_root: PathBuf::from(PROC_ROOT),
        }
    }

    pub fn with_proc_root(proc_root: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: proc_root.into(),
        }
    }

    pub fn discover_for_pid(
        &self,
        pid: u32,
    ) -> Result<LibsslUprobeTargetDiscoveryReport, LibsslUprobeDiscoveryError> {
        self.discover_for_pid_with_symbol_resolver(pid, &ObjectLibsslSymbolResolver)
    }

    fn discover_for_pid_with_symbol_resolver(
        &self,
        pid: u32,
        symbol_resolver: &impl LibsslSymbolResolver,
    ) -> Result<LibsslUprobeTargetDiscoveryReport, LibsslUprobeDiscoveryError> {
        let maps_path = self.proc_root.join(pid.to_string()).join("maps");
        let maps = fs::read_to_string(&maps_path).map_err(|source| {
            LibsslUprobeDiscoveryError::ReadMaps {
                pid,
                path: maps_path,
                source,
            }
        })?;
        discover_targets(pid, &self.proc_root, &maps, symbol_resolver)
    }
}

impl Default for LibsslUprobeTargetDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

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

    fn from_name(name: &str) -> Option<Self> {
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

trait LibsslSymbolResolver {
    fn resolve_symbols(
        &self,
        library: &LibsslMappedLibrary,
    ) -> Result<Vec<LibsslUprobeSymbol>, LibsslUprobeSymbolFailure>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ObjectLibsslSymbolResolver;

impl LibsslSymbolResolver for ObjectLibsslSymbolResolver {
    fn resolve_symbols(
        &self,
        library: &LibsslMappedLibrary,
    ) -> Result<Vec<LibsslUprobeSymbol>, LibsslUprobeSymbolFailure> {
        let mut file = fs::File::open(&library.read_path).map_err(|source| {
            LibsslUprobeSymbolFailure::InspectLibrary {
                path: library.read_path.clone(),
                reason: source.to_string(),
            }
        })?;
        let metadata =
            file.metadata()
                .map_err(|source| LibsslUprobeSymbolFailure::InspectLibrary {
                    path: library.read_path.clone(),
                    reason: source.to_string(),
                })?;
        if !metadata.is_file() {
            return Err(LibsslUprobeSymbolFailure::NotRegular {
                path: library.read_path.clone(),
            });
        }
        ensure_mapped_library_identity(&metadata, library)?;
        ensure_library_size(&library.read_path, metadata.len())?;
        let bytes = read_limited_object_bytes(&library.read_path, &mut file, metadata.len())?;
        let object = object::File::parse(bytes.as_slice()).map_err(|source| {
            LibsslUprobeSymbolFailure::ParseLibrary {
                path: library.read_path.clone(),
                reason: source.to_string(),
            }
        })?;
        let mut symbols = BTreeSet::new();
        for symbol in object.dynamic_symbols().chain(object.symbols()) {
            if !is_attachable_symbol_definition(&symbol) {
                continue;
            }
            if let Ok(name) = symbol.name()
                && let Some(symbol) = LibsslUprobeSymbol::from_name(name)
            {
                symbols.insert(symbol);
            }
        }
        Ok(SUPPORTED_LIBSSL_SYMBOLS
            .into_iter()
            .filter(|symbol| symbols.contains(symbol))
            .collect())
    }
}

fn ensure_library_size(path: &Path, size: u64) -> Result<(), LibsslUprobeSymbolFailure> {
    if size > MAX_LIBSSL_OBJECT_BYTES {
        return Err(LibsslUprobeSymbolFailure::TooLarge {
            path: path.to_path_buf(),
            size,
            limit: MAX_LIBSSL_OBJECT_BYTES,
        });
    }
    Ok(())
}

fn read_limited_object_bytes(
    path: &Path,
    file: &mut fs::File,
    checked_size: u64,
) -> Result<Vec<u8>, LibsslUprobeSymbolFailure> {
    let max_size = usize::try_from(MAX_LIBSSL_OBJECT_BYTES).expect("object byte limit fits usize");
    let mut bytes = Vec::new();
    let mut limited = file.take(MAX_LIBSSL_OBJECT_BYTES + 1);
    let mut buffer = [0_u8; 8192];
    loop {
        let read =
            limited
                .read(&mut buffer)
                .map_err(|source| LibsslUprobeSymbolFailure::ReadLibrary {
                    path: path.to_path_buf(),
                    reason: source.to_string(),
                })?;
        if read == 0 {
            break;
        }
        if bytes.len().saturating_add(read) > max_size {
            return Err(LibsslUprobeSymbolFailure::TooLarge {
                path: path.to_path_buf(),
                size: checked_size.max(MAX_LIBSSL_OBJECT_BYTES + 1),
                limit: MAX_LIBSSL_OBJECT_BYTES,
            });
        }
        bytes
            .try_reserve(read)
            .map_err(|_| LibsslUprobeSymbolFailure::TooLarge {
                path: path.to_path_buf(),
                size: checked_size,
                limit: MAX_LIBSSL_OBJECT_BYTES,
            })?;
        bytes.extend_from_slice(&buffer[..read]);
    }
    Ok(bytes)
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcMapsEntry {
    start_address: u64,
    end_address: u64,
    executable: bool,
    file_offset: u64,
    identity: LibsslMappedFileIdentity,
    path: Option<MappedPath>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CandidateLibrary {
    library: LibsslMappedLibrary,
    library_kind: LibsslLibraryKind,
    mappings: Vec<LibsslExecutableMapping>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MappedPath {
    path: PathBuf,
    deleted: bool,
}

fn discover_targets(
    pid: u32,
    proc_root: &Path,
    maps: &str,
    symbol_resolver: &impl LibsslSymbolResolver,
) -> Result<LibsslUprobeTargetDiscoveryReport, LibsslUprobeDiscoveryError> {
    let mut candidates = BTreeMap::<LibsslMappedLibrary, CandidateLibrary>::new();
    let mut degraded_reasons = Vec::new();
    for (index, line) in maps.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let entry = parse_proc_maps_entry(line).map_err(|reason| {
            LibsslUprobeDiscoveryError::InvalidMaps {
                pid,
                line_number: index + 1,
                reason,
            }
        })?;
        if !entry.executable {
            continue;
        }
        let Some(mapped_path) = entry.path else {
            continue;
        };
        let Some(library_kind) = classify_libssl_path(&mapped_path.path) else {
            continue;
        };
        if mapped_path.deleted {
            degraded_reasons.push(LibsslUprobeDegradationReason::DeletedMapping {
                pid,
                mapped_path: mapped_path.path,
            });
            continue;
        }
        let library = LibsslMappedLibrary {
            read_path: proc_root
                .join(pid.to_string())
                .join("root")
                .join(strip_root(&mapped_path.path)),
            mapped_path: mapped_path.path,
            identity: entry.identity,
            deleted: mapped_path.deleted,
        };
        let executable_mapping = LibsslExecutableMapping {
            start_address: entry.start_address,
            end_address: entry.end_address,
            file_offset: entry.file_offset,
        };
        candidates
            .entry(library.clone())
            .and_modify(|candidate| candidate.mappings.push(executable_mapping.clone()))
            .or_insert_with(|| CandidateLibrary {
                library,
                library_kind,
                mappings: vec![executable_mapping],
            });
    }

    let mut targets = Vec::new();
    for (_library, candidate) in candidates {
        match symbol_resolver
            .resolve_symbols(&candidate.library)
            .map(stable_symbol_order)
        {
            Ok(symbols) if !symbols.is_empty() => targets.push(LibsslUprobeTarget {
                pid,
                library: candidate.library,
                library_kind: candidate.library_kind,
                executable_mappings: candidate.mappings,
                symbols,
            }),
            Ok(_) => degraded_reasons.push(LibsslUprobeDegradationReason::UnsupportedSymbols {
                mapped_path: candidate.library.mapped_path,
            }),
            Err(error) => {
                degraded_reasons.push(LibsslUprobeDegradationReason::SymbolResolutionFailed {
                    mapped_path: candidate.library.mapped_path,
                    reason: error,
                });
            }
        }
    }

    Ok(LibsslUprobeTargetDiscoveryReport {
        pid,
        targets,
        degraded_reasons,
    })
}

fn stable_symbol_order(symbols: Vec<LibsslUprobeSymbol>) -> Vec<LibsslUprobeSymbol> {
    let symbols = symbols.into_iter().collect::<BTreeSet<_>>();
    SUPPORTED_LIBSSL_SYMBOLS
        .into_iter()
        .filter(|symbol| symbols.contains(symbol))
        .collect()
}

fn is_attachable_symbol_definition<'data>(symbol: &impl ObjectSymbol<'data>) -> bool {
    symbol.is_definition() && !symbol.is_undefined() && symbol.kind() == object::SymbolKind::Text
}

#[cfg(target_os = "linux")]
fn ensure_mapped_library_identity(
    metadata: &fs::Metadata,
    library: &LibsslMappedLibrary,
) -> Result<(), LibsslUprobeSymbolFailure> {
    let actual_identity = LibsslMappedFileIdentity::from_linux_metadata(metadata);
    if actual_identity == library.identity {
        return Ok(());
    }

    Err(LibsslUprobeSymbolFailure::MappedLibraryChanged {
        mapped_path: library.mapped_path.clone(),
        read_path: library.read_path.clone(),
        expected_identity: library.identity,
        actual_identity,
    })
}

#[cfg(not(target_os = "linux"))]
fn ensure_mapped_library_identity(
    _metadata: &fs::Metadata,
    _library: &LibsslMappedLibrary,
) -> Result<(), LibsslUprobeSymbolFailure> {
    Ok(())
}

fn parse_proc_maps_entry(line: &str) -> Result<ProcMapsEntry, String> {
    let (address_range, rest) =
        take_field(line).ok_or_else(|| "missing address range".to_string())?;
    let (permissions, rest) = take_field(rest).ok_or_else(|| "missing permissions".to_string())?;
    let (offset, rest) = take_field(rest).ok_or_else(|| "missing file offset".to_string())?;
    let (device, rest) = take_field(rest).ok_or_else(|| "missing device".to_string())?;
    let (inode, pathname) = take_field(rest).ok_or_else(|| "missing inode".to_string())?;
    let (start_address, end_address) = parse_address_range(address_range)?;
    let file_offset = parse_hex_u64(offset, "file offset")?;
    let (device_major, device_minor) = parse_proc_map_device(device)?;
    let inode = inode
        .parse::<u64>()
        .map_err(|error| format!("invalid inode {inode}: {error}"))?;
    let path = normalize_proc_maps_path(pathname.trim_start());

    Ok(ProcMapsEntry {
        start_address,
        end_address,
        executable: permissions
            .as_bytes()
            .get(2)
            .is_some_and(|byte| *byte == b'x'),
        file_offset,
        identity: LibsslMappedFileIdentity {
            device_major,
            device_minor,
            inode,
        },
        path,
    })
}

fn take_field(input: &str) -> Option<(&str, &str)> {
    let input = input.trim_start();
    if input.is_empty() {
        return None;
    }
    match input.find(char::is_whitespace) {
        Some(index) => Some((&input[..index], &input[index..])),
        None => Some((input, "")),
    }
}

fn parse_address_range(value: &str) -> Result<(u64, u64), String> {
    let (start, end) = value
        .split_once('-')
        .ok_or_else(|| format!("invalid address range {value}"))?;
    let start = parse_hex_u64(start, "range start")?;
    let end = parse_hex_u64(end, "range end")?;
    if end <= start {
        return Err(format!(
            "invalid address range {value}: end must exceed start"
        ));
    }
    Ok((start, end))
}

fn parse_hex_u64(value: &str, label: &str) -> Result<u64, String> {
    u64::from_str_radix(value, 16).map_err(|error| format!("invalid {label} {value}: {error}"))
}

impl LibsslMappedFileIdentity {
    #[cfg(target_os = "linux")]
    fn from_linux_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device_major: rustix::fs::major(metadata.dev()),
            device_minor: rustix::fs::minor(metadata.dev()),
            inode: metadata.ino(),
        }
    }
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

fn parse_proc_map_device(value: &str) -> Result<(u32, u32), String> {
    let (major, minor) = value
        .split_once(':')
        .ok_or_else(|| format!("invalid device {value}"))?;
    Ok((
        parse_hex_u32(major, "device major")?,
        parse_hex_u32(minor, "device minor")?,
    ))
}

fn parse_hex_u32(value: &str, label: &str) -> Result<u32, String> {
    u32::from_str_radix(value, 16).map_err(|error| format!("invalid {label} {value}: {error}"))
}

fn normalize_proc_maps_path(value: &str) -> Option<MappedPath> {
    if value.is_empty() || !value.starts_with('/') {
        return None;
    }
    let deleted = value.ends_with(DELETED_MAPPING_SUFFIX);
    Some(MappedPath {
        path: PathBuf::from(value.strip_suffix(DELETED_MAPPING_SUFFIX).unwrap_or(value)),
        deleted,
    })
}

fn strip_root(path: &Path) -> &Path {
    path.strip_prefix("/").unwrap_or(path)
}

fn classify_libssl_path(path: &Path) -> Option<LibsslLibraryKind> {
    let file_name = path.file_name()?.to_string_lossy().to_ascii_lowercase();
    if file_name.contains("boringssl") {
        return Some(LibsslLibraryKind::BoringSslLike);
    }
    if file_name.contains("libssl") {
        return Some(LibsslLibraryKind::OpenSslLike);
    }
    None
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs};

    use tempfile::tempdir;

    use super::*;
    use elf_fixture::minimal_elf_with_ssl_read_symbol;

    mod elf_fixture;

    #[test]
    fn discovery_finds_executable_libssl_mapping_with_supported_symbols()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = tempdir()?;
        let pid = 4242;
        let pid_dir = proc.path().join(pid.to_string());
        fs::create_dir_all(&pid_dir)?;
        fs::write(
            pid_dir.join("maps"),
            r#"
7f0000000000-7f0000001000 r--p 00000000 08:01 1 /usr/lib/libssl.so.3
7f0000001000-7f0000010000 r-xp 00001000 08:01 1 /usr/lib/libssl.so.3
7f0000010000-7f0000020000 r-xp 00000000 08:01 2 /usr/lib/libcrypto.so.3
7f0000020000-7f0000030000 r-xp 00000000 08:01 3 /opt/boringssl/libboringssl.so
"#,
        )?;
        let resolver = FakeSymbolResolver::new([
            (
                PathBuf::from("/usr/lib/libssl.so.3"),
                FakeSymbolResponse::Symbols(vec![
                    LibsslUprobeSymbol::SslWrite,
                    LibsslUprobeSymbol::SslRead,
                    LibsslUprobeSymbol::SslReadEx,
                ]),
            ),
            (
                PathBuf::from("/opt/boringssl/libboringssl.so"),
                FakeSymbolResponse::Symbols(vec![LibsslUprobeSymbol::SslWriteEx]),
            ),
        ]);
        let discovery = LibsslUprobeTargetDiscovery::with_proc_root(proc.path());

        let report = discovery.discover_for_pid_with_symbol_resolver(pid, &resolver)?;

        assert_eq!(report.pid, pid);
        assert!(report.degraded_reasons.is_empty());
        assert_eq!(report.targets.len(), 2);
        assert_eq!(
            report.targets[0].library.mapped_path,
            PathBuf::from("/opt/boringssl/libboringssl.so")
        );
        assert_eq!(
            report.targets[0].library.read_path,
            proc.path()
                .join(pid.to_string())
                .join("root")
                .join("opt/boringssl/libboringssl.so")
        );
        assert_eq!(
            report.targets[0].library.identity,
            LibsslMappedFileIdentity {
                device_major: 0x08,
                device_minor: 0x01,
                inode: 3,
            }
        );
        assert!(!report.targets[0].library.deleted);
        assert_eq!(
            report.targets[0].library_kind,
            LibsslLibraryKind::BoringSslLike
        );
        assert_eq!(
            report.targets[0].symbols,
            vec![LibsslUprobeSymbol::SslWriteEx]
        );
        assert_eq!(
            report.targets[1].library.mapped_path,
            PathBuf::from("/usr/lib/libssl.so.3")
        );
        assert_eq!(
            report.targets[1].library.read_path,
            proc.path()
                .join(pid.to_string())
                .join("root")
                .join("usr/lib/libssl.so.3")
        );
        assert_eq!(
            report.targets[1].library.identity,
            LibsslMappedFileIdentity {
                device_major: 0x08,
                device_minor: 0x01,
                inode: 1,
            }
        );
        assert!(!report.targets[1].library.deleted);
        assert_eq!(
            report.targets[1].library_kind,
            LibsslLibraryKind::OpenSslLike
        );
        assert_eq!(
            report.targets[1].symbols,
            vec![
                LibsslUprobeSymbol::SslRead,
                LibsslUprobeSymbol::SslWrite,
                LibsslUprobeSymbol::SslReadEx,
            ]
        );
        assert_eq!(
            report.targets[1].executable_mappings,
            vec![LibsslExecutableMapping {
                start_address: 0x7f0000001000,
                end_address: 0x7f0000010000,
                file_offset: 0x1000,
            }]
        );
        Ok(())
    }

    #[test]
    fn discovery_preserves_paths_with_spaces_and_rejects_deleted_mapping()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = tempdir()?;
        let pid = 7;
        let pid_dir = proc.path().join(pid.to_string());
        fs::create_dir_all(&pid_dir)?;
        fs::write(
            pid_dir.join("maps"),
            "7f0000001000-7f0000010000 r-xp 00001000 08:01 1 /opt/my app/libssl custom.so (deleted)\n",
        )?;
        let resolver = FakeSymbolResolver::new([(
            PathBuf::from("/opt/my app/libssl custom.so"),
            FakeSymbolResponse::Symbols(vec![LibsslUprobeSymbol::SslRead]),
        )]);
        let discovery = LibsslUprobeTargetDiscovery::with_proc_root(proc.path());

        let report = discovery.discover_for_pid_with_symbol_resolver(pid, &resolver)?;

        assert!(report.targets.is_empty());
        assert_eq!(report.degraded_reasons.len(), 1);
        assert!(matches!(
            &report.degraded_reasons[0],
            LibsslUprobeDegradationReason::DeletedMapping {
                pid: actual_pid,
                mapped_path,
            } if *actual_pid == pid && mapped_path == &PathBuf::from("/opt/my app/libssl custom.so")
        ));
        Ok(())
    }

    #[test]
    fn discovery_reports_degraded_reason_when_symbol_resolution_fails()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = tempdir()?;
        let pid = 8;
        let pid_dir = proc.path().join(pid.to_string());
        fs::create_dir_all(&pid_dir)?;
        fs::write(
            pid_dir.join("maps"),
            "7f0000001000-7f0000010000 r-xp 00001000 08:01 1 /usr/lib/libssl.so.3\n",
        )?;
        let resolver = FakeSymbolResolver::new([(
            PathBuf::from("/usr/lib/libssl.so.3"),
            FakeSymbolResponse::ParseError("not an ELF object".to_string()),
        )]);
        let discovery = LibsslUprobeTargetDiscovery::with_proc_root(proc.path());

        let report = discovery.discover_for_pid_with_symbol_resolver(pid, &resolver)?;

        assert!(report.targets.is_empty());
        assert_eq!(report.degraded_reasons.len(), 1);
        assert!(matches!(
            &report.degraded_reasons[0],
            LibsslUprobeDegradationReason::SymbolResolutionFailed {
                mapped_path,
                reason: LibsslUprobeSymbolFailure::ParseLibrary { reason, .. },
            } if mapped_path == &PathBuf::from("/usr/lib/libssl.so.3") && reason == "not an ELF object"
        ));
        Ok(())
    }

    #[test]
    fn discovery_rejects_malformed_maps() -> Result<(), Box<dyn std::error::Error>> {
        let proc = tempdir()?;
        let pid = 9;
        let pid_dir = proc.path().join(pid.to_string());
        fs::create_dir_all(&pid_dir)?;
        fs::write(pid_dir.join("maps"), "not-a-map-line\n")?;
        let resolver = FakeSymbolResolver::new([]);
        let discovery = LibsslUprobeTargetDiscovery::with_proc_root(proc.path());

        let error = discovery
            .discover_for_pid_with_symbol_resolver(pid, &resolver)
            .expect_err("malformed proc maps must reject discovery");

        assert!(matches!(
            error,
            LibsslUprobeDiscoveryError::InvalidMaps { pid: actual, line_number: 1, .. }
                if actual == pid
        ));
        Ok(())
    }

    #[test]
    fn object_symbol_resolver_rejects_invalid_object_file() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = tempdir()?;
        let path = temp.path().join("libssl.so");
        fs::write(&path, b"not an object")?;
        let library = mapped_library(&path)?;

        let error = ObjectLibsslSymbolResolver
            .resolve_symbols(&library)
            .expect_err("invalid object file must be rejected");

        assert!(matches!(
            error,
            LibsslUprobeSymbolFailure::ParseLibrary { path: actual, .. } if actual == path
        ));
        Ok(())
    }

    #[test]
    fn object_symbol_resolver_finds_defined_text_symbol_with_version_suffix()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let path = temp.path().join("libssl.so");
        fs::write(&path, minimal_elf_with_ssl_read_symbol())?;
        let library = mapped_library(&path)?;

        let symbols = ObjectLibsslSymbolResolver.resolve_symbols(&library)?;

        assert_eq!(symbols, vec![LibsslUprobeSymbol::SslRead]);
        Ok(())
    }

    #[test]
    fn object_symbol_resolver_rejects_oversized_library_before_reading()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let path = temp.path().join("libssl.so");
        let file = fs::File::create(&path)?;
        file.set_len(MAX_LIBSSL_OBJECT_BYTES + 1)?;
        let library = mapped_library(&path)?;

        let error = ObjectLibsslSymbolResolver
            .resolve_symbols(&library)
            .expect_err("oversized object file must be rejected");

        assert!(matches!(
            error,
            LibsslUprobeSymbolFailure::TooLarge { path: actual, .. } if actual == path
        ));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn object_symbol_resolver_rejects_library_identity_mismatch()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let path = temp.path().join("libssl.so");
        fs::write(&path, b"not an object")?;
        let mut library = mapped_library(&path)?;
        library.identity.inode += 1;

        let error = ObjectLibsslSymbolResolver
            .resolve_symbols(&library)
            .expect_err("library identity mismatch must be rejected before parsing");

        assert!(matches!(
            error,
            LibsslUprobeSymbolFailure::MappedLibraryChanged {
                read_path: actual_path,
                expected_identity,
                ..
            } if actual_path == path && expected_identity == library.identity
        ));
        Ok(())
    }

    #[derive(Debug, Clone)]
    struct FakeSymbolResolver {
        responses: BTreeMap<PathBuf, FakeSymbolResponse>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum FakeSymbolResponse {
        Symbols(Vec<LibsslUprobeSymbol>),
        ParseError(String),
    }

    impl FakeSymbolResolver {
        fn new(responses: impl IntoIterator<Item = (PathBuf, FakeSymbolResponse)>) -> Self {
            Self {
                responses: responses.into_iter().collect(),
            }
        }
    }

    impl LibsslSymbolResolver for FakeSymbolResolver {
        fn resolve_symbols(
            &self,
            library: &LibsslMappedLibrary,
        ) -> Result<Vec<LibsslUprobeSymbol>, LibsslUprobeSymbolFailure> {
            match self.responses.get(&library.mapped_path) {
                Some(FakeSymbolResponse::Symbols(symbols)) => Ok(symbols.clone()),
                Some(FakeSymbolResponse::ParseError(reason)) => {
                    Err(LibsslUprobeSymbolFailure::ParseLibrary {
                        path: library.read_path.clone(),
                        reason: reason.clone(),
                    })
                }
                None => Ok(Vec::new()),
            }
        }
    }

    fn mapped_library(read_path: &Path) -> Result<LibsslMappedLibrary, Box<dyn std::error::Error>> {
        let metadata = fs::metadata(read_path)?;
        #[cfg(target_os = "linux")]
        let identity = LibsslMappedFileIdentity::from_linux_metadata(&metadata);
        #[cfg(not(target_os = "linux"))]
        let identity = LibsslMappedFileIdentity {
            device_major: 0,
            device_minor: 0,
            inode: 0,
        };

        Ok(LibsslMappedLibrary {
            mapped_path: read_path.to_path_buf(),
            read_path: read_path.to_path_buf(),
            identity,
            deleted: false,
        })
    }
}
