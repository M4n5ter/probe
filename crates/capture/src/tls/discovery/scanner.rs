use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use probe_core::{ProcessGeneration, parse_linux_proc_stat};

use super::{
    model::{
        LibsslExecutableMapping, LibsslLibraryKind, LibsslMappedLibrary,
        LibsslUprobeDegradationReason, LibsslUprobeDiscoveryError,
        LibsslUprobeProcessGenerationFailure, LibsslUprobeProcessVerifier, LibsslUprobeSymbol,
        LibsslUprobeTarget, LibsslUprobeTargetDiscoveryReport,
    },
    proc_maps::{classify_libssl_path, parse_proc_maps_entry, strip_root},
    symbol::{LibsslSymbolResolver, ObjectLibsslSymbolResolver, stable_symbol_order},
};

const PROC_ROOT: &str = "/proc";

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
        let process_verifier = LibsslUprobeProcessVerifier::new(self.proc_root.clone());
        let process = read_process_generation(pid, &process_verifier)
            .map_err(|reason| LibsslUprobeDiscoveryError::ProcessGeneration { pid, reason })?;
        let maps_path = self.proc_root.join(pid.to_string()).join("maps");
        let maps = fs::read_to_string(&maps_path).map_err(|source| {
            LibsslUprobeDiscoveryError::ReadMaps {
                pid,
                path: maps_path,
                source,
            }
        })?;
        let report = discover_targets(
            pid,
            process,
            process_verifier.clone(),
            &self.proc_root,
            &maps,
            symbol_resolver,
        )?;
        verify_current_process_generation(process, &process_verifier)
            .map_err(|reason| LibsslUprobeDiscoveryError::ProcessGeneration { pid, reason })?;
        Ok(report)
    }
}

impl Default for LibsslUprobeTargetDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CandidateLibrary {
    library: LibsslMappedLibrary,
    library_kind: LibsslLibraryKind,
    mappings: Vec<LibsslExecutableMapping>,
}

fn discover_targets(
    pid: u32,
    process: ProcessGeneration,
    process_verifier: LibsslUprobeProcessVerifier,
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
            Ok(symbols) if has_plaintext_symbol(&symbols) => targets.push(LibsslUprobeTarget {
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

    Ok(LibsslUprobeTargetDiscoveryReport::new(
        process,
        process_verifier,
        targets,
        degraded_reasons,
    ))
}

pub(in crate::tls) fn verify_current_process_generation(
    process: ProcessGeneration,
    process_verifier: &LibsslUprobeProcessVerifier,
) -> Result<(), LibsslUprobeProcessGenerationFailure> {
    let current = read_process_generation(process.pid, process_verifier)?;
    if current.start_time_ticks != process.start_time_ticks {
        let path = process_verifier.stat_path(process.pid);
        return Err(LibsslUprobeProcessGenerationFailure::Changed {
            path,
            expected_start_time_ticks: process.start_time_ticks,
            actual_start_time_ticks: current.start_time_ticks,
        });
    }
    Ok(())
}

fn read_process_generation(
    pid: u32,
    process_verifier: &LibsslUprobeProcessVerifier,
) -> Result<ProcessGeneration, LibsslUprobeProcessGenerationFailure> {
    let stat_path = process_verifier.stat_path(pid);
    let stat = fs::read_to_string(&stat_path).map_err(|source| {
        LibsslUprobeProcessGenerationFailure::ReadStat {
            path: stat_path.clone(),
            reason: source.to_string(),
        }
    })?;
    let start_time_ticks = parse_linux_proc_stat(&stat)
        .map(|stat| stat.start_time_ticks)
        .map_err(|source| LibsslUprobeProcessGenerationFailure::InvalidStat {
            path: stat_path.clone(),
            reason: source.to_string(),
        })?;
    Ok(ProcessGeneration {
        pid,
        start_time_ticks,
    })
}

fn has_plaintext_symbol(symbols: &[LibsslUprobeSymbol]) -> bool {
    symbols.iter().any(|symbol| symbol.captures_plaintext())
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, path::Path};

    use tempfile::tempdir;

    use super::super::model::{
        LibsslMappedFileIdentity, LibsslUprobeSymbol, LibsslUprobeSymbolFailure,
    };
    use super::*;

    #[test]
    fn discovery_finds_executable_libssl_mapping_with_supported_symbols()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = tempdir()?;
        let pid = 4242;
        let pid_dir = proc.path().join(pid.to_string());
        fs::create_dir_all(&pid_dir)?;
        write_stat(&pid_dir, 424242)?;
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
        let targets = report.targets();

        assert_eq!(report.process().pid, pid);
        assert!(report.degraded_reasons().is_empty());
        assert_eq!(targets.len(), 2);
        assert_eq!(
            targets[0].library.mapped_path,
            PathBuf::from("/opt/boringssl/libboringssl.so")
        );
        assert_eq!(
            targets[0].library.read_path,
            proc.path()
                .join(pid.to_string())
                .join("root")
                .join("opt/boringssl/libboringssl.so")
        );
        assert_eq!(
            targets[0].library.identity,
            LibsslMappedFileIdentity {
                device_major: 0x08,
                device_minor: 0x01,
                inode: 3,
            }
        );
        assert!(!targets[0].library.deleted);
        assert_eq!(targets[0].library_kind, LibsslLibraryKind::BoringSslLike);
        assert_eq!(targets[0].symbols, vec![LibsslUprobeSymbol::SslWriteEx]);
        assert_eq!(
            targets[1].library.mapped_path,
            PathBuf::from("/usr/lib/libssl.so.3")
        );
        assert_eq!(
            targets[1].library.read_path,
            proc.path()
                .join(pid.to_string())
                .join("root")
                .join("usr/lib/libssl.so.3")
        );
        assert_eq!(
            targets[1].library.identity,
            LibsslMappedFileIdentity {
                device_major: 0x08,
                device_minor: 0x01,
                inode: 1,
            }
        );
        assert!(!targets[1].library.deleted);
        assert_eq!(targets[1].library_kind, LibsslLibraryKind::OpenSslLike);
        assert_eq!(
            targets[1].symbols,
            vec![
                LibsslUprobeSymbol::SslRead,
                LibsslUprobeSymbol::SslWrite,
                LibsslUprobeSymbol::SslReadEx,
            ]
        );
        assert_eq!(
            targets[1].executable_mappings,
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
        write_stat(&pid_dir, 700)?;
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

        assert!(report.targets().is_empty());
        assert_eq!(report.degraded_reasons().len(), 1);
        assert!(matches!(
            &report.degraded_reasons()[0],
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
        write_stat(&pid_dir, 800)?;
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

        assert!(report.targets().is_empty());
        assert_eq!(report.degraded_reasons().len(), 1);
        assert!(matches!(
            &report.degraded_reasons()[0],
            LibsslUprobeDegradationReason::SymbolResolutionFailed {
                mapped_path,
                reason: LibsslUprobeSymbolFailure::ParseLibrary { reason, .. },
            } if mapped_path == &PathBuf::from("/usr/lib/libssl.so.3") && reason == "not an ELF object"
        ));
        Ok(())
    }

    #[test]
    fn discovery_rejects_library_with_lifecycle_symbols_but_no_plaintext_symbol()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = tempdir()?;
        let pid = 10;
        let pid_dir = proc.path().join(pid.to_string());
        fs::create_dir_all(&pid_dir)?;
        write_stat(&pid_dir, 1000)?;
        fs::write(
            pid_dir.join("maps"),
            "7f0000001000-7f0000010000 r-xp 00001000 08:01 1 /usr/lib/libssl.so.3\n",
        )?;
        let resolver = FakeSymbolResolver::new([(
            PathBuf::from("/usr/lib/libssl.so.3"),
            FakeSymbolResponse::Symbols(vec![
                LibsslUprobeSymbol::SslSetFd,
                LibsslUprobeSymbol::SslClear,
                LibsslUprobeSymbol::SslFree,
            ]),
        )]);
        let discovery = LibsslUprobeTargetDiscovery::with_proc_root(proc.path());

        let report = discovery.discover_for_pid_with_symbol_resolver(pid, &resolver)?;

        assert!(report.targets().is_empty());
        assert_eq!(report.degraded_reasons().len(), 1);
        assert!(matches!(
            &report.degraded_reasons()[0],
            LibsslUprobeDegradationReason::UnsupportedSymbols { mapped_path }
                if mapped_path == &PathBuf::from("/usr/lib/libssl.so.3")
        ));
        Ok(())
    }

    #[test]
    fn discovery_rejects_malformed_maps() -> Result<(), Box<dyn std::error::Error>> {
        let proc = tempdir()?;
        let pid = 9;
        let pid_dir = proc.path().join(pid.to_string());
        fs::create_dir_all(&pid_dir)?;
        write_stat(&pid_dir, 900)?;
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
    fn discovery_rejects_pid_reuse_during_target_resolution()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = tempdir()?;
        let pid = 11;
        let pid_dir = proc.path().join(pid.to_string());
        fs::create_dir_all(&pid_dir)?;
        write_stat(&pid_dir, 1100)?;
        fs::write(
            pid_dir.join("maps"),
            "7f0000001000-7f0000010000 r-xp 00001000 08:01 1 /usr/lib/libssl.so.3\n",
        )?;
        let resolver = FakeSymbolResolver::new([(
            PathBuf::from("/usr/lib/libssl.so.3"),
            FakeSymbolResponse::Symbols(vec![LibsslUprobeSymbol::SslRead]),
        )])
        .with_stat_rewrite(pid_dir.clone(), 1101);
        let discovery = LibsslUprobeTargetDiscovery::with_proc_root(proc.path());

        let error = discovery
            .discover_for_pid_with_symbol_resolver(pid, &resolver)
            .expect_err("changed process starttime must reject discovery");

        assert!(matches!(
            error,
            LibsslUprobeDiscoveryError::ProcessGeneration {
                reason: LibsslUprobeProcessGenerationFailure::Changed {
                    expected_start_time_ticks: 1100,
                    actual_start_time_ticks: 1101,
                    ..
                },
                ..
            }
        ));
        Ok(())
    }

    #[derive(Debug, Clone)]
    struct FakeSymbolResolver {
        responses: BTreeMap<PathBuf, FakeSymbolResponse>,
        stat_rewrite: Option<(PathBuf, u64)>,
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
                stat_rewrite: None,
            }
        }

        fn with_stat_rewrite(mut self, pid_dir: PathBuf, start_time_ticks: u64) -> Self {
            self.stat_rewrite = Some((pid_dir, start_time_ticks));
            self
        }
    }

    impl LibsslSymbolResolver for FakeSymbolResolver {
        fn resolve_symbols(
            &self,
            library: &LibsslMappedLibrary,
        ) -> Result<Vec<LibsslUprobeSymbol>, LibsslUprobeSymbolFailure> {
            if let Some((pid_dir, start_time_ticks)) = &self.stat_rewrite {
                write_stat(pid_dir, *start_time_ticks).map_err(|source| {
                    LibsslUprobeSymbolFailure::ReadLibrary {
                        path: pid_dir.join("stat"),
                        reason: source.to_string(),
                    }
                })?;
            }
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

    fn write_stat(pid_dir: &Path, start_time_ticks: u64) -> std::io::Result<()> {
        let fields = std::iter::repeat_n("0", 18).collect::<Vec<_>>().join(" ");
        fs::write(
            pid_dir.join("stat"),
            format!("1 (openssl) S {fields} {start_time_ticks}\n"),
        )
    }
}
