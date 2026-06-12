use probe_core::Direction;

use super::{
    LibsslExecutableMapping, LibsslLibraryKind, LibsslMappedLibrary, LibsslUprobeDegradationReason,
    LibsslUprobeSymbol, LibsslUprobeTargetDiscoveryReport,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibsslUprobeAttachPlan {
    pub targets: Vec<LibsslUprobeAttachTarget>,
    pub degraded_reasons: Vec<LibsslUprobeDegradationReason>,
}

impl LibsslUprobeAttachPlan {
    pub fn from_discovery_report(report: LibsslUprobeTargetDiscoveryReport) -> Self {
        Self::from_discovery_reports([report])
    }

    pub fn from_discovery_reports(
        reports: impl IntoIterator<Item = LibsslUprobeTargetDiscoveryReport>,
    ) -> Self {
        let mut targets = Vec::new();
        let mut degraded_reasons = Vec::new();
        for report in reports {
            degraded_reasons.extend(report.degraded_reasons);
            targets.extend(
                report
                    .targets
                    .into_iter()
                    .map(LibsslUprobeAttachTarget::from),
            );
        }
        Self {
            targets,
            degraded_reasons,
        }
    }

    pub fn probe_count(&self) -> usize {
        self.targets
            .iter()
            .flat_map(|target| target.recipes.iter())
            .map(|recipe| recipe.probes.len())
            .sum()
    }

    pub fn has_attachable_probes(&self) -> bool {
        self.probe_count() > 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibsslUprobeAttachTarget {
    pub pid: u32,
    pub library: LibsslMappedLibrary,
    pub library_kind: LibsslLibraryKind,
    pub executable_mappings: Vec<LibsslExecutableMapping>,
    pub recipes: Vec<LibsslUprobeAttachRecipe>,
}

impl From<super::LibsslUprobeTarget> for LibsslUprobeAttachTarget {
    fn from(target: super::LibsslUprobeTarget) -> Self {
        Self {
            pid: target.pid,
            library: target.library,
            library_kind: target.library_kind,
            executable_mappings: target.executable_mappings,
            recipes: target
                .symbols
                .into_iter()
                .map(LibsslUprobeAttachRecipe::from_symbol)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LibsslUprobeAttachRecipe {
    pub symbol: LibsslUprobeSymbol,
    pub direction: Direction,
    pub probes: [LibsslUprobeAttachProbe; 2],
}

impl LibsslUprobeAttachRecipe {
    pub fn from_symbol(symbol: LibsslUprobeSymbol) -> Self {
        let direction = match symbol {
            LibsslUprobeSymbol::SslRead | LibsslUprobeSymbol::SslReadEx => Direction::Inbound,
            LibsslUprobeSymbol::SslWrite | LibsslUprobeSymbol::SslWriteEx => Direction::Outbound,
        };
        Self {
            symbol,
            direction,
            probes: [
                LibsslUprobeAttachProbe::new(LibsslUprobeAttachKind::Entry),
                LibsslUprobeAttachProbe::new(LibsslUprobeAttachKind::Return),
            ],
        }
    }

    pub fn function_name(self) -> &'static str {
        self.symbol.as_str()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LibsslUprobeAttachProbe {
    pub kind: LibsslUprobeAttachKind,
    pub offset: u64,
}

impl LibsslUprobeAttachProbe {
    pub fn new(kind: LibsslUprobeAttachKind) -> Self {
        Self { kind, offset: 0 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LibsslUprobeAttachKind {
    Entry,
    Return,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::{
        LibsslExecutableMapping, LibsslMappedFileIdentity, LibsslUprobeDegradationReason,
        LibsslUprobeSymbolFailure, LibsslUprobeTarget,
    };

    #[test]
    fn attach_plan_maps_libssl_symbols_to_probe_kind_and_direction() {
        let report = LibsslUprobeTargetDiscoveryReport {
            pid: 42,
            targets: vec![LibsslUprobeTarget {
                pid: 42,
                library: mapped_library("/usr/lib/libssl.so.3"),
                library_kind: LibsslLibraryKind::OpenSslLike,
                executable_mappings: vec![LibsslExecutableMapping {
                    start_address: 0x1000,
                    end_address: 0x2000,
                    file_offset: 0,
                }],
                symbols: vec![
                    LibsslUprobeSymbol::SslRead,
                    LibsslUprobeSymbol::SslWrite,
                    LibsslUprobeSymbol::SslReadEx,
                    LibsslUprobeSymbol::SslWriteEx,
                ],
            }],
            degraded_reasons: Vec::new(),
        };

        let plan = LibsslUprobeAttachPlan::from_discovery_report(report);

        assert!(plan.has_attachable_probes());
        assert_eq!(plan.probe_count(), 8);
        assert_eq!(plan.targets.len(), 1);
        assert_eq!(plan.targets[0].pid, 42);
        assert_eq!(
            plan.targets[0].recipes,
            vec![
                LibsslUprobeAttachRecipe {
                    symbol: LibsslUprobeSymbol::SslRead,
                    direction: Direction::Inbound,
                    probes: entry_and_return_probes(),
                },
                LibsslUprobeAttachRecipe {
                    symbol: LibsslUprobeSymbol::SslWrite,
                    direction: Direction::Outbound,
                    probes: entry_and_return_probes(),
                },
                LibsslUprobeAttachRecipe {
                    symbol: LibsslUprobeSymbol::SslReadEx,
                    direction: Direction::Inbound,
                    probes: entry_and_return_probes(),
                },
                LibsslUprobeAttachRecipe {
                    symbol: LibsslUprobeSymbol::SslWriteEx,
                    direction: Direction::Outbound,
                    probes: entry_and_return_probes(),
                },
            ]
        );
        assert_eq!(plan.targets[0].recipes[0].function_name(), "SSL_read");
        assert_eq!(plan.targets[0].recipes[3].function_name(), "SSL_write_ex");
    }

    #[test]
    fn attach_plan_preserves_discovery_degradation_reasons() {
        let reason = LibsslUprobeDegradationReason::SymbolResolutionFailed {
            mapped_path: PathBuf::from("/usr/lib/libssl.so.3"),
            reason: LibsslUprobeSymbolFailure::ParseLibrary {
                path: PathBuf::from("/proc/7/root/usr/lib/libssl.so.3"),
                reason: "bad elf".to_string(),
            },
        };
        let report = LibsslUprobeTargetDiscoveryReport {
            pid: 7,
            targets: Vec::new(),
            degraded_reasons: vec![reason.clone()],
        };

        let plan = LibsslUprobeAttachPlan::from_discovery_report(report);

        assert!(!plan.has_attachable_probes());
        assert_eq!(plan.degraded_reasons, vec![reason]);
    }

    fn mapped_library(path: &str) -> LibsslMappedLibrary {
        LibsslMappedLibrary {
            mapped_path: PathBuf::from(path),
            read_path: PathBuf::from("/proc/42/root").join(path.trim_start_matches('/')),
            identity: LibsslMappedFileIdentity {
                device_major: 8,
                device_minor: 1,
                inode: 100,
            },
            deleted: false,
        }
    }

    fn entry_and_return_probes() -> [LibsslUprobeAttachProbe; 2] {
        [
            LibsslUprobeAttachProbe::new(LibsslUprobeAttachKind::Entry),
            LibsslUprobeAttachProbe::new(LibsslUprobeAttachKind::Return),
        ]
    }
}
