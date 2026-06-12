use std::{
    collections::HashMap,
    fs::{File, Metadata},
    io::Read,
    path::{Path, PathBuf},
};

use aya_obj::{Object, ProgramSection, generated::bpf_map_type::BPF_MAP_TYPE_RINGBUF};
use ebpf_abi::{
    EBPF_CONNECT_PROGRAM_NAME, EBPF_CONNECT_TRACEPOINT_CATEGORY, EBPF_CONNECT_TRACEPOINT_NAME,
    EBPF_EVENTS_MAP_NAME,
};
use object::{Object as ObjectFile, ObjectSection};
use rustix::fs::{Mode, OFlags, open};
use serde::{Deserialize, Serialize};

const MAX_EBPF_OBJECT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfObjectProbeConfig {
    pub object_path: PathBuf,
    pub contract: EbpfObjectContract,
}

impl EbpfObjectProbeConfig {
    pub fn new(object_path: impl Into<PathBuf>) -> Self {
        Self {
            object_path: object_path.into(),
            contract: EbpfObjectContract::process_probe_scaffold(),
        }
    }

    pub fn with_contract(object_path: impl Into<PathBuf>, contract: EbpfObjectContract) -> Self {
        Self {
            object_path: object_path.into(),
            contract,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EbpfObjectProbeReport {
    pub object_path: PathBuf,
    pub object: EbpfProbeCheck,
    pub contract: EbpfObjectContractReport,
    pub programs: Vec<EbpfObjectProgram>,
    pub maps: Vec<EbpfObjectMap>,
}

impl EbpfObjectProbeReport {
    pub fn object_available(&self) -> bool {
        self.object.is_available()
    }

    pub fn preflight_available(&self) -> bool {
        self.object.is_available() && self.contract.is_available()
    }

    pub fn summary(&self) -> String {
        match &self.object {
            EbpfProbeCheck::Available => format!(
                "object {} parsed, contract={}, programs={}, maps={}",
                self.object_path.display(),
                self.contract.summary(),
                named_list_summary(self.programs.iter().map(|program| program.name.as_str())),
                named_list_summary(self.maps.iter().map(|map| map.name.as_str()))
            ),
            EbpfProbeCheck::Unavailable { reason } => {
                format!(
                    "object {} unavailable: {reason}",
                    self.object_path.display()
                )
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EbpfObjectContractReport {
    pub status: EbpfProbeCheck,
    pub maps: Vec<EbpfObjectContractCheck>,
    pub programs: Vec<EbpfObjectContractCheck>,
}

impl EbpfObjectContractReport {
    pub fn is_available(&self) -> bool {
        self.status.is_available()
            && self.maps.iter().all(EbpfObjectContractCheck::is_available)
            && self
                .programs
                .iter()
                .all(EbpfObjectContractCheck::is_available)
    }

    fn from_inventory(
        contract: &EbpfObjectContract,
        programs: &[EbpfObjectProgram],
        maps: &[EbpfObjectMap],
    ) -> Self {
        Self {
            status: EbpfProbeCheck::available(),
            maps: contract
                .maps
                .iter()
                .map(|expected| expected_map_check(maps, expected))
                .collect(),
            programs: contract
                .programs
                .iter()
                .map(|expected| expected_program_check(programs, expected))
                .collect(),
        }
    }

    fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            status: EbpfProbeCheck::unavailable(reason),
            maps: Vec::new(),
            programs: Vec::new(),
        }
    }

    pub fn summary(&self) -> String {
        if self.is_available() {
            return "available".to_string();
        }
        format!(
            "{}, {}",
            contract_check_summary("maps", &self.maps, &self.status),
            contract_check_summary("programs", &self.programs, &self.status)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EbpfObjectContract {
    pub maps: Vec<EbpfExpectedMap>,
    pub programs: Vec<EbpfExpectedProgram>,
}

impl EbpfObjectContract {
    pub fn new(maps: Vec<EbpfExpectedMap>, programs: Vec<EbpfExpectedProgram>) -> Self {
        Self { maps, programs }
    }

    pub fn process_probe_scaffold() -> Self {
        Self {
            maps: vec![EbpfExpectedMap {
                name: EBPF_EVENTS_MAP_NAME.to_string(),
                kind: EbpfObjectMapKind::Ringbuf,
            }],
            programs: vec![EbpfExpectedProgram {
                name: EBPF_CONNECT_PROGRAM_NAME.to_string(),
                kind: EbpfObjectProgramKind::Tracepoint,
                section: Some(expected_tracepoint_section()),
            }],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EbpfExpectedMap {
    pub name: String,
    pub kind: EbpfObjectMapKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EbpfExpectedProgram {
    pub name: String,
    pub kind: EbpfObjectProgramKind,
    pub section: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EbpfObjectContractCheck {
    pub name: String,
    pub check: EbpfProbeCheck,
}

impl EbpfObjectContractCheck {
    pub fn is_available(&self) -> bool {
        self.check.is_available()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EbpfObjectProgram {
    pub name: String,
    pub kind: EbpfObjectProgramKind,
    pub section: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum EbpfObjectProgramKind {
    Tracepoint,
    Unsupported,
}

impl From<&ProgramSection> for EbpfObjectProgramKind {
    fn from(section: &ProgramSection) -> Self {
        match section {
            ProgramSection::TracePoint => Self::Tracepoint,
            _ => Self::Unsupported,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EbpfObjectMap {
    pub name: String,
    pub kind: EbpfObjectMapKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum EbpfObjectMapKind {
    Ringbuf,
    Other { value: u32 },
}

impl From<u32> for EbpfObjectMapKind {
    fn from(map_type: u32) -> Self {
        if map_type == BPF_MAP_TYPE_RINGBUF as u32 {
            Self::Ringbuf
        } else {
            Self::Other { value: map_type }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum EbpfProbeCheck {
    Available,
    Unavailable { reason: String },
}

impl EbpfProbeCheck {
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available)
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Available => None,
            Self::Unavailable { reason } => Some(reason),
        }
    }

    pub fn available() -> Self {
        Self::Available
    }

    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self::Unavailable {
            reason: reason.into(),
        }
    }

    pub fn summary(&self) -> String {
        match self {
            Self::Available => "available".to_string(),
            Self::Unavailable { reason } => reason.clone(),
        }
    }
}

pub struct EbpfObjectProbe;

impl EbpfObjectProbe {
    pub fn probe(config: &EbpfObjectProbeConfig) -> EbpfObjectProbeReport {
        let object_path = config.object_path.clone();
        match open_regular_ebpf_object(&object_path)
            .and_then(|file| read_limited_ebpf_object_bytes(&object_path, file))
            .and_then(|bytes| {
                let object = Object::parse(&bytes).map_err(|error| {
                    format!("failed to parse eBPF object with aya-obj: {error}")
                })?;
                Ok((bytes, object))
            }) {
            Ok((bytes, object)) => {
                let section_names = section_names_by_index(&bytes).unwrap_or_default();
                let mut programs = object
                    .programs
                    .iter()
                    .map(|(name, program)| EbpfObjectProgram {
                        name: name.to_string(),
                        kind: EbpfObjectProgramKind::from(&program.section),
                        section: section_names.get(&program.section_index).cloned(),
                    })
                    .collect::<Vec<_>>();
                programs.sort_by(|left, right| left.name.cmp(&right.name));
                let mut maps = object
                    .maps
                    .iter()
                    .map(|(name, map)| EbpfObjectMap {
                        name: name.to_string(),
                        kind: EbpfObjectMapKind::from(map.map_type()),
                    })
                    .collect::<Vec<_>>();
                maps.sort_by(|left, right| left.name.cmp(&right.name));
                let contract =
                    EbpfObjectContractReport::from_inventory(&config.contract, &programs, &maps);
                EbpfObjectProbeReport {
                    object_path,
                    object: EbpfProbeCheck::available(),
                    contract,
                    programs,
                    maps,
                }
            }
            Err(error) => EbpfObjectProbeReport {
                object_path,
                contract: EbpfObjectContractReport::unavailable(
                    "object did not parse; expected eBPF contract could not be checked",
                ),
                object: EbpfProbeCheck::unavailable(error),
                programs: Vec::new(),
                maps: Vec::new(),
            },
        }
    }
}

fn expected_map_check(
    maps: &[EbpfObjectMap],
    expected: &EbpfExpectedMap,
) -> EbpfObjectContractCheck {
    let check = match maps.iter().find(|map| map.name == expected.name) {
        Some(map) if map.kind == expected.kind => EbpfProbeCheck::available(),
        Some(map) => EbpfProbeCheck::unavailable(format!(
            "eBPF map {} has kind {:?}, expected {:?}",
            expected.name, map.kind, expected.kind
        )),
        None => EbpfProbeCheck::unavailable(format!("missing eBPF map {}", expected.name)),
    };
    EbpfObjectContractCheck {
        name: expected.name.clone(),
        check,
    }
}

fn expected_program_check(
    programs: &[EbpfObjectProgram],
    expected: &EbpfExpectedProgram,
) -> EbpfObjectContractCheck {
    let check = match programs
        .iter()
        .find(|program| program.name == expected.name)
    {
        Some(program)
            if program.kind == expected.kind
                && expected
                    .section
                    .as_deref()
                    .is_none_or(|section| program.section.as_deref() == Some(section)) =>
        {
            EbpfProbeCheck::available()
        }
        Some(program) => EbpfProbeCheck::unavailable(format!(
            "eBPF program {} has kind {:?} and section {}, expected {:?} section {}",
            expected.name,
            program.kind,
            program.section.as_deref().unwrap_or("<unknown>"),
            expected.kind,
            expected.section.as_deref().unwrap_or("<any>")
        )),
        None => EbpfProbeCheck::unavailable(format!("missing eBPF program {}", expected.name)),
    };
    EbpfObjectContractCheck {
        name: expected.name.clone(),
        check,
    }
}

fn contract_check_summary(
    label: &str,
    checks: &[EbpfObjectContractCheck],
    status: &EbpfProbeCheck,
) -> String {
    if !status.is_available() {
        return format!("{label}={}", status.summary());
    }
    if checks.is_empty() {
        return format!("{label}=none");
    }
    let unavailable = checks
        .iter()
        .filter(|check| !check.is_available())
        .map(|check| format!("{}={}", check.name, check.check.summary()))
        .collect::<Vec<_>>();
    if unavailable.is_empty() {
        return format!("{label}=available");
    }
    format!("{label}={}", unavailable.join(","))
}

fn expected_tracepoint_section() -> String {
    format!("tracepoint/{EBPF_CONNECT_TRACEPOINT_CATEGORY}/{EBPF_CONNECT_TRACEPOINT_NAME}")
}

fn section_names_by_index(bytes: &[u8]) -> Result<HashMap<usize, String>, String> {
    let object = object::File::parse(bytes)
        .map_err(|error| format!("failed to parse ELF sections for eBPF object: {error}"))?;
    Ok(object
        .sections()
        .filter_map(|section| {
            section
                .name()
                .ok()
                .map(|name| (section.index().0, name.to_string()))
        })
        .collect())
}

fn open_regular_ebpf_object(path: &Path) -> Result<File, String> {
    match probe_regular_file(path, "eBPF object") {
        EbpfProbeCheck::Available => {}
        EbpfProbeCheck::Unavailable { reason } => return Err(reason),
    }
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|source| {
        format!(
            "failed to open eBPF object path {}: {source}",
            path.display()
        )
    })?;
    let file = File::from(fd);
    let metadata = file.metadata().map_err(|source| {
        format!(
            "failed to inspect eBPF object path {}: {source}",
            path.display()
        )
    })?;
    validate_opened_ebpf_object(path, &metadata)?;
    Ok(file)
}

fn validate_opened_ebpf_object(path: &Path, metadata: &Metadata) -> Result<(), String> {
    if !metadata.is_file() {
        return Err(format!(
            "eBPF object path {} is not a regular file",
            path.display()
        ));
    }
    if metadata.len() > MAX_EBPF_OBJECT_BYTES {
        return Err(ebpf_object_too_large_reason(
            path,
            metadata.len(),
            MAX_EBPF_OBJECT_BYTES,
        ));
    }
    Ok(())
}

fn read_limited_ebpf_object_bytes(path: &Path, file: File) -> Result<Vec<u8>, String> {
    read_limited_ebpf_object_bytes_with_limit(path, file, MAX_EBPF_OBJECT_BYTES)
}

fn read_limited_ebpf_object_bytes_with_limit(
    path: &Path,
    file: File,
    limit: u64,
) -> Result<Vec<u8>, String> {
    let mut reader = file.take(limit.saturating_add(1));
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).map_err(|source| {
        format!(
            "failed to read eBPF object path {}: {source}",
            path.display()
        )
    })?;
    let size = bytes.len() as u64;
    if size > limit {
        return Err(ebpf_object_too_large_reason(path, size, limit));
    }
    Ok(bytes)
}

fn ebpf_object_too_large_reason(path: &Path, size: u64, limit: u64) -> String {
    format!(
        "eBPF object path {} is too large: {size} bytes exceeds {limit} bytes",
        path.display()
    )
}

fn probe_regular_file(path: &Path, label: &str) -> EbpfProbeCheck {
    match path.symlink_metadata() {
        Ok(metadata) if metadata.file_type().is_file() => EbpfProbeCheck::available(),
        Ok(metadata) if metadata.file_type().is_symlink() => {
            EbpfProbeCheck::unavailable(format!("{label} path {} is a symlink", path.display()))
        }
        Ok(metadata) if metadata.is_dir() => {
            EbpfProbeCheck::unavailable(format!("{label} path {} is a directory", path.display()))
        }
        Ok(_) => EbpfProbeCheck::unavailable(format!(
            "{label} path {} is not a regular file",
            path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            EbpfProbeCheck::unavailable(format!("{label} path {} does not exist", path.display()))
        }
        Err(error) => EbpfProbeCheck::unavailable(format!(
            "failed to inspect {label} path {}: {error}",
            path.display()
        )),
    }
}

fn named_list_summary<'a>(items: impl Iterator<Item = &'a str>) -> String {
    let values = items.collect::<Vec<_>>();
    if values.is_empty() {
        return "none".to_string();
    }
    values.join(",")
}

#[cfg(test)]
mod tests {
    use std::fs;

    use ::object::{
        Architecture, BinaryFormat, Endianness, SectionKind, SymbolFlags, SymbolKind, SymbolScope,
        write::{Object as WriteObject, Symbol, SymbolSection},
    };
    use ebpf_abi::EBPF_RING_BUFFER_BYTES;

    use super::*;
    use tempfile::tempdir;

    #[test]
    fn object_probe_reports_missing_object() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let config = EbpfObjectProbeConfig::new(temp.path().join("missing.bpf.o"));

        let report = EbpfObjectProbe::probe(&config);

        assert!(!report.object_available());
        assert!(!report.preflight_available());
        assert!(report.summary().contains("does not exist"));
        assert!(report.programs.is_empty());
        assert!(report.maps.is_empty());
        assert!(!report.contract.is_available());
        Ok(())
    }

    #[test]
    fn object_probe_reports_invalid_object() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let object = temp.path().join("invalid.bpf.o");
        fs::write(&object, b"not an elf object")?;
        let config = EbpfObjectProbeConfig::new(object);

        let report = EbpfObjectProbe::probe(&config);

        assert!(!report.object_available());
        assert!(!report.preflight_available());
        assert!(report.summary().contains("failed to parse eBPF object"));
        assert!(report.programs.is_empty());
        assert!(report.maps.is_empty());
        assert!(!report.contract.is_available());
        Ok(())
    }

    #[test]
    fn object_probe_rejects_oversized_object_before_parse() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = tempdir()?;
        let object = temp.path().join("oversized.bpf.o");
        fs::File::create(&object)?.set_len(MAX_EBPF_OBJECT_BYTES + 1)?;
        let config = EbpfObjectProbeConfig::new(object);

        let report = EbpfObjectProbe::probe(&config);

        assert!(!report.object_available());
        assert!(!report.preflight_available());
        assert!(report.summary().contains("too large"));
        assert!(report.programs.is_empty());
        assert!(report.maps.is_empty());
        assert!(!report.contract.is_available());
        Ok(())
    }

    #[test]
    fn object_probe_accepts_generated_scaffold_object() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let object = temp.path().join("scaffold.bpf.o");
        write_minimal_ebpf_object(
            &object,
            &expected_tracepoint_section(),
            EbpfObjectMapKind::Ringbuf,
        )?;
        let config = EbpfObjectProbeConfig::new(&object);

        let report = EbpfObjectProbe::probe(&config);

        assert!(report.object_available(), "{}", report.summary());
        assert!(report.preflight_available(), "{}", report.summary());
        assert_eq!(report.maps.len(), 1);
        assert_eq!(report.maps[0].name, EBPF_EVENTS_MAP_NAME);
        assert_eq!(report.maps[0].kind, EbpfObjectMapKind::Ringbuf);
        assert_eq!(report.programs.len(), 1);
        assert_eq!(report.programs[0].name, EBPF_CONNECT_PROGRAM_NAME);
        assert_eq!(
            report.programs[0].section.as_deref(),
            Some(expected_tracepoint_section().as_str())
        );
        Ok(())
    }

    #[test]
    fn object_probe_rejects_generated_object_with_wrong_section()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let object = temp.path().join("wrong-section.bpf.o");
        write_minimal_ebpf_object(
            &object,
            "tracepoint/syscalls/sys_exit_connect",
            EbpfObjectMapKind::Ringbuf,
        )?;
        let config = EbpfObjectProbeConfig::new(&object);

        let report = EbpfObjectProbe::probe(&config);

        assert!(report.object_available(), "{}", report.summary());
        assert!(!report.preflight_available());
        assert!(
            report
                .summary()
                .contains("tracepoint/syscalls/sys_enter_connect")
        );
        Ok(())
    }

    #[test]
    fn object_contract_requires_ringbuf_map_and_tracepoint_program() {
        let report = process_probe_contract_report(
            &[EbpfObjectProgram {
                name: EBPF_CONNECT_PROGRAM_NAME.to_string(),
                kind: EbpfObjectProgramKind::Tracepoint,
                section: Some(expected_tracepoint_section()),
            }],
            &[EbpfObjectMap {
                name: EBPF_EVENTS_MAP_NAME.to_string(),
                kind: EbpfObjectMapKind::Ringbuf,
            }],
        );

        assert!(report.is_available());
        assert_eq!(report.summary(), "available");
    }

    #[test]
    fn object_contract_reports_missing_expected_names() {
        let report = process_probe_contract_report(
            &[EbpfObjectProgram {
                name: "different_program".to_string(),
                kind: EbpfObjectProgramKind::Tracepoint,
                section: Some(expected_tracepoint_section()),
            }],
            &[EbpfObjectMap {
                name: "DIFFERENT_MAP".to_string(),
                kind: EbpfObjectMapKind::Ringbuf,
            }],
        );

        assert!(!report.is_available());
        assert!(report.summary().contains(EBPF_EVENTS_MAP_NAME));
        assert!(report.summary().contains(EBPF_CONNECT_PROGRAM_NAME));
    }

    #[test]
    fn object_contract_rejects_wrong_map_kind() {
        let report = process_probe_contract_report(
            &[EbpfObjectProgram {
                name: EBPF_CONNECT_PROGRAM_NAME.to_string(),
                kind: EbpfObjectProgramKind::Tracepoint,
                section: Some(expected_tracepoint_section()),
            }],
            &[EbpfObjectMap {
                name: EBPF_EVENTS_MAP_NAME.to_string(),
                kind: EbpfObjectMapKind::Other { value: 1 },
            }],
        );

        assert!(!report.is_available());
        assert!(contract_reason(&report.maps, EBPF_EVENTS_MAP_NAME).contains("expected Ringbuf"));
    }

    #[test]
    fn object_contract_rejects_wrong_program_kind() {
        let report = process_probe_contract_report(
            &[EbpfObjectProgram {
                name: EBPF_CONNECT_PROGRAM_NAME.to_string(),
                kind: EbpfObjectProgramKind::Unsupported,
                section: Some("kprobe/sssa_sys_enter_connect".to_string()),
            }],
            &[EbpfObjectMap {
                name: EBPF_EVENTS_MAP_NAME.to_string(),
                kind: EbpfObjectMapKind::Ringbuf,
            }],
        );

        assert!(!report.is_available());
        assert!(
            contract_reason(&report.programs, EBPF_CONNECT_PROGRAM_NAME)
                .contains("expected Tracepoint")
        );
    }

    #[test]
    fn object_contract_rejects_wrong_tracepoint_section() {
        let report = process_probe_contract_report(
            &[EbpfObjectProgram {
                name: EBPF_CONNECT_PROGRAM_NAME.to_string(),
                kind: EbpfObjectProgramKind::Tracepoint,
                section: Some("tracepoint/syscalls/sys_exit_connect".to_string()),
            }],
            &[EbpfObjectMap {
                name: EBPF_EVENTS_MAP_NAME.to_string(),
                kind: EbpfObjectMapKind::Ringbuf,
            }],
        );

        assert!(!report.is_available());
        assert!(
            contract_reason(&report.programs, EBPF_CONNECT_PROGRAM_NAME)
                .contains("tracepoint/syscalls/sys_enter_connect")
        );
    }

    #[test]
    fn object_contract_accepts_custom_expected_program() {
        let contract = EbpfObjectContract::new(
            vec![EbpfExpectedMap {
                name: "CUSTOM_EVENTS".to_string(),
                kind: EbpfObjectMapKind::Ringbuf,
            }],
            vec![EbpfExpectedProgram {
                name: "custom_tracepoint".to_string(),
                kind: EbpfObjectProgramKind::Tracepoint,
                section: Some("tracepoint/custom/event".to_string()),
            }],
        );
        let report = EbpfObjectContractReport::from_inventory(
            &contract,
            &[EbpfObjectProgram {
                name: "custom_tracepoint".to_string(),
                kind: EbpfObjectProgramKind::Tracepoint,
                section: Some("tracepoint/custom/event".to_string()),
            }],
            &[EbpfObjectMap {
                name: "CUSTOM_EVENTS".to_string(),
                kind: EbpfObjectMapKind::Ringbuf,
            }],
        );

        assert!(report.is_available());
    }

    #[test]
    fn bounded_object_reader_rejects_file_larger_than_limit()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let object = temp.path().join("bounded.bpf.o");
        fs::write(&object, b"abcd")?;
        let file = File::open(&object)?;

        let error = read_limited_ebpf_object_bytes_with_limit(&object, file, 3)
            .expect_err("bounded reader must reject bytes beyond limit");

        assert!(error.contains("too large"));
        Ok(())
    }

    fn process_probe_contract_report(
        programs: &[EbpfObjectProgram],
        maps: &[EbpfObjectMap],
    ) -> EbpfObjectContractReport {
        EbpfObjectContractReport::from_inventory(
            &EbpfObjectContract::process_probe_scaffold(),
            programs,
            maps,
        )
    }

    fn contract_reason<'a>(checks: &'a [EbpfObjectContractCheck], name: &str) -> &'a str {
        match checks.iter().find(|check| check.name == name) {
            Some(check) => check.check.reason().unwrap_or("available"),
            None => "<missing check>",
        }
    }

    fn write_minimal_ebpf_object(
        path: &Path,
        program_section_name: &str,
        map_kind: EbpfObjectMapKind,
    ) -> Result<(), Box<dyn std::error::Error>> {
        fs::write(
            path,
            minimal_ebpf_object_bytes(program_section_name, map_kind)?,
        )?;
        Ok(())
    }

    fn minimal_ebpf_object_bytes(
        program_section_name: &str,
        map_kind: EbpfObjectMapKind,
    ) -> Result<Vec<u8>, ::object::write::Error> {
        let mut object = WriteObject::new(BinaryFormat::Elf, Architecture::Bpf, Endianness::Little);
        let maps_section = object.add_section(Vec::new(), b"maps".to_vec(), SectionKind::Data);
        let map_def = legacy_map_def_bytes(map_kind);
        object.set_section_data(maps_section, map_def.to_vec(), 4);
        object.add_symbol(Symbol {
            name: EBPF_EVENTS_MAP_NAME.as_bytes().to_vec(),
            value: 0,
            size: 20,
            kind: SymbolKind::Data,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(maps_section),
            flags: SymbolFlags::None,
        });

        let program_section = object.add_section(
            Vec::new(),
            program_section_name.as_bytes().to_vec(),
            SectionKind::Text,
        );
        object.set_section_data(program_section, vec![0; 8], 8);
        object.add_symbol(Symbol {
            name: EBPF_CONNECT_PROGRAM_NAME.as_bytes().to_vec(),
            value: 0,
            size: 8,
            kind: SymbolKind::Text,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(program_section),
            flags: SymbolFlags::None,
        });

        object.write()
    }

    fn legacy_map_def_bytes(kind: EbpfObjectMapKind) -> [u8; 20] {
        let map_type = match kind {
            EbpfObjectMapKind::Ringbuf => BPF_MAP_TYPE_RINGBUF as u32,
            EbpfObjectMapKind::Other { value } => value,
        };
        let fields = [map_type, 0, 0, EBPF_RING_BUFFER_BYTES, 0];
        let mut bytes = [0; 20];
        for (index, field) in fields.into_iter().enumerate() {
            let start = index * 4;
            bytes[start..start + 4].copy_from_slice(&field.to_le_bytes());
        }
        bytes
    }
}
