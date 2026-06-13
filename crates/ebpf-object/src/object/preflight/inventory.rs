use std::collections::HashMap;

use aya_obj::{
    Object, ProgramSection,
    generated::bpf_map_type::{
        BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_LRU_HASH, BPF_MAP_TYPE_PERCPU_ARRAY, BPF_MAP_TYPE_RINGBUF,
    },
    maps::PinningType,
};
use object::{Object as ObjectFile, ObjectSection};

use super::model::{
    EbpfObjectMap, EbpfObjectMapKind, EbpfObjectMapPinning, EbpfObjectProgram,
    EbpfObjectProgramKind,
};

pub(super) fn object_inventory(
    bytes: &[u8],
) -> Result<(Vec<EbpfObjectProgram>, Vec<EbpfObjectMap>), String> {
    let object = Object::parse(bytes)
        .map_err(|error| format!("failed to parse eBPF object with aya-obj: {error}"))?;
    let section_names = section_names_by_index(bytes)?;

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
            key_size: map.key_size(),
            value_size: map.value_size(),
            max_entries: map.max_entries(),
            map_flags: map.map_flags(),
            pinning: EbpfObjectMapPinning::from(map.pinning()),
        })
        .collect::<Vec<_>>();
    maps.sort_by(|left, right| left.name.cmp(&right.name));

    Ok((programs, maps))
}

impl From<&ProgramSection> for EbpfObjectProgramKind {
    fn from(section: &ProgramSection) -> Self {
        match section {
            ProgramSection::TracePoint => Self::Tracepoint,
            ProgramSection::UProbe { .. } => Self::Uprobe,
            ProgramSection::URetProbe { .. } => Self::Uretprobe,
            _ => Self::Unsupported,
        }
    }
}

impl From<u32> for EbpfObjectMapKind {
    fn from(map_type: u32) -> Self {
        match map_type {
            value if value == BPF_MAP_TYPE_RINGBUF as u32 => Self::Ringbuf,
            value if value == BPF_MAP_TYPE_HASH as u32 => Self::Hash,
            value if value == BPF_MAP_TYPE_LRU_HASH as u32 => Self::LruHash,
            value if value == BPF_MAP_TYPE_PERCPU_ARRAY as u32 => Self::PerCpuArray,
            value => Self::Other { value },
        }
    }
}

impl From<PinningType> for EbpfObjectMapPinning {
    fn from(pinning: PinningType) -> Self {
        match pinning {
            PinningType::None => Self::None,
            PinningType::ByName => Self::ByName,
        }
    }
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
