use std::{fs, path::Path};

use ::object::{
    Architecture, BinaryFormat, Endianness, SectionKind, SymbolFlags, SymbolKind, SymbolScope,
    write::{Object as WriteObject, Symbol, SymbolSection},
};
use aya_obj::generated::bpf_map_type::BPF_MAP_TYPE_RINGBUF;
use ebpf_abi::{
    EBPF_CLOSE_PROGRAM_NAME, EBPF_CONNECT_PROGRAM_NAME, EBPF_EVENTS_MAP_NAME,
    EBPF_RING_BUFFER_BYTES,
};

use super::model::{
    EbpfObjectContractCheck, EbpfObjectMap, EbpfObjectMapKind, EbpfObjectMapPinning,
    EbpfObjectProgram, EbpfObjectProgramKind,
};

pub(super) fn contract_tracepoint_program(name: &str, section: &str) -> EbpfObjectProgram {
    EbpfObjectProgram {
        name: name.to_string(),
        kind: EbpfObjectProgramKind::Tracepoint,
        section: Some(section.to_string()),
    }
}

pub(super) fn contract_ringbuf_map(name: &str) -> EbpfObjectMap {
    EbpfObjectMap {
        name: name.to_string(),
        kind: EbpfObjectMapKind::Ringbuf,
        key_size: 0,
        value_size: 0,
        max_entries: EBPF_RING_BUFFER_BYTES,
        map_flags: 0,
        pinning: EbpfObjectMapPinning::None,
    }
}

pub(super) fn contract_reason<'a>(checks: &'a [EbpfObjectContractCheck], name: &str) -> &'a str {
    match checks.iter().find(|check| check.name == name) {
        Some(check) => check.check.reason().unwrap_or("available"),
        None => "<missing check>",
    }
}

pub(super) fn write_process_probe_ebpf_object(
    path: &Path,
    connect_program_section_name: &str,
    close_program_section_name: &str,
    map_kind: EbpfObjectMapKind,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(
        path,
        process_probe_ebpf_object_bytes(
            connect_program_section_name,
            close_program_section_name,
            map_kind,
        )?,
    )?;
    Ok(())
}

fn process_probe_ebpf_object_bytes(
    connect_program_section_name: &str,
    close_program_section_name: &str,
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

    add_program_symbol(
        &mut object,
        EBPF_CONNECT_PROGRAM_NAME,
        connect_program_section_name,
    );
    add_program_symbol(
        &mut object,
        EBPF_CLOSE_PROGRAM_NAME,
        close_program_section_name,
    );

    object.write()
}

fn add_program_symbol(
    object: &mut WriteObject<'_>,
    program_name: &str,
    program_section_name: &str,
) {
    let program_section = object.add_section(
        Vec::new(),
        program_section_name.as_bytes().to_vec(),
        SectionKind::Text,
    );
    object.set_section_data(program_section, vec![0; 8], 8);
    object.add_symbol(Symbol {
        name: program_name.as_bytes().to_vec(),
        value: 0,
        size: 8,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(program_section),
        flags: SymbolFlags::None,
    });
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
