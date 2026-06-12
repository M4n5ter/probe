pub(super) fn minimal_elf_with_ssl_read_symbol() -> Vec<u8> {
    const ELF_HEADER_SIZE: usize = 64;
    const SECTION_HEADER_SIZE: usize = 64;
    const SECTION_COUNT: usize = 5;
    const TEXT_OFFSET: usize = ELF_HEADER_SIZE;
    const TEXT_SIZE: usize = 1;
    const SYMTAB_OFFSET: usize = 72;
    const SYMTAB_SIZE: usize = 48;
    const STRTAB_OFFSET: usize = SYMTAB_OFFSET + SYMTAB_SIZE;
    const SHSTRTAB_OFFSET: usize = 143;
    const SECTION_HEADERS_OFFSET: usize = 176;

    let strtab = b"\0SSL_read@@OPENSSL_3.0\0";
    let shstrtab = b"\0.text\0.symtab\0.strtab\0.shstrtab\0";
    let mut elf = vec![0_u8; SECTION_HEADERS_OFFSET + SECTION_HEADER_SIZE * SECTION_COUNT];

    elf[0..16].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    write_u16(&mut elf, 16, 1);
    write_u16(&mut elf, 18, 62);
    write_u32(&mut elf, 20, 1);
    write_u64(&mut elf, 40, SECTION_HEADERS_OFFSET as u64);
    write_u16(&mut elf, 52, ELF_HEADER_SIZE as u16);
    write_u16(&mut elf, 58, SECTION_HEADER_SIZE as u16);
    write_u16(&mut elf, 60, SECTION_COUNT as u16);
    write_u16(&mut elf, 62, 4);

    elf[TEXT_OFFSET] = 0xc3;
    write_section_header(
        &mut elf,
        1,
        SectionHeader {
            name: 1,
            section_type: 1,
            flags: 0x6,
            offset: TEXT_OFFSET as u64,
            size: TEXT_SIZE as u64,
            link: 0,
            info: 0,
            align: 1,
            entry_size: 0,
        },
    );

    write_symbol(
        &mut elf,
        SYMTAB_OFFSET + 24,
        1,
        0x12,
        1,
        0,
        TEXT_SIZE as u64,
    );
    write_section_header(
        &mut elf,
        2,
        SectionHeader {
            name: 7,
            section_type: 2,
            flags: 0,
            offset: SYMTAB_OFFSET as u64,
            size: SYMTAB_SIZE as u64,
            link: 3,
            info: 1,
            align: 8,
            entry_size: 24,
        },
    );

    elf[STRTAB_OFFSET..STRTAB_OFFSET + strtab.len()].copy_from_slice(strtab);
    write_section_header(
        &mut elf,
        3,
        SectionHeader {
            name: 15,
            section_type: 3,
            flags: 0,
            offset: STRTAB_OFFSET as u64,
            size: strtab.len() as u64,
            link: 0,
            info: 0,
            align: 1,
            entry_size: 0,
        },
    );

    elf[SHSTRTAB_OFFSET..SHSTRTAB_OFFSET + shstrtab.len()].copy_from_slice(shstrtab);
    write_section_header(
        &mut elf,
        4,
        SectionHeader {
            name: 23,
            section_type: 3,
            flags: 0,
            offset: SHSTRTAB_OFFSET as u64,
            size: shstrtab.len() as u64,
            link: 0,
            info: 0,
            align: 1,
            entry_size: 0,
        },
    );

    elf
}

#[derive(Debug, Clone, Copy)]
struct SectionHeader {
    name: u32,
    section_type: u32,
    flags: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    align: u64,
    entry_size: u64,
}

fn write_section_header(elf: &mut [u8], index: usize, section: SectionHeader) {
    let offset = 176 + index * 64;
    write_u32(elf, offset, section.name);
    write_u32(elf, offset + 4, section.section_type);
    write_u64(elf, offset + 8, section.flags);
    write_u64(elf, offset + 24, section.offset);
    write_u64(elf, offset + 32, section.size);
    write_u32(elf, offset + 40, section.link);
    write_u32(elf, offset + 44, section.info);
    write_u64(elf, offset + 48, section.align);
    write_u64(elf, offset + 56, section.entry_size);
}

fn write_symbol(
    elf: &mut [u8],
    offset: usize,
    name: u32,
    info: u8,
    section_index: u16,
    value: u64,
    size: u64,
) {
    write_u32(elf, offset, name);
    elf[offset + 4] = info;
    write_u16(elf, offset + 6, section_index);
    write_u64(elf, offset + 8, value);
    write_u64(elf, offset + 16, size);
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
