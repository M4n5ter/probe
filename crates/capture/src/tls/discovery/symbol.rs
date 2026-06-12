use std::{collections::BTreeSet, fs};

#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;

use object::{Object, ObjectSymbol};
use probe_io::{BoundedFileError, BoundedFileErrorKind, read_bounded_regular_file};

#[cfg(target_os = "linux")]
use super::model::LibsslMappedFileIdentity;
use super::model::{
    LibsslMappedLibrary, LibsslUprobeSymbol, LibsslUprobeSymbolFailure, SUPPORTED_LIBSSL_SYMBOLS,
};

const MAX_LIBSSL_OBJECT_BYTES: u64 = 128 * 1024 * 1024;

pub(super) trait LibsslSymbolResolver {
    fn resolve_symbols(
        &self,
        library: &LibsslMappedLibrary,
    ) -> Result<Vec<LibsslUprobeSymbol>, LibsslUprobeSymbolFailure>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ObjectLibsslSymbolResolver;

impl LibsslSymbolResolver for ObjectLibsslSymbolResolver {
    fn resolve_symbols(
        &self,
        library: &LibsslMappedLibrary,
    ) -> Result<Vec<LibsslUprobeSymbol>, LibsslUprobeSymbolFailure> {
        let read = read_bounded_regular_file(&library.read_path, MAX_LIBSSL_OBJECT_BYTES)
            .map_err(libssl_bounded_file_error)?;
        ensure_mapped_library_identity(read.metadata(), library)?;
        let object = object::File::parse(read.bytes()).map_err(|source| {
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

pub(super) fn stable_symbol_order(symbols: Vec<LibsslUprobeSymbol>) -> Vec<LibsslUprobeSymbol> {
    let symbols = symbols.into_iter().collect::<BTreeSet<_>>();
    SUPPORTED_LIBSSL_SYMBOLS
        .into_iter()
        .filter(|symbol| symbols.contains(symbol))
        .collect()
}

#[cfg(target_os = "linux")]
fn ensure_mapped_library_identity(
    metadata: &fs::Metadata,
    library: &LibsslMappedLibrary,
) -> Result<(), LibsslUprobeSymbolFailure> {
    let actual_identity = mapped_file_identity_from_metadata(metadata);
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

#[cfg(target_os = "linux")]
fn mapped_file_identity_from_metadata(metadata: &fs::Metadata) -> LibsslMappedFileIdentity {
    LibsslMappedFileIdentity {
        device_major: rustix::fs::major(metadata.dev()),
        device_minor: rustix::fs::minor(metadata.dev()),
        inode: metadata.ino(),
    }
}

fn libssl_bounded_file_error(error: BoundedFileError) -> LibsslUprobeSymbolFailure {
    let mut parts = error.into_parts();
    match parts.kind {
        BoundedFileErrorKind::NotFound => LibsslUprobeSymbolFailure::InspectLibrary {
            path: parts.path,
            reason: "TLS library path does not exist".to_string(),
        },
        BoundedFileErrorKind::Inspect | BoundedFileErrorKind::Open => {
            let source = parts.expect_source();
            LibsslUprobeSymbolFailure::InspectLibrary {
                path: parts.path,
                reason: source.to_string(),
            }
        }
        BoundedFileErrorKind::Read => {
            let source = parts.expect_source();
            LibsslUprobeSymbolFailure::ReadLibrary {
                path: parts.path,
                reason: source.to_string(),
            }
        }
        BoundedFileErrorKind::Directory
        | BoundedFileErrorKind::NotRegular
        | BoundedFileErrorKind::Symlink => {
            LibsslUprobeSymbolFailure::NotRegular { path: parts.path }
        }
        BoundedFileErrorKind::TooLarge => {
            let size_limit = parts.expect_size_limit();
            LibsslUprobeSymbolFailure::TooLarge {
                path: parts.path,
                size: size_limit.size,
                limit: size_limit.limit,
            }
        }
    }
}

fn is_attachable_symbol_definition<'data>(symbol: &impl ObjectSymbol<'data>) -> bool {
    symbol.is_definition() && !symbol.is_undefined() && symbol.kind() == object::SymbolKind::Text
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use tempfile::tempdir;

    use super::*;

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

    fn mapped_library(read_path: &Path) -> Result<LibsslMappedLibrary, Box<dyn std::error::Error>> {
        let metadata = fs::metadata(read_path)?;
        #[cfg(target_os = "linux")]
        let identity = mapped_file_identity_from_metadata(&metadata);
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

    fn minimal_elf_with_ssl_read_symbol() -> Vec<u8> {
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
}
