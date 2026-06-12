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

    use super::super::elf_fixture::minimal_elf_with_ssl_read_symbol;
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
}
