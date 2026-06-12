mod file;

#[cfg(test)]
pub(crate) use file::MAX_TLS_MATERIAL_BYTES;
pub(crate) use file::{TlsMaterialFileError, check_tls_material_source, read_tls_material};
