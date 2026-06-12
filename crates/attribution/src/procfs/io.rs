use std::{fs, io, path::Path};

use super::{AttributionError, tcp_table::ProcfsTcpTable};

pub(super) fn read_to_string(path: &Path) -> Result<String, AttributionError> {
    fs::read_to_string(path).map_err(|source| AttributionError::Read {
        path: path.display().to_string(),
        source,
    })
}

pub(super) fn read_optional_to_string(path: &Path) -> Result<Option<String>, AttributionError> {
    match fs::read_to_string(path) {
        Ok(content) => Ok(Some(content)),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(AttributionError::Read {
            path: path.display().to_string(),
            source,
        }),
    }
}

pub(super) fn read_bytes(path: &Path) -> Result<Vec<u8>, AttributionError> {
    fs::read(path).map_err(|source| AttributionError::Read {
        path: path.display().to_string(),
        source,
    })
}

pub(super) fn read_link_to_string(path: &Path) -> Result<String, AttributionError> {
    fs::read_link(path)
        .map(|path| path.display().to_string())
        .map_err(|source| AttributionError::ReadLink {
            path: path.display().to_string(),
            source,
        })
}

pub(super) fn read_tcp_table_to_string(table: &ProcfsTcpTable) -> Result<String, AttributionError> {
    fs::read_to_string(&table.path).map_err(|source| AttributionError::Read {
        path: table.path.display().to_string(),
        source,
    })
}
