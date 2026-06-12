use std::path::{Path, PathBuf};

use super::model::{LibsslLibraryKind, LibsslMappedFileIdentity};

const DELETED_MAPPING_SUFFIX: &str = " (deleted)";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProcMapsEntry {
    pub(super) start_address: u64,
    pub(super) end_address: u64,
    pub(super) executable: bool,
    pub(super) file_offset: u64,
    pub(super) identity: LibsslMappedFileIdentity,
    pub(super) path: Option<MappedPath>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MappedPath {
    pub(super) path: PathBuf,
    pub(super) deleted: bool,
}

pub(super) fn parse_proc_maps_entry(line: &str) -> Result<ProcMapsEntry, String> {
    let (address_range, rest) =
        take_field(line).ok_or_else(|| "missing address range".to_string())?;
    let (permissions, rest) = take_field(rest).ok_or_else(|| "missing permissions".to_string())?;
    let (offset, rest) = take_field(rest).ok_or_else(|| "missing file offset".to_string())?;
    let (device, rest) = take_field(rest).ok_or_else(|| "missing device".to_string())?;
    let (inode, pathname) = take_field(rest).ok_or_else(|| "missing inode".to_string())?;
    let (start_address, end_address) = parse_address_range(address_range)?;
    let file_offset = parse_hex_u64(offset, "file offset")?;
    let (device_major, device_minor) = parse_proc_map_device(device)?;
    let inode = inode
        .parse::<u64>()
        .map_err(|error| format!("invalid inode {inode}: {error}"))?;
    let path = normalize_proc_maps_path(pathname.trim_start());

    Ok(ProcMapsEntry {
        start_address,
        end_address,
        executable: permissions
            .as_bytes()
            .get(2)
            .is_some_and(|byte| *byte == b'x'),
        file_offset,
        identity: LibsslMappedFileIdentity {
            device_major,
            device_minor,
            inode,
        },
        path,
    })
}

pub(super) fn strip_root(path: &Path) -> &Path {
    path.strip_prefix("/").unwrap_or(path)
}

pub(super) fn classify_libssl_path(path: &Path) -> Option<LibsslLibraryKind> {
    let file_name = path.file_name()?.to_string_lossy().to_ascii_lowercase();
    if file_name.contains("boringssl") {
        return Some(LibsslLibraryKind::BoringSslLike);
    }
    if file_name.contains("libssl") {
        return Some(LibsslLibraryKind::OpenSslLike);
    }
    None
}

fn take_field(input: &str) -> Option<(&str, &str)> {
    let input = input.trim_start();
    if input.is_empty() {
        return None;
    }
    match input.find(char::is_whitespace) {
        Some(index) => Some((&input[..index], &input[index..])),
        None => Some((input, "")),
    }
}

fn parse_address_range(value: &str) -> Result<(u64, u64), String> {
    let (start, end) = value
        .split_once('-')
        .ok_or_else(|| format!("invalid address range {value}"))?;
    let start = parse_hex_u64(start, "range start")?;
    let end = parse_hex_u64(end, "range end")?;
    if end <= start {
        return Err(format!(
            "invalid address range {value}: end must exceed start"
        ));
    }
    Ok((start, end))
}

fn parse_hex_u64(value: &str, label: &str) -> Result<u64, String> {
    u64::from_str_radix(value, 16).map_err(|error| format!("invalid {label} {value}: {error}"))
}

fn parse_proc_map_device(value: &str) -> Result<(u32, u32), String> {
    let (major, minor) = value
        .split_once(':')
        .ok_or_else(|| format!("invalid device {value}"))?;
    Ok((
        parse_hex_u32(major, "device major")?,
        parse_hex_u32(minor, "device minor")?,
    ))
}

fn parse_hex_u32(value: &str, label: &str) -> Result<u32, String> {
    u32::from_str_radix(value, 16).map_err(|error| format!("invalid {label} {value}: {error}"))
}

fn normalize_proc_maps_path(value: &str) -> Option<MappedPath> {
    if value.is_empty() || !value.starts_with('/') {
        return None;
    }
    let deleted = value.ends_with(DELETED_MAPPING_SUFFIX);
    Some(MappedPath {
        path: PathBuf::from(value.strip_suffix(DELETED_MAPPING_SUFFIX).unwrap_or(value)),
        deleted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_maps_parser_preserves_deleted_path_with_spaces() {
        let entry = parse_proc_maps_entry(
            "7f0000001000-7f0000010000 r-xp 00001000 08:01 42 /opt/my app/libssl custom.so (deleted)",
        )
        .expect("maps entry should parse");

        let mapped_path = entry.path.expect("path should be mapped");
        assert!(entry.executable);
        assert_eq!(entry.start_address, 0x7f0000001000);
        assert_eq!(entry.end_address, 0x7f0000010000);
        assert_eq!(entry.file_offset, 0x1000);
        assert_eq!(entry.identity.device_major, 0x08);
        assert_eq!(entry.identity.device_minor, 0x01);
        assert_eq!(entry.identity.inode, 42);
        assert_eq!(
            mapped_path.path,
            PathBuf::from("/opt/my app/libssl custom.so")
        );
        assert!(mapped_path.deleted);
    }

    #[test]
    fn proc_maps_parser_rejects_invalid_address_range() {
        let error =
            parse_proc_maps_entry("7f0000010000-7f0000010000 r-xp 00001000 08:01 1 /libssl.so")
                .expect_err("empty address range must be rejected");

        assert!(error.contains("end must exceed start"));
    }

    #[test]
    fn libssl_path_classifier_distinguishes_supported_tls_libraries() {
        assert_eq!(
            classify_libssl_path(Path::new("/usr/lib/libssl.so.3")),
            Some(LibsslLibraryKind::OpenSslLike)
        );
        assert_eq!(
            classify_libssl_path(Path::new("/opt/boringssl/libboringssl.so")),
            Some(LibsslLibraryKind::BoringSslLike)
        );
        assert_eq!(
            classify_libssl_path(Path::new("/usr/lib/libcrypto.so")),
            None
        );
    }
}
