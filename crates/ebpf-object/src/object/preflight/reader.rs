use std::{
    fs::{File, Metadata},
    io::Read,
    path::Path,
};

use rustix::fs::{Mode, OFlags, open};

use super::model::EbpfProbeCheck;

pub(super) const MAX_EBPF_OBJECT_BYTES: u64 = 64 * 1024 * 1024;

pub(super) fn read_ebpf_object_bytes(path: &Path) -> Result<Vec<u8>, String> {
    open_regular_ebpf_object(path).and_then(|file| read_limited_ebpf_object_bytes(path, file))
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

#[cfg(test)]
mod tests {
    use std::fs::{self, File};

    use tempfile::tempdir;

    use super::*;

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
}
