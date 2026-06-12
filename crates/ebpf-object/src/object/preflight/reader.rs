use std::path::Path;

use probe_io::{BoundedFileError, BoundedFileErrorKind, read_bounded_regular_file};

pub(super) const MAX_EBPF_OBJECT_BYTES: u64 = 64 * 1024 * 1024;

pub(super) fn read_ebpf_object_bytes(path: &Path) -> Result<Vec<u8>, String> {
    read_bounded_regular_file(path, MAX_EBPF_OBJECT_BYTES)
        .map(|read| read.into_bytes())
        .map_err(ebpf_object_file_reason)
}

fn ebpf_object_too_large_reason(path: &Path, size: u64, limit: u64) -> String {
    format!(
        "eBPF object path {} is too large: {size} bytes exceeds {limit} bytes",
        path.display()
    )
}

fn ebpf_object_file_reason(error: BoundedFileError) -> String {
    let mut parts = error.into_parts();
    match parts.kind {
        BoundedFileErrorKind::NotFound => {
            format!("eBPF object path {} does not exist", parts.path.display())
        }
        BoundedFileErrorKind::Inspect => {
            let source = parts.expect_source();
            format!(
                "failed to inspect eBPF object path {}: {source}",
                parts.path.display()
            )
        }
        BoundedFileErrorKind::Open => {
            let source = parts.expect_source();
            format!(
                "failed to open eBPF object path {}: {source}",
                parts.path.display()
            )
        }
        BoundedFileErrorKind::Read => {
            let source = parts.expect_source();
            format!(
                "failed to read eBPF object path {}: {source}",
                parts.path.display()
            )
        }
        BoundedFileErrorKind::Symlink => {
            format!("eBPF object path {} is a symlink", parts.path.display())
        }
        BoundedFileErrorKind::Directory => {
            format!("eBPF object path {} is a directory", parts.path.display())
        }
        BoundedFileErrorKind::NotRegular => {
            format!(
                "eBPF object path {} is not a regular file",
                parts.path.display()
            )
        }
        BoundedFileErrorKind::TooLarge => {
            let size_limit = parts.expect_size_limit();
            ebpf_object_too_large_reason(&parts.path, size_limit.size, size_limit.limit)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn object_reader_rejects_file_larger_than_limit() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let object = temp.path().join("bounded.bpf.o");
        fs::File::create(&object)?.set_len(MAX_EBPF_OBJECT_BYTES + 1)?;

        let error =
            read_ebpf_object_bytes(&object).expect_err("oversized eBPF object must be rejected");

        assert!(error.contains("too large"));
        Ok(())
    }
}
