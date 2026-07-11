use std::{fs::File, io};

use rustix::fs::{FallocateFlags, fallocate};

pub fn preallocate(file: &File, length: u64) -> io::Result<()> {
    if length == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "preallocated file length must be non-zero",
        ));
    }
    fallocate(file, FallocateFlags::empty(), 0, length).map_err(io::Error::from)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt;

    use tempfile::tempfile;

    use super::*;

    #[test]
    fn preallocation_reserves_blocks_and_sets_the_file_length() {
        let file = tempfile().expect("temporary file");
        preallocate(&file, 1024 * 1024).expect("preallocate file");

        let metadata = file.metadata().expect("preallocated metadata");
        assert_eq!(metadata.len(), 1024 * 1024);
        assert!(metadata.blocks() > 0);
    }

    #[test]
    fn preallocation_rejects_an_empty_reserve() {
        let file = tempfile().expect("temporary file");
        assert_eq!(
            preallocate(&file, 0).expect_err("zero reserve").kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
