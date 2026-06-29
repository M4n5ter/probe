use super::{
    EbpfCloseRangeTracepointObservation, EbpfCloseTracepointObservation, EbpfSocketReadObservation,
    EbpfSocketWriteObservation,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DescriptorLease {
    tgid: u32,
    fd: i32,
    fd_table_epoch: u64,
    fd_generation: u64,
}

impl DescriptorLease {
    pub(super) const fn new(
        tgid: u32,
        fd: i32,
        fd_table_epoch: u64,
        fd_generation: u64,
    ) -> Option<Self> {
        if fd < 0 || fd_table_epoch == 0 || fd_generation == 0 {
            return None;
        }
        Some(Self {
            tgid,
            fd,
            fd_table_epoch,
            fd_generation,
        })
    }

    pub(super) const fn tgid(self) -> u32 {
        self.tgid
    }

    pub(super) const fn fd(self) -> i32 {
        self.fd
    }

    pub(super) const fn fd_table_epoch(self) -> u64 {
        self.fd_table_epoch
    }

    pub(super) const fn fd_generation(self) -> u64 {
        self.fd_generation
    }

    pub(super) const fn key(self) -> DescriptorLeaseKey {
        DescriptorLeaseKey {
            tgid: self.tgid,
            fd: self.fd,
            fd_generation: self.fd_generation,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct DescriptorLeaseKey {
    tgid: u32,
    fd: i32,
    fd_generation: u64,
}

impl DescriptorLeaseKey {
    pub(super) const fn from_observed(tgid: u32, fd: i32, fd_generation: u64) -> Option<Self> {
        if fd < 0 || fd_generation == 0 {
            return None;
        }
        Some(Self {
            tgid,
            fd,
            fd_generation,
        })
    }

    pub(super) fn from_close(close: &EbpfCloseTracepointObservation) -> Option<Self> {
        Self::from_observed(close.process.tgid, close.fd, close.fd_generation)
    }

    pub(super) fn from_write(write: &EbpfSocketWriteObservation) -> Option<Self> {
        Self::from_observed(write.process.tgid, write.fd, write.fd_generation)
    }

    pub(super) fn from_read(read: &EbpfSocketReadObservation) -> Option<Self> {
        Self::from_observed(read.process.tgid, read.fd, read.fd_generation)
    }

    pub(super) const fn fd(self) -> i32 {
        self.fd
    }

    pub(super) const fn tgid(self) -> u32 {
        self.tgid
    }

    pub(super) const fn fd_generation(self) -> u64 {
        self.fd_generation
    }

    pub(super) fn is_in_close_range(
        self,
        close_range: &EbpfCloseRangeTracepointObservation,
    ) -> bool {
        self.tgid == close_range.process.tgid
            && (close_range.first_fd..=close_range.last_fd).contains(&(self.fd as u32))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_lease_rejects_invalid_identity_material() {
        assert!(DescriptorLease::new(100, -1, 9, 10).is_none());
        assert!(DescriptorLease::new(100, 7, 0, 10).is_none());
        assert!(DescriptorLease::new(100, 7, 9, 0).is_none());
    }

    #[test]
    fn descriptor_lease_key_rejects_unmatched_events_without_generation() {
        assert!(DescriptorLeaseKey::from_observed(100, -1, 10).is_none());
        assert!(DescriptorLeaseKey::from_observed(100, 7, 0).is_none());
    }
}
