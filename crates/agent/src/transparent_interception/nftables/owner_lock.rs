use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

use rustix::fs::{FlockOperation, flock};

use crate::transparent_interception::TransparentInterceptionError;

const LOCK_DIR: &str = "/run/sssa-probe/transparent-interception";

pub(super) trait NftablesOwnerLock: Send {
    fn acquire(
        &mut self,
        owner_name: &str,
    ) -> Result<NftablesOwnerLockGuard, TransparentInterceptionError>;
}

pub(super) struct SystemNftablesOwnerLock {
    directory: PathBuf,
}

impl Default for SystemNftablesOwnerLock {
    fn default() -> Self {
        Self {
            directory: PathBuf::from(LOCK_DIR),
        }
    }
}

impl NftablesOwnerLock for SystemNftablesOwnerLock {
    fn acquire(
        &mut self,
        owner_name: &str,
    ) -> Result<NftablesOwnerLockGuard, TransparentInterceptionError> {
        fs::create_dir_all(&self.directory).map_err(lock_io_error)?;
        let path = self.directory.join(format!("{owner_name}.lock"));
        let mut file = open_lock_file(&path)?;
        flock(&file, FlockOperation::NonBlockingLockExclusive)
            .map_err(|error| lock_acquisition_error(owner_name, error))?;
        file.set_len(0).map_err(lock_io_error)?;
        writeln!(file, "pid={}", std::process::id()).map_err(lock_io_error)?;
        Ok(NftablesOwnerLockGuard {
            inner: NftablesOwnerLockGuardInner::File { file },
        })
    }
}

pub(super) struct NftablesOwnerLockGuard {
    inner: NftablesOwnerLockGuardInner,
}

enum NftablesOwnerLockGuardInner {
    File {
        file: File,
    },
    #[cfg(test)]
    Noop,
}

impl Drop for NftablesOwnerLockGuard {
    fn drop(&mut self) {
        match &mut self.inner {
            NftablesOwnerLockGuardInner::File { file } => {
                let _ = flock(file, FlockOperation::Unlock);
            }
            #[cfg(test)]
            NftablesOwnerLockGuardInner::Noop => {}
        }
    }
}

#[cfg(test)]
pub(super) struct NoopNftablesOwnerLock;

#[cfg(test)]
impl NftablesOwnerLock for NoopNftablesOwnerLock {
    fn acquire(
        &mut self,
        _owner_name: &str,
    ) -> Result<NftablesOwnerLockGuard, TransparentInterceptionError> {
        Ok(NftablesOwnerLockGuard {
            inner: NftablesOwnerLockGuardInner::Noop,
        })
    }
}

fn open_lock_file(path: &Path) -> Result<File, TransparentInterceptionError> {
    OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .map_err(lock_io_error)
}

fn lock_acquisition_error(
    owner_name: &str,
    error: rustix::io::Errno,
) -> TransparentInterceptionError {
    let reason = if error == rustix::io::Errno::AGAIN || error == rustix::io::Errno::WOULDBLOCK {
        format!("transparent interception owner {owner_name} is already active")
    } else {
        format!("failed to acquire transparent interception owner lock {owner_name}: {error}")
    };
    TransparentInterceptionError::Nftables(reason)
}

fn lock_io_error(error: io::Error) -> TransparentInterceptionError {
    TransparentInterceptionError::Nftables(format!(
        "transparent interception owner lock error: {error}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_owner_lock_rejects_concurrent_owner() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let mut first = SystemNftablesOwnerLock {
            directory: temp.path().to_path_buf(),
        };
        let mut second = SystemNftablesOwnerLock {
            directory: temp.path().to_path_buf(),
        };

        let guard = first.acquire("inbound_tproxy")?;
        let path = temp.path().join("inbound_tproxy.lock");
        assert!(path.exists());

        let error = match second.acquire("inbound_tproxy") {
            Ok(_) => panic!("same owner must be single-writer"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("already active"));
        drop(guard);
        assert!(path.exists());
        second.acquire("inbound_tproxy")?;
        Ok(())
    }
}
