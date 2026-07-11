use std::{fmt, fs, io, path::Path};

use probe_core::{BootId, BootIdParseError, BootScopedInstant, MonotonicInstant};
use rustix::time::{ClockId, clock_gettime};

const LINUX_BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";

pub(crate) trait ActionClock: Send + Sync {
    fn now(&self) -> Result<BootScopedInstant, ActionClockError>;
}

pub(crate) struct LinuxActionClock {
    boot: BootId,
}

impl LinuxActionClock {
    pub(crate) fn open() -> Result<Self, ActionClockError> {
        Self::with_boot_id_path(Path::new(LINUX_BOOT_ID_PATH))
    }

    fn with_boot_id_path(path: &Path) -> Result<Self, ActionClockError> {
        let text = fs::read_to_string(path).map_err(ActionClockError::ReadBootId)?;
        let boot = text.parse().map_err(ActionClockError::ParseBootId)?;
        Ok(Self { boot })
    }
}

impl ActionClock for LinuxActionClock {
    fn now(&self) -> Result<BootScopedInstant, ActionClockError> {
        let timespec = clock_gettime(ClockId::Monotonic);
        let seconds = u64::try_from(timespec.tv_sec).map_err(|_| ActionClockError::OutOfRange)?;
        let nanoseconds =
            u64::try_from(timespec.tv_nsec).map_err(|_| ActionClockError::OutOfRange)?;
        let instant = seconds
            .checked_mul(1_000_000_000)
            .and_then(|value| value.checked_add(nanoseconds))
            .ok_or(ActionClockError::OutOfRange)?;
        Ok(BootScopedInstant::new(
            self.boot,
            MonotonicInstant::from_nanos(instant),
        ))
    }
}

#[derive(Debug)]
pub enum ActionClockError {
    ReadBootId(io::Error),
    ParseBootId(BootIdParseError),
    OutOfRange,
}

impl fmt::Display for ActionClockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReadBootId(error) => write!(formatter, "failed to read Linux boot ID: {error}"),
            Self::ParseBootId(error) => write!(formatter, "failed to parse Linux boot ID: {error}"),
            Self::OutOfRange => formatter.write_str("Linux monotonic clock is out of range"),
        }
    }
}

impl std::error::Error for ActionClockError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ReadBootId(error) => Some(error),
            Self::ParseBootId(error) => Some(error),
            Self::OutOfRange => None,
        }
    }
}
