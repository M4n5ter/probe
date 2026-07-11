use std::fmt;

use super::BootId;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MonotonicInstant(u64);

impl MonotonicInstant {
    pub const fn from_nanos(value: u64) -> Self {
        Self(value)
    }

    pub const fn as_nanos(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootScopedInstant {
    boot: BootId,
    instant: MonotonicInstant,
}

impl BootScopedInstant {
    pub const fn new(boot: BootId, instant: MonotonicInstant) -> Self {
        Self { boot, instant }
    }

    pub const fn boot(self) -> BootId {
        self.boot
    }

    pub const fn instant(self) -> MonotonicInstant {
        self.instant
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimeInterval {
    start: MonotonicInstant,
    end: MonotonicInstant,
}

impl TimeInterval {
    pub fn new(start: MonotonicInstant, end: MonotonicInstant) -> Result<Self, TimeIntervalError> {
        if start <= end {
            Ok(Self { start, end })
        } else {
            Err(TimeIntervalError::EndBeforeStart { start, end })
        }
    }

    pub const fn point(at: MonotonicInstant) -> Self {
        Self { start: at, end: at }
    }

    pub const fn start(self) -> MonotonicInstant {
        self.start
    }

    pub const fn end(self) -> MonotonicInstant {
        self.end
    }

    pub const fn contains(self, other: Self) -> bool {
        self.start.0 <= other.start.0 && self.end.0 >= other.end.0
    }

    pub const fn overlaps(self, other: Self) -> bool {
        self.start.0 <= other.end.0 && other.start.0 <= self.end.0
    }

    pub fn expand(self, nanos: u64) -> Result<Self, TimeIntervalError> {
        let start = self.start.0.saturating_sub(nanos);
        let end = self
            .end
            .0
            .checked_add(nanos)
            .ok_or(TimeIntervalError::ExpansionOverflow {
                end: self.end,
                nanos,
            })?;
        Ok(Self {
            start: MonotonicInstant(start),
            end: MonotonicInstant(end),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CalibratedInterval<C> {
    interval: TimeInterval,
    calibration: C,
    max_error_ns: u64,
}

impl<C: Copy> CalibratedInterval<C> {
    /// Creates a calibrated observation whose interval contains every possible event time.
    pub const fn new(interval: TimeInterval, calibration: C, max_error_ns: u64) -> Self {
        Self {
            interval,
            calibration,
            max_error_ns,
        }
    }

    pub const fn interval(self) -> TimeInterval {
        self.interval
    }

    pub const fn calibration(self) -> C {
        self.calibration
    }

    pub const fn max_error_ns(self) -> u64 {
        self.max_error_ns
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidityInterval {
    possible: TimeInterval,
    guaranteed: TimeInterval,
}

impl ValidityInterval {
    pub fn new(
        possible: TimeInterval,
        guaranteed: TimeInterval,
    ) -> Result<Self, ValidityIntervalError> {
        if possible.contains(guaranteed) {
            Ok(Self {
                possible,
                guaranteed,
            })
        } else {
            Err(ValidityIntervalError)
        }
    }

    pub const fn exact(interval: TimeInterval) -> Self {
        Self {
            possible: interval,
            guaranteed: interval,
        }
    }

    pub const fn possible(self) -> TimeInterval {
        self.possible
    }

    pub const fn guaranteed(self) -> TimeInterval {
        self.guaranteed
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidityIntervalError;

impl fmt::Display for ValidityIntervalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("guaranteed validity lies outside possible validity")
    }
}

impl std::error::Error for ValidityIntervalError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CalibratedValidity<C> {
    validity: ValidityInterval,
    calibration: C,
    max_error_ns: u64,
}

impl<C: Copy> CalibratedValidity<C> {
    pub const fn new(validity: ValidityInterval, calibration: C, max_error_ns: u64) -> Self {
        Self {
            validity,
            calibration,
            max_error_ns,
        }
    }

    pub const fn possible(self) -> TimeInterval {
        self.validity.possible()
    }

    pub const fn guaranteed(self) -> TimeInterval {
        self.validity.guaranteed()
    }

    pub const fn calibration(self) -> C {
        self.calibration
    }

    pub const fn max_error_ns(self) -> u64 {
        self.max_error_ns
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimeIntervalError {
    EndBeforeStart {
        start: MonotonicInstant,
        end: MonotonicInstant,
    },
    ExpansionOverflow {
        end: MonotonicInstant,
        nanos: u64,
    },
}

impl fmt::Display for TimeIntervalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EndBeforeStart { start, end } => write!(
                formatter,
                "time interval end {} precedes start {}",
                end.as_nanos(),
                start.as_nanos()
            ),
            Self::ExpansionOverflow { end, nanos } => write!(
                formatter,
                "expanding monotonic time {} by {nanos}ns overflows",
                end.as_nanos()
            ),
        }
    }
}

impl std::error::Error for TimeIntervalError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intervals_preserve_uncertainty_and_checked_expansion() {
        let interval = TimeInterval::new(
            MonotonicInstant::from_nanos(10),
            MonotonicInstant::from_nanos(20),
        )
        .expect("interval");
        let expanded = interval.expand(5).expect("expanded interval");

        assert_eq!(expanded.start().as_nanos(), 5);
        assert_eq!(expanded.end().as_nanos(), 25);
        assert!(expanded.contains(interval));
        assert!(interval.overlaps(TimeInterval::point(MonotonicInstant::from_nanos(20))));
    }

    #[test]
    fn validity_separates_possible_from_guaranteed_ownership() {
        let possible = TimeInterval::new(
            MonotonicInstant::from_nanos(10),
            MonotonicInstant::from_nanos(30),
        )
        .expect("possible interval");
        let guaranteed = TimeInterval::new(
            MonotonicInstant::from_nanos(15),
            MonotonicInstant::from_nanos(25),
        )
        .expect("guaranteed interval");

        let validity = ValidityInterval::new(possible, guaranteed).expect("validity interval");
        assert_eq!(validity.possible(), possible);
        assert_eq!(validity.guaranteed(), guaranteed);
        assert_eq!(
            ValidityInterval::new(guaranteed, possible),
            Err(ValidityIntervalError)
        );
    }
}
