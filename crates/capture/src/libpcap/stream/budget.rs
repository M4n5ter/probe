use std::collections::{HashMap, VecDeque};

use super::{MAX_TOTAL_PENDING_BYTES, MAX_TOTAL_PENDING_SEGMENTS, StreamKey};

#[derive(Debug, Default)]
pub(super) struct PendingIndex {
    counts: HashMap<StreamKey, PendingCount>,
    totals: PendingCount,
    queue: VecDeque<PendingVictim>,
    activity: HashMap<StreamKey, u64>,
}

impl PendingIndex {
    pub(super) fn update(
        &mut self,
        key: &StreamKey,
        activity_monotonic_ns: u64,
        after: PendingCount,
    ) {
        if after.has_pending() {
            let before = self.counts.insert(key.clone(), after).unwrap_or_default();
            self.totals = self.totals.remove(before).add(after);
            self.activity.insert(key.clone(), activity_monotonic_ns);
            self.queue.push_back(PendingVictim {
                key: key.clone(),
                activity_monotonic_ns,
            });
            self.compact_if_needed();
        } else {
            self.remove(key);
        }
    }

    pub(super) fn remove(&mut self, key: &StreamKey) {
        let before = self.counts.remove(key).unwrap_or_default();
        self.totals = self.totals.remove(before);
        self.activity.remove(key);
    }

    pub(super) fn clear(&mut self, key: &StreamKey) {
        self.remove(key);
    }

    pub(super) fn has_pending(&self) -> bool {
        self.totals.has_pending()
    }

    pub(super) fn exceeds_limit(&self) -> bool {
        self.totals.segments > MAX_TOTAL_PENDING_SEGMENTS
            || self.totals.bytes > MAX_TOTAL_PENDING_BYTES
    }

    pub(super) fn keys(&self) -> Vec<StreamKey> {
        let mut keys = self.counts.keys().cloned().collect::<Vec<_>>();
        keys.sort_by(|left, right| {
            self.activity
                .get(left)
                .copied()
                .unwrap_or_default()
                .cmp(&self.activity.get(right).copied().unwrap_or_default())
                .then_with(|| left.flow_id.0.cmp(&right.flow_id.0))
                .then_with(|| {
                    direction_order(left.direction).cmp(&direction_order(right.direction))
                })
        });
        keys
    }

    pub(super) fn pop_oldest(&mut self) -> Option<StreamKey> {
        while let Some(victim) = self.queue.pop_front() {
            if self
                .activity
                .get(&victim.key)
                .is_some_and(|activity| *activity == victim.activity_monotonic_ns)
                && self.counts.contains_key(&victim.key)
            {
                return Some(victim.key);
            }
        }
        None
    }

    fn compact_if_needed(&mut self) {
        let max_stale = self.counts.len().saturating_mul(4).saturating_add(1024);
        if self.queue.len() <= max_stale {
            return;
        }
        let activity = &self.activity;
        let counts = &self.counts;
        self.queue.retain(|victim| {
            activity
                .get(&victim.key)
                .is_some_and(|active| *active == victim.activity_monotonic_ns)
                && counts.contains_key(&victim.key)
        });
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct PendingCount {
    pub(super) segments: usize,
    pub(super) bytes: usize,
}

impl PendingCount {
    pub(super) fn has_pending(self) -> bool {
        self.segments != 0 || self.bytes != 0
    }

    fn add(self, other: Self) -> Self {
        Self {
            segments: self.segments.saturating_add(other.segments),
            bytes: self.bytes.saturating_add(other.bytes),
        }
    }

    fn remove(self, other: Self) -> Self {
        Self {
            segments: self.segments.saturating_sub(other.segments),
            bytes: self.bytes.saturating_sub(other.bytes),
        }
    }
}

#[derive(Debug)]
struct PendingVictim {
    key: StreamKey,
    activity_monotonic_ns: u64,
}

fn direction_order(direction: probe_core::Direction) -> u8 {
    match direction {
        probe_core::Direction::Inbound => 0,
        probe_core::Direction::Outbound => 1,
    }
}

#[cfg(test)]
mod tests {
    use probe_core::{Direction, FlowIdentity};

    use super::*;

    #[test]
    fn pending_victims_returns_oldest_current_candidate() {
        let mut index = PendingIndex::default();
        let first = stream_key("first", Direction::Outbound);
        let second = stream_key("second", Direction::Outbound);

        index.update(&first, 1, pending_count(1, 10));
        index.update(&second, 2, pending_count(1, 10));
        index.update(&first, 3, pending_count(2, 20));

        assert_eq!(index.pop_oldest(), Some(second));
        assert_eq!(index.pop_oldest(), Some(first));
        assert_eq!(index.pop_oldest(), None);
    }

    #[test]
    fn pending_victims_ignores_cleared_candidates() {
        let mut index = PendingIndex::default();
        let first = stream_key("first", Direction::Outbound);
        let second = stream_key("second", Direction::Outbound);

        index.update(&first, 1, pending_count(1, 10));
        index.update(&second, 2, pending_count(1, 10));
        index.remove(&first);

        assert_eq!(index.pop_oldest(), Some(second));
        assert_eq!(index.pop_oldest(), None);
    }

    fn pending_count(segments: usize, bytes: usize) -> PendingCount {
        PendingCount { segments, bytes }
    }

    fn stream_key(flow_id: &str, direction: Direction) -> StreamKey {
        StreamKey::new(FlowIdentity(flow_id.to_string()), direction)
    }
}
