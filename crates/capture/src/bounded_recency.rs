use std::{
    collections::{HashMap, VecDeque},
    hash::Hash,
};

#[derive(Debug)]
pub(crate) struct BoundedRecencyMap<K, V> {
    entries: HashMap<K, V>,
    recency_order: VecDeque<K>,
    max_entries: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BoundedInsertDisplacement<K, V> {
    Replaced { key: K, value: V },
    Evicted { key: K, value: V },
    Dropped { key: K, value: V },
}

impl<K, V> BoundedRecencyMap<K, V>
where
    K: Clone + Eq + Hash,
{
    pub(crate) fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            recency_order: VecDeque::new(),
            max_entries,
        }
    }

    pub(crate) fn insert(&mut self, key: K, value: V) {
        let _ = self.insert_displacing(key, value);
    }

    pub(crate) fn insert_displacing(
        &mut self,
        key: K,
        value: V,
    ) -> Option<BoundedInsertDisplacement<K, V>> {
        if self.max_entries == 0 {
            return Some(BoundedInsertDisplacement::Dropped { key, value });
        }
        if self.entries.contains_key(&key) {
            self.recency_order.retain(|tracked_key| tracked_key != &key);
            self.recency_order.push_back(key.clone());
            self.entries
                .insert(key.clone(), value)
                .map(|value| BoundedInsertDisplacement::Replaced { key, value })
        } else {
            let evicted = self.evict_until_available();
            self.recency_order.push_back(key.clone());
            self.entries.insert(key, value);
            evicted.map(|(key, value)| BoundedInsertDisplacement::Evicted { key, value })
        }
    }

    pub(crate) fn remove(&mut self, key: &K) -> Option<V> {
        let value = self.entries.remove(key)?;
        self.recency_order.retain(|tracked_key| tracked_key != key);
        Some(value)
    }

    pub(crate) fn clear(&mut self) {
        self.entries.clear();
        self.recency_order.clear();
    }

    pub(crate) fn get(&self, key: &K) -> Option<&V> {
        self.entries.get(key)
    }

    pub(crate) fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.entries.get_mut(key)
    }

    pub(crate) fn refresh(&mut self, key: &K) -> bool {
        if !self.entries.contains_key(key) {
            return false;
        }
        self.recency_order.retain(|tracked_key| tracked_key != key);
        self.recency_order.push_back(key.clone());
        true
    }

    pub(crate) fn keys(&self) -> impl Iterator<Item = &K> {
        self.entries.keys()
    }

    pub(crate) fn values_by_recency(&self) -> impl Iterator<Item = &V> {
        self.recency_order
            .iter()
            .filter_map(|key| self.entries.get(key))
    }

    fn evict_until_available(&mut self) -> Option<(K, V)> {
        while self.entries.len() >= self.max_entries {
            let Some(evicted) = self.recency_order.pop_front() else {
                self.entries.clear();
                return None;
            };
            if let Some(value) = self.entries.remove(&evicted) {
                return Some((evicted, value));
            }
        }
        None
    }
}
