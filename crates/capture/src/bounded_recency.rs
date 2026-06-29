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
        if self.max_entries == 0 {
            return;
        }
        if self.entries.contains_key(&key) {
            self.recency_order.retain(|tracked_key| tracked_key != &key);
        } else {
            self.evict_until_available();
        }
        self.recency_order.push_back(key.clone());
        self.entries.insert(key, value);
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

    fn evict_until_available(&mut self) {
        while self.entries.len() >= self.max_entries {
            let Some(evicted) = self.recency_order.pop_front() else {
                self.entries.clear();
                break;
            };
            if self.entries.remove(&evicted).is_some() {
                break;
            }
        }
    }
}
