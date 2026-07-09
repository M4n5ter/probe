use std::collections::BTreeSet;

use crate::process_catalog::ProcessCatalog;

use super::scrollbar::drag_position_to_scroll;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessViewState {
    selected_index: Option<usize>,
    scroll: usize,
    filter: String,
    visible_rows: usize,
    monitored_process_keys: BTreeSet<String>,
}

impl Default for ProcessViewState {
    fn default() -> Self {
        Self {
            selected_index: Some(0),
            scroll: 0,
            filter: String::new(),
            visible_rows: 12,
            monitored_process_keys: BTreeSet::new(),
        }
    }
}

impl ProcessViewState {
    pub(crate) fn selected_index(&self) -> Option<usize> {
        self.selected_index
    }

    pub(crate) fn scroll(&self) -> usize {
        self.scroll
    }

    pub(crate) fn filter(&self) -> &str {
        &self.filter
    }

    pub(crate) fn monitored_scope_count(&self) -> usize {
        self.monitored_process_keys.len()
    }

    pub(crate) fn monitors_process(&self, observation_key: &str) -> bool {
        self.monitored_process_keys.contains(observation_key)
    }

    pub(crate) fn replace_monitors(
        &mut self,
        process_keys: impl IntoIterator<Item = String>,
        catalog: &ProcessCatalog,
    ) {
        self.monitored_process_keys = process_keys.into_iter().collect();
        if self.filter.is_empty()
            && let Some(index) = catalog
                .entries()
                .iter()
                .position(|entry| self.monitors_process(&entry.observation_key()))
        {
            self.selected_index = Some(index);
            self.keep_selected_visible(catalog);
        }
    }

    pub(crate) fn set_viewport_rows(&mut self, rows: usize, catalog: &ProcessCatalog) {
        self.visible_rows = rows.max(1);
        self.clamp(catalog);
    }

    pub(crate) fn set_filter(&mut self, filter: String, catalog: &ProcessCatalog) {
        self.filter = filter.trim().to_string();
        self.scroll = 0;
        self.clamp(catalog);
    }

    pub(crate) fn clear_filter(&mut self, catalog: &ProcessCatalog) -> bool {
        if self.filter.is_empty() {
            return false;
        }
        self.filter.clear();
        self.scroll = 0;
        self.clamp(catalog);
        true
    }

    pub(crate) fn select(&mut self, index: usize, catalog: &ProcessCatalog) {
        if index < catalog.entries().len() {
            self.selected_index = Some(index);
            self.keep_selected_visible(catalog);
        }
    }

    pub(crate) fn set_single_monitor(&mut self, index: usize, catalog: &ProcessCatalog) -> bool {
        let Some(process) = catalog.entries().get(index) else {
            return false;
        };
        let key = process.observation_key();
        self.monitored_process_keys.clear();
        self.monitored_process_keys.insert(key);
        self.select(index, catalog);
        true
    }

    pub(crate) fn toggle_monitor(
        &mut self,
        index: usize,
        catalog: &ProcessCatalog,
    ) -> Option<bool> {
        let key = catalog.entries().get(index)?.observation_key();
        let monitored = if self.monitored_process_keys.remove(&key) {
            false
        } else {
            self.monitored_process_keys.insert(key);
            true
        };
        self.select(index, catalog);
        Some(monitored)
    }

    pub(crate) fn move_selection(&mut self, delta: isize, catalog: &ProcessCatalog) {
        let indices = self.filtered_indices(catalog);
        if indices.is_empty() {
            self.selected_index = None;
            self.scroll = 0;
            return;
        }
        let position = self
            .selected_index
            .and_then(|selected| indices.iter().position(|index| *index == selected))
            .unwrap_or_default();
        self.selected_index = Some(indices[offset_index(position, indices.len(), delta)]);
        self.keep_selected_visible(catalog);
    }

    pub(crate) fn drag_scrollbar(
        &mut self,
        offset: usize,
        height: usize,
        catalog: &ProcessCatalog,
    ) {
        let indices = self.filtered_indices(catalog);
        if indices.is_empty() {
            self.selected_index = None;
            self.scroll = 0;
            return;
        }
        let max_scroll = indices.len().saturating_sub(self.visible_rows.max(1));
        self.scroll = drag_position_to_scroll(offset, height, max_scroll);
        let selected_is_visible =
            self.selected_filtered_position(catalog)
                .is_some_and(|position| {
                    position >= self.scroll
                        && position < self.scroll.saturating_add(self.visible_rows.max(1))
                });
        if !selected_is_visible {
            self.selected_index = indices.get(self.scroll).copied();
        }
    }

    pub(crate) fn filtered_indices(&self, catalog: &ProcessCatalog) -> Vec<usize> {
        catalog
            .entries()
            .iter()
            .enumerate()
            .filter_map(|(index, process)| process.matches_query(&self.filter).then_some(index))
            .collect()
    }

    pub(crate) fn clamp(&mut self, catalog: &ProcessCatalog) {
        let indices = self.filtered_indices(catalog);
        self.selected_index = match (self.selected_index, indices.first().copied()) {
            (_, None) => None,
            (Some(selected), Some(_)) if indices.contains(&selected) => Some(selected),
            (_, Some(first)) => Some(first),
        };
        if self.scroll >= indices.len() {
            self.scroll = indices.len().saturating_sub(1);
        }
        self.keep_selected_visible(catalog);
    }

    fn keep_selected_visible(&mut self, catalog: &ProcessCatalog) {
        let Some(position) = self.selected_filtered_position(catalog) else {
            self.scroll = 0;
            return;
        };
        if position < self.scroll {
            self.scroll = position;
        }
        let end = self.scroll.saturating_add(self.visible_rows);
        if position >= end {
            self.scroll = position.saturating_sub(self.visible_rows - 1);
        }
    }

    fn selected_filtered_position(&self, catalog: &ProcessCatalog) -> Option<usize> {
        let selected = self.selected_index?;
        self.filtered_indices(catalog)
            .into_iter()
            .position(|index| index == selected)
    }
}

fn offset_index(index: usize, len: usize, delta: isize) -> usize {
    if len == 0 {
        return 0;
    }
    let raw = index as isize + delta;
    raw.clamp(0, len.saturating_sub(1) as isize) as usize
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::process_catalog::ProcessEntry;

    #[test]
    fn replace_monitors_selects_and_reveals_configured_process() {
        let catalog = ProcessCatalog::from_entries([
            process(1, "alpha", "/usr/bin/alpha"),
            process(2, "beta", "/usr/bin/beta"),
            process(3, "gamma", "/usr/bin/gamma"),
            process(4, "backend", "/app/backend"),
        ]);
        let mut view = ProcessViewState::default();
        view.set_viewport_rows(2, &catalog);

        view.replace_monitors(["process:process-key-4".to_string()], &catalog);

        assert_eq!(view.selected_index(), Some(3));
        assert_eq!(view.scroll(), 2);
        assert!(view.monitors_process("process:process-key-4"));
    }

    #[test]
    fn dragging_scrollbar_moves_process_viewport_and_selection() {
        let catalog = ProcessCatalog::from_entries([
            process(1, "alpha", "/usr/bin/alpha"),
            process(2, "beta", "/usr/bin/beta"),
            process(3, "gamma", "/usr/bin/gamma"),
            process(4, "backend", "/app/backend"),
        ]);
        let mut view = ProcessViewState::default();
        view.set_viewport_rows(2, &catalog);

        view.drag_scrollbar(3, 4, &catalog);

        assert_eq!(view.scroll(), 2);
        assert_eq!(view.selected_index(), Some(2));
    }

    fn process(pid: u32, name: &str, exe_path: &str) -> ProcessEntry {
        ProcessEntry {
            pid,
            process_key: format!("process-key-{pid}"),
            name: name.to_string(),
            exe_path: Some(PathBuf::from(exe_path)),
            argv: Vec::new(),
            uid: 1000,
            gid: 1000,
            cgroup_path: None,
        }
    }
}
