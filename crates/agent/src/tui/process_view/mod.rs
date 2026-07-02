use super::processes::ProcessCatalog;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessViewState {
    selected_index: Option<usize>,
    scroll: usize,
    filter: String,
    visible_rows: usize,
}

impl Default for ProcessViewState {
    fn default() -> Self {
        Self {
            selected_index: Some(0),
            scroll: 0,
            filter: String::new(),
            visible_rows: 12,
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
