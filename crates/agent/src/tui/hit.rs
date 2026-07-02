use ratatui::layout::Rect;

use super::{app::TuiTab, controls::ControlId, fields::FieldId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HitTarget {
    Tab(TuiTab),
    Field(FieldId),
    Control(ControlId),
    Process(usize),
    ProcessArgv(usize),
    ProcessMonitor(usize),
    TrafficProcess(usize),
    TrafficRow(usize),
    TrafficDetailPanel,
    TextEditPanel,
    TrafficDetailClose,
    TextEditSubmit,
    TextEditCancel,
    Save,
    Reload,
    Quit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScrollTarget {
    ProcessList,
    TrafficProcessList,
    TrafficEvents,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HitArea {
    rect: Rect,
    target: Option<HitTarget>,
    scroll_target: Option<ScrollTarget>,
}

impl HitArea {
    pub(crate) fn new(rect: Rect, target: HitTarget) -> Self {
        Self {
            rect,
            target: Some(target),
            scroll_target: None,
        }
    }

    pub(crate) fn scroll(rect: Rect, target: ScrollTarget) -> Self {
        Self {
            rect,
            target: None,
            scroll_target: Some(target),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct HitMap {
    areas: Vec<HitArea>,
}

impl HitMap {
    pub(crate) fn new(areas: Vec<HitArea>) -> Self {
        Self { areas }
    }

    pub(crate) fn hit(&self, column: u16, row: u16) -> Option<HitTarget> {
        self.areas
            .iter()
            .rev()
            .filter(|area| contains(area.rect, column, row))
            .find_map(|area| area.target)
    }

    pub(crate) fn scroll_target(&self, column: u16, row: u16) -> Option<ScrollTarget> {
        self.areas
            .iter()
            .rev()
            .filter(|area| contains(area.rect, column, row))
            .find_map(|area| area.scroll_target)
    }
}

fn contains(rect: Rect, column: u16, row: u16) -> bool {
    column >= rect.x
        && column < rect.x.saturating_add(rect.width)
        && row >= rect.y
        && row < rect.y.saturating_add(rect.height)
}
