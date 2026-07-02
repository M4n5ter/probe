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
pub(crate) struct HitArea {
    rect: Rect,
    target: HitTarget,
}

impl HitArea {
    pub(crate) fn new(rect: Rect, target: HitTarget) -> Self {
        Self { rect, target }
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
            .find(|area| contains(area.rect, column, row))
            .map(|area| area.target)
    }
}

fn contains(rect: Rect, column: u16, row: u16) -> bool {
    column >= rect.x
        && column < rect.x.saturating_add(rect.width)
        && row >= rect.y
        && row < rect.y.saturating_add(rect.height)
}
