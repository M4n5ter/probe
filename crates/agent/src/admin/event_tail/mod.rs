mod decode;
mod error;
mod model;
mod read;
mod selector;

#[cfg(test)]
pub(crate) use model::EventTailOmissionReason;
pub(crate) use model::{
    EventDetailSnapshot, EventDetailTooLargeSnapshot, EventTailAttributionMode,
    EventTailBudgetSnapshot, EventTailEvent, EventTailKind, EventTailOmission, EventTailRecord,
    EventTailSnapshot,
};
pub(crate) use read::default_tail_scan_limit;
pub(super) use read::{EventTailRequest, read_event_detail, read_event_tail};
pub(crate) use selector::UnknownProcessCandidateSelector;
