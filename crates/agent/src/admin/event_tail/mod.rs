mod decode;
mod error;
mod model;
mod read;

#[cfg(test)]
pub(crate) use model::EventTailOmissionReason;
pub(crate) use model::{
    EventDetailSnapshot, EventDetailTooLargeSnapshot, EventTailAttributionMode,
    EventTailBudgetSnapshot, EventTailEvent, EventTailKind, EventTailOmission, EventTailRecord,
    EventTailSnapshot,
};
pub(super) use read::{EventTailRequest, read_event_detail, read_event_tail};
