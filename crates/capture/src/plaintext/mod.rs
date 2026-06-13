mod event;
mod provider;

pub use event::{
    PlaintextChunk, PlaintextConnection, PlaintextEvent, PlaintextEventKind, PlaintextGap,
    PlaintextSource,
};
pub use provider::{PlaintextEventProvider, PlaintextEventProviderError};
