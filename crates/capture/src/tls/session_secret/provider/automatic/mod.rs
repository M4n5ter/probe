mod binder;
mod buffered;
mod candidates;
mod provider;

pub(super) use binder::{Tls13SessionSecretAutomaticAction, Tls13SessionSecretAutomaticBinder};
pub use provider::Tls13SessionSecretAutoBindingProvider;

const TLS13_AUTO_BIND_MAX_SEQUENCE_NUMBER: u64 = 32;
