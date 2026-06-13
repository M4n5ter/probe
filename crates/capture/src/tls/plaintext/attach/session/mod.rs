mod lifecycle;
mod links;
mod target;
mod uprobe;

pub(in crate::tls::plaintext) use lifecycle::{AttachFailurePolicy, LibsslUprobeAttachSession};
