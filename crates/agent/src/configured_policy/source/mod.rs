mod loader;

#[cfg(test)]
pub(crate) use loader::MAX_POLICY_SOURCE_BYTES;
pub(crate) use loader::{LoadedPolicySource, inspect_policy_source, load_policy_source};
