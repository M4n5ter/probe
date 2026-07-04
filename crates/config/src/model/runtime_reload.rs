use serde::{Deserialize, Serialize};

pub const DEFAULT_RUNTIME_RELOAD_WATCH_DEBOUNCE_MS: u64 = 500;
pub const MIN_RUNTIME_RELOAD_WATCH_DEBOUNCE_MS: u64 = 50;
pub const MAX_RUNTIME_RELOAD_WATCH_DEBOUNCE_MS: u64 = 60_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeReloadConfig {
    pub watch_config: bool,
    pub debounce_ms: u64,
}

impl Default for RuntimeReloadConfig {
    fn default() -> Self {
        Self {
            watch_config: true,
            debounce_ms: DEFAULT_RUNTIME_RELOAD_WATCH_DEBOUNCE_MS,
        }
    }
}
