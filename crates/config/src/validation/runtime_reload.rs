use crate::{
    ConfigViolation, MAX_RUNTIME_RELOAD_WATCH_DEBOUNCE_MS, MIN_RUNTIME_RELOAD_WATCH_DEBOUNCE_MS,
    RuntimeReloadConfig,
};

pub(super) fn validate(
    runtime_reload: &RuntimeReloadConfig,
    violations: &mut Vec<ConfigViolation>,
) {
    if !(MIN_RUNTIME_RELOAD_WATCH_DEBOUNCE_MS..=MAX_RUNTIME_RELOAD_WATCH_DEBOUNCE_MS)
        .contains(&runtime_reload.debounce_ms)
    {
        violations.push(ConfigViolation {
            field: "runtime_reload.debounce_ms".to_string(),
            reason: format!(
                "runtime config reload watcher debounce_ms must be between {MIN_RUNTIME_RELOAD_WATCH_DEBOUNCE_MS} and {MAX_RUNTIME_RELOAD_WATCH_DEBOUNCE_MS}"
            ),
        });
    }
}
