use probe_core::SelectorRegistry;

use crate::ConfigViolation;

pub(super) fn validate(registry: &SelectorRegistry, violations: &mut Vec<ConfigViolation>) {
    for (name, selector) in registry.iter() {
        if name.trim().is_empty() {
            violations.push(ConfigViolation {
                field: "selectors".to_string(),
                reason: "selector name cannot be empty".to_string(),
            });
            continue;
        }
        if let Err(error) = selector.resolve_refs_with_registry(registry) {
            violations.push(ConfigViolation {
                field: format!("selectors.{name}"),
                reason: error.to_string(),
            });
        }
    }
}
