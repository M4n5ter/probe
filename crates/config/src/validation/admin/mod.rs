use crate::{AdminConfig, ConfigViolation};

pub(super) fn validate(admin: &AdminConfig, violations: &mut Vec<ConfigViolation>) {
    if !admin.enabled {
        return;
    }
    if admin.socket_path.as_os_str().is_empty() {
        violations.push(ConfigViolation {
            field: "admin.socket_path".to_string(),
            reason: "enabled admin socket requires a socket path".to_string(),
        });
    } else if !admin.socket_path.is_absolute() {
        violations.push(ConfigViolation {
            field: "admin.socket_path".to_string(),
            reason: "admin socket path must be absolute".to_string(),
        });
    }
}
