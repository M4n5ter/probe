use crate::{AdminConfig, ConfigViolation};

pub(super) fn validate(admin: &AdminConfig, violations: &mut Vec<ConfigViolation>) {
    if !admin.enabled {
        if admin.prometheus.enabled {
            violations.push(ConfigViolation {
                field: "admin.prometheus.enabled".to_string(),
                reason: "prometheus metrics listener requires admin.enabled = true".to_string(),
            });
        }
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
    if admin.prometheus.enabled {
        validate_prometheus_listener(admin, violations);
    }
}

fn validate_prometheus_listener(admin: &AdminConfig, violations: &mut Vec<ConfigViolation>) {
    let listen_addr = admin.prometheus.listen_addr;
    if !listen_addr.ip().is_loopback() {
        violations.push(ConfigViolation {
            field: "admin.prometheus.listen_addr".to_string(),
            reason: "prometheus metrics listener must bind to a loopback address".to_string(),
        });
    }
    if listen_addr.port() == 0 {
        violations.push(ConfigViolation {
            field: "admin.prometheus.listen_addr".to_string(),
            reason: "prometheus metrics listener requires a non-zero port".to_string(),
        });
    }
}
