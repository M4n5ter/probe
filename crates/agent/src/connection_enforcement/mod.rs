mod linux_socket_destroy;
mod runtime;

use probe_config::ConnectionEnforcementBackendConfig;

pub(crate) use runtime::ConnectionEnforcementRuntime;

pub(crate) fn resolve(backend: ConnectionEnforcementBackendConfig) -> ConnectionEnforcementRuntime {
    match backend {
        ConnectionEnforcementBackendConfig::None => ConnectionEnforcementRuntime::unavailable(
            "connection-level enforcement backend is not configured",
        ),
        ConnectionEnforcementBackendConfig::LinuxSocketDestroy => linux_socket_destroy::resolve(),
    }
}
