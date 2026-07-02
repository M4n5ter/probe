use std::path::{Path, PathBuf};

use probe_config::{
    default_admin_socket_path, default_enforcement_policy_path, default_export_file_path,
    default_mitm_ca_certificate_path, default_mitm_ca_private_key_path,
    default_mitm_plaintext_bridge_path, default_mitm_tls_root,
};

pub(super) const DEFAULT_MITM_PROXY_LISTEN_PORT: u16 = 15002;
pub(super) const DEFAULT_MITM_POLICY_HOOK_PORT: u16 = 15003;
const MITM_PROXY_BINARY_NAME: &str = "traffic-probe-mitm-proxy";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LocalProbeProfile {
    pub(super) export_file: PathBuf,
    pub(super) admin_socket: PathBuf,
    pub(super) mitm: LocalMitmProfile,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LocalMitmProfile {
    pub(super) proxy_listen_port: u16,
    pub(super) policy_hook_port: u16,
    pub(super) proxy_program: PathBuf,
    pub(super) enforcement_policy_file: PathBuf,
    pub(super) plaintext_feed: PathBuf,
    pub(super) tls_root: PathBuf,
    pub(super) ca_certificate: PathBuf,
    pub(super) ca_private_key: PathBuf,
}

impl Default for LocalProbeProfile {
    fn default() -> Self {
        Self {
            export_file: default_export_file_path(),
            admin_socket: default_admin_socket_path(),
            mitm: LocalMitmProfile::default(),
        }
    }
}

impl Default for LocalMitmProfile {
    fn default() -> Self {
        Self {
            proxy_listen_port: DEFAULT_MITM_PROXY_LISTEN_PORT,
            policy_hook_port: DEFAULT_MITM_POLICY_HOOK_PORT,
            proxy_program: default_mitm_proxy_program(),
            enforcement_policy_file: default_enforcement_policy_path(),
            plaintext_feed: default_mitm_plaintext_bridge_path(),
            tls_root: default_mitm_tls_root(),
            ca_certificate: default_mitm_ca_certificate_path(),
            ca_private_key: default_mitm_ca_private_key_path(),
        }
    }
}

impl LocalProbeProfile {
    #[cfg(test)]
    pub(super) fn with_root(root: &Path) -> Self {
        Self {
            export_file: root.join("export").join("events.jsonl"),
            admin_socket: root.join("run").join("admin.sock"),
            mitm: LocalMitmProfile::with_root(root),
        }
    }
}

impl LocalMitmProfile {
    #[cfg(test)]
    pub(super) fn with_root(root: &Path) -> Self {
        Self {
            proxy_program: root.join("bin").join(MITM_PROXY_BINARY_NAME),
            enforcement_policy_file: root.join("policy").join("enforcement.toml"),
            plaintext_feed: root.join("mitm").join("feed.jsonl"),
            tls_root: root.join("tls"),
            ca_certificate: root.join("tls").join("mitm-ca.pem"),
            ca_private_key: root.join("tls").join("mitm-ca.key"),
            ..Self::default()
        }
    }

    pub(super) fn readiness_target(&self) -> String {
        format!("127.0.0.1:{}", self.proxy_listen_port)
    }

    pub(super) fn policy_hook_endpoint(&self) -> String {
        format!(
            "http://127.0.0.1:{}/mitm-policy-hook",
            self.policy_hook_port
        )
    }

    pub(super) fn proxy_program_is_executable(&self) -> bool {
        is_executable_file(&self.proxy_program)
    }
}

fn default_mitm_proxy_program() -> PathBuf {
    let sibling = std::env::current_exe().ok().and_then(|path| {
        path.parent()
            .map(|parent| parent.join(MITM_PROXY_BINARY_NAME))
    });
    let system = PathBuf::from("/usr/local/bin").join(MITM_PROXY_BINARY_NAME);
    sibling
        .clone()
        .filter(|path| is_executable_file(path))
        .or_else(|| is_executable_file(&system).then_some(system.clone()))
        .or(sibling)
        .unwrap_or(system)
}

fn is_executable_file(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        path.metadata()
            .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}
