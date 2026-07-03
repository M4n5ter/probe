use std::path::PathBuf;

use probe_config::{
    default_admin_socket_path, default_enforcement_policy_path, default_export_file_path,
    default_mitm_ca_certificate_path, default_mitm_ca_private_key_path,
    default_mitm_plaintext_bridge_path, default_mitm_tls_root,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LocalProbeProfile {
    pub(super) export_file: PathBuf,
    pub(super) admin_socket: PathBuf,
    pub(super) mitm: LocalMitmProfile,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LocalMitmProfile {
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
    pub(super) fn with_root(root: &std::path::Path) -> Self {
        Self {
            export_file: root.join("export").join("events.jsonl"),
            admin_socket: root.join("run").join("admin.sock"),
            mitm: LocalMitmProfile::with_root(root),
        }
    }
}

impl LocalMitmProfile {
    #[cfg(test)]
    pub(super) fn with_root(root: &std::path::Path) -> Self {
        Self {
            enforcement_policy_file: root.join("policy").join("enforcement.toml"),
            plaintext_feed: root.join("mitm").join("feed.jsonl"),
            tls_root: root.join("tls"),
            ca_certificate: root.join("tls").join("mitm-ca.pem"),
            ca_private_key: root.join("tls").join("mitm-ca.key"),
        }
    }
}
