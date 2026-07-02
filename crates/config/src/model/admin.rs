use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};

use serde::{Deserialize, Serialize};

use super::paths::default_admin_socket_path;

pub const DEFAULT_ADMIN_PROMETHEUS_LISTEN_ADDR: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9464);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdminConfig {
    pub enabled: bool,
    pub socket_path: PathBuf,
    pub prometheus: AdminPrometheusConfig,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            socket_path: default_admin_socket_path(),
            prometheus: AdminPrometheusConfig::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdminPrometheusConfig {
    pub enabled: bool,
    pub listen_addr: SocketAddr,
}

impl Default for AdminPrometheusConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: DEFAULT_ADMIN_PROMETHEUS_LISTEN_ADDR,
        }
    }
}
