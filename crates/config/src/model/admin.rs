use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdminConfig {
    pub enabled: bool,
    pub socket_path: PathBuf,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            socket_path: PathBuf::from("/run/traffic-probe/admin.sock"),
        }
    }
}
