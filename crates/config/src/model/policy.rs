use std::path::PathBuf;

use probe_core::Selector;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyConfig {
    pub id: String,
    pub path: PathBuf,
    pub enabled: bool,
    pub selector: Option<Selector>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            id: "default".to_string(),
            path: PathBuf::new(),
            enabled: true,
            selector: None,
        }
    }
}
