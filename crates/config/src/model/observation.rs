use probe_core::{Direction, Selector};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProcessObservationConfig {
    pub id: String,
    pub selector: Selector,
    pub data_path: ObservationDataPathMode,
    #[serde(default = "default_observation_directions")]
    pub directions: Vec<Direction>,
}

impl Default for ProcessObservationConfig {
    fn default() -> Self {
        Self {
            id: String::new(),
            selector: Selector::default(),
            data_path: ObservationDataPathMode::Auto,
            directions: default_observation_directions(),
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationDataPathMode {
    #[default]
    Auto,
    Ebpf,
    Libpcap,
}

fn default_observation_directions() -> Vec<Direction> {
    vec![Direction::Inbound, Direction::Outbound]
}

impl ObservationDataPathMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Ebpf => "ebpf",
            Self::Libpcap => "libpcap",
        }
    }
}
