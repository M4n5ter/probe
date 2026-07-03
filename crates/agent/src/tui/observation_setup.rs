use probe_config::{AgentConfig, ObservationDataPathMode, ProcessObservationConfig};
use probe_core::{Direction, Selector};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProcessObservationMode {
    Auto,
    Ebpf,
    Libpcap,
}

impl ProcessObservationMode {
    pub(crate) fn data_path(self) -> ObservationDataPathMode {
        match self {
            Self::Auto => ObservationDataPathMode::Auto,
            Self::Ebpf => ObservationDataPathMode::Ebpf,
            Self::Libpcap => ObservationDataPathMode::Libpcap,
        }
    }

    pub(crate) fn label(self) -> &'static str {
        self.data_path().label()
    }
}

pub(crate) fn upsert_process_observation(
    config: &mut AgentConfig,
    id: String,
    selector: Selector,
    mode: ProcessObservationMode,
) {
    let observation = ProcessObservationConfig {
        id,
        selector,
        data_path: mode.data_path(),
        directions: vec![Direction::Inbound, Direction::Outbound],
    };
    if let Some(existing) = config
        .observations
        .iter_mut()
        .find(|existing| existing.id == observation.id)
    {
        *existing = observation;
    } else {
        config.observations.push(observation);
    }
}
