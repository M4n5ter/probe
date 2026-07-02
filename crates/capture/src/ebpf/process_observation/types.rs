use ebpf_abi::EbpfProcessTracepointSpec;
use probe_core::TcpEndpoint;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EbpfProcessObservation {
    Connect(EbpfConnectTracepointObservation),
    Accept(EbpfAcceptTracepointObservation),
    Close(EbpfCloseTracepointObservation),
    CloseRange(EbpfCloseRangeTracepointObservation),
    ProcessLifecycle(EbpfProcessLifecycleObservation),
    Write(EbpfSocketWriteObservation),
    Read(EbpfSocketReadObservation),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfProcessObservationRuntimeDiagnostics {
    pub tracepoints: Result<EbpfProcessObservationTracepointDiagnostics, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfProcessObservationTracepointDiagnostics {
    pub firings: Vec<EbpfProcessObservationTracepointFiring>,
    pub active_liveness: Result<EbpfProcessObservationActiveTracepointLiveness, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfProcessObservationTracepointFiring {
    pub program_name: &'static str,
    pub category: &'static str,
    pub tracepoint_name: &'static str,
    pub firing_count: u64,
}

impl EbpfProcessObservationTracepointFiring {
    pub(crate) fn from_tracepoint_spec(spec: EbpfProcessTracepointSpec, firing_count: u64) -> Self {
        Self {
            program_name: spec.program_name,
            category: spec.category,
            tracepoint_name: spec.tracepoint_name,
            firing_count,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfProcessObservationActiveTracepointLiveness {
    pub programs: Vec<EbpfProcessObservationActiveTracepointLivenessProgram>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EbpfProcessObservationActiveTracepointLivenessProgram {
    pub program_name: &'static str,
    pub category: &'static str,
    pub tracepoint_name: &'static str,
    pub state: EbpfProcessObservationActiveTracepointLivenessState,
    pub before_firing_count: u64,
    pub after_firing_count: u64,
    pub reason: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfProcessObservationActiveTracepointLivenessState {
    Advanced,
    NotAdvanced,
    Unsupported,
}

impl EbpfProcessObservation {
    pub fn command_lossy(&self) -> String {
        self.process().command_lossy()
    }

    pub fn process(&self) -> &EbpfObservedProcess {
        match self {
            Self::Connect(observation) => &observation.process,
            Self::Accept(observation) => &observation.process,
            Self::Close(observation) => &observation.process,
            Self::CloseRange(observation) => &observation.process,
            Self::ProcessLifecycle(observation) => &observation.process,
            Self::Write(observation) => &observation.process,
            Self::Read(observation) => &observation.process,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EbpfObservedProcess {
    pub pid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub gid: u32,
    pub command: [u8; 16],
}

impl EbpfObservedProcess {
    pub fn command_lossy(&self) -> String {
        let len = self
            .command
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(self.command.len());
        String::from_utf8_lossy(&self.command[..len]).into_owned()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EbpfConnectTracepointObservation {
    pub process: EbpfObservedProcess,
    pub fd: i32,
    pub addrlen: u32,
    pub fd_table_epoch: u64,
    pub fd_generation: u64,
    pub endpoint: EbpfSocketEndpoint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EbpfAcceptTracepointObservation {
    pub process: EbpfObservedProcess,
    pub fd: i32,
    pub listen_fd: i32,
    pub addrlen: u32,
    pub fd_table_epoch: u64,
    pub fd_generation: u64,
    pub endpoint: EbpfSocketEndpoint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EbpfCloseTracepointObservation {
    pub process: EbpfObservedProcess,
    pub fd: i32,
    pub fd_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EbpfCloseRangeTracepointObservation {
    pub process: EbpfObservedProcess,
    pub first_fd: u32,
    pub last_fd: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EbpfProcessLifecycleObservation {
    pub process: EbpfObservedProcess,
    pub kind: EbpfProcessLifecycleKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EbpfProcessLifecycleKind {
    Exit,
    Exec,
}

impl EbpfProcessLifecycleKind {
    pub(crate) const fn boundary_description(self) -> &'static str {
        match self {
            Self::Exit => "TGID leader exit",
            Self::Exec => "process exec",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EbpfSocketWriteObservation {
    pub process: EbpfObservedProcess,
    pub fd: i32,
    pub fd_generation: u64,
    pub original_len: u32,
    pub buffer: Vec<u8>,
    pub truncated: bool,
    pub read_failed: bool,
    pub kernel_transfer: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EbpfSocketReadObservation {
    pub process: EbpfObservedProcess,
    pub fd: i32,
    pub fd_generation: u64,
    pub original_len: u32,
    pub buffer: Vec<u8>,
    pub truncated: bool,
    pub read_failed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EbpfSocketEndpoint {
    Remote(TcpEndpoint),
    SockaddrReadFailed,
    UnsupportedAddressFamily { value: u16 },
    Missing,
}

impl EbpfSocketEndpoint {
    pub fn remote_endpoint(self) -> Option<TcpEndpoint> {
        match self {
            Self::Remote(endpoint) => Some(endpoint),
            Self::SockaddrReadFailed | Self::UnsupportedAddressFamily { .. } | Self::Missing => {
                None
            }
        }
    }
}
