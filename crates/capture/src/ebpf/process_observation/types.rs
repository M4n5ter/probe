use probe_core::TcpEndpoint;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EbpfProcessObservation {
    Connect(EbpfConnectTracepointObservation),
}

impl EbpfProcessObservation {
    pub fn command_lossy(&self) -> String {
        self.process().command_lossy()
    }

    pub fn process(&self) -> &EbpfObservedProcess {
        match self {
            Self::Connect(observation) => &observation.process,
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
    pub endpoint: EbpfConnectEndpoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EbpfConnectEndpoint {
    Remote(TcpEndpoint),
    SockaddrReadFailed,
    UnsupportedAddressFamily { value: u16 },
    Missing,
}

impl EbpfConnectEndpoint {
    pub fn remote_endpoint(self) -> Option<TcpEndpoint> {
        match self {
            Self::Remote(endpoint) => Some(endpoint),
            Self::SockaddrReadFailed | Self::UnsupportedAddressFamily { .. } | Self::Missing => {
                None
            }
        }
    }
}
