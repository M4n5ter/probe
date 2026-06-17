use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessGeneration {
    pub pid: u32,
    pub start_time_ticks: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub tgid: u32,
    pub start_time_ticks: u64,
    pub boot_id: String,
    pub exe_path: String,
    pub cmdline_hash: String,
    pub uid: u32,
    pub gid: u32,
    pub cgroup: Option<String>,
    pub systemd_service: Option<String>,
    pub container_id: Option<String>,
    pub runtime_hint: Option<String>,
}

impl ProcessIdentity {
    pub fn generation(&self) -> ProcessGeneration {
        ProcessGeneration {
            pid: self.pid,
            start_time_ticks: self.start_time_ticks,
        }
    }

    pub fn stable_key(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.boot_id.as_bytes());
        hasher.update(&self.pid.to_be_bytes());
        hasher.update(&self.start_time_ticks.to_be_bytes());
        hasher.update(self.exe_path.as_bytes());
        hasher.update(self.cmdline_hash.as_bytes());
        hasher.finalize().to_hex().to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessContext {
    pub identity: ProcessIdentity,
    pub name: String,
    pub cmdline: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddressPort {
    pub address: String,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowIdentity(pub String);

impl FlowIdentity {
    pub fn stable(
        process: &ProcessIdentity,
        local: &AddressPort,
        remote: &AddressPort,
        protocol: TransportProtocol,
        start_monotonic_ns: u64,
        socket_cookie: Option<u64>,
    ) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(process.stable_key().as_bytes());
        hasher.update(local.address.as_bytes());
        hasher.update(&local.port.to_be_bytes());
        hasher.update(remote.address.as_bytes());
        hasher.update(&remote.port.to_be_bytes());
        hasher.update(format!("{protocol:?}").as_bytes());
        hasher.update(&start_monotonic_ns.to_be_bytes());
        if let Some(socket_cookie) = socket_cookie {
            hasher.update(&socket_cookie.to_be_bytes());
        }
        Self(hasher.finalize().to_hex().to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowContext {
    pub id: FlowIdentity,
    pub process: ProcessContext,
    pub local: AddressPort,
    pub remote: AddressPort,
    pub protocol: TransportProtocol,
    pub start_monotonic_ns: u64,
    pub socket_cookie: Option<u64>,
    pub attribution_confidence: u8,
}
