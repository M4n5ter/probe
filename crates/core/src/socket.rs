use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::identity::AddressPort;

impl From<TcpEndpoint> for AddressPort {
    fn from(endpoint: TcpEndpoint) -> Self {
        Self {
            address: endpoint.address.to_string(),
            port: endpoint.port,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TcpEndpoint {
    pub address: IpAddr,
    pub port: u16,
}

impl TcpEndpoint {
    pub fn new(address: IpAddr, port: u16) -> Self {
        Self { address, port }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TcpConnection {
    pub local: TcpEndpoint,
    pub remote: TcpEndpoint,
}

impl TcpConnection {
    pub fn new(local: TcpEndpoint, remote: TcpEndpoint) -> Self {
        Self { local, remote }
    }
}
