mod family;
mod inbound;
mod outbound;
mod projection;
mod resources;
mod route;

use thiserror::Error;

pub use family::TransparentLinuxIpFamily;
pub use inbound::InboundTproxyLifecyclePlan;
pub use outbound::OutboundRedirectLifecyclePlan;
pub use resources::{
    InboundTproxyArtifactSpec, OutboundRedirectArtifactSpec, TransparentLinuxResources,
};

const INBOUND_TPROXY_OWNER_LOCK: &str = "inbound_tproxy";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TransparentLinuxPlanError {
    #[error(
        "transparent interception proxy listen port {proxy_port} must not be part of setup-time local port interception scope"
    )]
    ProxyPortInInterceptedLocalPorts { proxy_port: u16 },
    #[error(
        "transparent interception requires an explicit local port scope for proxy listen port {proxy_port}; wildcard local port interception needs a complete proxy self-bypass lifecycle first"
    )]
    WildcardLocalPortsRequireProxyBypass { proxy_port: u16 },
    #[error(
        "outbound MITM redirect requires an explicit remote port scope for proxy listen port {proxy_port}; wildcard remote port interception needs L7 proxy classification before rule installation"
    )]
    OutboundRedirectRequiresRemotePorts { proxy_port: u16 },
}

fn hex_mark(mark: u32) -> String {
    format!("0x{mark:x}")
}
