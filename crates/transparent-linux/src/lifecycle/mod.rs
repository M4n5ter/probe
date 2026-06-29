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

pub fn cleanup_all_policy_route_ip_commands(mark: u32, route_table: u32) -> Vec<Vec<String>> {
    TransparentLinuxIpFamily::all()
        .into_iter()
        .flat_map(|family| {
            [
                family.rule_command("del", mark, route_table),
                family.route_command("del", route_table),
            ]
        })
        .collect()
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TransparentLinuxPlanError {
    #[error(
        "transparent interception proxy listen port {proxy_port} must not be part of setup-time local port interception scope"
    )]
    ProxyPortInInterceptedLocalPorts { proxy_port: u16 },
    #[error(
        "transparent interception requires an explicit local port scope because wildcard local port interception would include proxy listen port {proxy_port}"
    )]
    WildcardLocalPortsIncludeProxyPort { proxy_port: u16 },
    #[error(
        "outbound transparent proxy redirect requires an explicit remote port scope for proxy listen port {proxy_port}; wildcard remote port interception needs flow-aware outbound scope resolution before rule installation"
    )]
    OutboundRedirectRequiresRemotePorts { proxy_port: u16 },
}

fn hex_mark(mark: u32) -> String {
    format!("0x{mark:x}")
}
