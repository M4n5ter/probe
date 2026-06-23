use serde::{Deserialize, Serialize};

const TRANSPARENT_INTERCEPTION_NFTABLES_TABLE: &str = "sssa_probe";
const TRANSPARENT_INTERCEPTION_INBOUND_TPROXY_MARK: u32 = 0x5353_4101;
const TRANSPARENT_INTERCEPTION_OUTBOUND_PROXY_BYPASS_MARK: u32 = 0x5353_4102;
const TRANSPARENT_INTERCEPTION_INBOUND_TPROXY_ROUTE_TABLE: u32 = 53_534;
const TRANSPARENT_INTERCEPTION_OUTBOUND_CHAIN: &str = "outbound_transparent_proxy";
const TRANSPARENT_INTERCEPTION_OUTPUT_HOOK: &str = "output";
const TRANSPARENT_INTERCEPTION_DSTNAT_PRIORITY: &str = "dstnat";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparentLinuxResources {
    pub table_name: String,
    pub inbound_tproxy_mark: u32,
    pub outbound_proxy_bypass_mark: u32,
    pub inbound_tproxy_route_table: u32,
}

impl TransparentLinuxResources {
    pub fn reserved() -> Self {
        Self {
            table_name: TRANSPARENT_INTERCEPTION_NFTABLES_TABLE.to_string(),
            inbound_tproxy_mark: TRANSPARENT_INTERCEPTION_INBOUND_TPROXY_MARK,
            outbound_proxy_bypass_mark: TRANSPARENT_INTERCEPTION_OUTBOUND_PROXY_BYPASS_MARK,
            inbound_tproxy_route_table: TRANSPARENT_INTERCEPTION_INBOUND_TPROXY_ROUTE_TABLE,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundTproxyArtifactSpec {
    pub resources: TransparentLinuxResources,
    pub proxy_port: u16,
}

impl InboundTproxyArtifactSpec {
    pub fn new(resources: TransparentLinuxResources, proxy_port: u16) -> Self {
        Self {
            resources,
            proxy_port,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundRedirectArtifactSpec {
    pub table_name: String,
    pub chain_name: String,
    pub hook: String,
    pub priority: String,
    pub proxy_port: u16,
    pub proxy_bypass_mark: u32,
}

impl OutboundRedirectArtifactSpec {
    pub fn outbound_transparent_proxy(
        resources: TransparentLinuxResources,
        proxy_port: u16,
    ) -> Self {
        Self {
            table_name: resources.table_name,
            chain_name: TRANSPARENT_INTERCEPTION_OUTBOUND_CHAIN.to_string(),
            hook: TRANSPARENT_INTERCEPTION_OUTPUT_HOOK.to_string(),
            priority: TRANSPARENT_INTERCEPTION_DSTNAT_PRIORITY.to_string(),
            proxy_port,
            proxy_bypass_mark: resources.outbound_proxy_bypass_mark,
        }
    }
}
