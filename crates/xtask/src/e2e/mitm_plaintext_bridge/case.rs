use super::{feed, tls};

pub(super) const EXTERNAL_INBOUND_CASE_NAME: &str = "e2e-mitm-plaintext-bridge-live-sidecar";
pub(super) const POLICY_HOOK_INBOUND_CASE_NAME: &str =
    "e2e-mitm-policy-hook-plaintext-bridge-live-sidecar";
pub(super) const MANAGED_INBOUND_CASE_NAME: &str = "e2e-managed-mitm-plaintext-bridge-live-sidecar";
pub(super) const MANAGED_POLICY_HOOK_INBOUND_CASE_NAME: &str =
    "e2e-managed-mitm-policy-hook-plaintext-bridge-live-sidecar";
pub(super) const PRODUCT_PROXY_TRANSPARENT_HTTPS_POLICY_HOOK_CASE_NAME: &str =
    "e2e-product-mitm-proxy-transparent-https-policy-hook";
pub(super) const PRODUCT_PROXY_OUTBOUND_TRANSPARENT_HTTPS_POLICY_HOOK_CASE_NAME: &str =
    "e2e-product-outbound-mitm-proxy-transparent-https-policy-hook";
pub(super) const PRODUCT_PROXY_TRANSPARENT_HTTPS_DNS_DISCOVERY_CASE_NAME: &str =
    "e2e-product-mitm-proxy-transparent-https-dns-discovery";
pub(super) const PRODUCT_PROXY_OUTBOUND_TRANSPARENT_HTTPS_DNS_DISCOVERY_CASE_NAME: &str =
    "e2e-product-outbound-mitm-proxy-transparent-https-dns-discovery";
pub(super) const PRODUCT_PROXY_TRANSPARENT_HTTPS_WEBSOCKET_CASE_NAME: &str =
    "e2e-product-mitm-proxy-transparent-https-websocket";
pub(super) const PRODUCT_PROXY_OUTBOUND_TRANSPARENT_HTTPS_WEBSOCKET_CASE_NAME: &str =
    "e2e-product-outbound-mitm-proxy-transparent-https-websocket";
pub(super) const EXTERNAL_OUTBOUND_CASE_NAME: &str =
    "e2e-outbound-mitm-plaintext-bridge-live-sidecar";
pub(super) const MANAGED_OUTBOUND_CASE_NAME: &str =
    "e2e-managed-outbound-mitm-plaintext-bridge-live-sidecar";
pub(super) const EXTERNAL_INBOUND_IN_NETNS_ENV: &str =
    "TRAFFIC_PROBE_E2E_MITM_PLAINTEXT_BRIDGE_NETNS";
pub(super) const POLICY_HOOK_INBOUND_IN_NETNS_ENV: &str =
    "TRAFFIC_PROBE_E2E_MITM_POLICY_HOOK_PLAINTEXT_BRIDGE_NETNS";
pub(super) const MANAGED_INBOUND_IN_NETNS_ENV: &str =
    "TRAFFIC_PROBE_E2E_MANAGED_MITM_PLAINTEXT_BRIDGE_NETNS";
pub(super) const MANAGED_POLICY_HOOK_INBOUND_IN_NETNS_ENV: &str =
    "TRAFFIC_PROBE_E2E_MANAGED_MITM_POLICY_HOOK_PLAINTEXT_BRIDGE_NETNS";
pub(super) const EXTERNAL_OUTBOUND_IN_NETNS_ENV: &str =
    "TRAFFIC_PROBE_E2E_OUTBOUND_MITM_PLAINTEXT_BRIDGE_NETNS";
pub(super) const MANAGED_OUTBOUND_IN_NETNS_ENV: &str =
    "TRAFFIC_PROBE_E2E_MANAGED_OUTBOUND_MITM_PLAINTEXT_BRIDGE_NETNS";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MitmBridgeCase {
    ExternalInbound,
    ExternalInboundPolicyHook,
    ManagedInbound,
    ManagedInboundPolicyHook,
    ProductProxyTransparentHttpsPolicyHook,
    ProductProxyOutboundTransparentHttpsPolicyHook,
    ProductProxyTransparentHttpsDnsDiscovery,
    ProductProxyOutboundTransparentHttpsDnsDiscovery,
    ProductProxyTransparentHttpsWebSocket,
    ProductProxyOutboundTransparentHttpsWebSocket,
    ExternalOutbound,
    ManagedOutbound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MitmBridgeDirection {
    Inbound,
    Outbound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MitmBackendKind {
    External,
    ManagedProcess,
    ProductProxy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MitmPolicyHookExercise {
    None,
    ExternalServerDelegatedDeny,
    ManagedFixtureDelegatedDeny,
    ProductProxyDelegatedDeny,
    ProductProxyEndpointOnly,
}

impl MitmPolicyHookExercise {
    pub(super) const fn enabled(self) -> bool {
        !matches!(self, Self::None)
    }

    pub(super) const fn expects_delegated_decision(self) -> bool {
        matches!(
            self,
            Self::ExternalServerDelegatedDeny
                | Self::ManagedFixtureDelegatedDeny
                | Self::ProductProxyDelegatedDeny
        )
    }

    pub(super) const fn uses_external_server(self) -> bool {
        matches!(self, Self::ExternalServerDelegatedDeny)
    }

    pub(super) const fn uses_managed_fixture(self) -> bool {
        matches!(self, Self::ManagedFixtureDelegatedDeny)
    }

    pub(super) const fn execution_reason(self) -> &'static str {
        match self {
            Self::ProductProxyDelegatedDeny | Self::ProductProxyEndpointOnly => {
                feed::POLICY_HOOK_PRODUCT_PROXY_RESPONSE_REASON
            }
            Self::None | Self::ExternalServerDelegatedDeny | Self::ManagedFixtureDelegatedDeny => {
                feed::POLICY_HOOK_RESPONSE_REASON
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MitmDataPlaneExercise {
    None,
    ManagedPlaintext,
    ProductProxyTransparentTls {
        upstream: MitmProductProxyUpstreamExercise,
    },
    ProductProxyTransparentTlsWebSocket {
        upstream: MitmProductProxyUpstreamExercise,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MitmProductProxyUpstreamExercise {
    Route(MitmProductProxyRouteExercise),
    DnsDiscovery,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MitmProductProxyRouteExercise {
    ExactServerName,
    WildcardE2eSuffix,
}

impl MitmProductProxyRouteExercise {
    pub(super) const fn host(self) -> &'static str {
        match self {
            Self::ExactServerName => tls::SERVER_NAME,
            Self::WildcardE2eSuffix => "*.e2e.test",
        }
    }
}

impl MitmProductProxyUpstreamExercise {
    pub(super) const fn server_name(self) -> &'static str {
        match self {
            Self::Route(_) => tls::SERVER_NAME,
            Self::DnsDiscovery => tls::DNS_DISCOVERY_SERVER_NAME,
        }
    }
}

impl MitmDataPlaneExercise {
    pub(super) const fn product_proxy_upstream(self) -> Option<MitmProductProxyUpstreamExercise> {
        match self {
            Self::ProductProxyTransparentTls { upstream }
            | Self::ProductProxyTransparentTlsWebSocket { upstream } => Some(upstream),
            Self::None | Self::ManagedPlaintext => None,
        }
    }

    pub(super) const fn product_proxy_server_name(self) -> Option<&'static str> {
        match self.product_proxy_upstream() {
            Some(upstream) => Some(upstream.server_name()),
            None => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct MitmBridgeCaseSpec {
    pub(super) backend: MitmBackendKind,
    pub(super) direction: MitmBridgeDirection,
    pub(super) policy_hook: MitmPolicyHookExercise,
    pub(super) data_plane: MitmDataPlaneExercise,
}

impl MitmBridgeCase {
    pub(super) const fn spec(self) -> MitmBridgeCaseSpec {
        match self {
            Self::ExternalInbound => MitmBridgeCaseSpec {
                backend: MitmBackendKind::External,
                direction: MitmBridgeDirection::Inbound,
                policy_hook: MitmPolicyHookExercise::None,
                data_plane: MitmDataPlaneExercise::None,
            },
            Self::ExternalInboundPolicyHook => MitmBridgeCaseSpec {
                backend: MitmBackendKind::External,
                direction: MitmBridgeDirection::Inbound,
                policy_hook: MitmPolicyHookExercise::ExternalServerDelegatedDeny,
                data_plane: MitmDataPlaneExercise::None,
            },
            Self::ManagedInbound => MitmBridgeCaseSpec {
                backend: MitmBackendKind::ManagedProcess,
                direction: MitmBridgeDirection::Inbound,
                policy_hook: MitmPolicyHookExercise::None,
                data_plane: MitmDataPlaneExercise::ManagedPlaintext,
            },
            Self::ManagedInboundPolicyHook => MitmBridgeCaseSpec {
                backend: MitmBackendKind::ManagedProcess,
                direction: MitmBridgeDirection::Inbound,
                policy_hook: MitmPolicyHookExercise::ManagedFixtureDelegatedDeny,
                data_plane: MitmDataPlaneExercise::ManagedPlaintext,
            },
            Self::ProductProxyTransparentHttpsPolicyHook => MitmBridgeCaseSpec {
                backend: MitmBackendKind::ProductProxy,
                direction: MitmBridgeDirection::Inbound,
                policy_hook: MitmPolicyHookExercise::ProductProxyDelegatedDeny,
                data_plane: MitmDataPlaneExercise::ProductProxyTransparentTls {
                    upstream: MitmProductProxyUpstreamExercise::Route(
                        MitmProductProxyRouteExercise::ExactServerName,
                    ),
                },
            },
            Self::ProductProxyOutboundTransparentHttpsPolicyHook => MitmBridgeCaseSpec {
                backend: MitmBackendKind::ProductProxy,
                direction: MitmBridgeDirection::Outbound,
                policy_hook: MitmPolicyHookExercise::ProductProxyDelegatedDeny,
                data_plane: MitmDataPlaneExercise::ProductProxyTransparentTls {
                    upstream: MitmProductProxyUpstreamExercise::Route(
                        MitmProductProxyRouteExercise::ExactServerName,
                    ),
                },
            },
            Self::ProductProxyTransparentHttpsDnsDiscovery => MitmBridgeCaseSpec {
                backend: MitmBackendKind::ProductProxy,
                direction: MitmBridgeDirection::Inbound,
                policy_hook: MitmPolicyHookExercise::ProductProxyDelegatedDeny,
                data_plane: MitmDataPlaneExercise::ProductProxyTransparentTls {
                    upstream: MitmProductProxyUpstreamExercise::DnsDiscovery,
                },
            },
            Self::ProductProxyOutboundTransparentHttpsDnsDiscovery => MitmBridgeCaseSpec {
                backend: MitmBackendKind::ProductProxy,
                direction: MitmBridgeDirection::Outbound,
                policy_hook: MitmPolicyHookExercise::ProductProxyDelegatedDeny,
                data_plane: MitmDataPlaneExercise::ProductProxyTransparentTls {
                    upstream: MitmProductProxyUpstreamExercise::DnsDiscovery,
                },
            },
            Self::ProductProxyTransparentHttpsWebSocket => MitmBridgeCaseSpec {
                backend: MitmBackendKind::ProductProxy,
                direction: MitmBridgeDirection::Inbound,
                policy_hook: MitmPolicyHookExercise::ProductProxyEndpointOnly,
                data_plane: MitmDataPlaneExercise::ProductProxyTransparentTlsWebSocket {
                    upstream: MitmProductProxyUpstreamExercise::Route(
                        MitmProductProxyRouteExercise::WildcardE2eSuffix,
                    ),
                },
            },
            Self::ProductProxyOutboundTransparentHttpsWebSocket => MitmBridgeCaseSpec {
                backend: MitmBackendKind::ProductProxy,
                direction: MitmBridgeDirection::Outbound,
                policy_hook: MitmPolicyHookExercise::ProductProxyEndpointOnly,
                data_plane: MitmDataPlaneExercise::ProductProxyTransparentTlsWebSocket {
                    upstream: MitmProductProxyUpstreamExercise::Route(
                        MitmProductProxyRouteExercise::ExactServerName,
                    ),
                },
            },
            Self::ExternalOutbound => MitmBridgeCaseSpec {
                backend: MitmBackendKind::External,
                direction: MitmBridgeDirection::Outbound,
                policy_hook: MitmPolicyHookExercise::None,
                data_plane: MitmDataPlaneExercise::None,
            },
            Self::ManagedOutbound => MitmBridgeCaseSpec {
                backend: MitmBackendKind::ManagedProcess,
                direction: MitmBridgeDirection::Outbound,
                policy_hook: MitmPolicyHookExercise::None,
                data_plane: MitmDataPlaneExercise::ManagedPlaintext,
            },
        }
    }

    pub(super) const fn case_name(self) -> &'static str {
        match self {
            Self::ExternalInbound => EXTERNAL_INBOUND_CASE_NAME,
            Self::ExternalInboundPolicyHook => POLICY_HOOK_INBOUND_CASE_NAME,
            Self::ManagedInbound => MANAGED_INBOUND_CASE_NAME,
            Self::ManagedInboundPolicyHook => MANAGED_POLICY_HOOK_INBOUND_CASE_NAME,
            Self::ProductProxyTransparentHttpsPolicyHook => {
                PRODUCT_PROXY_TRANSPARENT_HTTPS_POLICY_HOOK_CASE_NAME
            }
            Self::ProductProxyOutboundTransparentHttpsPolicyHook => {
                PRODUCT_PROXY_OUTBOUND_TRANSPARENT_HTTPS_POLICY_HOOK_CASE_NAME
            }
            Self::ProductProxyTransparentHttpsDnsDiscovery => {
                PRODUCT_PROXY_TRANSPARENT_HTTPS_DNS_DISCOVERY_CASE_NAME
            }
            Self::ProductProxyOutboundTransparentHttpsDnsDiscovery => {
                PRODUCT_PROXY_OUTBOUND_TRANSPARENT_HTTPS_DNS_DISCOVERY_CASE_NAME
            }
            Self::ProductProxyTransparentHttpsWebSocket => {
                PRODUCT_PROXY_TRANSPARENT_HTTPS_WEBSOCKET_CASE_NAME
            }
            Self::ProductProxyOutboundTransparentHttpsWebSocket => {
                PRODUCT_PROXY_OUTBOUND_TRANSPARENT_HTTPS_WEBSOCKET_CASE_NAME
            }
            Self::ExternalOutbound => EXTERNAL_OUTBOUND_CASE_NAME,
            Self::ManagedOutbound => MANAGED_OUTBOUND_CASE_NAME,
        }
    }

    pub(super) const fn netns_env(self) -> &'static str {
        match self {
            Self::ExternalInbound => EXTERNAL_INBOUND_IN_NETNS_ENV,
            Self::ExternalInboundPolicyHook => POLICY_HOOK_INBOUND_IN_NETNS_ENV,
            Self::ManagedInbound => MANAGED_INBOUND_IN_NETNS_ENV,
            Self::ManagedInboundPolicyHook => MANAGED_POLICY_HOOK_INBOUND_IN_NETNS_ENV,
            Self::ProductProxyTransparentHttpsPolicyHook => {
                "TRAFFIC_PROBE_E2E_PRODUCT_MITM_PROXY_TRANSPARENT_HTTPS_POLICY_HOOK_NETNS"
            }
            Self::ProductProxyOutboundTransparentHttpsPolicyHook => {
                "TRAFFIC_PROBE_E2E_PRODUCT_OUTBOUND_MITM_PROXY_TRANSPARENT_HTTPS_POLICY_HOOK_NETNS"
            }
            Self::ProductProxyTransparentHttpsDnsDiscovery => {
                "TRAFFIC_PROBE_E2E_PRODUCT_MITM_PROXY_TRANSPARENT_HTTPS_DNS_DISCOVERY_NETNS"
            }
            Self::ProductProxyOutboundTransparentHttpsDnsDiscovery => {
                "TRAFFIC_PROBE_E2E_PRODUCT_OUTBOUND_MITM_PROXY_TRANSPARENT_HTTPS_DNS_DISCOVERY_NETNS"
            }
            Self::ProductProxyTransparentHttpsWebSocket => {
                "TRAFFIC_PROBE_E2E_PRODUCT_MITM_PROXY_TRANSPARENT_HTTPS_WEBSOCKET_NETNS"
            }
            Self::ProductProxyOutboundTransparentHttpsWebSocket => {
                "TRAFFIC_PROBE_E2E_PRODUCT_OUTBOUND_MITM_PROXY_TRANSPARENT_HTTPS_WEBSOCKET_NETNS"
            }
            Self::ExternalOutbound => EXTERNAL_OUTBOUND_IN_NETNS_ENV,
            Self::ManagedOutbound => MANAGED_OUTBOUND_IN_NETNS_ENV,
        }
    }

    pub(super) const fn temp_root_name(self) -> &'static str {
        match self {
            Self::ExternalInbound => "mitm-bridge",
            Self::ExternalInboundPolicyHook => "mitm-policy-hook-bridge",
            Self::ManagedInbound => "managed-mitm-bridge",
            Self::ManagedInboundPolicyHook => "managed-mitm-policy-hook-bridge",
            Self::ProductProxyTransparentHttpsPolicyHook => "product-mitm-https",
            Self::ProductProxyOutboundTransparentHttpsPolicyHook => "product-outbound-mitm-https",
            Self::ProductProxyTransparentHttpsDnsDiscovery => "product-mitm-https-dns-discovery",
            Self::ProductProxyOutboundTransparentHttpsDnsDiscovery => "product-out-mitm-dns",
            Self::ProductProxyTransparentHttpsWebSocket => "product-mitm-https-websocket",
            Self::ProductProxyOutboundTransparentHttpsWebSocket => {
                "product-outbound-mitm-https-websocket"
            }
            Self::ExternalOutbound => "outbound-mitm-bridge",
            Self::ManagedOutbound => "managed-outbound-mitm-bridge",
        }
    }

    pub(super) const fn failure_label(self) -> &'static str {
        match self {
            Self::ExternalInbound => "e2e MITM plaintext bridge live sidecar",
            Self::ExternalInboundPolicyHook => "e2e MITM policy hook plaintext bridge live sidecar",
            Self::ManagedInbound => "e2e managed MITM plaintext bridge live sidecar",
            Self::ManagedInboundPolicyHook => {
                "e2e managed MITM policy hook plaintext bridge live sidecar"
            }
            Self::ProductProxyTransparentHttpsPolicyHook => {
                "e2e product MITM proxy transparent HTTPS policy hook"
            }
            Self::ProductProxyOutboundTransparentHttpsPolicyHook => {
                "e2e product outbound MITM proxy transparent HTTPS policy hook"
            }
            Self::ProductProxyTransparentHttpsDnsDiscovery => {
                "e2e product MITM proxy transparent HTTPS DNS discovery"
            }
            Self::ProductProxyOutboundTransparentHttpsDnsDiscovery => {
                "e2e product outbound MITM proxy transparent HTTPS DNS discovery"
            }
            Self::ProductProxyTransparentHttpsWebSocket => {
                "e2e product MITM proxy transparent HTTPS WebSocket"
            }
            Self::ProductProxyOutboundTransparentHttpsWebSocket => {
                "e2e product outbound MITM proxy transparent HTTPS WebSocket"
            }
            Self::ExternalOutbound => "e2e outbound MITM plaintext bridge live sidecar",
            Self::ManagedOutbound => "e2e managed outbound MITM plaintext bridge live sidecar",
        }
    }

    pub(super) const fn success_label(self) -> &'static str {
        match self {
            Self::ExternalInbound => "e2e MITM plaintext bridge live sidecar passed",
            Self::ExternalInboundPolicyHook => {
                "e2e MITM policy hook plaintext bridge live sidecar passed"
            }
            Self::ManagedInbound => "e2e managed MITM plaintext bridge live sidecar passed",
            Self::ManagedInboundPolicyHook => {
                "e2e managed MITM policy hook plaintext bridge live sidecar passed"
            }
            Self::ProductProxyTransparentHttpsPolicyHook => {
                "e2e product MITM proxy transparent HTTPS policy hook passed"
            }
            Self::ProductProxyOutboundTransparentHttpsPolicyHook => {
                "e2e product outbound MITM proxy transparent HTTPS policy hook passed"
            }
            Self::ProductProxyTransparentHttpsDnsDiscovery => {
                "e2e product MITM proxy transparent HTTPS DNS discovery passed"
            }
            Self::ProductProxyOutboundTransparentHttpsDnsDiscovery => {
                "e2e product outbound MITM proxy transparent HTTPS DNS discovery passed"
            }
            Self::ProductProxyTransparentHttpsWebSocket => {
                "e2e product MITM proxy transparent HTTPS WebSocket passed"
            }
            Self::ProductProxyOutboundTransparentHttpsWebSocket => {
                "e2e product outbound MITM proxy transparent HTTPS WebSocket passed"
            }
            Self::ExternalOutbound => "e2e outbound MITM plaintext bridge live sidecar passed",
            Self::ManagedOutbound => {
                "e2e managed outbound MITM plaintext bridge live sidecar passed"
            }
        }
    }

    pub(super) const fn backend(self) -> MitmBackendKind {
        self.spec().backend
    }

    pub(super) const fn direction(self) -> MitmBridgeDirection {
        self.spec().direction
    }

    pub(super) const fn policy_hook_execution_reason(self) -> &'static str {
        self.spec().policy_hook.execution_reason()
    }
}
