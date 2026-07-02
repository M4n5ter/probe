use std::process::ExitCode;

use serde::Serialize;

use super::capability::{E2eCapability, capability_ids, capability_summary};
use crate::e2e::{
    E2eOutcome,
    admin_enforcement_reload::{
        run as run_admin_enforcement_reload,
        run_runtime_actions as run_admin_runtime_actions_reload,
    },
    admin_policy_reload::run as run_admin_policy_reload,
    capture_loss_event_feed::run as run_capture_loss_event_feed,
    ebpf_process_loopback::run as run_ebpf_process_loopback,
    ebpf_process_output_loss::run as run_ebpf_process_output_loss,
    file_exporter::run as run_file_exporter,
    gap_plaintext_feed::run as run_gap_plaintext_feed,
    libpcap_loopback::run as run_libpcap_loopback,
    libpcap_websocket_loopback::run as run_libpcap_websocket_loopback,
    linux_socket_destroy_enforcement::run as run_linux_socket_destroy_enforcement,
    local_validation::run as run_local_validation,
    mitm_plaintext_bridge::{
        run as run_mitm_plaintext_bridge_live_sidecar,
        run_managed as run_managed_mitm_plaintext_bridge_live_sidecar,
        run_managed_outbound as run_managed_outbound_mitm_plaintext_bridge_live_sidecar,
        run_managed_policy_hook as run_managed_mitm_policy_hook_plaintext_bridge_live_sidecar,
        run_outbound as run_outbound_mitm_plaintext_bridge_live_sidecar,
        run_policy_hook as run_mitm_policy_hook_plaintext_bridge_live_sidecar,
        run_product_proxy_outbound_transparent_https_dns_discovery as run_product_outbound_mitm_proxy_transparent_https_dns_discovery,
        run_product_proxy_outbound_transparent_https_policy_hook as run_product_outbound_mitm_proxy_transparent_https_policy_hook,
        run_product_proxy_outbound_transparent_https_websocket as run_product_outbound_mitm_proxy_transparent_https_websocket,
        run_product_proxy_transparent_https_dns_discovery as run_product_mitm_proxy_transparent_https_dns_discovery,
        run_product_proxy_transparent_https_policy_hook as run_product_mitm_proxy_transparent_https_policy_hook,
        run_product_proxy_transparent_https_websocket as run_product_mitm_proxy_transparent_https_websocket,
    },
    plaintext_feed::run as run_plaintext_feed,
    product_mitm_proxy_local::run as run_product_mitm_proxy_local,
    remote_enforcement_policy::run as run_remote_enforcement_policy,
    remote_policy_bundle::run as run_remote_policy_bundle,
    remote_policy_polling::run as run_remote_policy_polling,
    replay::run as run_replay,
    sse_plaintext_feed::run as run_sse_plaintext_feed,
    tls_material_auto_binding_loopback::{
        run as run_tls_session_secret_auto_binding_loopback,
        run_key_log as run_tls_key_log_auto_binding_loopback,
        run_key_log_refresh as run_tls_key_log_material_refresh_auto_binding_loopback,
        run_refresh as run_tls_session_secret_material_refresh_auto_binding_loopback,
    },
    tls_plaintext_dynamic_library::{
        run as run_tls_plaintext_dynamic_library_loopback,
        run_unloadable as run_tls_plaintext_dynamic_library_unload_loopback,
    },
    tls_plaintext_loopback::{
        run as run_tls_plaintext_loopback, run_dynamic as run_tls_plaintext_dynamic_loopback,
        run_target_lifecycle as run_tls_plaintext_target_lifecycle_loopback,
    },
    tls_plaintext_output_loss::run as run_tls_plaintext_output_loss,
    tls_plaintext_provider_loopback::run as run_tls_plaintext_provider_loopback,
    transparent_linux_outbound_redirect_artifact::{
        run as run_transparent_linux_outbound_redirect_artifact,
        run_cgroup as run_transparent_linux_outbound_cgroup_artifact,
    },
    transparent_outbound_proxy_loopback::{
        run as run_transparent_outbound_proxy_loopback,
        run_external as run_transparent_outbound_external_proxy_loopback,
        run_flow_classified as run_transparent_outbound_flow_classifier_loopback,
        run_owner_scoped as run_transparent_outbound_owner_proxy_loopback,
        run_remote_policy_bundle as run_transparent_outbound_remote_policy_bundle_loopback,
    },
    transparent_tproxy_loopback::{
        run as run_transparent_tproxy_loopback,
        run_flow_classified as run_transparent_tproxy_flow_classifier_loopback,
        run_process_derived as run_transparent_tproxy_process_derived_loopback,
        run_process_scoped as run_transparent_tproxy_process_loopback,
    },
    unix_http_exporter::run as run_unix_http_exporter,
    webhook_exporter::run as run_webhook_exporter,
    websocket_plaintext_feed::run as run_websocket_plaintext_feed,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(in crate::e2e::suite) enum E2eRequirement {
    User,
    RootCapNetRaw,
    RootBpffs,
    RootNetAdmin,
}

impl E2eRequirement {
    pub(in crate::e2e::suite) fn is_privileged(self) -> bool {
        !matches!(self, Self::User)
    }

    pub(in crate::e2e::suite) fn label(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::RootCapNetRaw => "root/CAP_NET_RAW",
            Self::RootBpffs => "root/bpffs",
            Self::RootNetAdmin => "root/net-admin",
        }
    }

    pub(in crate::e2e::suite) fn id(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::RootCapNetRaw => "root_cap_net_raw",
            Self::RootBpffs => "root_bpffs",
            Self::RootNetAdmin => "root_net_admin",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(in crate::e2e::suite) struct E2eCase {
    pub(in crate::e2e::suite) name: &'static str,
    pub(in crate::e2e::suite) requirement: E2eRequirement,
    pub(super) capabilities: &'static [E2eCapability],
    pub(in crate::e2e::suite) run: E2eCaseRun,
}

impl E2eCase {
    pub(in crate::e2e::suite) fn capability_summary(&self) -> String {
        capability_summary(self.capabilities)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(in crate::e2e::suite) struct E2eCaseMetadata {
    pub(in crate::e2e::suite) name: &'static str,
    pub(in crate::e2e::suite) requirement: E2eRequirementMetadata,
    pub(in crate::e2e::suite) capabilities: Vec<&'static str>,
}

impl E2eCaseMetadata {
    pub(in crate::e2e::suite) fn from_case(case: &E2eCase) -> Self {
        Self {
            name: case.name,
            requirement: E2eRequirementMetadata::from_requirement(case.requirement),
            capabilities: capability_ids(case.capabilities),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(in crate::e2e::suite) struct E2eRequirementMetadata {
    pub(in crate::e2e::suite) id: &'static str,
    pub(in crate::e2e::suite) label: &'static str,
    pub(in crate::e2e::suite) privileged: bool,
}

impl E2eRequirementMetadata {
    fn from_requirement(requirement: E2eRequirement) -> Self {
        Self {
            id: requirement.id(),
            label: requirement.label(),
            privileged: requirement.is_privileged(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(in crate::e2e::suite) enum E2eCaseRun {
    ExitCode(fn() -> ExitCode),
    Outcome(fn() -> E2eOutcome),
}

impl E2eCaseRun {
    pub(in crate::e2e::suite) fn run(self) -> E2eOutcome {
        match self {
            Self::ExitCode(run) => E2eOutcome::from_exit_code(run()),
            Self::Outcome(run) => run(),
        }
    }
}

pub(super) const E2E_CASES: &[E2eCase] = &[
    E2eCase {
        name: "e2e-replay",
        requirement: E2eRequirement::User,
        capabilities: &[
            E2eCapability::ReplayPipeline,
            E2eCapability::HttpParsing,
            E2eCapability::LuaPolicyBundle,
            E2eCapability::DurableSpoolExport,
        ],
        run: E2eCaseRun::ExitCode(run_replay),
    },
    E2eCase {
        name: "e2e-plaintext-feed",
        requirement: E2eRequirement::User,
        capabilities: &[
            E2eCapability::PlaintextFeed,
            E2eCapability::HttpParsing,
            E2eCapability::LuaPolicyBundle,
            E2eCapability::DurableSpoolExport,
        ],
        run: E2eCaseRun::ExitCode(run_plaintext_feed),
    },
    E2eCase {
        name: "e2e-sse-plaintext-feed",
        requirement: E2eRequirement::User,
        capabilities: &[
            E2eCapability::PlaintextFeed,
            E2eCapability::SseParsing,
            E2eCapability::LuaPolicyBundle,
            E2eCapability::DurableSpoolExport,
        ],
        run: E2eCaseRun::ExitCode(run_sse_plaintext_feed),
    },
    E2eCase {
        name: "e2e-gap-plaintext-feed",
        requirement: E2eRequirement::User,
        capabilities: &[
            E2eCapability::PlaintextFeed,
            E2eCapability::GapSemantics,
            E2eCapability::HttpParsing,
            E2eCapability::DurableSpoolExport,
        ],
        run: E2eCaseRun::ExitCode(run_gap_plaintext_feed),
    },
    E2eCase {
        name: "e2e-capture-loss-event-feed",
        requirement: E2eRequirement::User,
        capabilities: &[
            E2eCapability::CaptureEventFeed,
            E2eCapability::CaptureLossEvent,
            E2eCapability::DurableSpoolExport,
        ],
        run: E2eCaseRun::ExitCode(run_capture_loss_event_feed),
    },
    E2eCase {
        name: "e2e-local-validation",
        requirement: E2eRequirement::User,
        capabilities: &[
            E2eCapability::CaptureEventFeed,
            E2eCapability::HttpParsing,
            E2eCapability::LuaPolicyBundle,
            E2eCapability::DurableSpoolExport,
            E2eCapability::FileExport,
            E2eCapability::AdminTail,
        ],
        run: E2eCaseRun::ExitCode(run_local_validation),
    },
    E2eCase {
        name: "e2e-product-mitm-proxy-local",
        requirement: E2eRequirement::User,
        capabilities: &[
            E2eCapability::CaptureEventFeed,
            E2eCapability::HttpParsing,
            E2eCapability::DurableSpoolExport,
            E2eCapability::MitmPlaintextBridge,
            E2eCapability::ProductMitmHttps,
        ],
        run: E2eCaseRun::ExitCode(run_product_mitm_proxy_local),
    },
    E2eCase {
        name: "e2e-websocket-plaintext-feed",
        requirement: E2eRequirement::User,
        capabilities: &[
            E2eCapability::PlaintextFeed,
            E2eCapability::WebSocketParsing,
            E2eCapability::LuaPolicyBundle,
            E2eCapability::DurableSpoolExport,
        ],
        run: E2eCaseRun::ExitCode(run_websocket_plaintext_feed),
    },
    E2eCase {
        name: "e2e-webhook-exporter",
        requirement: E2eRequirement::User,
        capabilities: &[
            E2eCapability::DurableSpoolExport,
            E2eCapability::WebhookExport,
        ],
        run: E2eCaseRun::ExitCode(run_webhook_exporter),
    },
    E2eCase {
        name: "e2e-file-exporter",
        requirement: E2eRequirement::User,
        capabilities: &[E2eCapability::DurableSpoolExport, E2eCapability::FileExport],
        run: E2eCaseRun::ExitCode(run_file_exporter),
    },
    E2eCase {
        name: "e2e-unix-http-exporter",
        requirement: E2eRequirement::User,
        capabilities: &[
            E2eCapability::DurableSpoolExport,
            E2eCapability::UnixHttpExport,
        ],
        run: E2eCaseRun::ExitCode(run_unix_http_exporter),
    },
    E2eCase {
        name: "e2e-remote-enforcement-policy",
        requirement: E2eRequirement::User,
        capabilities: &[E2eCapability::RemoteEnforcementPolicy],
        run: E2eCaseRun::ExitCode(run_remote_enforcement_policy),
    },
    E2eCase {
        name: "e2e-remote-policy-bundle",
        requirement: E2eRequirement::User,
        capabilities: &[
            E2eCapability::LuaPolicyBundle,
            E2eCapability::RemotePolicyBundle,
        ],
        run: E2eCaseRun::ExitCode(run_remote_policy_bundle),
    },
    E2eCase {
        name: "e2e-remote-policy-polling",
        requirement: E2eRequirement::User,
        capabilities: &[
            E2eCapability::LuaPolicyBundle,
            E2eCapability::RemotePolicyPolling,
        ],
        run: E2eCaseRun::ExitCode(run_remote_policy_polling),
    },
    E2eCase {
        name: "e2e-libpcap-loopback",
        requirement: E2eRequirement::RootCapNetRaw,
        capabilities: &[
            E2eCapability::LibpcapLiveCapture,
            E2eCapability::HttpParsing,
            E2eCapability::LuaPolicyBundle,
            E2eCapability::DurableSpoolExport,
        ],
        run: E2eCaseRun::ExitCode(run_libpcap_loopback),
    },
    E2eCase {
        name: "e2e-libpcap-websocket-loopback",
        requirement: E2eRequirement::RootCapNetRaw,
        capabilities: &[
            E2eCapability::LibpcapLiveCapture,
            E2eCapability::WebSocketParsing,
            E2eCapability::DurableSpoolExport,
        ],
        run: E2eCaseRun::ExitCode(run_libpcap_websocket_loopback),
    },
    E2eCase {
        name: "e2e-admin-policy-reload",
        requirement: E2eRequirement::RootCapNetRaw,
        capabilities: &[
            E2eCapability::AdminReload,
            E2eCapability::LibpcapLiveCapture,
            E2eCapability::LuaPolicyBundle,
        ],
        run: E2eCaseRun::ExitCode(run_admin_policy_reload),
    },
    E2eCase {
        name: "e2e-admin-enforcement-reload",
        requirement: E2eRequirement::RootCapNetRaw,
        capabilities: &[
            E2eCapability::AdminReload,
            E2eCapability::RemoteEnforcementPolicy,
        ],
        run: E2eCaseRun::ExitCode(run_admin_enforcement_reload),
    },
    E2eCase {
        name: "e2e-admin-runtime-actions-reload",
        requirement: E2eRequirement::RootCapNetRaw,
        capabilities: &[
            E2eCapability::AdminReload,
            E2eCapability::LibpcapLiveCapture,
            E2eCapability::LuaPolicyBundle,
            E2eCapability::RemoteEnforcementPolicy,
        ],
        run: E2eCaseRun::ExitCode(run_admin_runtime_actions_reload),
    },
    E2eCase {
        name: "e2e-linux-socket-destroy-enforcement",
        requirement: E2eRequirement::RootCapNetRaw,
        capabilities: &[E2eCapability::SocketDestroyEnforcement],
        run: E2eCaseRun::Outcome(run_linux_socket_destroy_enforcement),
    },
    E2eCase {
        name: "e2e-ebpf-process-loopback",
        requirement: E2eRequirement::RootBpffs,
        capabilities: &[
            E2eCapability::ProcessEbpfObservation,
            E2eCapability::HttpParsing,
            E2eCapability::LuaPolicyBundle,
            E2eCapability::DurableSpoolExport,
        ],
        run: E2eCaseRun::ExitCode(run_ebpf_process_loopback),
    },
    E2eCase {
        name: "e2e-ebpf-process-output-loss",
        requirement: E2eRequirement::RootBpffs,
        capabilities: &[
            E2eCapability::ProcessEbpfObservation,
            E2eCapability::ProcessEbpfOutputLoss,
            E2eCapability::CaptureLossEvent,
            E2eCapability::GapSemantics,
        ],
        run: E2eCaseRun::ExitCode(run_ebpf_process_output_loss),
    },
    E2eCase {
        name: "e2e-tls-plaintext-provider-loopback",
        requirement: E2eRequirement::RootBpffs,
        capabilities: &[
            E2eCapability::LibsslPlaintext,
            E2eCapability::HttpParsing,
            E2eCapability::DurableSpoolExport,
        ],
        run: E2eCaseRun::ExitCode(run_tls_plaintext_provider_loopback),
    },
    E2eCase {
        name: "e2e-tls-plaintext-output-loss",
        requirement: E2eRequirement::RootBpffs,
        capabilities: &[
            E2eCapability::LibsslPlaintext,
            E2eCapability::TlsPlaintextOutputLoss,
            E2eCapability::CaptureLossEvent,
            E2eCapability::GapSemantics,
        ],
        run: E2eCaseRun::ExitCode(run_tls_plaintext_output_loss),
    },
    E2eCase {
        name: "e2e-tls-plaintext-loopback",
        requirement: E2eRequirement::RootBpffs,
        capabilities: &[
            E2eCapability::LibsslPlaintext,
            E2eCapability::HttpParsing,
            E2eCapability::LuaPolicyBundle,
            E2eCapability::DurableSpoolExport,
        ],
        run: E2eCaseRun::ExitCode(run_tls_plaintext_loopback),
    },
    E2eCase {
        name: "e2e-tls-plaintext-dynamic-loopback",
        requirement: E2eRequirement::RootBpffs,
        capabilities: &[E2eCapability::LibsslPlaintext],
        run: E2eCaseRun::ExitCode(run_tls_plaintext_dynamic_loopback),
    },
    E2eCase {
        name: "e2e-tls-plaintext-target-lifecycle-loopback",
        requirement: E2eRequirement::RootBpffs,
        capabilities: &[E2eCapability::LibsslPlaintext],
        run: E2eCaseRun::ExitCode(run_tls_plaintext_target_lifecycle_loopback),
    },
    E2eCase {
        name: "e2e-tls-plaintext-dynamic-library-loopback",
        requirement: E2eRequirement::RootBpffs,
        capabilities: &[E2eCapability::LibsslPlaintext],
        run: E2eCaseRun::ExitCode(run_tls_plaintext_dynamic_library_loopback),
    },
    E2eCase {
        name: "e2e-tls-plaintext-dynamic-library-unload-loopback",
        requirement: E2eRequirement::RootBpffs,
        capabilities: &[E2eCapability::LibsslPlaintext],
        run: E2eCaseRun::ExitCode(run_tls_plaintext_dynamic_library_unload_loopback),
    },
    E2eCase {
        name: "e2e-tls-session-secret-auto-binding-loopback",
        requirement: E2eRequirement::RootCapNetRaw,
        capabilities: &[
            E2eCapability::TlsSessionSecretMaterial,
            E2eCapability::HttpParsing,
            E2eCapability::DurableSpoolExport,
        ],
        run: E2eCaseRun::ExitCode(run_tls_session_secret_auto_binding_loopback),
    },
    E2eCase {
        name: "e2e-tls-session-secret-material-refresh-auto-binding-loopback",
        requirement: E2eRequirement::RootCapNetRaw,
        capabilities: &[E2eCapability::TlsSessionSecretMaterial],
        run: E2eCaseRun::ExitCode(run_tls_session_secret_material_refresh_auto_binding_loopback),
    },
    E2eCase {
        name: "e2e-tls-keylog-auto-binding-loopback",
        requirement: E2eRequirement::RootCapNetRaw,
        capabilities: &[
            E2eCapability::TlsKeyLogMaterial,
            E2eCapability::HttpParsing,
            E2eCapability::DurableSpoolExport,
        ],
        run: E2eCaseRun::ExitCode(run_tls_key_log_auto_binding_loopback),
    },
    E2eCase {
        name: "e2e-tls-keylog-material-refresh-auto-binding-loopback",
        requirement: E2eRequirement::RootCapNetRaw,
        capabilities: &[E2eCapability::TlsKeyLogMaterial],
        run: E2eCaseRun::ExitCode(run_tls_key_log_material_refresh_auto_binding_loopback),
    },
    E2eCase {
        name: "e2e-transparent-tproxy-loopback",
        requirement: E2eRequirement::RootNetAdmin,
        capabilities: &[E2eCapability::TransparentInbound],
        run: E2eCaseRun::ExitCode(run_transparent_tproxy_loopback),
    },
    E2eCase {
        name: "e2e-transparent-tproxy-process-loopback",
        requirement: E2eRequirement::RootNetAdmin,
        capabilities: &[
            E2eCapability::TransparentInbound,
            E2eCapability::ProcessScopedInterception,
        ],
        run: E2eCaseRun::ExitCode(run_transparent_tproxy_process_loopback),
    },
    E2eCase {
        name: "e2e-transparent-tproxy-process-derived-loopback",
        requirement: E2eRequirement::RootNetAdmin,
        capabilities: &[
            E2eCapability::TransparentInbound,
            E2eCapability::ProcessScopedInterception,
        ],
        run: E2eCaseRun::ExitCode(run_transparent_tproxy_process_derived_loopback),
    },
    E2eCase {
        name: "e2e-transparent-tproxy-flow-classifier-loopback",
        requirement: E2eRequirement::RootNetAdmin,
        capabilities: &[
            E2eCapability::TransparentInbound,
            E2eCapability::FlowClassifiedInterception,
        ],
        run: E2eCaseRun::ExitCode(run_transparent_tproxy_flow_classifier_loopback),
    },
    E2eCase {
        name: "e2e-transparent-linux-outbound-redirect-artifact-netns",
        requirement: E2eRequirement::RootNetAdmin,
        capabilities: &[
            E2eCapability::TransparentOutbound,
            E2eCapability::LinuxTransparentArtifact,
        ],
        run: E2eCaseRun::ExitCode(run_transparent_linux_outbound_redirect_artifact),
    },
    E2eCase {
        name: "e2e-transparent-linux-outbound-cgroup-artifact-netns",
        requirement: E2eRequirement::RootNetAdmin,
        capabilities: &[
            E2eCapability::TransparentOutbound,
            E2eCapability::LinuxCgroupArtifact,
        ],
        run: E2eCaseRun::Outcome(run_transparent_linux_outbound_cgroup_artifact),
    },
    E2eCase {
        name: "e2e-transparent-outbound-proxy-loopback",
        requirement: E2eRequirement::RootNetAdmin,
        capabilities: &[E2eCapability::TransparentOutbound],
        run: E2eCaseRun::ExitCode(run_transparent_outbound_proxy_loopback),
    },
    E2eCase {
        name: "e2e-transparent-outbound-external-proxy-loopback",
        requirement: E2eRequirement::RootNetAdmin,
        capabilities: &[E2eCapability::TransparentOutbound],
        run: E2eCaseRun::ExitCode(run_transparent_outbound_external_proxy_loopback),
    },
    E2eCase {
        name: "e2e-transparent-outbound-owner-proxy-loopback",
        requirement: E2eRequirement::RootNetAdmin,
        capabilities: &[
            E2eCapability::TransparentOutbound,
            E2eCapability::OwnerScopedInterception,
        ],
        run: E2eCaseRun::ExitCode(run_transparent_outbound_owner_proxy_loopback),
    },
    E2eCase {
        name: "e2e-transparent-outbound-remote-policy-bundle-loopback",
        requirement: E2eRequirement::RootNetAdmin,
        capabilities: &[
            E2eCapability::TransparentOutbound,
            E2eCapability::RemotePolicyBundle,
        ],
        run: E2eCaseRun::ExitCode(run_transparent_outbound_remote_policy_bundle_loopback),
    },
    E2eCase {
        name: "e2e-transparent-outbound-flow-classifier-loopback",
        requirement: E2eRequirement::RootNetAdmin,
        capabilities: &[
            E2eCapability::TransparentOutbound,
            E2eCapability::FlowClassifiedInterception,
        ],
        run: E2eCaseRun::ExitCode(run_transparent_outbound_flow_classifier_loopback),
    },
    E2eCase {
        name: "e2e-mitm-plaintext-bridge-live-sidecar",
        requirement: E2eRequirement::RootNetAdmin,
        capabilities: &[E2eCapability::MitmPlaintextBridge],
        run: E2eCaseRun::ExitCode(run_mitm_plaintext_bridge_live_sidecar),
    },
    E2eCase {
        name: "e2e-mitm-policy-hook-plaintext-bridge-live-sidecar",
        requirement: E2eRequirement::RootNetAdmin,
        capabilities: &[
            E2eCapability::MitmPlaintextBridge,
            E2eCapability::MitmPolicyHook,
        ],
        run: E2eCaseRun::ExitCode(run_mitm_policy_hook_plaintext_bridge_live_sidecar),
    },
    E2eCase {
        name: "e2e-managed-mitm-plaintext-bridge-live-sidecar",
        requirement: E2eRequirement::RootNetAdmin,
        capabilities: &[
            E2eCapability::MitmPlaintextBridge,
            E2eCapability::ManagedMitmBackend,
        ],
        run: E2eCaseRun::ExitCode(run_managed_mitm_plaintext_bridge_live_sidecar),
    },
    E2eCase {
        name: "e2e-managed-mitm-policy-hook-plaintext-bridge-live-sidecar",
        requirement: E2eRequirement::RootNetAdmin,
        capabilities: &[
            E2eCapability::MitmPlaintextBridge,
            E2eCapability::MitmPolicyHook,
            E2eCapability::ManagedMitmBackend,
        ],
        run: E2eCaseRun::ExitCode(run_managed_mitm_policy_hook_plaintext_bridge_live_sidecar),
    },
    E2eCase {
        name: "e2e-product-mitm-proxy-transparent-https-policy-hook",
        requirement: E2eRequirement::RootNetAdmin,
        capabilities: &[
            E2eCapability::TransparentInbound,
            E2eCapability::MitmPlaintextBridge,
            E2eCapability::MitmPolicyHook,
            E2eCapability::ProductMitmHttps,
        ],
        run: E2eCaseRun::ExitCode(run_product_mitm_proxy_transparent_https_policy_hook),
    },
    E2eCase {
        name: "e2e-product-outbound-mitm-proxy-transparent-https-policy-hook",
        requirement: E2eRequirement::RootNetAdmin,
        capabilities: &[
            E2eCapability::TransparentOutbound,
            E2eCapability::MitmPlaintextBridge,
            E2eCapability::MitmPolicyHook,
            E2eCapability::ProductMitmHttps,
        ],
        run: E2eCaseRun::ExitCode(run_product_outbound_mitm_proxy_transparent_https_policy_hook),
    },
    E2eCase {
        name: "e2e-product-mitm-proxy-transparent-https-dns-discovery",
        requirement: E2eRequirement::RootNetAdmin,
        capabilities: &[
            E2eCapability::TransparentInbound,
            E2eCapability::MitmPlaintextBridge,
            E2eCapability::MitmPolicyHook,
            E2eCapability::ProductMitmHttps,
            E2eCapability::ProductMitmDnsDiscovery,
        ],
        run: E2eCaseRun::ExitCode(run_product_mitm_proxy_transparent_https_dns_discovery),
    },
    E2eCase {
        name: "e2e-product-outbound-mitm-proxy-transparent-https-dns-discovery",
        requirement: E2eRequirement::RootNetAdmin,
        capabilities: &[
            E2eCapability::TransparentOutbound,
            E2eCapability::MitmPlaintextBridge,
            E2eCapability::MitmPolicyHook,
            E2eCapability::ProductMitmHttps,
            E2eCapability::ProductMitmDnsDiscovery,
        ],
        run: E2eCaseRun::ExitCode(run_product_outbound_mitm_proxy_transparent_https_dns_discovery),
    },
    E2eCase {
        name: "e2e-product-mitm-proxy-transparent-https-websocket",
        requirement: E2eRequirement::RootNetAdmin,
        capabilities: &[
            E2eCapability::TransparentInbound,
            E2eCapability::MitmPlaintextBridge,
            E2eCapability::ProductMitmHttps,
            E2eCapability::ProductMitmWebSocket,
            E2eCapability::WebSocketParsing,
        ],
        run: E2eCaseRun::ExitCode(run_product_mitm_proxy_transparent_https_websocket),
    },
    E2eCase {
        name: "e2e-product-outbound-mitm-proxy-transparent-https-websocket",
        requirement: E2eRequirement::RootNetAdmin,
        capabilities: &[
            E2eCapability::TransparentOutbound,
            E2eCapability::MitmPlaintextBridge,
            E2eCapability::ProductMitmHttps,
            E2eCapability::ProductMitmWebSocket,
            E2eCapability::WebSocketParsing,
        ],
        run: E2eCaseRun::ExitCode(run_product_outbound_mitm_proxy_transparent_https_websocket),
    },
    E2eCase {
        name: "e2e-outbound-mitm-plaintext-bridge-live-sidecar",
        requirement: E2eRequirement::RootNetAdmin,
        capabilities: &[
            E2eCapability::TransparentOutbound,
            E2eCapability::MitmPlaintextBridge,
        ],
        run: E2eCaseRun::ExitCode(run_outbound_mitm_plaintext_bridge_live_sidecar),
    },
    E2eCase {
        name: "e2e-managed-outbound-mitm-plaintext-bridge-live-sidecar",
        requirement: E2eRequirement::RootNetAdmin,
        capabilities: &[
            E2eCapability::TransparentOutbound,
            E2eCapability::MitmPlaintextBridge,
            E2eCapability::ManagedMitmBackend,
        ],
        run: E2eCaseRun::ExitCode(run_managed_outbound_mitm_plaintext_bridge_live_sidecar),
    },
];

pub(in crate::e2e::suite) fn case_by_name(name: &str) -> Option<&'static E2eCase> {
    E2E_CASES.iter().find(|case| case.name == name)
}

pub(in crate::e2e::suite) fn case_names() -> impl Iterator<Item = &'static str> {
    E2E_CASES.iter().map(|case| case.name)
}

pub(in crate::e2e::suite) fn cases() -> &'static [E2eCase] {
    E2E_CASES
}
