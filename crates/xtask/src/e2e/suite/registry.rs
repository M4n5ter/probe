use std::{collections::BTreeSet, process::ExitCode};

use super::super::{
    admin_enforcement_reload::run as run_admin_enforcement_reload,
    admin_policy_reload::run as run_admin_policy_reload,
    capture_loss_event_feed::run as run_capture_loss_event_feed,
    ebpf_process_loopback::run as run_ebpf_process_loopback,
    file_exporter::run as run_file_exporter,
    gap_plaintext_feed::run as run_gap_plaintext_feed,
    libpcap_loopback::run as run_libpcap_loopback,
    libpcap_websocket_loopback::run as run_libpcap_websocket_loopback,
    mitm_plaintext_bridge::run as run_mitm_plaintext_bridge_live_sidecar,
    plaintext_feed::run as run_plaintext_feed,
    remote_enforcement_policy::run as run_remote_enforcement_policy,
    remote_policy_bundle::run as run_remote_policy_bundle,
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
    tls_plaintext_provider_loopback::run as run_tls_plaintext_provider_loopback,
    transparent_linux_outbound_redirect_artifact::run as run_transparent_linux_outbound_redirect_artifact,
    transparent_outbound_proxy_loopback::{
        run as run_transparent_outbound_proxy_loopback,
        run_external as run_transparent_outbound_external_proxy_loopback,
        run_owner_scoped as run_transparent_outbound_owner_proxy_loopback,
        run_remote_policy_bundle as run_transparent_outbound_remote_policy_bundle_loopback,
    },
    transparent_tproxy_loopback::{
        run as run_transparent_tproxy_loopback,
        run_process_scoped as run_transparent_tproxy_process_loopback,
    },
    webhook_exporter::run as run_webhook_exporter,
    websocket_plaintext_feed::run as run_websocket_plaintext_feed,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SuiteSelection {
    Default,
    IncludePrivileged,
    OnlyPrivileged,
    Cases(BTreeSet<String>),
    Profile(E2eProfileId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum E2eRequirement {
    User,
    RootCapNetRaw,
    RootBpffs,
    RootNetAdmin,
}

impl E2eRequirement {
    pub(super) fn is_privileged(self) -> bool {
        !matches!(self, Self::User)
    }

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::RootCapNetRaw => "root/CAP_NET_RAW",
            Self::RootBpffs => "root/bpffs",
            Self::RootNetAdmin => "root/net-admin",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct E2eCase {
    pub(super) name: &'static str,
    pub(super) requirement: E2eRequirement,
    pub(super) run: fn() -> ExitCode,
}

#[derive(Debug, Clone, Copy)]
struct E2eProfile {
    id: E2eProfileId,
    name: &'static str,
    description: &'static str,
    cases: E2eProfileCases,
}

#[derive(Debug, Clone, Copy)]
enum E2eProfileCases {
    Named(&'static [&'static str]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum E2eProfileId {
    Baseline,
    LiveCore,
    ProcessEbpf,
    TlsPlaintext,
    TransparentInterception,
    LinuxArtifacts,
    Product,
}

const E2E_CASES: &[E2eCase] = &[
    E2eCase {
        name: "e2e-plaintext-feed",
        requirement: E2eRequirement::User,
        run: run_plaintext_feed,
    },
    E2eCase {
        name: "e2e-sse-plaintext-feed",
        requirement: E2eRequirement::User,
        run: run_sse_plaintext_feed,
    },
    E2eCase {
        name: "e2e-gap-plaintext-feed",
        requirement: E2eRequirement::User,
        run: run_gap_plaintext_feed,
    },
    E2eCase {
        name: "e2e-capture-loss-event-feed",
        requirement: E2eRequirement::User,
        run: run_capture_loss_event_feed,
    },
    E2eCase {
        name: "e2e-websocket-plaintext-feed",
        requirement: E2eRequirement::User,
        run: run_websocket_plaintext_feed,
    },
    E2eCase {
        name: "e2e-webhook-exporter",
        requirement: E2eRequirement::User,
        run: run_webhook_exporter,
    },
    E2eCase {
        name: "e2e-file-exporter",
        requirement: E2eRequirement::User,
        run: run_file_exporter,
    },
    E2eCase {
        name: "e2e-remote-enforcement-policy",
        requirement: E2eRequirement::User,
        run: run_remote_enforcement_policy,
    },
    E2eCase {
        name: "e2e-remote-policy-bundle",
        requirement: E2eRequirement::User,
        run: run_remote_policy_bundle,
    },
    E2eCase {
        name: "e2e-libpcap-loopback",
        requirement: E2eRequirement::RootCapNetRaw,
        run: run_libpcap_loopback,
    },
    E2eCase {
        name: "e2e-libpcap-websocket-loopback",
        requirement: E2eRequirement::RootCapNetRaw,
        run: run_libpcap_websocket_loopback,
    },
    E2eCase {
        name: "e2e-admin-policy-reload",
        requirement: E2eRequirement::RootCapNetRaw,
        run: run_admin_policy_reload,
    },
    E2eCase {
        name: "e2e-admin-enforcement-reload",
        requirement: E2eRequirement::RootCapNetRaw,
        run: run_admin_enforcement_reload,
    },
    E2eCase {
        name: "e2e-ebpf-process-loopback",
        requirement: E2eRequirement::RootBpffs,
        run: run_ebpf_process_loopback,
    },
    E2eCase {
        name: "e2e-tls-plaintext-provider-loopback",
        requirement: E2eRequirement::RootBpffs,
        run: run_tls_plaintext_provider_loopback,
    },
    E2eCase {
        name: "e2e-tls-plaintext-loopback",
        requirement: E2eRequirement::RootBpffs,
        run: run_tls_plaintext_loopback,
    },
    E2eCase {
        name: "e2e-tls-plaintext-dynamic-loopback",
        requirement: E2eRequirement::RootBpffs,
        run: run_tls_plaintext_dynamic_loopback,
    },
    E2eCase {
        name: "e2e-tls-plaintext-target-lifecycle-loopback",
        requirement: E2eRequirement::RootBpffs,
        run: run_tls_plaintext_target_lifecycle_loopback,
    },
    E2eCase {
        name: "e2e-tls-plaintext-dynamic-library-loopback",
        requirement: E2eRequirement::RootBpffs,
        run: run_tls_plaintext_dynamic_library_loopback,
    },
    E2eCase {
        name: "e2e-tls-plaintext-dynamic-library-unload-loopback",
        requirement: E2eRequirement::RootBpffs,
        run: run_tls_plaintext_dynamic_library_unload_loopback,
    },
    E2eCase {
        name: "e2e-tls-session-secret-auto-binding-loopback",
        requirement: E2eRequirement::RootCapNetRaw,
        run: run_tls_session_secret_auto_binding_loopback,
    },
    E2eCase {
        name: "e2e-tls-session-secret-material-refresh-auto-binding-loopback",
        requirement: E2eRequirement::RootCapNetRaw,
        run: run_tls_session_secret_material_refresh_auto_binding_loopback,
    },
    E2eCase {
        name: "e2e-tls-keylog-auto-binding-loopback",
        requirement: E2eRequirement::RootCapNetRaw,
        run: run_tls_key_log_auto_binding_loopback,
    },
    E2eCase {
        name: "e2e-tls-keylog-material-refresh-auto-binding-loopback",
        requirement: E2eRequirement::RootCapNetRaw,
        run: run_tls_key_log_material_refresh_auto_binding_loopback,
    },
    E2eCase {
        name: "e2e-transparent-tproxy-loopback",
        requirement: E2eRequirement::RootNetAdmin,
        run: run_transparent_tproxy_loopback,
    },
    E2eCase {
        name: "e2e-transparent-tproxy-process-loopback",
        requirement: E2eRequirement::RootNetAdmin,
        run: run_transparent_tproxy_process_loopback,
    },
    E2eCase {
        name: "e2e-transparent-linux-outbound-redirect-artifact-netns",
        requirement: E2eRequirement::RootNetAdmin,
        run: run_transparent_linux_outbound_redirect_artifact,
    },
    E2eCase {
        name: "e2e-transparent-outbound-proxy-loopback",
        requirement: E2eRequirement::RootNetAdmin,
        run: run_transparent_outbound_proxy_loopback,
    },
    E2eCase {
        name: "e2e-transparent-outbound-external-proxy-loopback",
        requirement: E2eRequirement::RootNetAdmin,
        run: run_transparent_outbound_external_proxy_loopback,
    },
    E2eCase {
        name: "e2e-transparent-outbound-owner-proxy-loopback",
        requirement: E2eRequirement::RootNetAdmin,
        run: run_transparent_outbound_owner_proxy_loopback,
    },
    E2eCase {
        name: "e2e-transparent-outbound-remote-policy-bundle-loopback",
        requirement: E2eRequirement::RootNetAdmin,
        run: run_transparent_outbound_remote_policy_bundle_loopback,
    },
    E2eCase {
        name: "e2e-mitm-plaintext-bridge-live-sidecar",
        requirement: E2eRequirement::RootNetAdmin,
        run: run_mitm_plaintext_bridge_live_sidecar,
    },
];

const E2E_PROFILES: &[E2eProfile] = &[
    E2eProfile {
        id: E2eProfileId::Baseline,
        name: "baseline",
        description: "non-privileged replay/plaintext/export/policy regression suite",
        cases: E2eProfileCases::Named(&[
            "e2e-plaintext-feed",
            "e2e-sse-plaintext-feed",
            "e2e-gap-plaintext-feed",
            "e2e-capture-loss-event-feed",
            "e2e-websocket-plaintext-feed",
            "e2e-webhook-exporter",
            "e2e-file-exporter",
            "e2e-remote-enforcement-policy",
            "e2e-remote-policy-bundle",
        ]),
    },
    E2eProfile {
        id: E2eProfileId::LiveCore,
        name: "live-core",
        description: "root/CAP_NET_RAW live libpcap, admin reload, and TLS material suite",
        cases: E2eProfileCases::Named(&[
            "e2e-libpcap-loopback",
            "e2e-libpcap-websocket-loopback",
            "e2e-admin-policy-reload",
            "e2e-admin-enforcement-reload",
            "e2e-tls-session-secret-auto-binding-loopback",
            "e2e-tls-session-secret-material-refresh-auto-binding-loopback",
            "e2e-tls-keylog-auto-binding-loopback",
            "e2e-tls-keylog-material-refresh-auto-binding-loopback",
        ]),
    },
    E2eProfile {
        id: E2eProfileId::ProcessEbpf,
        name: "process-ebpf",
        description: "root/bpffs eBPF process observation suite",
        cases: E2eProfileCases::Named(&["e2e-ebpf-process-loopback"]),
    },
    E2eProfile {
        id: E2eProfileId::TlsPlaintext,
        name: "tls-plaintext",
        description: "root/bpffs libssl plaintext instrumentation lifecycle suite",
        cases: E2eProfileCases::Named(&[
            "e2e-tls-plaintext-provider-loopback",
            "e2e-tls-plaintext-loopback",
            "e2e-tls-plaintext-dynamic-loopback",
            "e2e-tls-plaintext-target-lifecycle-loopback",
            "e2e-tls-plaintext-dynamic-library-loopback",
            "e2e-tls-plaintext-dynamic-library-unload-loopback",
        ]),
    },
    E2eProfile {
        id: E2eProfileId::TransparentInterception,
        name: "transparent-interception",
        description: "root/net-admin transparent interception suite",
        cases: E2eProfileCases::Named(&[
            "e2e-transparent-tproxy-loopback",
            "e2e-transparent-tproxy-process-loopback",
            "e2e-transparent-outbound-proxy-loopback",
            "e2e-transparent-outbound-external-proxy-loopback",
            "e2e-transparent-outbound-owner-proxy-loopback",
            "e2e-transparent-outbound-remote-policy-bundle-loopback",
            "e2e-mitm-plaintext-bridge-live-sidecar",
        ]),
    },
    E2eProfile {
        id: E2eProfileId::LinuxArtifacts,
        name: "linux-artifacts",
        description: "root/net-admin transparent Linux artifact acceptance suite",
        cases: E2eProfileCases::Named(&["e2e-transparent-linux-outbound-redirect-artifact-netns"]),
    },
    E2eProfile {
        id: E2eProfileId::Product,
        name: "product",
        description: "full product capability suite across replay, live capture, eBPF, TLS, and transparent interception",
        cases: E2eProfileCases::Named(&[
            "e2e-plaintext-feed",
            "e2e-sse-plaintext-feed",
            "e2e-gap-plaintext-feed",
            "e2e-capture-loss-event-feed",
            "e2e-websocket-plaintext-feed",
            "e2e-webhook-exporter",
            "e2e-file-exporter",
            "e2e-remote-enforcement-policy",
            "e2e-remote-policy-bundle",
            "e2e-libpcap-loopback",
            "e2e-libpcap-websocket-loopback",
            "e2e-admin-policy-reload",
            "e2e-admin-enforcement-reload",
            "e2e-ebpf-process-loopback",
            "e2e-tls-plaintext-provider-loopback",
            "e2e-tls-plaintext-loopback",
            "e2e-tls-plaintext-dynamic-loopback",
            "e2e-tls-plaintext-target-lifecycle-loopback",
            "e2e-tls-plaintext-dynamic-library-loopback",
            "e2e-tls-plaintext-dynamic-library-unload-loopback",
            "e2e-tls-session-secret-auto-binding-loopback",
            "e2e-tls-session-secret-material-refresh-auto-binding-loopback",
            "e2e-tls-keylog-auto-binding-loopback",
            "e2e-tls-keylog-material-refresh-auto-binding-loopback",
            "e2e-transparent-tproxy-loopback",
            "e2e-transparent-tproxy-process-loopback",
            "e2e-transparent-outbound-proxy-loopback",
            "e2e-transparent-outbound-external-proxy-loopback",
            "e2e-transparent-outbound-owner-proxy-loopback",
            "e2e-transparent-outbound-remote-policy-bundle-loopback",
            "e2e-mitm-plaintext-bridge-live-sidecar",
        ]),
    },
];

pub(super) fn select_cases(selection: &SuiteSelection) -> Result<Vec<&'static E2eCase>, String> {
    match selection {
        SuiteSelection::Default => select_profile_cases(E2eProfileId::Baseline),
        SuiteSelection::IncludePrivileged => select_profile_cases(E2eProfileId::Product),
        SuiteSelection::OnlyPrivileged => Ok(E2E_CASES
            .iter()
            .filter(|case| case.requirement.is_privileged())
            .collect()),
        SuiteSelection::Cases(names) => {
            for name in names {
                if !E2E_CASES.iter().any(|case| case.name == name) {
                    return Err(format!("unknown e2e case `{name}`"));
                }
            }
            Ok(E2E_CASES
                .iter()
                .filter(|case| names.contains(case.name))
                .collect())
        }
        SuiteSelection::Profile(profile_id) => select_profile_cases(*profile_id),
    }
}

pub(super) fn case_by_name(name: &str) -> Option<&'static E2eCase> {
    E2E_CASES.iter().find(|case| case.name == name)
}

pub(super) fn profile_id_by_name(name: &str) -> Result<E2eProfileId, String> {
    E2E_PROFILES
        .iter()
        .find(|profile| profile.name == name)
        .map(|profile| profile.id)
        .ok_or_else(|| format!("unknown e2e profile `{name}`"))
}

fn select_profile_cases(profile_id: E2eProfileId) -> Result<Vec<&'static E2eCase>, String> {
    let Some(profile) = E2E_PROFILES.iter().find(|profile| profile.id == profile_id) else {
        return Err(format!("unregistered e2e profile `{profile_id:?}`"));
    };
    let selected = profile.cases.select(profile.name)?;
    if selected.is_empty() {
        return Err(format!("e2e profile `{}` selected no cases", profile.name));
    }
    Ok(selected)
}

impl E2eProfileCases {
    fn select(self, profile_name: &str) -> Result<Vec<&'static E2eCase>, String> {
        match self {
            Self::Named(names) => names
                .iter()
                .map(|name| {
                    case_by_name(name).ok_or_else(|| {
                        format!("e2e profile `{profile_name}` references unknown case `{name}`")
                    })
                })
                .collect(),
        }
    }
}

pub(super) fn case_names() -> impl Iterator<Item = &'static str> {
    E2E_CASES.iter().map(|case| case.name)
}

pub(super) fn cases() -> &'static [E2eCase] {
    E2E_CASES
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct E2eProfileListing {
    pub(super) name: &'static str,
    pub(super) requirements: String,
    pub(super) description: &'static str,
    pub(super) case_names: Vec<&'static str>,
}

pub(super) fn profile_listings() -> Result<Vec<E2eProfileListing>, String> {
    E2E_PROFILES
        .iter()
        .map(|profile| {
            let cases = select_profile_cases(profile.id)?;
            Ok(E2eProfileListing {
                name: profile.name,
                requirements: requirement_summary(&cases),
                description: profile.description,
                case_names: cases.iter().map(|case| case.name).collect(),
            })
        })
        .collect()
}

fn requirement_summary(cases: &[&E2eCase]) -> String {
    let requirements = cases
        .iter()
        .map(|case| case.requirement)
        .collect::<BTreeSet<_>>();
    requirements
        .iter()
        .map(|requirement| requirement.label())
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ExpectedProfile {
        name: &'static str,
        requirements: &'static str,
        description: &'static str,
        cases: ExpectedProfileCases,
    }

    enum ExpectedProfileCases {
        Named(&'static [&'static str]),
    }

    impl ExpectedProfile {
        fn case_names(&self) -> Vec<&'static str> {
            match self.cases {
                ExpectedProfileCases::Named(cases) => cases.to_vec(),
            }
        }
    }

    const EXPECTED_PROFILES: &[ExpectedProfile] = &[
        ExpectedProfile {
            name: "baseline",
            requirements: "user",
            description: "non-privileged replay/plaintext/export/policy regression suite",
            cases: ExpectedProfileCases::Named(&[
                "e2e-plaintext-feed",
                "e2e-sse-plaintext-feed",
                "e2e-gap-plaintext-feed",
                "e2e-capture-loss-event-feed",
                "e2e-websocket-plaintext-feed",
                "e2e-webhook-exporter",
                "e2e-file-exporter",
                "e2e-remote-enforcement-policy",
                "e2e-remote-policy-bundle",
            ]),
        },
        ExpectedProfile {
            name: "live-core",
            requirements: "root/CAP_NET_RAW",
            description: "root/CAP_NET_RAW live libpcap, admin reload, and TLS material suite",
            cases: ExpectedProfileCases::Named(&[
                "e2e-libpcap-loopback",
                "e2e-libpcap-websocket-loopback",
                "e2e-admin-policy-reload",
                "e2e-admin-enforcement-reload",
                "e2e-tls-session-secret-auto-binding-loopback",
                "e2e-tls-session-secret-material-refresh-auto-binding-loopback",
                "e2e-tls-keylog-auto-binding-loopback",
                "e2e-tls-keylog-material-refresh-auto-binding-loopback",
            ]),
        },
        ExpectedProfile {
            name: "process-ebpf",
            requirements: "root/bpffs",
            description: "root/bpffs eBPF process observation suite",
            cases: ExpectedProfileCases::Named(&["e2e-ebpf-process-loopback"]),
        },
        ExpectedProfile {
            name: "tls-plaintext",
            requirements: "root/bpffs",
            description: "root/bpffs libssl plaintext instrumentation lifecycle suite",
            cases: ExpectedProfileCases::Named(&[
                "e2e-tls-plaintext-provider-loopback",
                "e2e-tls-plaintext-loopback",
                "e2e-tls-plaintext-dynamic-loopback",
                "e2e-tls-plaintext-target-lifecycle-loopback",
                "e2e-tls-plaintext-dynamic-library-loopback",
                "e2e-tls-plaintext-dynamic-library-unload-loopback",
            ]),
        },
        ExpectedProfile {
            name: "transparent-interception",
            requirements: "root/net-admin",
            description: "root/net-admin transparent interception suite",
            cases: ExpectedProfileCases::Named(&[
                "e2e-transparent-tproxy-loopback",
                "e2e-transparent-tproxy-process-loopback",
                "e2e-transparent-outbound-proxy-loopback",
                "e2e-transparent-outbound-external-proxy-loopback",
                "e2e-transparent-outbound-owner-proxy-loopback",
                "e2e-transparent-outbound-remote-policy-bundle-loopback",
                "e2e-mitm-plaintext-bridge-live-sidecar",
            ]),
        },
        ExpectedProfile {
            name: "linux-artifacts",
            requirements: "root/net-admin",
            description: "root/net-admin transparent Linux artifact acceptance suite",
            cases: ExpectedProfileCases::Named(&[
                "e2e-transparent-linux-outbound-redirect-artifact-netns",
            ]),
        },
        ExpectedProfile {
            name: "product",
            requirements: "user,root/CAP_NET_RAW,root/bpffs,root/net-admin",
            description: "full product capability suite across replay, live capture, eBPF, TLS, and transparent interception",
            cases: ExpectedProfileCases::Named(&[
                "e2e-plaintext-feed",
                "e2e-sse-plaintext-feed",
                "e2e-gap-plaintext-feed",
                "e2e-capture-loss-event-feed",
                "e2e-websocket-plaintext-feed",
                "e2e-webhook-exporter",
                "e2e-file-exporter",
                "e2e-remote-enforcement-policy",
                "e2e-remote-policy-bundle",
                "e2e-libpcap-loopback",
                "e2e-libpcap-websocket-loopback",
                "e2e-admin-policy-reload",
                "e2e-admin-enforcement-reload",
                "e2e-ebpf-process-loopback",
                "e2e-tls-plaintext-provider-loopback",
                "e2e-tls-plaintext-loopback",
                "e2e-tls-plaintext-dynamic-loopback",
                "e2e-tls-plaintext-target-lifecycle-loopback",
                "e2e-tls-plaintext-dynamic-library-loopback",
                "e2e-tls-plaintext-dynamic-library-unload-loopback",
                "e2e-tls-session-secret-auto-binding-loopback",
                "e2e-tls-session-secret-material-refresh-auto-binding-loopback",
                "e2e-tls-keylog-auto-binding-loopback",
                "e2e-tls-keylog-material-refresh-auto-binding-loopback",
                "e2e-transparent-tproxy-loopback",
                "e2e-transparent-tproxy-process-loopback",
                "e2e-transparent-outbound-proxy-loopback",
                "e2e-transparent-outbound-external-proxy-loopback",
                "e2e-transparent-outbound-owner-proxy-loopback",
                "e2e-transparent-outbound-remote-policy-bundle-loopback",
                "e2e-mitm-plaintext-bridge-live-sidecar",
            ]),
        },
    ];

    #[test]
    fn registry_invariants_hold() {
        let mut case_names = BTreeSet::new();
        for case in E2E_CASES {
            assert!(case_names.insert(case.name), "duplicate case {}", case.name);
        }

        let mut profile_names = BTreeSet::new();
        let mut profile_ids = BTreeSet::new();
        for profile in E2E_PROFILES {
            assert!(
                profile_names.insert(profile.name),
                "duplicate profile name {}",
                profile.name
            );
            assert!(
                profile_ids.insert(profile.id),
                "duplicate profile id {:?}",
                profile.id
            );
            let selected = select_profile_cases(profile.id).expect("profile should resolve cases");
            assert!(!selected.is_empty(), "empty profile {}", profile.name);

            let mut profile_case_names = BTreeSet::new();
            for case_name in selected.iter().map(|case| case.name) {
                assert!(
                    profile_case_names.insert(case_name),
                    "duplicate case {case_name} in profile {}",
                    profile.name
                );
                assert!(
                    case_names.contains(case_name),
                    "profile {} references unknown case {case_name}",
                    profile.name
                );
            }
        }

        let curated_profile_case_names = E2E_PROFILES
            .iter()
            .flat_map(|profile| {
                select_profile_cases(profile.id)
                    .expect("profile should resolve cases")
                    .into_iter()
                    .map(|case| case.name)
            })
            .collect::<BTreeSet<_>>();
        for case in E2E_CASES {
            assert!(
                curated_profile_case_names.contains(case.name),
                "registered case {} is not covered by any curated profile",
                case.name
            );
        }
    }

    #[test]
    fn profile_listings_expose_public_contract() {
        let listings = profile_listings().expect("profile listing rows");
        let expected = EXPECTED_PROFILES
            .iter()
            .map(|profile| E2eProfileListing {
                name: profile.name,
                requirements: profile.requirements.to_string(),
                description: profile.description,
                case_names: profile.case_names(),
            })
            .collect::<Vec<_>>();

        assert_eq!(listings, expected);
    }
}
