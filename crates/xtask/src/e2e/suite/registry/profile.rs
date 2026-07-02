use std::collections::BTreeSet;

use super::case::{E2E_CASES, E2eCase, case_by_name};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::e2e::suite) enum SuiteSelection {
    Default,
    IncludePrivileged,
    OnlyPrivileged,
    Cases(BTreeSet<String>),
    Profile(E2eProfileId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(in crate::e2e::suite) enum E2eProfileId {
    Baseline,
    LiveCore,
    ProcessEbpf,
    TlsPlaintext,
    TransparentInterception,
    LinuxArtifacts,
    Product,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct E2eProfile {
    pub(super) id: E2eProfileId,
    pub(super) name: &'static str,
    pub(super) description: &'static str,
    pub(super) include_in_product: bool,
    pub(super) cases: E2eProfileCases,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum E2eProfileCases {
    Named(&'static [&'static str]),
    ProductComponents,
}

const E2E_PROFILES: &[E2eProfile] = &[
    E2eProfile {
        id: E2eProfileId::Baseline,
        name: "baseline",
        description: "non-privileged replay/plaintext/export/policy regression suite",
        include_in_product: true,
        cases: E2eProfileCases::Named(&[
            "e2e-replay",
            "e2e-plaintext-feed",
            "e2e-sse-plaintext-feed",
            "e2e-gap-plaintext-feed",
            "e2e-capture-loss-event-feed",
            "e2e-websocket-plaintext-feed",
            "e2e-webhook-exporter",
            "e2e-file-exporter",
            "e2e-remote-enforcement-policy",
            "e2e-remote-policy-bundle",
            "e2e-remote-policy-polling",
        ]),
    },
    E2eProfile {
        id: E2eProfileId::LiveCore,
        name: "live-core",
        description: "root/CAP_NET_RAW live libpcap, admin reload, and TLS material suite",
        include_in_product: true,
        cases: E2eProfileCases::Named(&[
            "e2e-libpcap-loopback",
            "e2e-libpcap-websocket-loopback",
            "e2e-admin-policy-reload",
            "e2e-admin-enforcement-reload",
            "e2e-admin-runtime-actions-reload",
            "e2e-linux-socket-destroy-enforcement",
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
        include_in_product: true,
        cases: E2eProfileCases::Named(&[
            "e2e-ebpf-process-loopback",
            "e2e-ebpf-process-output-loss",
        ]),
    },
    E2eProfile {
        id: E2eProfileId::TlsPlaintext,
        name: "tls-plaintext",
        description: "root/bpffs libssl plaintext instrumentation lifecycle suite",
        include_in_product: true,
        cases: E2eProfileCases::Named(&[
            "e2e-tls-plaintext-provider-loopback",
            "e2e-tls-plaintext-output-loss",
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
        include_in_product: true,
        cases: E2eProfileCases::Named(&[
            "e2e-transparent-tproxy-loopback",
            "e2e-transparent-tproxy-process-loopback",
            "e2e-transparent-tproxy-process-derived-loopback",
            "e2e-transparent-tproxy-flow-classifier-loopback",
            "e2e-transparent-outbound-proxy-loopback",
            "e2e-transparent-outbound-external-proxy-loopback",
            "e2e-transparent-outbound-owner-proxy-loopback",
            "e2e-transparent-outbound-remote-policy-bundle-loopback",
            "e2e-transparent-outbound-flow-classifier-loopback",
            "e2e-mitm-plaintext-bridge-live-sidecar",
            "e2e-mitm-policy-hook-plaintext-bridge-live-sidecar",
            "e2e-managed-mitm-plaintext-bridge-live-sidecar",
            "e2e-managed-mitm-policy-hook-plaintext-bridge-live-sidecar",
            "e2e-product-mitm-proxy-transparent-https-policy-hook",
            "e2e-product-outbound-mitm-proxy-transparent-https-policy-hook",
            "e2e-product-mitm-proxy-transparent-https-dns-discovery",
            "e2e-product-outbound-mitm-proxy-transparent-https-dns-discovery",
            "e2e-product-mitm-proxy-transparent-https-websocket",
            "e2e-product-outbound-mitm-proxy-transparent-https-websocket",
            "e2e-outbound-mitm-plaintext-bridge-live-sidecar",
            "e2e-managed-outbound-mitm-plaintext-bridge-live-sidecar",
        ]),
    },
    E2eProfile {
        id: E2eProfileId::LinuxArtifacts,
        name: "linux-artifacts",
        description: "root/net-admin transparent Linux artifact acceptance suite",
        include_in_product: true,
        cases: E2eProfileCases::Named(&[
            "e2e-transparent-linux-outbound-redirect-artifact-netns",
            "e2e-transparent-linux-outbound-cgroup-artifact-netns",
        ]),
    },
    E2eProfile {
        id: E2eProfileId::Product,
        name: "product",
        description: "full product capability and Linux artifact acceptance suite",
        include_in_product: false,
        cases: E2eProfileCases::ProductComponents,
    },
];

pub(super) fn profiles() -> &'static [E2eProfile] {
    E2E_PROFILES
}

pub(in crate::e2e::suite) fn select_cases(
    selection: &SuiteSelection,
) -> Result<Vec<&'static E2eCase>, String> {
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

pub(in crate::e2e::suite) fn profile_id_by_name(name: &str) -> Result<E2eProfileId, String> {
    E2E_PROFILES
        .iter()
        .find(|profile| profile.name == name)
        .map(|profile| profile.id)
        .ok_or_else(|| format!("unknown e2e profile `{name}`"))
}

pub(super) fn select_profile_cases(
    profile_id: E2eProfileId,
) -> Result<Vec<&'static E2eCase>, String> {
    select_profile_cases_inner(profile_id, &mut BTreeSet::new())
}

fn select_profile_cases_inner(
    profile_id: E2eProfileId,
    visiting: &mut BTreeSet<E2eProfileId>,
) -> Result<Vec<&'static E2eCase>, String> {
    if !visiting.insert(profile_id) {
        return Err(format!("e2e profile `{profile_id:?}` includes itself"));
    }
    let Some(profile) = E2E_PROFILES.iter().find(|profile| profile.id == profile_id) else {
        return Err(format!("unregistered e2e profile `{profile_id:?}`"));
    };
    let selected = profile.cases.select(profile.name, visiting)?;
    visiting.remove(&profile_id);
    if selected.is_empty() {
        return Err(format!("e2e profile `{}` selected no cases", profile.name));
    }
    Ok(selected)
}

impl E2eProfileCases {
    fn select(
        self,
        profile_name: &str,
        visiting: &mut BTreeSet<E2eProfileId>,
    ) -> Result<Vec<&'static E2eCase>, String> {
        match self {
            Self::Named(names) => names
                .iter()
                .map(|name| {
                    case_by_name(name).ok_or_else(|| {
                        format!("e2e profile `{profile_name}` references unknown case `{name}`")
                    })
                })
                .collect(),
            Self::ProductComponents => {
                let mut selected = Vec::new();
                let mut seen = BTreeSet::new();
                for profile in product_component_profiles() {
                    for case in select_profile_cases_inner(profile.id, visiting)? {
                        if !seen.insert(case.name) {
                            return Err(format!(
                                "e2e profile `{profile_name}` includes duplicate case `{}`",
                                case.name
                            ));
                        }
                        selected.push(case);
                    }
                }
                Ok(selected)
            }
        }
    }
}

pub(super) fn product_component_profiles() -> impl Iterator<Item = &'static E2eProfile> {
    E2E_PROFILES
        .iter()
        .filter(|profile| profile.include_in_product)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::e2e::suite) struct E2eProfileListing {
    pub(in crate::e2e::suite) name: &'static str,
    pub(in crate::e2e::suite) requirements: String,
    pub(in crate::e2e::suite) capabilities: String,
    pub(in crate::e2e::suite) description: &'static str,
    pub(in crate::e2e::suite) case_names: Vec<&'static str>,
}

pub(in crate::e2e::suite) fn profile_listings() -> Result<Vec<E2eProfileListing>, String> {
    E2E_PROFILES
        .iter()
        .map(|profile| {
            let cases = select_profile_cases(profile.id)?;
            Ok(E2eProfileListing {
                name: profile.name,
                requirements: requirement_summary(&cases),
                capabilities: capability_summary_for_cases(&cases),
                description: profile.description,
                case_names: cases.iter().map(|case| case.name).collect(),
            })
        })
        .collect()
}

pub(super) fn requirement_ids(cases: &[&E2eCase]) -> Vec<&'static str> {
    cases
        .iter()
        .map(|case| case.requirement)
        .collect::<BTreeSet<_>>()
        .iter()
        .map(|requirement| requirement.id())
        .collect()
}

pub(super) fn capability_ids_for_cases(cases: &[&E2eCase]) -> Vec<&'static str> {
    cases
        .iter()
        .flat_map(|case| case.capabilities.iter().copied())
        .collect::<BTreeSet<_>>()
        .iter()
        .map(|capability| capability.id())
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

fn capability_summary_for_cases(cases: &[&E2eCase]) -> String {
    capability_ids_for_cases(cases).join(",")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e2e::suite::registry::{capability::E2eCapability, case::cases};

    #[test]
    fn registry_invariants_hold() {
        let mut case_names = BTreeSet::new();
        for case in cases() {
            assert!(case_names.insert(case.name), "duplicate case {}", case.name);
            assert!(
                !case.capabilities.is_empty(),
                "case {} must declare at least one capability",
                case.name
            );
            let capability_count = case.capabilities.iter().collect::<BTreeSet<_>>().len();
            assert_eq!(
                capability_count,
                case.capabilities.len(),
                "case {} declares duplicate capabilities",
                case.name
            );
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
            if profile.id == E2eProfileId::Product {
                assert!(
                    !profile.include_in_product,
                    "product profile must not include itself"
                );
            }
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

        let product_case_names = select_profile_cases(E2eProfileId::Product)
            .expect("product profile should resolve cases")
            .into_iter()
            .map(|case| case.name)
            .collect::<BTreeSet<_>>();
        for profile in product_component_profiles() {
            for case in select_profile_cases(profile.id)
                .expect("product component profile should resolve cases")
            {
                assert!(
                    product_case_names.contains(case.name),
                    "product profile does not include case {} from component profile {}",
                    case.name,
                    profile.name
                );
            }
        }

        let product_cases =
            select_profile_cases(E2eProfileId::Product).expect("product profile should resolve");
        let product_capabilities = capability_ids_for_cases(&product_cases);
        assert_eq!(
            product_capabilities,
            E2eCapability::ALL
                .iter()
                .map(|capability| capability.id())
                .collect::<Vec<_>>(),
            "product profile should cover every declared e2e capability"
        );

        let curated_profile_case_names = E2E_PROFILES
            .iter()
            .flat_map(|profile| {
                select_profile_cases(profile.id)
                    .expect("profile should resolve cases")
                    .into_iter()
                    .map(|case| case.name)
            })
            .collect::<BTreeSet<_>>();
        for case in cases() {
            assert!(
                curated_profile_case_names.contains(case.name),
                "registered case {} is not covered by any curated profile",
                case.name
            );
        }
    }

    #[test]
    fn profile_listings_expose_derived_public_contract() {
        let listings = profile_listings().expect("profile listing rows");
        let baseline = listings
            .iter()
            .find(|profile| profile.name == "baseline")
            .expect("baseline listing");
        assert_eq!(baseline.requirements, "user");
        assert!(baseline.capabilities.contains("http_parsing"));
        assert!(baseline.capabilities.contains("websocket_parsing"));
        assert_eq!(
            baseline.case_names.first(),
            Some(&"e2e-replay"),
            "baseline should preserve canonical case order"
        );

        let product_cases =
            select_profile_cases(E2eProfileId::Product).expect("product profile should resolve");
        let product = listings
            .iter()
            .find(|profile| profile.name == "product")
            .expect("product listing");
        assert_eq!(
            product.requirements,
            "user,root/CAP_NET_RAW,root/bpffs,root/net-admin"
        );
        assert_eq!(
            product.capabilities,
            capability_summary_for_cases(&product_cases)
        );
        assert_eq!(
            product.case_names,
            product_cases
                .iter()
                .map(|case| case.name)
                .collect::<Vec<_>>()
        );
    }
}
