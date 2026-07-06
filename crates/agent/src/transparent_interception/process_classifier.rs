use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv6Addr},
};

use attribution::ProcfsSocketResolver;
use interception::{
    TransparentInterceptionHostRuleBoundary, TransparentInterceptionHostRuleScope,
    TransparentInterceptionHostRuleSet, TransparentInterceptionPortScope,
    TransparentInterceptionProcessScope, TransparentInterceptionProcessScopeExpression,
    TransparentInterceptionRemoteAddressScope,
};
use probe_core::{
    CapabilityKind, CapabilityState, CompiledSelector, Direction, ProcessContext, RuntimeMode,
    Selector, TrafficSelector,
};

use super::TransparentInterceptionError;

pub(crate) struct TransparentInterceptionProcessClassifier {
    resolver: ProcfsSocketResolver,
}

impl TransparentInterceptionProcessClassifier {
    pub(crate) fn new() -> Self {
        Self {
            resolver: ProcfsSocketResolver::new(),
        }
    }

    #[cfg(test)]
    fn with_resolver(resolver: ProcfsSocketResolver) -> Self {
        Self { resolver }
    }

    pub(crate) fn capability_from_resolver(resolver: &ProcfsSocketResolver) -> CapabilityState {
        match resolver.probe_tcp_listener_process_attribution() {
            Ok(()) => CapabilityState::degraded(
                CapabilityKind::TransparentProcessClassifier,
                "setup-time procfs listener classification can derive or prove inbound TCP listener ports for process-scoped transparent interception when procfs TCP tables and fd owner scan are complete, but it is not a dynamic cgroup/owner mark classifier and cannot track listener changes after rules are installed",
            ),
            Err(error) => CapabilityState::unavailable(
                CapabilityKind::TransparentProcessClassifier,
                format!(
                    "setup-time procfs listener classification requires complete procfs TCP listener owner attribution: {error}"
                ),
            ),
        }
    }

    pub(crate) fn executable_host_rule_scope(
        &mut self,
        reason: String,
        host_rule_boundary: TransparentInterceptionHostRuleBoundary,
        process_scope: TransparentInterceptionProcessScope,
        capability: &CapabilityState,
    ) -> Result<TransparentInterceptionHostRuleSet, TransparentInterceptionError> {
        match capability.mode {
            RuntimeMode::Available | RuntimeMode::Degraded => {}
            RuntimeMode::Unavailable => {
                return Err(unavailable_classifier_error(reason, capability));
            }
        }

        let matcher = ProcessScopeMatcher::compile(process_scope.expression())?;
        let TransparentInterceptionHostRuleBoundary::HostRules(rules) = host_rule_boundary else {
            return self.derived_listener_host_rule_scope(&matcher);
        };

        let Some(local_ports) = rules.explicit_local_ports() else {
            return Err(setup_error(
                "transparent process classifier requires explicit local ports before rules can be installed",
            ));
        };
        for port in local_ports {
            self.require_matching_listener(port, &matcher)?;
        }
        Ok(rules)
    }

    fn derived_listener_host_rule_scope(
        &mut self,
        matcher: &ProcessScopeMatcher,
    ) -> Result<TransparentInterceptionHostRuleSet, TransparentInterceptionError> {
        let lookup = self.resolver.resolve_tcp_listeners().map_err(|error| {
            setup_error(format!(
                "transparent process classifier failed to inspect TCP listeners: {error}",
            ))
        })?;
        if !lookup.unattributed_listeners.is_empty() {
            return Err(setup_error(format!(
                "transparent process classifier cannot derive process-scoped host rules while unattributed TCP listeners are visible: {:?}",
                lookup.unattributed_listeners
            )));
        }

        let mut ports = BTreeMap::<(u16, DerivedListenerRuleFamily), DerivedPortMatch>::new();
        for listener in lookup.listeners {
            for family in
                DerivedListenerRuleFamily::from_listener_address(listener.observed.local.address)
                    .iter()
                    .copied()
            {
                let entry = ports
                    .entry((listener.observed.local.port, family))
                    .or_default();
                if matcher.matches(&listener.observed.process) {
                    entry.has_matching_holder = true;
                } else {
                    entry.non_matching_holder.get_or_insert_with(|| {
                        format!(
                            "pid={}, name={}",
                            listener.observed.process.identity.pid, listener.observed.process.name
                        )
                    });
                }
            }
        }

        let mut matching_ipv4_ports = Vec::new();
        let mut matching_ipv6_ports = Vec::new();
        for ((port, family), port_match) in ports {
            if !port_match.has_matching_holder {
                continue;
            }
            if let Some(holder) = port_match.non_matching_holder {
                return Err(setup_error(format!(
                    "transparent process classifier cannot derive a safe host rule for local port {port}; the port also has a non-matching TCP listener holder: {holder}"
                )));
            }
            match family {
                DerivedListenerRuleFamily::Ipv4 => matching_ipv4_ports.push(port),
                DerivedListenerRuleFamily::Ipv6 => matching_ipv6_ports.push(port),
            }
        }
        if matching_ipv4_ports.is_empty() && matching_ipv6_ports.is_empty() {
            return Err(setup_error(
                "transparent process classifier found no attributed TCP listeners matching the process selector",
            ));
        }

        let mut scopes = Vec::new();
        if !matching_ipv4_ports.is_empty() {
            scopes.push(derived_listener_scope(
                matching_ipv4_ports,
                TransparentInterceptionRemoteAddressScope::any_ipv4(),
            )?);
        }
        if !matching_ipv6_ports.is_empty() {
            scopes.push(derived_listener_scope(
                matching_ipv6_ports,
                TransparentInterceptionRemoteAddressScope::any_ipv6(),
            )?);
        }
        TransparentInterceptionHostRuleSet::new(scopes)
            .map_err(|error| setup_error(error.to_string()))
    }

    fn require_matching_listener(
        &mut self,
        local_port: u16,
        matcher: &ProcessScopeMatcher,
    ) -> Result<(), TransparentInterceptionError> {
        let lookup = self
            .resolver
            .resolve_tcp_listeners_by_local_port(local_port)
            .map_err(|error| {
                setup_error(format!(
                    "transparent process classifier failed to inspect TCP listeners for local port {local_port}: {error}",
                ))
            })?;
        if !lookup.unattributed_listeners.is_empty() {
            return Err(setup_error(format!(
                "transparent process classifier cannot attribute every TCP listener for local port {local_port}; unattributed listeners: {:?}",
                lookup.unattributed_listeners
            )));
        }
        if lookup.listeners.is_empty() {
            return Err(setup_error(format!(
                "transparent process classifier found no attributed TCP listener for local port {local_port}",
            )));
        }
        for listener in lookup.listeners {
            if !matcher.matches(&listener.observed.process) {
                return Err(setup_error(format!(
                    "transparent process classifier found a TCP listener for local port {local_port} that does not match the process selector: pid={}, name={}",
                    listener.observed.process.identity.pid, listener.observed.process.name
                )));
            }
        }
        Ok(())
    }
}

#[derive(Default)]
struct DerivedPortMatch {
    has_matching_holder: bool,
    non_matching_holder: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum DerivedListenerRuleFamily {
    Ipv4,
    Ipv6,
}

impl DerivedListenerRuleFamily {
    fn from_listener_address(address: IpAddr) -> &'static [Self] {
        match address {
            IpAddr::V4(_) => &[Self::Ipv4],
            IpAddr::V6(address) if address == Ipv6Addr::UNSPECIFIED => &[Self::Ipv4, Self::Ipv6],
            IpAddr::V6(_) => &[Self::Ipv6],
        }
    }
}

fn derived_listener_scope(
    local_ports: Vec<u16>,
    remote_addresses: TransparentInterceptionRemoteAddressScope,
) -> Result<TransparentInterceptionHostRuleScope, TransparentInterceptionError> {
    TransparentInterceptionHostRuleScope::new(
        TransparentInterceptionPortScope::only(local_ports),
        TransparentInterceptionPortScope::any(),
        remote_addresses,
    )
    .map_err(|error| setup_error(error.to_string()))
}

impl Default for TransparentInterceptionProcessClassifier {
    fn default() -> Self {
        Self::new()
    }
}

struct ProcessScopeMatcher {
    expression: ProcessScopeMatcherExpression,
}

impl ProcessScopeMatcher {
    fn compile(
        expression: &TransparentInterceptionProcessScopeExpression,
    ) -> Result<Self, TransparentInterceptionError> {
        Ok(Self {
            expression: ProcessScopeMatcherExpression::compile(expression)?,
        })
    }

    fn matches(&self, process: &ProcessContext) -> bool {
        self.expression.matches(process)
    }
}

enum ProcessScopeMatcherExpression {
    Match(CompiledSelector),
    All(Vec<ProcessScopeMatcherExpression>),
    Any(Vec<ProcessScopeMatcherExpression>),
}

impl ProcessScopeMatcherExpression {
    fn compile(
        expression: &TransparentInterceptionProcessScopeExpression,
    ) -> Result<Self, TransparentInterceptionError> {
        match expression {
            TransparentInterceptionProcessScopeExpression::Match { process } => {
                Selector::term(process.clone(), TrafficSelector::default())
                    .compile()
                    .map(Self::Match)
                    .map_err(|error| {
                        setup_error(format!(
                            "transparent process classifier selector is invalid: {error}"
                        ))
                    })
            }
            TransparentInterceptionProcessScopeExpression::All { expressions } => expressions
                .iter()
                .map(Self::compile)
                .collect::<Result<Vec<_>, _>>()
                .map(Self::All),
            TransparentInterceptionProcessScopeExpression::Any { expressions } => expressions
                .iter()
                .map(Self::compile)
                .collect::<Result<Vec<_>, _>>()
                .map(Self::Any),
        }
    }

    fn matches(&self, process: &ProcessContext) -> bool {
        match self {
            Self::Match(selector) => {
                selector.matches_unattributed_flow(process, Direction::Inbound)
            }
            Self::All(expressions) => expressions
                .iter()
                .all(|expression| expression.matches(process)),
            Self::Any(expressions) => expressions
                .iter()
                .any(|expression| expression.matches(process)),
        }
    }
}

fn unavailable_classifier_error(
    reason: String,
    capability: &CapabilityState,
) -> TransparentInterceptionError {
    setup_error(format!(
        "{reason}; transparent process classifier {} capability is unavailable: {}",
        capability.kind.wire_name(),
        capability
            .reason
            .as_deref()
            .unwrap_or("no unavailable reason reported")
    ))
}

fn setup_error(reason: impl Into<String>) -> TransparentInterceptionError {
    TransparentInterceptionError::Setup(reason.into())
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::symlink, path::Path};

    use ::runtime::TransparentInterceptionClassificationPlan;
    use attribution::ProcfsSocketResolver;
    use interception::{
        TransparentInterceptionHostRuleScope, TransparentInterceptionPortScope,
        TransparentInterceptionProcessScope, TransparentInterceptionRemoteAddressScope,
        TransparentInterceptionSetupDirection, TransparentInterceptionSetupPlan,
        TransparentInterceptionSetupSelectorSources, TransparentInterceptionSetupSelectors,
    };
    use probe_config::{
        EnforcementInterceptionConfig, TransparentInterceptionProxyConfig,
        TransparentInterceptionStrategyConfig,
    };
    use probe_core::{
        CapabilityKind, CapabilityState, Direction, ProcessSelector, ResolvedSelector, RuntimeMode,
        Selector, TrafficSelector,
    };
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn process_classifier_capability_is_degraded_for_complete_listener_probe()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = FakeProc::new()?;
        proc.write_tcp_table(&[])?;
        let resolver = ProcfsSocketResolver::with_paths(proc.root(), proc.boot_id_path());

        let capability =
            TransparentInterceptionProcessClassifier::capability_from_resolver(&resolver);

        assert_eq!(capability.mode, RuntimeMode::Degraded);
        assert!(
            capability
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("derive or prove inbound TCP listener ports"))
        );
        Ok(())
    }

    #[test]
    fn process_classifier_capability_is_unavailable_when_tcp6_probe_fails()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = FakeProc::new()?;
        proc.write_tcp_table(&[])?;
        fs::remove_file(proc.root().join("net/tcp6"))?;
        let resolver = ProcfsSocketResolver::with_paths(proc.root(), proc.boot_id_path());

        let capability =
            TransparentInterceptionProcessClassifier::capability_from_resolver(&resolver);

        assert_eq!(capability.mode, RuntimeMode::Unavailable);
        assert!(
            capability
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("tcp6"))
        );
        Ok(())
    }

    #[test]
    fn process_classifier_allows_host_rules_for_matching_listener()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = FakeProc::new()?;
        proc.write_tcp_table(&[tcp_line(0, "0100007F:20FB", "00000000:0000", "0A", 424_242)])?;
        proc.write_process_with_socket(321, "demo-listener", 424_242)?;
        let mut classifier = TransparentInterceptionProcessClassifier::with_resolver(
            ProcfsSocketResolver::with_paths(proc.root(), proc.boot_id_path()),
        );
        let scope = host_scope(8443);

        let result = classifier.executable_host_rule_scope(
            "needs process classifier".to_string(),
            TransparentInterceptionHostRuleBoundary::HostRules(scope.clone()),
            process_scope(ProcessSelector {
                names: vec!["demo-listener".to_string()],
                ..ProcessSelector::default()
            })?,
            &CapabilityState::degraded(CapabilityKind::TransparentProcessClassifier, "procfs"),
        )?;

        assert_eq!(result, scope);
        Ok(())
    }

    #[test]
    fn process_classifier_allows_host_rules_for_any_matching_listener()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = FakeProc::new()?;
        proc.write_tcp_table(&[tcp_line(0, "0100007F:20FB", "00000000:0000", "0A", 424_242)])?;
        proc.write_process_with_socket(321, "api-listener", 424_242)?;
        let mut classifier = TransparentInterceptionProcessClassifier::with_resolver(
            ProcfsSocketResolver::with_paths(proc.root(), proc.boot_id_path()),
        );
        let scope = host_scope(8443);

        let result = classifier.executable_host_rule_scope(
            "needs process classifier".to_string(),
            TransparentInterceptionHostRuleBoundary::HostRules(scope.clone()),
            process_scope_from_selector(Selector::Any {
                selectors: vec![
                    Selector::term(
                        ProcessSelector {
                            names: vec!["worker-listener".to_string()],
                            ..ProcessSelector::default()
                        },
                        inbound_local_port(8443),
                    ),
                    Selector::term(
                        ProcessSelector {
                            names: vec!["api-listener".to_string()],
                            ..ProcessSelector::default()
                        },
                        inbound_local_port(8443),
                    ),
                ],
            })?,
            &CapabilityState::degraded(CapabilityKind::TransparentProcessClassifier, "procfs"),
        )?;

        assert_eq!(result, scope);
        Ok(())
    }

    #[test]
    fn process_classifier_derives_host_rules_for_process_only_matching_listeners()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = FakeProc::new()?;
        proc.write_tcp_table(&[
            tcp_line(0, "0100007F:20FB", "00000000:0000", "0A", 424_242),
            tcp_line(1, "0100007F:24E3", "00000000:0000", "0A", 535_353),
        ])?;
        proc.write_process_with_socket(321, "demo-listener", 424_242)?;
        proc.write_process_with_socket(654, "other-listener", 535_353)?;
        let mut classifier = TransparentInterceptionProcessClassifier::with_resolver(
            ProcfsSocketResolver::with_paths(proc.root(), proc.boot_id_path()),
        );

        let result = classifier.executable_host_rule_scope(
            "needs process classifier".to_string(),
            TransparentInterceptionHostRuleBoundary::NoHostRuleBoundary,
            process_only_scope(ProcessSelector {
                names: vec!["demo-listener".to_string()],
                ..ProcessSelector::default()
            })?,
            &CapabilityState::degraded(CapabilityKind::TransparentProcessClassifier, "procfs"),
        )?;

        let scope = single_scope(&result);
        assert_eq!(scope.local_ports().only_values(), Some(&[8443][..]));
        assert!(scope.remote_addresses().ipv4_any());
        assert!(!scope.remote_addresses().ipv6_any());
        Ok(())
    }

    #[test]
    fn process_classifier_derives_dual_family_rules_for_ipv6_wildcard_listener()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = FakeProc::new()?;
        proc.write_tcp_table(&[])?;
        proc.write_tcp6_table(&[tcp_line(
            0,
            "00000000000000000000000000000000:20FB",
            "00000000000000000000000000000000:0000",
            "0A",
            424_242,
        )])?;
        proc.write_process_with_socket(321, "demo-listener", 424_242)?;
        let mut classifier = TransparentInterceptionProcessClassifier::with_resolver(
            ProcfsSocketResolver::with_paths(proc.root(), proc.boot_id_path()),
        );

        let result = classifier.executable_host_rule_scope(
            "needs process classifier".to_string(),
            TransparentInterceptionHostRuleBoundary::NoHostRuleBoundary,
            process_only_scope(ProcessSelector {
                names: vec!["demo-listener".to_string()],
                ..ProcessSelector::default()
            })?,
            &CapabilityState::degraded(CapabilityKind::TransparentProcessClassifier, "procfs"),
        )?;

        let scope = single_scope(&result);
        assert_eq!(scope.local_ports().only_values(), Some(&[8443][..]));
        assert!(scope.remote_addresses().is_any());
        Ok(())
    }

    #[test]
    fn process_classifier_rejects_process_only_mixed_listener_holders()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = FakeProc::new()?;
        proc.write_tcp_table(&[tcp_line(0, "0100007F:20FB", "00000000:0000", "0A", 424_242)])?;
        proc.write_process_with_socket(321, "demo-listener", 424_242)?;
        proc.write_process_with_socket(654, "other-listener", 424_242)?;
        let mut classifier = TransparentInterceptionProcessClassifier::with_resolver(
            ProcfsSocketResolver::with_paths(proc.root(), proc.boot_id_path()),
        );

        let error = classifier
            .executable_host_rule_scope(
                "needs process classifier".to_string(),
                TransparentInterceptionHostRuleBoundary::NoHostRuleBoundary,
                process_only_scope(ProcessSelector {
                    names: vec!["demo-listener".to_string()],
                    ..ProcessSelector::default()
                })?,
                &CapabilityState::degraded(CapabilityKind::TransparentProcessClassifier, "procfs"),
            )
            .expect_err("mixed listener holders must not produce process-only host rules");

        assert!(
            error
                .to_string()
                .contains("non-matching TCP listener holder")
        );
        assert!(error.to_string().contains("pid=654"));
        Ok(())
    }

    #[test]
    fn process_classifier_rejects_process_only_when_any_listener_is_unattributed()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = FakeProc::new()?;
        proc.write_tcp_table(&[
            tcp_line(0, "0100007F:20FB", "00000000:0000", "0A", 424_242),
            tcp_line(1, "0100007F:24E3", "00000000:0000", "0A", 535_353),
        ])?;
        proc.write_process_with_socket(321, "demo-listener", 424_242)?;
        let mut classifier = TransparentInterceptionProcessClassifier::with_resolver(
            ProcfsSocketResolver::with_paths(proc.root(), proc.boot_id_path()),
        );

        let error = classifier
            .executable_host_rule_scope(
                "needs process classifier".to_string(),
                TransparentInterceptionHostRuleBoundary::NoHostRuleBoundary,
                process_only_scope(ProcessSelector {
                    names: vec!["demo-listener".to_string()],
                    ..ProcessSelector::default()
                })?,
                &CapabilityState::degraded(CapabilityKind::TransparentProcessClassifier, "procfs"),
            )
            .expect_err("unattributed listener must fail closed for process-only setup");

        assert!(error.to_string().contains("unattributed TCP listener"));
        assert!(error.to_string().contains("535353"));
        Ok(())
    }

    #[test]
    fn process_classifier_rejects_process_only_without_matching_listener()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = FakeProc::new()?;
        proc.write_tcp_table(&[tcp_line(0, "0100007F:20FB", "00000000:0000", "0A", 424_242)])?;
        proc.write_process_with_socket(321, "other-listener", 424_242)?;
        let mut classifier = TransparentInterceptionProcessClassifier::with_resolver(
            ProcfsSocketResolver::with_paths(proc.root(), proc.boot_id_path()),
        );

        let error = classifier
            .executable_host_rule_scope(
                "needs process classifier".to_string(),
                TransparentInterceptionHostRuleBoundary::NoHostRuleBoundary,
                process_only_scope(ProcessSelector {
                    names: vec!["demo-listener".to_string()],
                    ..ProcessSelector::default()
                })?,
                &CapabilityState::degraded(CapabilityKind::TransparentProcessClassifier, "procfs"),
            )
            .expect_err("process-only setup requires at least one matching listener");

        assert!(
            error
                .to_string()
                .contains("no attributed TCP listeners matching")
        );
        Ok(())
    }

    #[test]
    fn process_classifier_rejects_non_matching_listener() -> Result<(), Box<dyn std::error::Error>>
    {
        let proc = FakeProc::new()?;
        proc.write_tcp_table(&[tcp_line(0, "0100007F:20FB", "00000000:0000", "0A", 424_242)])?;
        proc.write_process_with_socket(321, "other-listener", 424_242)?;
        let mut classifier = TransparentInterceptionProcessClassifier::with_resolver(
            ProcfsSocketResolver::with_paths(proc.root(), proc.boot_id_path()),
        );

        let error = classifier
            .executable_host_rule_scope(
                "needs process classifier".to_string(),
                TransparentInterceptionHostRuleBoundary::HostRules(host_scope(8443)),
                process_scope(ProcessSelector {
                    names: vec!["demo-listener".to_string()],
                    ..ProcessSelector::default()
                })?,
                &CapabilityState::degraded(CapabilityKind::TransparentProcessClassifier, "procfs"),
            )
            .expect_err("non-matching listener must not produce host rules");

        assert!(error.to_string().contains("does not match"));
        Ok(())
    }

    #[test]
    fn process_classifier_uses_observed_holder_not_logical_owner()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = FakeProc::new()?;
        proc.write_tcp_table(&[tcp_line(0, "00000000:1F91", "00000000:0000", "0A", 909_090)])?;
        proc.write_process_with_socket_and_cmdline(
            123,
            "docker-proxy",
            909_090,
            &[
                "/usr/bin/docker-proxy",
                "-proto",
                "tcp",
                "-host-ip",
                "0.0.0.0",
                "-host-port",
                "8081",
                "-container-ip",
                "172.19.0.3",
                "-container-port",
                "8080",
            ],
        )?;
        proc.write_process_with_socket(321, "demo-backend", 424_242)?;
        proc.write_process_tcp_table(
            321,
            "net:[4026532661]",
            &[
                tcp_line(0, "00000000:1F90", "00000000:0000", "0A", 424_242),
                tcp_line(1, "030013AC:1F90", "010013AC:C001", "01", 111_111),
            ],
        )?;
        let mut classifier = TransparentInterceptionProcessClassifier::with_resolver(
            ProcfsSocketResolver::with_paths(proc.root(), proc.boot_id_path()),
        );

        let error = classifier
            .executable_host_rule_scope(
                "needs process classifier".to_string(),
                TransparentInterceptionHostRuleBoundary::HostRules(host_scope(8081)),
                process_scope_from_selector(Selector::term(
                    ProcessSelector {
                        names: vec!["demo-backend".to_string()],
                        ..ProcessSelector::default()
                    },
                    inbound_local_port(8081),
                ))?,
                &CapabilityState::degraded(CapabilityKind::TransparentProcessClassifier, "procfs"),
            )
            .expect_err("logical owner must not authorize transparent host rules");

        assert!(error.to_string().contains("does not match"));
        assert!(error.to_string().contains("docker-proxy"));
        Ok(())
    }

    #[test]
    fn process_classifier_rejects_non_matching_shared_listener_holder()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = FakeProc::new()?;
        proc.write_tcp_table(&[tcp_line(0, "0100007F:20FB", "00000000:0000", "0A", 424_242)])?;
        proc.write_process_with_socket(321, "demo-listener", 424_242)?;
        proc.write_process_with_socket(654, "other-listener", 424_242)?;
        let mut classifier = TransparentInterceptionProcessClassifier::with_resolver(
            ProcfsSocketResolver::with_paths(proc.root(), proc.boot_id_path()),
        );

        let error = classifier
            .executable_host_rule_scope(
                "needs process classifier".to_string(),
                TransparentInterceptionHostRuleBoundary::HostRules(host_scope(8443)),
                process_scope(ProcessSelector {
                    names: vec!["demo-listener".to_string()],
                    ..ProcessSelector::default()
                })?,
                &CapabilityState::degraded(CapabilityKind::TransparentProcessClassifier, "procfs"),
            )
            .expect_err("shared listener holders must all match the process selector");

        assert!(error.to_string().contains("pid=654"));
        Ok(())
    }

    #[test]
    fn effective_setup_proves_only_final_process_scoped_ports()
    -> Result<(), Box<dyn std::error::Error>> {
        let proc = FakeProc::new()?;
        proc.write_tcp_table(&[tcp_line(0, "0100007F:20FB", "00000000:0000", "0A", 424_242)])?;
        proc.write_process_with_socket(321, "demo-listener", 424_242)?;
        let mut classifier = TransparentInterceptionProcessClassifier::with_resolver(
            ProcfsSocketResolver::with_paths(proc.root(), proc.boot_id_path()),
        );
        let config = EnforcementInterceptionConfig {
            strategy: TransparentInterceptionStrategyConfig::InboundTproxy,
            selector: None,
            proxy: TransparentInterceptionProxyConfig {
                listen_port: Some(15001),
                ..TransparentInterceptionProxyConfig::default()
            },
            ..EnforcementInterceptionConfig::default()
        };
        let execution_plan =
            ::runtime::TransparentInterceptionExecutionPlan::try_from_config(&config)
                .expect("test transparent interception config should be valid");
        let local_selector = resolved_process_selector(vec![8443, 9443]);
        let final_selector = resolved_process_selector(vec![8443]);
        let selectors = TransparentInterceptionSetupSelectors::from_sources(
            TransparentInterceptionSetupSelectorSources {
                local_enforcement_selector: Some(&local_selector),
                effective_enforcement_selector: Some(&final_selector),
                interception_selector: None,
            },
        );

        let scope = crate::transparent_interception::effective_setup_scope(
            &execution_plan,
            &degraded_process_classifier(),
            &mut classifier,
            selectors,
        )?
        .expect("inbound TPROXY setup should produce host rules");

        assert_eq!(
            single_scope(scope.setup_rules())
                .local_ports()
                .only_values(),
            Some(&[8443][..])
        );
        Ok(())
    }

    fn process_scope(
        process: ProcessSelector,
    ) -> Result<TransparentInterceptionProcessScope, Box<dyn std::error::Error>> {
        process_scope_from_selector(Selector::term(
            process,
            TrafficSelector {
                local_ports: vec![8443],
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        ))
    }

    fn process_only_scope(
        process: ProcessSelector,
    ) -> Result<TransparentInterceptionProcessScope, Box<dyn std::error::Error>> {
        process_scope_from_selector(Selector::term(
            process,
            TrafficSelector {
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        ))
    }

    fn process_scope_from_selector(
        selector: Selector,
    ) -> Result<TransparentInterceptionProcessScope, Box<dyn std::error::Error>> {
        match TransparentInterceptionSetupPlan::from_selector(
            Some(&selector),
            TransparentInterceptionSetupDirection::Inbound,
        )? {
            TransparentInterceptionSetupPlan::RequiresProcessClassifier {
                process_scope, ..
            } => Ok(process_scope),
            plan => panic!("expected process classifier setup plan: {plan:?}"),
        }
    }

    fn host_scope(local_port: u16) -> TransparentInterceptionHostRuleSet {
        let scope = TransparentInterceptionHostRuleScope::new(
            TransparentInterceptionPortScope::only(vec![local_port]),
            TransparentInterceptionPortScope::any(),
            TransparentInterceptionRemoteAddressScope::any(),
        )
        .expect("test scope should contain a local port");
        TransparentInterceptionHostRuleSet::single(scope)
    }

    fn single_scope(
        rules: &TransparentInterceptionHostRuleSet,
    ) -> &TransparentInterceptionHostRuleScope {
        let [scope] = rules.scopes() else {
            panic!(
                "test setup should produce one host-rule scope, got {:?}",
                rules.scopes()
            );
        };
        scope
    }

    fn inbound_local_port(local_port: u16) -> TrafficSelector {
        TrafficSelector {
            local_ports: vec![local_port],
            directions: vec![Direction::Inbound],
            ..TrafficSelector::default()
        }
    }

    fn resolved_process_selector(local_ports: Vec<u16>) -> ResolvedSelector {
        ResolvedSelector::new(Selector::term(
            ProcessSelector {
                names: vec!["demo-listener".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector {
                local_ports,
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        ))
        .expect("test selector should be valid")
    }

    fn degraded_process_classifier() -> TransparentInterceptionClassificationPlan {
        TransparentInterceptionClassificationPlan {
            process_classifier: CapabilityState::degraded(
                CapabilityKind::TransparentProcessClassifier,
                "procfs",
            ),
            flow_classifier: CapabilityState::unavailable(
                CapabilityKind::TransparentFlowClassifier,
                "not built",
            ),
        }
    }

    struct FakeProc {
        root: TempDir,
        boot_id_path: std::path::PathBuf,
    }

    impl FakeProc {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let root = tempfile::tempdir()?;
            fs::create_dir(root.path().join("net"))?;
            fs::write(root.path().join("net/tcp6"), tcp_header())?;
            let boot_id_path = root.path().join("boot_id");
            fs::write(&boot_id_path, "boot-test\n")?;
            Ok(Self { root, boot_id_path })
        }

        fn root(&self) -> &Path {
            self.root.path()
        }

        fn boot_id_path(&self) -> &Path {
            &self.boot_id_path
        }

        fn write_tcp_table(&self, lines: &[String]) -> Result<(), std::io::Error> {
            fs::write(
                self.root.path().join("net/tcp"),
                format!("{}{}", tcp_header(), lines.join("")),
            )
        }

        fn write_tcp6_table(&self, lines: &[String]) -> Result<(), std::io::Error> {
            fs::write(
                self.root.path().join("net/tcp6"),
                format!("{}{}", tcp_header(), lines.join("")),
            )
        }

        fn write_process_with_socket(
            &self,
            pid: u32,
            name: &str,
            inode: u64,
        ) -> Result<(), Box<dyn std::error::Error>> {
            self.write_process_with_socket_and_cmdline(pid, name, inode, &[name, "--serve"])
        }

        fn write_process_with_socket_and_cmdline(
            &self,
            pid: u32,
            name: &str,
            inode: u64,
            cmdline: &[&str],
        ) -> Result<(), Box<dyn std::error::Error>> {
            let process_root = self.root.path().join(pid.to_string());
            fs::create_dir(&process_root)?;
            fs::create_dir(process_root.join("fd"))?;
            fs::write(process_root.join("stat"), stat(pid, name, 99))?;
            fs::write(
                process_root.join("status"),
                format!(
                    "Name:\t{name}\nTgid:\t{pid}\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n"
                ),
            )?;
            fs::write(process_root.join("cmdline"), nul_joined(cmdline))?;
            fs::write(
                process_root.join("cgroup"),
                "0::/system.slice/demo.service\n",
            )?;
            symlink("/usr/bin/demo-listener", process_root.join("exe"))?;
            symlink(format!("socket:[{inode}]"), process_root.join("fd/7"))?;
            Ok(())
        }

        fn write_process_tcp_table(
            &self,
            pid: u32,
            network_namespace: &str,
            lines: &[String],
        ) -> Result<(), Box<dyn std::error::Error>> {
            let process_root = self.root.path().join(pid.to_string());
            fs::create_dir_all(process_root.join("net"))?;
            fs::create_dir_all(process_root.join("ns"))?;
            let namespace_path = process_root.join("ns/net");
            if !namespace_path.exists() {
                symlink(network_namespace, &namespace_path)?;
            }
            fs::write(
                process_root.join("net/tcp"),
                format!("{}{}", tcp_header(), lines.join("")),
            )?;
            fs::write(process_root.join("net/tcp6"), tcp_header())?;
            Ok(())
        }
    }

    fn tcp_header() -> &'static str {
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    }

    fn tcp_line(index: u32, local: &str, remote: &str, state: &str, inode: u64) -> String {
        format!(
            "{index:4}: {local} {remote} {state} 00000000:00000000 00:00000000 00000000 1000 0 {inode} 1 0000000000000000\n"
        )
    }

    fn stat(pid: u32, name: &str, start_time_ticks: u64) -> String {
        format!(
            "{pid} ({name}) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 {start_time_ticks} 20\n"
        )
    }

    fn nul_joined(values: &[&str]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|value| value.as_bytes().iter().copied().chain([0]))
            .collect()
    }
}
