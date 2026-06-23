use attribution::ProcfsSocketResolver;
use interception::{
    TransparentInterceptionHostRuleBoundary, TransparentInterceptionHostRuleScope,
    TransparentInterceptionProcessScope, TransparentInterceptionProcessScopeExpression,
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
                "setup-time procfs listener classification can prove all visible TCP listener holder processes for explicit local ports when procfs TCP tables and fd owner scan are complete, but it is not a dynamic cgroup/owner mark classifier and cannot track listener changes after rules are installed",
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
    ) -> Result<TransparentInterceptionHostRuleScope, TransparentInterceptionError> {
        match capability.mode {
            RuntimeMode::Available | RuntimeMode::Degraded => {}
            RuntimeMode::Unavailable => {
                return Err(unavailable_classifier_error(reason, capability));
            }
        }

        let TransparentInterceptionHostRuleBoundary::Scope(scope) = host_rule_boundary else {
            return Err(setup_error(
                "transparent process classifier requires a host-rule boundary before rules can be installed",
            ));
        };
        let Some(local_ports) = scope.local_ports().only_values() else {
            return Err(setup_error(
                "transparent process classifier requires explicit local ports before rules can be installed",
            ));
        };
        let matcher = ProcessScopeMatcher::compile(process_scope.expression())?;

        for port in local_ports {
            self.require_matching_listener(*port, &matcher)?;
        }
        Ok(scope)
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
        if !lookup.unattributed_socket_inodes.is_empty() {
            return Err(setup_error(format!(
                "transparent process classifier cannot attribute every TCP listener for local port {local_port}; unattributed socket inodes: {:?}",
                lookup.unattributed_socket_inodes
            )));
        }
        if lookup.listeners.is_empty() {
            return Err(setup_error(format!(
                "transparent process classifier found no attributed TCP listener for local port {local_port}",
            )));
        }
        for listener in lookup.listeners {
            if !matcher.matches(&listener.process) {
                return Err(setup_error(format!(
                    "transparent process classifier found a TCP listener for local port {local_port} that does not match the process selector: pid={}, name={}",
                    listener.process.identity.pid, listener.process.name
                )));
            }
        }
        Ok(())
    }
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
        TransparentInterceptionPortScope, TransparentInterceptionProcessScope,
        TransparentInterceptionRemoteAddressScope, TransparentInterceptionSetupPlan,
        TransparentInterceptionSetupSelectorSources, TransparentInterceptionSetupSelectors,
    };
    use probe_config::{
        EnforcementInterceptionConfig, TransparentInterceptionProxyConfig,
        TransparentInterceptionStrategyConfig,
    };
    use probe_core::{
        CapabilityKind, CapabilityState, Direction, ProcessSelector, RuntimeMode, Selector,
        TrafficSelector,
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
                .is_some_and(|reason| reason.contains("all visible TCP listener holder processes"))
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
            TransparentInterceptionHostRuleBoundary::Scope(scope.clone()),
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
                TransparentInterceptionHostRuleBoundary::Scope(host_scope(8443)),
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
                TransparentInterceptionHostRuleBoundary::Scope(host_scope(8443)),
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
        };
        let execution_plan =
            ::runtime::TransparentInterceptionExecutionPlan::try_from_config(&config)
                .expect("test transparent interception config should be valid");
        let local_selector = process_selector(vec![8443, 9443]);
        let final_selector = process_selector(vec![8443]);
        let selectors = TransparentInterceptionSetupSelectors::from_sources(
            TransparentInterceptionSetupSelectorSources {
                local_enforcement_selector: Some(&local_selector),
                effective_enforcement_selector: Some(&final_selector),
                interception_selector: config.selector.as_ref(),
            },
        );

        let scope = crate::transparent_interception::effective_setup_scope(
            &execution_plan,
            &::runtime::TransparentInterceptionOutboundRedirectPlan::NotConfigured,
            &degraded_process_classifier(),
            &mut classifier,
            selectors,
        )?
        .expect("inbound TPROXY setup should produce host rules");

        assert_eq!(scope.local_ports().only_values(), Some(&[8443][..]));
        Ok(())
    }

    fn process_scope(
        process: ProcessSelector,
    ) -> Result<TransparentInterceptionProcessScope, Box<dyn std::error::Error>> {
        let selector = Selector::term(
            process,
            TrafficSelector {
                local_ports: vec![8443],
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        );
        match TransparentInterceptionSetupPlan::from_inbound_tproxy_selector(Some(&selector))? {
            TransparentInterceptionSetupPlan::RequiresProcessClassifier {
                process_scope, ..
            } => Ok(process_scope),
            plan => panic!("expected process classifier setup plan: {plan:?}"),
        }
    }

    fn host_scope(local_port: u16) -> TransparentInterceptionHostRuleScope {
        TransparentInterceptionHostRuleScope::new(
            TransparentInterceptionPortScope::only(vec![local_port]),
            TransparentInterceptionPortScope::any(),
            TransparentInterceptionRemoteAddressScope::default(),
        )
        .expect("test scope should contain a local port")
    }

    fn process_selector(local_ports: Vec<u16>) -> Selector {
        Selector::term(
            ProcessSelector {
                names: vec!["demo-listener".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector {
                local_ports,
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        )
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

        fn write_process_with_socket(
            &self,
            pid: u32,
            name: &str,
            inode: u64,
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
            fs::write(process_root.join("cmdline"), format!("{name}\0--serve\0"))?;
            fs::write(
                process_root.join("cgroup"),
                "0::/system.slice/demo.service\n",
            )?;
            symlink("/usr/bin/demo-listener", process_root.join("exe"))?;
            symlink(format!("socket:[{inode}]"), process_root.join("fd/7"))?;
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
}
