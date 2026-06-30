mod assertions;
mod backend;
mod bridge_assertions;
mod case;
mod config;
mod data_plane;
mod feed;
mod policy_hook;
mod tls;
mod transparent_tls;
mod websocket;
mod websocket_assertions;
mod websocket_upstream;

use std::{
    env, fs,
    path::Path,
    process::{Command, ExitCode},
};

use assertions::{
    assert_backend_owned_policy_hook_execution, assert_mitm_backend_runtime,
    assert_outbound_redirect_reaches_mitm_backend, assert_spool_outputs,
    exercise_l7_mitm_health_transition, exercise_managed_plaintext_data_plane,
};
use backend::{cleanup_managed_backend, prepare_mitm_backend, unused_intercept_port};
use case::{MitmBackendKind, MitmBridgeCase};
use config::{AgentConfigInputs, fixture_config, write_agent_config, write_policy_bundle};
use feed::{
    append_bridge_feed_from_harness, expected_libpcap_targets,
    expected_policy_alert_messages_for_case, initialize_bridge_feed,
};
use policy_hook::{MitmPolicyHookServer, assert_policy_hook_requests};
use transparent_tls::exercise_product_proxy_transparent_tls_path;

use super::{
    harness::{
        ChildSupervisor, UnixSocketReadySignal, create_temp_root, e2e_error,
        ensure_e2e_packages_built, reexec_current_case_in_fresh_network_namespace,
        stop_running_child, trusted_system_command, verify_fresh_network_namespace,
    },
    loopback::{
        LabeledRunResult, RunResult, merge_labeled_run_results, spawn_agent,
        spawn_http1_loopback_fixture, start_http1_loopback_fixture,
        wait_for_agent_enforcement_decision_count_at_least, wait_for_agent_policy_progress,
        wait_for_agent_ready, wait_for_http1_loopback_fixture_exit,
        wait_for_http1_loopback_fixture_ready,
    },
};

pub(crate) fn run() -> ExitCode {
    run_case(MitmBridgeCase::ExternalInbound)
}

pub(crate) fn run_managed() -> ExitCode {
    run_case(MitmBridgeCase::ManagedInbound)
}

pub(crate) fn run_managed_policy_hook() -> ExitCode {
    run_case(MitmBridgeCase::ManagedInboundPolicyHook)
}

pub(crate) fn run_product_proxy_transparent_https_policy_hook() -> ExitCode {
    run_case(MitmBridgeCase::ProductProxyTransparentHttpsPolicyHook)
}

pub(crate) fn run_product_proxy_outbound_transparent_https_policy_hook() -> ExitCode {
    run_case(MitmBridgeCase::ProductProxyOutboundTransparentHttpsPolicyHook)
}

pub(crate) fn run_product_proxy_transparent_https_dns_discovery() -> ExitCode {
    run_case(MitmBridgeCase::ProductProxyTransparentHttpsDnsDiscovery)
}

pub(crate) fn run_product_proxy_outbound_transparent_https_dns_discovery() -> ExitCode {
    run_case(MitmBridgeCase::ProductProxyOutboundTransparentHttpsDnsDiscovery)
}

pub(crate) fn run_product_proxy_transparent_https_websocket() -> ExitCode {
    run_case(MitmBridgeCase::ProductProxyTransparentHttpsWebSocket)
}

pub(crate) fn run_product_proxy_outbound_transparent_https_websocket() -> ExitCode {
    run_case(MitmBridgeCase::ProductProxyOutboundTransparentHttpsWebSocket)
}

pub(crate) fn run_policy_hook() -> ExitCode {
    run_case(MitmBridgeCase::ExternalInboundPolicyHook)
}

pub(crate) fn run_outbound() -> ExitCode {
    run_case(MitmBridgeCase::ExternalOutbound)
}

pub(crate) fn run_managed_outbound() -> ExitCode {
    run_case(MitmBridgeCase::ManagedOutbound)
}

fn run_case(case: MitmBridgeCase) -> ExitCode {
    match run_outer(case) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{} failed: {error}", case.failure_label());
            ExitCode::FAILURE
        }
    }
}

fn run_outer(case: MitmBridgeCase) -> Result<(), Box<dyn std::error::Error>> {
    if env::var_os(transparent_tls::CLIENT_OWNER_ENV).is_some() {
        require_root()?;
        return transparent_tls::run_client_namespace_owner();
    }
    if env::var_os(case.netns_env()).is_some() {
        require_root()?;
        verify_fresh_network_namespace(case.netns_env())?;
        bring_loopback_up()?;
        return run_inner(case);
    }

    ensure_e2e_packages_built(["agent", "e2e-fixture"])?;
    if case.backend() == MitmBackendKind::ProductProxy {
        ensure_e2e_packages_built(["mitm-proxy"])?;
    }
    require_root()?;
    reexec_current_case_in_fresh_network_namespace(
        case.netns_env(),
        case.case_name(),
        "network-namespace MITM plaintext bridge e2e",
    )
}

fn run_inner(case: MitmBridgeCase) -> Result<(), Box<dyn std::error::Error>> {
    let root = create_temp_root(case.temp_root_name())?;
    match run_at(&root, case) {
        Ok(()) => {
            fs::remove_dir_all(&root)?;
            println!("{}", case.success_label());
            Ok(())
        }
        Err(error) => {
            eprintln!("e2e artifacts retained at {}", root.display());
            Err(error)
        }
    }
}

fn run_at(root: &Path, case: MitmBridgeCase) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(root)?;
    let fixture_ready_path = root.join("fixture.ready");
    let fixture_start_path = root.join("fixture.start");
    let agent_ready_socket_path = root.join("agent.ready.sock");
    let admin_socket_path = root.join("admin.sock");
    let policy_path = root.join("mitm-bridge-e2e-policy.bundle");
    let enforcement_manifest_path = root.join("mitm-bridge-enforcement.toml");
    let bridge_feed_path = root.join("mitm-bridge-capture-events.jsonl");
    let config_path = root.join("agent.toml");
    let spool_path = root.join("spool");
    let mitm_ca = tls::write_mitm_ca(root)?;

    write_policy_bundle(&policy_path, case)?;
    config::write_enforcement_manifest(&enforcement_manifest_path)?;
    let policy_hook_server = case
        .spec()
        .policy_hook
        .uses_external_server()
        .then(MitmPolicyHookServer::start)
        .transpose()?;

    let supervisor = ChildSupervisor::new()?;
    let mut fixture = supervisor.watch(
        spawn_http1_loopback_fixture(&fixture_ready_path, &fixture_start_path, fixture_config())?,
        "fixture",
    );
    let fixture_ready =
        wait_for_http1_loopback_fixture_ready(fixture.child_mut(), &fixture_ready_path)?;
    let intercept_port = unused_intercept_port([fixture_ready.listen_port]);
    let mut mitm_backend = prepare_mitm_backend(
        case,
        root,
        &bridge_feed_path,
        [fixture_ready.listen_port, intercept_port],
        intercept_port,
    )?;
    initialize_bridge_feed(case, &bridge_feed_path)?;
    write_agent_config(AgentConfigInputs {
        case,
        config_path: &config_path,
        policy_path: &policy_path,
        enforcement_manifest_path: Some(enforcement_manifest_path.as_path()),
        bridge_feed_path: &bridge_feed_path,
        mitm_ca_certificate_path: &mitm_ca.certificate_path,
        mitm_ca_private_key_path: &mitm_ca.private_key_path,
        spool_path: &spool_path,
        admin_socket_path: &admin_socket_path,
        capture_port: fixture_ready.listen_port,
        mitm_backend: &mitm_backend.config,
        policy_hook_endpoint: policy_hook_server
            .as_ref()
            .map(MitmPolicyHookServer::endpoint)
            .or_else(|| mitm_backend.policy_hook_endpoint.clone()),
        proxy_port: mitm_backend.proxy_port,
        intercept_port,
    })?;

    let mut ready_signal = UnixSocketReadySignal::bind(agent_ready_socket_path)?;
    let mut agent = supervisor.watch(spawn_agent(&config_path, &ready_signal)?, "agent");
    let agent_ready = wait_for_agent_ready(agent.child_mut(), &mut ready_signal);
    let backend_status = run_after_success([&agent_ready], || {
        assert_mitm_backend_runtime(case, &admin_socket_path, &mitm_backend)
    });
    let outbound_redirect = run_after_success([&agent_ready, &backend_status], || {
        assert_outbound_redirect_reaches_mitm_backend(case, intercept_port)
    });
    let fixture_start =
        run_after_success([&agent_ready, &backend_status, &outbound_redirect], || {
            start_http1_loopback_fixture(&fixture_start_path, &fixture_ready.start_nonce)
        });
    let primary_progress = run_after_success(
        [
            &agent_ready,
            &backend_status,
            &outbound_redirect,
            &fixture_start,
        ],
        || {
            wait_for_agent_policy_progress(
                agent.child_mut(),
                &admin_socket_path,
                expected_libpcap_targets().len() as u64,
            )
        },
    );
    let backend_data_plane = run_after_success(
        [
            &agent_ready,
            &backend_status,
            &outbound_redirect,
            &primary_progress,
        ],
        || exercise_backend_data_plane(case, &supervisor, intercept_port, &mitm_ca, &mitm_backend),
    );
    let bridge_feed_append = run_after_success(
        [&outbound_redirect, &primary_progress, &backend_data_plane],
        || append_bridge_feed_from_harness(case, &bridge_feed_path),
    );
    let bridge_progress = run_after_success(
        [
            &outbound_redirect,
            &primary_progress,
            &backend_data_plane,
            &bridge_feed_append,
        ],
        || {
            wait_for_agent_policy_progress(
                agent.child_mut(),
                &admin_socket_path,
                expected_policy_alert_messages_for_case(case).len() as u64,
            )
        },
    );
    let health_transition = run_after_success(
        [
            &agent_ready,
            &backend_status,
            &outbound_redirect,
            &backend_data_plane,
            &bridge_progress,
        ],
        || exercise_l7_mitm_health_transition(case, &mut mitm_backend, &admin_socket_path),
    );
    let policy_hook_decision = run_after_success(
        [
            &agent_ready,
            &backend_status,
            &outbound_redirect,
            &backend_data_plane,
            &bridge_progress,
        ],
        || {
            if case.spec().policy_hook.expects_delegated_decision() {
                wait_for_agent_enforcement_decision_count_at_least(
                    agent.child_mut(),
                    &admin_socket_path,
                    1,
                )
                .map(|_| ())
            } else {
                Ok(())
            }
        },
    );
    let fixture_result = if all_succeeded([
        &agent_ready,
        &backend_status,
        &outbound_redirect,
        &fixture_start,
    ]) {
        wait_for_http1_loopback_fixture_exit(fixture.child_mut())
    } else {
        stop_running_child(fixture.child_mut(), "fixture")
    };
    fixture.unwatch();
    let agent_result = stop_running_child(agent.child_mut(), "agent");
    agent.unwatch();
    let managed_backend_cleanup_result =
        cleanup_managed_backend(mitm_backend.managed_pid_file(), agent_result.is_ok());
    let policy_hook_requests = run_after_success(
        [
            &agent_ready,
            &backend_status,
            &outbound_redirect,
            &bridge_progress,
            &policy_hook_decision,
            &agent_result,
        ],
        || assert_policy_hook_requests(case, policy_hook_server.as_ref()),
    );
    let backend_policy_hook_execution = run_after_success(
        [
            &agent_ready,
            &backend_status,
            &outbound_redirect,
            &bridge_progress,
            &policy_hook_decision,
            &agent_result,
        ],
        || assert_backend_owned_policy_hook_execution(case, &mitm_backend),
    );
    let phases = MitmBridgePhases {
        fixture: fixture_result,
        agent_ready,
        backend_status,
        outbound_redirect,
        fixture_start,
        primary_progress,
        bridge_feed_append,
        backend_data_plane,
        bridge_progress,
        health_transition,
        policy_hook_decision,
        policy_hook_requests,
        backend_policy_hook_execution,
        agent: agent_result,
        managed_backend_cleanup: managed_backend_cleanup_result,
    };
    let spool_result = if phases.completed_pipeline() {
        assert_spool_outputs(case, &mitm_backend, &spool_path)
    } else {
        skipped_after_upstream_failure()
    };

    merge_labeled_run_results(phases.into_labeled_results(spool_result))
}

fn exercise_backend_data_plane(
    case: MitmBridgeCase,
    supervisor: &ChildSupervisor,
    intercept_port: u16,
    mitm_ca: &tls::MitmCaMaterial,
    mitm_backend: &backend::PreparedMitmBackend,
) -> Result<(), Box<dyn std::error::Error>> {
    let scenario = data_plane::scenario(case);
    if scenario.is_none() {
        return Ok(());
    }
    if scenario.is_managed_plaintext() {
        return exercise_managed_plaintext_data_plane(case, mitm_backend, intercept_port);
    }
    if scenario.uses_product_proxy_transparent_tls() {
        return exercise_product_proxy_transparent_tls_path(
            case,
            supervisor,
            intercept_port,
            mitm_ca,
            mitm_backend,
        );
    }
    Err(e2e_error(format!(
        "{} configured an unsupported MITM data-plane exercise {:?}",
        case.case_name(),
        case.spec().data_plane
    ))
    .into())
}

struct MitmBridgePhases {
    fixture: RunResult,
    agent_ready: RunResult,
    backend_status: RunResult,
    outbound_redirect: RunResult,
    fixture_start: RunResult,
    primary_progress: RunResult,
    bridge_feed_append: RunResult,
    backend_data_plane: RunResult,
    bridge_progress: RunResult,
    health_transition: RunResult,
    policy_hook_decision: RunResult,
    policy_hook_requests: RunResult,
    backend_policy_hook_execution: RunResult,
    agent: RunResult,
    managed_backend_cleanup: RunResult,
}

impl MitmBridgePhases {
    fn completed_pipeline(&self) -> bool {
        all_succeeded([
            &self.fixture,
            &self.agent_ready,
            &self.backend_status,
            &self.outbound_redirect,
            &self.fixture_start,
            &self.primary_progress,
            &self.backend_data_plane,
            &self.bridge_feed_append,
            &self.bridge_progress,
            &self.health_transition,
            &self.policy_hook_decision,
            &self.policy_hook_requests,
            &self.backend_policy_hook_execution,
            &self.agent,
            &self.managed_backend_cleanup,
        ])
    }

    fn into_labeled_results(self, spool: RunResult) -> [LabeledRunResult; 16] {
        [
            ("fixture", self.fixture),
            ("agent readiness", self.agent_ready),
            ("MITM backend runtime status", self.backend_status),
            ("outbound MITM redirect", self.outbound_redirect),
            ("fixture start", self.fixture_start),
            ("agent primary policy progress", self.primary_progress),
            ("MITM backend data plane", self.backend_data_plane),
            ("MITM bridge feed append", self.bridge_feed_append),
            ("agent MITM bridge policy progress", self.bridge_progress),
            ("L7 MITM backend health transition", self.health_transition),
            ("MITM policy hook decision", self.policy_hook_decision),
            ("MITM policy hook requests", self.policy_hook_requests),
            (
                "backend-owned MITM policy hook execution",
                self.backend_policy_hook_execution,
            ),
            ("agent", self.agent),
            ("managed MITM backend cleanup", self.managed_backend_cleanup),
            ("spool assertion", spool),
        ]
    }
}

fn run_after_success<const N: usize>(
    previous: [&RunResult; N],
    run: impl FnOnce() -> RunResult,
) -> RunResult {
    if all_succeeded(previous) {
        run()
    } else {
        skipped_after_upstream_failure()
    }
}

fn all_succeeded<const N: usize>(results: [&RunResult; N]) -> bool {
    results.iter().all(|result| result.is_ok())
}

fn skipped_after_upstream_failure() -> RunResult {
    Ok(())
}

fn bring_loopback_up() -> Result<(), Box<dyn std::error::Error>> {
    ip(["link", "set", "lo", "up"])
}

fn ip(args: impl IntoIterator<Item = &'static str>) -> Result<(), Box<dyn std::error::Error>> {
    let command =
        trusted_system_command(["/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip", "/bin/ip"], "ip")?;
    let status = Command::new(command).args(args).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(e2e_error(format!("ip command exited with {status}")).into())
    }
}

fn require_root() -> Result<(), Box<dyn std::error::Error>> {
    if rustix::process::geteuid().as_raw() == 0 {
        Ok(())
    } else {
        Err(e2e_error("MITM plaintext bridge e2e must run as root").into())
    }
}
