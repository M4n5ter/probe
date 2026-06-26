use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, ExitCode, Output, Stdio},
};

use interception::{TransparentInterceptionSetupDirection, TransparentInterceptionSetupPlan};
use probe_core::{Direction, ProcessSelector, Selector, TrafficSelector};
use transparent_linux::{
    OutboundRedirectArtifactSpec, OutboundRedirectLifecyclePlan, TransparentLinuxResources,
};

use super::harness::{
    e2e_error, reexec_current_case_in_fresh_network_namespace, run_with_temp_root,
    trusted_system_command, verify_fresh_network_namespace,
};

const CASE_NAME: &str = "e2e-transparent-linux-outbound-redirect-artifact-netns";
const IN_NETNS_ENV: &str = "TRAFFIC_PROBE_E2E_TRANSPARENT_LINUX_OUTBOUND_REDIRECT_ARTIFACT_NETNS";
const PROXY_PORT: u16 = 15001;

pub(crate) fn run() -> ExitCode {
    match run_outer() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("e2e transparent Linux outbound redirect artifact failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_outer() -> Result<(), Box<dyn std::error::Error>> {
    require_root()?;
    if std::env::var_os(IN_NETNS_ENV).is_some() {
        verify_fresh_network_namespace(IN_NETNS_ENV)?;
        run_inner()
    } else {
        reexec_current_case_in_fresh_network_namespace(
            IN_NETNS_ENV,
            CASE_NAME,
            "network-namespace outbound redirect artifact acceptance",
        )
    }
}

fn run_inner() -> Result<(), Box<dyn std::error::Error>> {
    run_with_temp_root("transparent-linux-outbound-redirect-artifact-netns", run_at)?;
    println!("e2e transparent Linux outbound redirect artifact netns passed");
    Ok(())
}

fn run_at(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(root)?;
    let artifact = outbound_redirect_artifact()?;
    let setup = root.join("outbound-redirect-setup.nft");
    let cleanup = root.join("outbound-redirect-cleanup.nft");
    fs::write(&setup, artifact.setup_nft_script())?;
    fs::write(&cleanup, artifact.cleanup_nft_script())?;

    let nft = nft_command()?;
    nft_success(
        nft_output(&nft, ["--check", "-f"], Some(&setup))?,
        "nft --check setup",
    )?;
    nft_success(nft_output(&nft, ["-f"], Some(&setup))?, "nft setup")?;
    let result = verify_installed_rules_and_cleanup(&nft, &cleanup);
    if result.is_err() {
        cleanup_owned_table_best_effort(&nft, &cleanup);
    }
    result
}

fn outbound_redirect_artifact() -> Result<OutboundRedirectLifecyclePlan, Box<dyn std::error::Error>>
{
    let selector = outbound_redirect_selector();
    let setup_rules = match TransparentInterceptionSetupPlan::from_selector(
        Some(&selector),
        TransparentInterceptionSetupDirection::Outbound,
    )? {
        TransparentInterceptionSetupPlan::HostRules(rules) => rules,
        _ => {
            return Err(e2e_error(
                "outbound redirect artifact selector must project to host rules",
            )
            .into());
        }
    };
    Ok(OutboundRedirectLifecyclePlan::from_spec_and_rule_set(
        OutboundRedirectArtifactSpec::outbound_transparent_proxy(
            TransparentLinuxResources::reserved(),
            PROXY_PORT,
        ),
        setup_rules,
    )?)
}

fn outbound_redirect_selector() -> Selector {
    Selector::term(
        ProcessSelector::default(),
        TrafficSelector {
            remote_ports: vec![443],
            directions: vec![Direction::Outbound],
            remote_addresses: vec!["203.0.113.10".to_string()],
            ..TrafficSelector::default()
        },
    )
}

fn verify_installed_rules_and_cleanup(
    nft: &Path,
    cleanup: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let listing = nft_output(nft, ["list", "table", "inet", "traffic_probe"], None)?;
    nft_success(listing.clone(), "nft list table")?;
    assert_installed_rules(&String::from_utf8_lossy(&listing.stdout))?;
    nft_success(
        nft_output(nft, ["--check", "-f"], Some(cleanup))?,
        "nft --check cleanup",
    )?;
    nft_success(nft_output(nft, ["-f"], Some(cleanup))?, "nft cleanup")?;
    assert_cleanup_removed_table(nft)?;
    Ok(())
}

fn cleanup_owned_table_best_effort(nft: &Path, cleanup: &Path) {
    let _ = nft_output(nft, ["-f"], Some(cleanup));
}

fn assert_installed_rules(listing: &str) -> Result<(), Box<dyn std::error::Error>> {
    for expected in [
        "chain outbound_transparent_proxy",
        "type nat hook output priority dstnat; policy accept;",
        "meta mark 0x54500102 return",
        "tcp dport 443",
        "ip daddr 203.0.113.10",
        "redirect to :15001",
    ] {
        if !listing.contains(expected) {
            return Err(e2e_error(format!(
                "outbound redirect artifact table listing is missing `{expected}`: {listing}"
            ))
            .into());
        }
    }
    Ok(())
}

fn assert_cleanup_removed_table(nft: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let output = nft_output(nft, ["list", "table", "inet", "traffic_probe"], None)?;
    if output.status.success() {
        return Err(e2e_error(format!(
            "outbound redirect artifact cleanup left owned table behind: {}",
            String::from_utf8_lossy(&output.stdout)
        ))
        .into());
    }
    Ok(())
}

fn nft_output<const N: usize>(
    nft: &Path,
    args: [&str; N],
    file: Option<&Path>,
) -> Result<Output, Box<dyn std::error::Error>> {
    let mut command = Command::new(nft);
    command.args(args).stdin(Stdio::null());
    if let Some(file) = file {
        command.arg(file);
    }
    Ok(command.output()?)
}

fn nft_success(output: Output, command_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    if output.status.success() {
        Ok(())
    } else {
        Err(e2e_error(format!(
            "{command_name} failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ))
        .into())
    }
}

fn require_root() -> Result<(), Box<dyn std::error::Error>> {
    if rustix::process::geteuid().as_raw() == 0 {
        Ok(())
    } else {
        Err(e2e_error("transparent outbound redirect artifact acceptance must run as root").into())
    }
}

fn nft_command() -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(trusted_system_command(
        ["/usr/sbin/nft", "/usr/bin/nft", "/sbin/nft", "/bin/nft"],
        "nft",
    )?)
}
