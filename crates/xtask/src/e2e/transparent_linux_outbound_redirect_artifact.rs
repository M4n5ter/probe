use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, ExitCode, Output, Stdio},
};

use interception::{TransparentInterceptionSetupDirection, TransparentInterceptionSetupPlan};
use probe_core::{CgroupPath, Direction, ProcessSelector, Selector, TrafficSelector};
use transparent_linux::{
    OutboundRedirectArtifactSpec, OutboundRedirectLifecyclePlan, TransparentLinuxResources,
};

use super::{
    E2eOutcome,
    harness::{
        create_temp_root, e2e_error, reexec_current_case_in_fresh_network_namespace,
        reexec_current_case_in_fresh_network_namespace_with_env, run_with_temp_root,
        trusted_system_command, verify_fresh_network_namespace,
    },
};

const CASE_NAME: &str = "e2e-transparent-linux-outbound-redirect-artifact-netns";
const CGROUP_CASE_NAME: &str = "e2e-transparent-linux-outbound-cgroup-artifact-netns";
const IN_NETNS_ENV: &str = "TRAFFIC_PROBE_E2E_TRANSPARENT_LINUX_OUTBOUND_REDIRECT_ARTIFACT_NETNS";
const CGROUP_IN_NETNS_ENV: &str =
    "TRAFFIC_PROBE_E2E_TRANSPARENT_LINUX_OUTBOUND_CGROUP_ARTIFACT_NETNS";
const CGROUP_PATH_ENV: &str = "TRAFFIC_PROBE_E2E_TRANSPARENT_LINUX_OUTBOUND_CGROUP_PATH";
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const PROXY_PORT: u16 = 15001;

type E2eResult<T> = Result<T, Box<dyn std::error::Error>>;

pub(crate) fn run() -> ExitCode {
    run_case(ArtifactCase::TrafficOnly)
}

pub(crate) fn run_cgroup() -> E2eOutcome {
    match run_cgroup_case() {
        Ok(CgroupRunOutcome::Passed) => E2eOutcome::Passed,
        Ok(CgroupRunOutcome::Skipped(reason)) => E2eOutcome::Skipped(reason),
        Err(error) => {
            eprintln!(
                "e2e transparent Linux outbound redirect socket-cgroup artifact failed: {error}"
            );
            E2eOutcome::Failed
        }
    }
}

fn run_case(case: ArtifactCase) -> ExitCode {
    match run_outer(&case) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!(
                "e2e transparent Linux outbound redirect {} artifact failed: {error}",
                case.label()
            );
            ExitCode::FAILURE
        }
    }
}

enum CgroupRunOutcome {
    Passed,
    Skipped(String),
}

enum SocketCgroupPathSelection {
    Selected { cgroup_path: String },
    Unsupported(String),
}

fn run_cgroup_case() -> E2eResult<CgroupRunOutcome> {
    require_root()?;
    if env::var_os(CGROUP_IN_NETNS_ENV).is_some() {
        verify_fresh_network_namespace(CGROUP_IN_NETNS_ENV)?;
        let cgroup_path = selected_cgroup_path_from_env()?;
        run_inner(&ArtifactCase::SocketCgroup { cgroup_path })?;
        return Ok(CgroupRunOutcome::Passed);
    }

    let cgroup_path = match select_socket_cgroup_resolver_path()? {
        SocketCgroupPathSelection::Selected { cgroup_path } => cgroup_path,
        SocketCgroupPathSelection::Unsupported(reason) => {
            return Ok(CgroupRunOutcome::Skipped(reason));
        }
    };
    reexec_current_case_in_fresh_network_namespace_with_env(
        CGROUP_IN_NETNS_ENV,
        CGROUP_CASE_NAME,
        "network-namespace outbound socket-cgroup artifact acceptance",
        &[(CGROUP_PATH_ENV, cgroup_path.as_str())],
    )?;
    Ok(CgroupRunOutcome::Passed)
}

#[derive(Debug, Clone)]
enum ArtifactCase {
    TrafficOnly,
    SocketCgroup { cgroup_path: String },
}

impl ArtifactCase {
    fn case_name(&self) -> &'static str {
        match self {
            Self::TrafficOnly => CASE_NAME,
            Self::SocketCgroup { .. } => CGROUP_CASE_NAME,
        }
    }

    fn marker_env(&self) -> &'static str {
        match self {
            Self::TrafficOnly => IN_NETNS_ENV,
            Self::SocketCgroup { .. } => CGROUP_IN_NETNS_ENV,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Self::TrafficOnly => "traffic-only",
            Self::SocketCgroup { .. } => "socket-cgroup",
        }
    }

    fn temp_root(&self) -> &'static str {
        match self {
            Self::TrafficOnly => "transparent-linux-outbound-redirect-artifact-netns",
            Self::SocketCgroup { .. } => "transparent-linux-outbound-cgroup-artifact-netns",
        }
    }

    fn uses_socket_cgroup(&self) -> bool {
        match self {
            Self::TrafficOnly => false,
            Self::SocketCgroup { .. } => true,
        }
    }
}

fn run_outer(case: &ArtifactCase) -> E2eResult<()> {
    require_root()?;
    if env::var_os(case.marker_env()).is_some() {
        verify_fresh_network_namespace(case.marker_env())?;
        run_inner(case)
    } else {
        reexec_current_case_in_fresh_network_namespace(
            case.marker_env(),
            case.case_name(),
            "network-namespace outbound redirect artifact acceptance",
        )
    }
}

fn run_inner(case: &ArtifactCase) -> E2eResult<()> {
    run_with_temp_root(case.temp_root(), |root| run_at(root, case))?;
    println!(
        "e2e transparent Linux outbound redirect {} artifact netns passed",
        case.label()
    );
    Ok(())
}

fn run_at(root: &Path, case: &ArtifactCase) -> E2eResult<()> {
    fs::create_dir_all(root)?;
    let artifact = outbound_redirect_artifact(case)?;
    let setup = root.join("outbound-redirect-setup.nft");
    let cleanup = root.join("outbound-redirect-cleanup.nft");
    let setup_script = artifact.setup_nft_script();
    assert_setup_script(&setup_script, case)?;
    fs::write(&setup, setup_script)?;
    fs::write(&cleanup, artifact.cleanup_nft_script())?;

    let nft = nft_command()?;
    nft_success(
        nft_output(&nft, ["--check", "-f"], Some(&setup))?,
        "nft --check setup",
    )?;
    nft_success(nft_output(&nft, ["-f"], Some(&setup))?, "nft setup")?;
    let result = verify_installed_rules_and_cleanup(&nft, &cleanup, case);
    if result.is_err() {
        cleanup_owned_table_best_effort(&nft, &cleanup);
    }
    result
}

fn outbound_redirect_artifact(case: &ArtifactCase) -> E2eResult<OutboundRedirectLifecyclePlan> {
    outbound_redirect_artifact_for_process(process_selector_for_case(case))
}

fn process_selector_for_case(case: &ArtifactCase) -> ProcessSelector {
    match case {
        ArtifactCase::TrafficOnly => ProcessSelector::default(),
        ArtifactCase::SocketCgroup { cgroup_path } => ProcessSelector {
            cgroup_paths: vec![cgroup_path.clone()],
            ..ProcessSelector::default()
        },
    }
}

fn outbound_redirect_artifact_for_process(
    process: ProcessSelector,
) -> E2eResult<OutboundRedirectLifecyclePlan> {
    let selector = outbound_redirect_selector(process);
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

fn outbound_redirect_selector(process: ProcessSelector) -> Selector {
    Selector::term(
        process,
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
    case: &ArtifactCase,
) -> E2eResult<()> {
    let listing = nft_output(nft, ["list", "table", "inet", "traffic_probe"], None)?;
    nft_success(listing.clone(), "nft list table")?;
    assert_installed_rules(&String::from_utf8_lossy(&listing.stdout))?;
    assert_cgroup_rule_listing(&String::from_utf8_lossy(&listing.stdout), case)?;
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

fn assert_installed_rules(listing: &str) -> E2eResult<()> {
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

fn assert_setup_script(setup_script: &str, case: &ArtifactCase) -> E2eResult<()> {
    if case.uses_socket_cgroup() {
        assert_socket_cgroup_setup_script(setup_script)?;
    }
    Ok(())
}

fn assert_socket_cgroup_setup_script(setup_script: &str) -> E2eResult<()> {
    if !setup_script.contains("socket cgroupv2 level") {
        return Err(e2e_error(format!(
            "outbound redirect cgroup artifact setup script is missing socket cgroupv2 match: {setup_script}"
        ))
        .into());
    }
    Ok(())
}

fn select_socket_cgroup_resolver_path() -> E2eResult<SocketCgroupPathSelection> {
    let candidates = match existing_cgroup_paths_for_artifact() {
        Ok(paths) => paths,
        Err(error) => return Ok(SocketCgroupPathSelection::Unsupported(error.to_string())),
    };
    let nft = nft_command()?;

    let mut rejected = Vec::new();
    for cgroup_path in candidates {
        match check_socket_cgroup_resolver_path(&nft, &cgroup_path)? {
            SocketCgroupPathSelection::Selected { cgroup_path } => {
                return Ok(SocketCgroupPathSelection::Selected { cgroup_path });
            }
            SocketCgroupPathSelection::Unsupported(reason) => {
                rejected.push(CgroupPathRejection {
                    cgroup_path,
                    reason,
                });
            }
        }
    }

    Ok(SocketCgroupPathSelection::Unsupported(format!(
        "nft socket-cgroup resolver did not accept any existing non-root cgroup v2 path under {CGROUP_ROOT}: {}",
        cgroup_rejection_summary(&rejected)
    )))
}

struct CgroupPathRejection {
    cgroup_path: String,
    reason: String,
}

fn cgroup_rejection_summary(rejected: &[CgroupPathRejection]) -> String {
    let Some(first) = rejected.first() else {
        return "no candidate paths were checked".to_string();
    };
    let suffix = match rejected.len().saturating_sub(1) {
        0 => String::new(),
        count => format!("; {count} additional candidate(s) rejected"),
    };
    format!("{}: {}{}", first.cgroup_path, first.reason, suffix)
}

fn check_socket_cgroup_resolver_path(
    nft: &Path,
    cgroup_path: &str,
) -> E2eResult<SocketCgroupPathSelection> {
    let root = create_temp_root("transparent-linux-outbound-cgroup-artifact-preflight")?;
    let result = (|| -> E2eResult<SocketCgroupPathSelection> {
        let setup_script = socket_cgroup_resolver_probe_script(cgroup_path);
        let setup = root.join("outbound-cgroup-preflight.nft");
        fs::write(&setup, setup_script)?;
        socket_cgroup_check_outcome(
            nft_output(nft, ["--check", "-f"], Some(&setup))?,
            cgroup_path,
        )
    })();
    fs::remove_dir_all(&root)?;
    result
}

fn socket_cgroup_resolver_probe_script(cgroup_path: &str) -> String {
    let level = cgroup_path.split('/').count();
    let table = format!("traffic_probe_e2e_probe_{}", std::process::id());
    let path = nft_string_literal(cgroup_path);
    format!(
        "table inet {table} {{
    chain outbound_probe {{
        type nat hook output priority dstnat; policy accept;
    }}
}}
add rule inet {table} outbound_probe meta l4proto tcp meta nfproto ipv4 socket cgroupv2 level {level} {path} tcp dport 443 ip daddr 203.0.113.10 redirect to :15001
"
    )
}

fn nft_string_literal(value: &str) -> String {
    let mut literal = String::with_capacity(value.len() + 2);
    literal.push('"');
    for character in value.chars() {
        if character == '"' || character == '\\' {
            literal.push('\\');
        }
        literal.push(character);
    }
    literal.push('"');
    literal
}

fn socket_cgroup_check_outcome(
    output: Output,
    cgroup_path: &str,
) -> E2eResult<SocketCgroupPathSelection> {
    if output.status.success() {
        return Ok(SocketCgroupPathSelection::Selected {
            cgroup_path: cgroup_path.to_string(),
        });
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if socket_cgroup_resolver_rejected(&stderr) {
        return Ok(SocketCgroupPathSelection::Unsupported(format!(
            "nft socket-cgroup resolver rejected path with {}: {}",
            output.status,
            concise_nft_error(&stderr)
        )));
    }

    Err(e2e_error(format!(
        "nft --check socket-cgroup setup failed unexpectedly with {}: {stderr}",
        output.status
    ))
    .into())
}

fn socket_cgroup_resolver_rejected(stderr: &str) -> bool {
    let stderr = stderr.to_ascii_lowercase();
    stderr.contains("no such file or directory")
        || stderr.contains("operation not supported")
        || stderr.contains("not supported")
        || stderr.contains("unsupported")
        || (stderr.contains("invalid") && stderr.contains("cgroup"))
}

fn concise_nft_error(stderr: &str) -> &str {
    let line = stderr
        .lines()
        .find(|line| line.contains("Error:"))
        .unwrap_or_else(|| stderr.trim())
        .trim();
    line.find("Error:").map_or(line, |index| &line[index..])
}

fn assert_cgroup_rule_listing(listing: &str, case: &ArtifactCase) -> E2eResult<()> {
    if case.uses_socket_cgroup() && !listing.contains("socket cgroupv2 level") {
        return Err(e2e_error(format!(
            "outbound redirect cgroup artifact listing is missing socket cgroupv2 match: {listing}"
        ))
        .into());
    }
    Ok(())
}

fn selected_cgroup_path_from_env() -> E2eResult<String> {
    let raw = env::var(CGROUP_PATH_ENV).map_err(|_| {
        e2e_error(format!(
            "missing selected cgroup path env {CGROUP_PATH_ENV}"
        ))
    })?;
    let path = CgroupPath::parse(&raw).map_err(|error| {
        e2e_error(format!(
            "selected cgroup path `{raw}` from {CGROUP_PATH_ENV} is invalid: {error}"
        ))
    })?;
    let metadata = fs::metadata(Path::new(CGROUP_ROOT).join(path.as_str())).map_err(|error| {
        e2e_error(format!(
            "selected cgroup path `{}` from {CGROUP_PATH_ENV} is not visible under {CGROUP_ROOT}: {error}",
            path.as_str()
        ))
    })?;
    if !metadata.is_dir() {
        return Err(e2e_error(format!(
            "selected cgroup path `{raw}` from {CGROUP_PATH_ENV} is not a directory"
        ))
        .into());
    }
    Ok(path.into_string())
}

fn existing_cgroup_paths_for_artifact() -> E2eResult<Vec<String>> {
    let mut candidates = Vec::new();
    if let Some(path) = current_process_cgroup_path()? {
        candidates.push(path);
    }
    candidates.extend(
        ["init.scope", "system.slice", "user.slice"]
            .into_iter()
            .map(str::to_string),
    );
    candidates.extend(existing_top_level_cgroup_paths()?);

    let mut paths = Vec::new();
    for candidate in candidates {
        if let Some(path) = normalize_existing_cgroup_path(&candidate)
            && !paths.contains(&path)
        {
            paths.push(path);
        }
    }
    if paths.is_empty() {
        return Err(e2e_error(format!(
            "outbound redirect cgroup artifact requires an existing non-root cgroup v2 path under {CGROUP_ROOT}"
        ))
        .into());
    }
    Ok(paths)
}

fn current_process_cgroup_path() -> E2eResult<Option<String>> {
    let content = fs::read_to_string("/proc/self/cgroup")?;
    Ok(content.lines().find_map(|line| {
        let mut fields = line.splitn(3, ':');
        let _hierarchy = fields.next()?;
        let _controllers = fields.next()?;
        Some(fields.next()?.trim().to_string())
    }))
}

fn existing_top_level_cgroup_paths() -> E2eResult<Vec<String>> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(CGROUP_ROOT)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            paths.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    Ok(paths)
}

fn normalize_existing_cgroup_path(path: &str) -> Option<String> {
    let path = CgroupPath::parse(path).ok()?;
    fs::metadata(Path::new(CGROUP_ROOT).join(path.as_str()))
        .ok()
        .filter(|metadata| metadata.is_dir())?;
    Some(path.into_string())
}

fn assert_cleanup_removed_table(nft: &Path) -> E2eResult<()> {
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
) -> E2eResult<Output> {
    let mut command = Command::new(nft);
    command.args(args).stdin(Stdio::null());
    if let Some(file) = file {
        command.arg(file);
    }
    Ok(command.output()?)
}

fn nft_success(output: Output, command_name: &str) -> E2eResult<()> {
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

fn require_root() -> E2eResult<()> {
    if rustix::process::geteuid().as_raw() == 0 {
        Ok(())
    } else {
        Err(e2e_error("transparent outbound redirect artifact acceptance must run as root").into())
    }
}

fn nft_command() -> E2eResult<PathBuf> {
    Ok(trusted_system_command(
        ["/usr/sbin/nft", "/usr/bin/nft", "/sbin/nft", "/bin/nft"],
        "nft",
    )?)
}
