use std::{
    env, fs, io,
    io::{IsTerminal, Read, Write},
    process::{Command, Stdio},
};

use super::{e2e_error, trusted_system_command, wall_time_unix_ns};

const NETNS_REEXEC_MAGIC: &str = "sssa-probe-e2e-netns-reexec";

pub(crate) fn reexec_current_case_in_fresh_network_namespace(
    marker_env: &'static str,
    case_name: &'static str,
    failure_label: &'static str,
) -> Result<(), Box<dyn std::error::Error>> {
    let current_exe = env::current_exe()?;
    let parent_netns = current_network_namespace()?;
    let token = format!("{case_name}:{}:{}", std::process::id(), wall_time_unix_ns());
    let mut child = Command::new(trusted_system_command(
        ["/usr/bin/unshare", "/bin/unshare"],
        "unshare",
    )?)
    .arg("-n")
    .arg("--")
    .arg(current_exe)
    .arg(case_name)
    .env(marker_env, &token)
    .stdin(Stdio::piped())
    .spawn()?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| e2e_error("failed to open netns reexec stdin pipe"))?;
    stdin.write_all(netns_reexec_envelope(marker_env, &parent_netns, &token).as_bytes())?;
    drop(stdin);
    let status = child.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(e2e_error(format!("{failure_label} exited with {status}")).into())
    }
}

pub(crate) fn verify_fresh_network_namespace(
    marker_env: &'static str,
) -> Result<(), Box<dyn std::error::Error>> {
    if env::var_os(marker_env).is_none() {
        return Err(e2e_error(format!("missing network namespace marker {marker_env}")).into());
    }
    if io::stdin().is_terminal() {
        return Err(
            e2e_error("network namespace marker is set without a reexec stdin envelope").into(),
        );
    }
    let marker_token = required_env(marker_env)?;
    let envelope = read_netns_reexec_envelope_from_stdin()?;
    if envelope.marker_env != marker_env {
        return Err(e2e_error(format!(
            "network namespace envelope marker mismatch: expected {marker_env}, got {}",
            envelope.marker_env
        ))
        .into());
    }
    if envelope.token != marker_token {
        return Err(e2e_error(format!(
            "network namespace marker token mismatch for {marker_env}"
        ))
        .into());
    }
    let current = current_network_namespace()?;
    if current == envelope.parent_netns {
        return Err(e2e_error(format!(
            "network namespace marker {marker_env} is set, but current netns is still {current}"
        ))
        .into());
    }
    Ok(())
}

fn current_network_namespace() -> Result<String, io::Error> {
    fs::read_link("/proc/self/ns/net").map(|path| path.to_string_lossy().into_owned())
}

fn netns_reexec_envelope(marker_env: &str, parent_netns: &str, token: &str) -> String {
    format!("{NETNS_REEXEC_MAGIC}\n{marker_env}\n{parent_netns}\n{token}\n")
}

fn read_netns_reexec_envelope_from_stdin() -> Result<NetnsReexecEnvelope, io::Error> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    parse_netns_reexec_envelope(&input)
}

fn parse_netns_reexec_envelope(input: &str) -> Result<NetnsReexecEnvelope, io::Error> {
    let mut lines = input.lines();
    match lines.next() {
        Some(NETNS_REEXEC_MAGIC) => {}
        _ => return Err(e2e_error("invalid network namespace reexec envelope")),
    }
    let marker_env = required_envelope_line(&mut lines, "marker")?;
    let parent_netns = required_envelope_line(&mut lines, "parent netns")?;
    let token = required_envelope_line(&mut lines, "token")?;
    if token.is_empty() {
        return Err(e2e_error("empty network namespace reexec token"));
    }
    if lines.next().is_some() {
        return Err(e2e_error(
            "network namespace reexec envelope has trailing data",
        ));
    }
    Ok(NetnsReexecEnvelope {
        marker_env: marker_env.to_string(),
        parent_netns: parent_netns.to_string(),
        token: token.to_string(),
    })
}

fn required_envelope_line<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    name: &'static str,
) -> Result<&'a str, io::Error> {
    lines.next().ok_or_else(|| {
        e2e_error(format!(
            "network namespace reexec envelope is missing {name}"
        ))
    })
}

fn required_env(name: &str) -> Result<String, io::Error> {
    env::var(name).map_err(|_| e2e_error(format!("missing required environment variable {name}")))
}

#[derive(Debug)]
struct NetnsReexecEnvelope {
    marker_env: String,
    parent_netns: String,
    token: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netns_reexec_envelope_requires_pipe_payload() {
        let error = parse_netns_reexec_envelope("").expect_err("empty envelope must fail");

        assert!(error.to_string().contains("invalid network namespace"));
    }

    #[test]
    fn netns_reexec_envelope_rejects_trailing_data() {
        let input = format!("{NETNS_REEXEC_MAGIC}\nSSSA_TEST\nnet:[1]\ntoken\nextra\n");
        let error = parse_netns_reexec_envelope(&input).expect_err("trailing data must fail");

        assert!(error.to_string().contains("trailing data"));
    }

    #[test]
    fn netns_reexec_envelope_parses_parent_netns_and_token() {
        let input = netns_reexec_envelope("SSSA_TEST", "net:[1]", "token");

        let envelope = parse_netns_reexec_envelope(&input).expect("envelope should parse");

        assert_eq!(envelope.marker_env, "SSSA_TEST");
        assert_eq!(envelope.parent_netns, "net:[1]");
        assert_eq!(envelope.token, "token");
    }
}
