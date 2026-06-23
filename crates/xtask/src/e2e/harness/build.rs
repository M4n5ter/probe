use std::{
    collections::BTreeSet,
    env,
    ffi::OsString,
    fs, io,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use super::e2e_error;

pub(crate) fn cargo_executable() -> OsString {
    env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"))
}

pub(crate) fn workspace_root() -> Result<PathBuf, std::io::Error> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|crates_dir| crates_dir.parent())
        .map(Path::to_path_buf)
        .ok_or_else(|| e2e_error("failed to resolve workspace root"))
}

pub(crate) fn run_agent_with_max_events(
    config_path: &Path,
    max_events: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let max_events = max_events.to_string();
    let status = Command::new(cargo_executable())
        .current_dir(workspace_root()?)
        .args(["run", "-p", "agent", "--locked", "--", "run", "--config"])
        .arg(config_path)
        .args(["--max-events", &max_events])
        .status()?;
    if status.success() {
        return Ok(());
    }

    Err(e2e_error(format!("agent run exited with {status}")).into())
}

pub(crate) fn debug_binary(binary: &str) -> Result<PathBuf, std::io::Error> {
    let target_dir = match env::var_os("CARGO_TARGET_DIR") {
        Some(path) => {
            let path = PathBuf::from(path);
            if path.is_absolute() {
                path
            } else {
                workspace_root()?.join(path)
            }
        }
        None => workspace_root()?.join("target"),
    };
    let path = target_dir.join("debug").join(binary_name(binary));
    if path.is_file() {
        validate_debug_binary_fresh(&path)?;
        return Ok(path);
    }

    Err(e2e_error(format!(
        "missing debug binary {}; run `cargo build -p agent -p e2e-fixture -p xtask --locked` before privileged e2e",
        path.display()
    )))
}

pub(crate) fn ensure_e2e_packages_built<const N: usize>(
    packages: [&str; N],
) -> Result<(), io::Error> {
    for package in packages {
        ensure_e2e_package_built(package)?;
    }
    Ok(())
}

pub(crate) fn trusted_system_command<const N: usize>(
    candidates: [&str; N],
    name: &str,
) -> Result<PathBuf, io::Error> {
    first_existing_system_command(candidates, name)
}

fn ensure_e2e_package_built(package: &str) -> Result<(), io::Error> {
    let mut command = cargo_build_command_for_package(package)?;
    let status = command.status().map_err(|source| {
        e2e_error(format!(
            "failed to run `cargo build -p {package} --locked --quiet` before privileged e2e: {source}"
        ))
    })?;
    if status.success() {
        Ok(())
    } else {
        Err(e2e_error(format!(
            "`cargo build -p {package} --locked --quiet` failed with {status}; rebuild before privileged e2e"
        )))
    }
}

fn cargo_build_command_for_package(package: &str) -> Result<Command, io::Error> {
    let mut command = match sudo_invoking_user()? {
        Some(user) => {
            let cargo = cargo_executable_for_user(&user)?;
            let mut command = Command::new(setpriv_command()?);
            command
                .arg("--reuid")
                .arg(user.uid.to_string())
                .arg("--regid")
                .arg(user.gid.to_string())
                .arg("--clear-groups")
                .arg("--")
                .arg(cargo)
                .env("HOME", &user.home);
            command
        }
        None => Command::new(cargo_executable()),
    };
    command
        .args(["build", "-p", package, "--locked", "--quiet"])
        .stdin(Stdio::null());
    Ok(command)
}

struct InvokingUser {
    uid: u32,
    gid: u32,
    home: PathBuf,
}

fn sudo_invoking_user() -> Result<Option<InvokingUser>, io::Error> {
    if rustix::process::geteuid().as_raw() != 0 || env::var_os("SUDO_USER").is_none() {
        return Ok(None);
    }
    let user =
        env::var("SUDO_USER").map_err(|_| e2e_error("root e2e process is missing SUDO_USER"))?;
    let uid = parse_sudo_id("SUDO_UID")?;
    let gid = parse_sudo_id("SUDO_GID")?;
    let home = passwd_home_for_user(&user)
        .ok_or_else(|| e2e_error(format!("failed to resolve home directory for {user}")))?;
    Ok(Some(InvokingUser { uid, gid, home }))
}

fn parse_sudo_id(name: &'static str) -> Result<u32, io::Error> {
    env::var(name)
        .map_err(|_| e2e_error(format!("root e2e process is missing {name}")))?
        .parse::<u32>()
        .map_err(|source| e2e_error(format!("invalid {name}: {source}")))
}

fn cargo_executable_for_user(user: &InvokingUser) -> Result<OsString, io::Error> {
    let path = user.home.join(".cargo/bin/cargo");
    if path.is_file() {
        Ok(path.into_os_string())
    } else {
        Err(e2e_error(format!(
            "failed to find cargo for sudo user at {}; run privileged e2e via the developer account that owns the Rust toolchain",
            path.display()
        )))
    }
}

fn passwd_home_for_user(user: &str) -> Option<PathBuf> {
    let passwd = fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() >= 6 && fields[0] == user {
            Some(PathBuf::from(fields[5]))
        } else {
            None
        }
    })
}

fn setpriv_command() -> Result<PathBuf, io::Error> {
    first_existing_system_command(["/usr/bin/setpriv", "/bin/setpriv"], "setpriv")
}

fn first_existing_system_command<const N: usize>(
    candidates: [&str; N],
    name: &str,
) -> Result<PathBuf, io::Error> {
    candidates
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .ok_or_else(|| e2e_error(format!("missing trusted system command {name}")))
}

fn binary_name(binary: &str) -> String {
    format!("{binary}{}", env::consts::EXE_SUFFIX)
}

fn validate_debug_binary_fresh(path: &Path) -> Result<(), io::Error> {
    let binary_mtime = fs::metadata(path)?.modified()?;
    for input in cargo_dep_info_build_inputs(path)? {
        let input_mtime = fs::metadata(&input).map_err(|source| {
            e2e_error(format!(
                "debug binary {} was built from missing or unreadable input {}; run `cargo build -p agent -p e2e-fixture -p xtask --locked` before privileged e2e: {source}",
                path.display(),
                input.display()
            ))
        })?.modified()?;
        if input_mtime > binary_mtime {
            return Err(e2e_error(format!(
                "debug binary {} is older than build input {}; run `cargo build -p agent -p e2e-fixture -p xtask --locked` before privileged e2e",
                path.display(),
                input.display()
            )));
        }
    }
    Ok(())
}

fn cargo_dep_info_build_inputs(binary_path: &Path) -> Result<Vec<PathBuf>, io::Error> {
    let root = workspace_root()?;
    let dep_info_path = binary_path.with_extension("d");
    let dep_info = fs::read_to_string(&dep_info_path).map_err(|source| {
        e2e_error(format!(
            "missing Cargo dep-info for debug binary {}; run `cargo build -p agent -p e2e-fixture -p xtask --locked` before privileged e2e: {source}",
            binary_path.display()
        ))
    })?;
    let inputs = parse_dep_info_dependencies(&dep_info)
        .into_iter()
        .map(|path| {
            if path.is_absolute() {
                path
            } else {
                root.join(path)
            }
        })
        .collect::<BTreeSet<_>>();
    if inputs.is_empty() {
        return Err(e2e_error(format!(
            "Cargo dep-info {} did not list any inputs for {}; rebuild before privileged e2e",
            dep_info_path.display(),
            binary_path.display()
        )));
    }
    Ok(inputs.into_iter().collect())
}

fn parse_dep_info_dependencies(contents: &str) -> Vec<PathBuf> {
    let Some(section) = dep_info_dependency_section(contents) else {
        return Vec::new();
    };
    parse_makefile_tokens(section)
        .into_iter()
        .map(PathBuf::from)
        .collect()
}

fn dep_info_dependency_section(contents: &str) -> Option<&str> {
    let mut escaped = false;
    for (index, character) in contents.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' => escaped = true,
            ':' => return Some(&contents[index + character.len_utf8()..]),
            _ => {}
        }
    }
    None
}

fn parse_makefile_tokens(contents: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut characters = contents.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '\\' => match characters.next() {
                Some('\n') => {}
                Some('\r') => {
                    if matches!(characters.peek(), Some('\n')) {
                        let _ = characters.next();
                    }
                }
                Some(escaped) => token.push(escaped),
                None => token.push('\\'),
            },
            character if character.is_whitespace() => {
                if !token.is_empty() {
                    tokens.push(std::mem::take(&mut token));
                }
            }
            _ => token.push(character),
        }
    }
    if !token.is_empty() {
        tokens.push(token);
    }
    tokens
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn dep_info_dependencies_handle_makefile_escapes() {
        let deps = parse_dep_info_dependencies(
            "/tmp/target/debug/fixture: /tmp/src/main.rs /tmp/src/space\\ file.rs \\\n /tmp/src/next.rs\n",
        );

        assert_eq!(
            deps,
            vec![
                PathBuf::from("/tmp/src/main.rs"),
                PathBuf::from("/tmp/src/space file.rs"),
                PathBuf::from("/tmp/src/next.rs"),
            ]
        );
    }
}
