use std::{
    env,
    ffi::OsString,
    path::{Path, PathBuf},
};

pub const PROBE_HOME_ENV: &str = "PROBE_HOME";
pub const DEFAULT_PROBE_HOME_STATE_DIR: &str = "traffic-probe";
pub const FALLBACK_PROBE_HOME: &str = "/var/lib/traffic-probe";

pub fn probe_home() -> PathBuf {
    probe_home_from_env(|name| env::var_os(name))
}

fn probe_home_from_env(mut read_env: impl FnMut(&str) -> Option<OsString>) -> PathBuf {
    read_env(PROBE_HOME_ENV)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            read_env("XDG_STATE_HOME")
                .filter(|value| !value.is_empty())
                .map(|path| PathBuf::from(path).join(DEFAULT_PROBE_HOME_STATE_DIR))
        })
        .or_else(|| {
            read_env("HOME")
                .filter(|value| !value.is_empty())
                .map(|path| {
                    PathBuf::from(path)
                        .join(".local")
                        .join("state")
                        .join(DEFAULT_PROBE_HOME_STATE_DIR)
                })
        })
        .unwrap_or_else(|| PathBuf::from(FALLBACK_PROBE_HOME))
}

pub fn probe_home_path(relative: impl AsRef<Path>) -> PathBuf {
    probe_home().join(relative.as_ref())
}

pub fn default_config_path() -> PathBuf {
    probe_home_path("config/agent.toml")
}

pub fn default_storage_path() -> PathBuf {
    probe_home_path("spool")
}

pub fn default_export_file_path() -> PathBuf {
    probe_home_path("export/events.jsonl")
}

pub fn default_export_unix_http_socket_path() -> PathBuf {
    probe_home_path("run/export.sock")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_home_prefers_explicit_environment() {
        let path = probe_home_from_env(|name| match name {
            PROBE_HOME_ENV => Some(OsString::from("/custom/probe")),
            "XDG_STATE_HOME" => Some(OsString::from("/state")),
            "HOME" => Some(OsString::from("/home/operator")),
            _ => None,
        });

        assert_eq!(path, PathBuf::from("/custom/probe"));
    }

    #[test]
    fn probe_home_uses_xdg_state_home_before_home() {
        let path = probe_home_from_env(|name| match name {
            "XDG_STATE_HOME" => Some(OsString::from("/home/operator/.local/state")),
            "HOME" => Some(OsString::from("/home/operator")),
            _ => None,
        });

        assert_eq!(
            path,
            PathBuf::from("/home/operator/.local/state/traffic-probe")
        );
    }

    #[test]
    fn probe_home_uses_home_local_state_when_xdg_state_home_is_absent() {
        let path = probe_home_from_env(|name| match name {
            "HOME" => Some(OsString::from("/home/operator")),
            _ => None,
        });

        assert_eq!(
            path,
            PathBuf::from("/home/operator/.local/state/traffic-probe")
        );
    }

    #[test]
    fn probe_home_falls_back_to_machine_state_without_user_home() {
        let path = probe_home_from_env(|_| None);

        assert_eq!(path, PathBuf::from(FALLBACK_PROBE_HOME));
    }
}
