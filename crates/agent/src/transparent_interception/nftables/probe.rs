use std::{
    fs,
    path::{Path, PathBuf},
};

use probe_core::{CapabilityKind, CapabilityState};

use super::command::{find_nft_command, is_root};

pub(super) struct NftablesInterceptionProbe {
    nft: Option<PathBuf>,
    running_as_root: bool,
    os_release: Option<OsRelease>,
    package_manager: Option<PackageManager>,
}

impl Default for NftablesInterceptionProbe {
    fn default() -> Self {
        Self {
            nft: find_nft_command(),
            running_as_root: is_root(),
            os_release: OsRelease::load(),
            package_manager: PackageManager::detect(),
        }
    }
}

pub(super) enum NftablesInterceptionProbeResult {
    Available { nft: PathBuf },
    Unavailable(CapabilityState),
}

impl NftablesInterceptionProbe {
    pub(super) fn resolve(&self) -> NftablesInterceptionProbeResult {
        if !cfg!(target_os = "linux") {
            return unavailable("transparent interception requires Linux");
        }

        let Some(nft) = self.nft.clone() else {
            return unavailable(missing_nft_reason(
                self.running_as_root,
                self.os_release.as_ref(),
                self.package_manager,
            ));
        };

        if !self.running_as_root {
            return unavailable(
                "transparent interception requires root to install nftables rules and host routing state",
            );
        }

        NftablesInterceptionProbeResult::Available { nft }
    }
}

fn unavailable(reason: impl Into<String>) -> NftablesInterceptionProbeResult {
    NftablesInterceptionProbeResult::Unavailable(CapabilityState::unavailable(
        CapabilityKind::TransparentInterception,
        reason,
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OsRelease {
    ids: Vec<String>,
}

impl OsRelease {
    fn load() -> Option<Self> {
        fs::read_to_string("/etc/os-release")
            .ok()
            .and_then(|content| Self::parse(&content))
    }

    fn parse(content: &str) -> Option<Self> {
        let mut ids = Vec::new();
        for line in content.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            if matches!(key, "ID" | "ID_LIKE") {
                ids.extend(parse_os_release_words(value));
            }
        }
        (!ids.is_empty()).then_some(Self { ids })
    }

    fn contains(&self, id: &str) -> bool {
        self.ids.iter().any(|candidate| candidate == id)
    }
}

fn missing_nft_reason(
    running_as_root: bool,
    os_release: Option<&OsRelease>,
    package_manager: Option<PackageManager>,
) -> String {
    let command = nftables_install_command(running_as_root, os_release, package_manager)
        .unwrap_or_else(|| "install the nftables package for this distribution".to_string());
    format!(
        "transparent interception requires nft at a trusted system path; install nftables with `{command}`"
    )
}

fn nftables_install_command(
    running_as_root: bool,
    os_release: Option<&OsRelease>,
    package_manager: Option<PackageManager>,
) -> Option<String> {
    let package_command = nftables_install_command_for_os(os_release)
        .or_else(|| package_manager.map(PackageManager::nftables_install_command))?;
    Some(if running_as_root {
        package_command.to_string()
    } else {
        format!("sudo {package_command}")
    })
}

fn nftables_install_command_for_os(os_release: Option<&OsRelease>) -> Option<&'static str> {
    Some(match os_release {
        Some(release) if release.contains("debian") || release.contains("ubuntu") => {
            "apt install nftables"
        }
        Some(release)
            if release.contains("fedora")
                || release.contains("rhel")
                || release.contains("rocky")
                || release.contains("almalinux")
                || release.contains("centos") =>
        {
            "dnf install nftables"
        }
        Some(release) if release.contains("arch") => "pacman -S nftables",
        Some(release) if release.contains("alpine") => "apk add nftables",
        _ => return None,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PackageManager {
    Apt,
    Dnf,
    Pacman,
    Apk,
}

impl PackageManager {
    fn detect() -> Option<Self> {
        [
            (Self::Apt, ["/usr/bin/apt", "/bin/apt"].as_slice()),
            (Self::Dnf, ["/usr/bin/dnf", "/bin/dnf"].as_slice()),
            (Self::Pacman, ["/usr/bin/pacman", "/bin/pacman"].as_slice()),
            (
                Self::Apk,
                ["/sbin/apk", "/usr/sbin/apk", "/bin/apk", "/usr/bin/apk"].as_slice(),
            ),
        ]
        .into_iter()
        .find_map(|(manager, paths)| {
            paths
                .iter()
                .any(|path| Path::new(path).is_file())
                .then_some(manager)
        })
    }

    fn nftables_install_command(self) -> &'static str {
        match self {
            Self::Apt => "apt install nftables",
            Self::Dnf => "dnf install nftables",
            Self::Pacman => "pacman -S nftables",
            Self::Apk => "apk add nftables",
        }
    }
}

fn parse_os_release_words(value: &str) -> impl Iterator<Item = String> + '_ {
    unquote_os_release_value(value)
        .split_whitespace()
        .map(|word| word.to_ascii_lowercase())
}

fn unquote_os_release_value(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .or_else(|| {
            value
                .strip_prefix('\'')
                .and_then(|value| value.strip_suffix('\''))
        })
        .unwrap_or(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_reports_missing_root_and_nft_reasons() {
        let missing_nft = unavailable_probe_reason(NftablesInterceptionProbe {
            nft: None,
            running_as_root: false,
            os_release: OsRelease::parse("ID=ubuntu\n"),
            package_manager: None,
        });
        assert!(missing_nft.contains("requires nft"));
        assert!(missing_nft.contains("sudo apt install nftables"));

        let missing_root = unavailable_probe_reason(NftablesInterceptionProbe {
            nft: Some(PathBuf::from("/not/executed")),
            running_as_root: false,
            os_release: None,
            package_manager: None,
        });
        assert!(missing_root.contains("requires root"));
    }

    #[test]
    fn missing_nft_hint_omits_sudo_when_running_as_root() {
        let missing_nft = unavailable_probe_reason(NftablesInterceptionProbe {
            nft: None,
            running_as_root: true,
            os_release: OsRelease::parse("ID_LIKE=\"rhel fedora\"\n"),
            package_manager: None,
        });

        assert!(missing_nft.contains("dnf install nftables"));
        assert!(!missing_nft.contains("sudo dnf"));
    }

    #[test]
    fn missing_nft_hint_supports_common_distributions() {
        assert_eq!(
            nftables_install_command(false, OsRelease::parse("ID=arch\n").as_ref(), None)
                .as_deref(),
            Some("sudo pacman -S nftables")
        );
        assert_eq!(
            nftables_install_command(false, OsRelease::parse("ID=alpine\n").as_ref(), None)
                .as_deref(),
            Some("sudo apk add nftables")
        );
        assert_eq!(
            nftables_install_command(false, OsRelease::parse("ID=unknown\n").as_ref(), None),
            None
        );
    }

    #[test]
    fn missing_nft_hint_falls_back_to_detected_package_manager() {
        for (manager, expected) in [
            (PackageManager::Apt, "sudo apt install nftables"),
            (PackageManager::Dnf, "sudo dnf install nftables"),
            (PackageManager::Pacman, "sudo pacman -S nftables"),
            (PackageManager::Apk, "sudo apk add nftables"),
        ] {
            assert_eq!(
                nftables_install_command(
                    false,
                    OsRelease::parse("ID=unknown\n").as_ref(),
                    Some(manager),
                )
                .as_deref(),
                Some(expected)
            );
        }
    }

    fn unavailable_probe_reason(probe: NftablesInterceptionProbe) -> String {
        match probe.resolve() {
            NftablesInterceptionProbeResult::Available { .. } => {
                panic!("probe should be unavailable")
            }
            NftablesInterceptionProbeResult::Unavailable(capability) => capability
                .reason
                .expect("unavailable transparent interception reason"),
        }
    }
}
