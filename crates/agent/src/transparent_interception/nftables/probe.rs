use std::path::PathBuf;

use probe_core::{CapabilityKind, CapabilityState};

use super::command::{find_ip_command, find_nft_command, is_root};

pub(super) struct NftablesInterceptionProbe {
    nft: Option<PathBuf>,
    ip: Option<PathBuf>,
    running_as_root: bool,
}

impl Default for NftablesInterceptionProbe {
    fn default() -> Self {
        Self {
            nft: find_nft_command(),
            ip: find_ip_command(),
            running_as_root: is_root(),
        }
    }
}

pub(super) enum NftablesInterceptionProbeResult {
    Available { nft: PathBuf, ip: Option<PathBuf> },
    Unavailable(CapabilityState),
}

impl NftablesInterceptionProbe {
    pub(super) fn resolve(&self) -> NftablesInterceptionProbeResult {
        if !cfg!(target_os = "linux") {
            return unavailable("transparent interception requires Linux");
        }

        let Some(nft) = self.nft.clone() else {
            return unavailable("transparent interception requires nft at a trusted system path");
        };

        if !self.running_as_root {
            return unavailable(
                "transparent interception requires root to install nftables rules and host routing state",
            );
        }

        let Some(ip) = self.ip.clone() else {
            return unavailable(
                "transparent interception requires ip at a trusted system path for host routing state",
            );
        };
        let ip = Some(ip);

        NftablesInterceptionProbeResult::Available { nft, ip }
    }
}

fn unavailable(reason: impl Into<String>) -> NftablesInterceptionProbeResult {
    NftablesInterceptionProbeResult::Unavailable(CapabilityState::unavailable(
        CapabilityKind::TransparentInterception,
        reason,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_reports_missing_root_nft_and_ip_reasons() {
        let missing_nft = unavailable_probe_reason(NftablesInterceptionProbe {
            nft: None,
            ip: Some(PathBuf::from("/not/executed")),
            running_as_root: true,
        });
        assert!(missing_nft.contains("requires nft"));

        let missing_root = unavailable_probe_reason(NftablesInterceptionProbe {
            nft: Some(PathBuf::from("/not/executed")),
            ip: Some(PathBuf::from("/not/executed")),
            running_as_root: false,
        });
        assert!(missing_root.contains("requires root"));

        let missing_ip = unavailable_probe_reason(NftablesInterceptionProbe {
            nft: Some(PathBuf::from("/not/executed")),
            ip: None,
            running_as_root: true,
        });
        assert!(missing_ip.contains("requires ip"));
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
