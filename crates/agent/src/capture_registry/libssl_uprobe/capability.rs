use capture::EbpfHostProbeReport;
use ebpf_object::{EbpfObjectArtifact, EbpfObjectProbe, EbpfObjectProbeReport};
use probe_config::{AgentConfig, TlsPlaintextProvider};
use probe_core::{CapabilityKind, CapabilityState, RuntimeMode};

pub(in crate::capture_registry) fn capability(
    config: &AgentConfig,
    host: &EbpfHostProbeReport,
    procfs_socket_attribution: &CapabilityState,
) -> CapabilityState {
    if config.tls.plaintext.provider != TlsPlaintextProvider::LibsslUprobe {
        return CapabilityState::unavailable(
            CapabilityKind::LibsslUprobe,
            "libssl_uprobe plaintext provider is not selected",
        );
    }
    if !host.kernel_prerequisites_available() {
        return CapabilityState::unavailable(
            CapabilityKind::LibsslUprobe,
            format!(
                "libssl uprobe requires eBPF host prerequisites: {}",
                host.summary()
            ),
        );
    }
    let Some(object_path) = config.tls.plaintext.libssl_uprobe_object_path.as_ref() else {
        return CapabilityState::unavailable(
            CapabilityKind::LibsslUprobe,
            format!(
                "tls.plaintext.libssl_uprobe_object_path is not configured; host probe: {}",
                host.summary()
            ),
        );
    };
    let object =
        EbpfObjectProbe::probe(&EbpfObjectArtifact::TlsPlaintext.probe_config(object_path));
    capability_from_object_report(object, procfs_socket_attribution)
}

fn capability_from_object_report(
    object: EbpfObjectProbeReport,
    procfs_socket_attribution: &CapabilityState,
) -> CapabilityState {
    if !object.object_available() {
        return CapabilityState::unavailable(
            CapabilityKind::LibsslUprobe,
            format!(
                "eBPF TLS plaintext object preflight via aya-obj failed: {}",
                object.summary()
            ),
        );
    }
    if !object.preflight_available() {
        return CapabilityState::unavailable(
            CapabilityKind::LibsslUprobe,
            format!(
                "eBPF TLS plaintext object contract preflight via aya-obj failed: {}",
                object.summary()
            ),
        );
    }
    if procfs_socket_attribution.mode == RuntimeMode::Unavailable {
        return CapabilityState::unavailable(
            CapabilityKind::LibsslUprobe,
            format!(
                "libssl uprobe plaintext provider requires procfs_socket_attribution for fd-to-flow resolution, but {}",
                procfs_socket_attribution
                    .reason
                    .as_deref()
                    .unwrap_or("procfs socket attribution is unavailable")
            ),
        );
    }
    CapabilityState::degraded(
        CapabilityKind::LibsslUprobe,
        format!(
            "eBPF TLS plaintext object preflight via aya-obj succeeded ({}), procfs socket attribution is usable, and the capture loader exists, but agent dynamic attach lifecycle and flow resolver runtime wiring are not implemented",
            object.summary()
        ),
    )
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use capture::UnprivilegedBpfStatus;
    use ebpf_object::{EbpfObjectContractReport, EbpfObjectMap, EbpfObjectProgram, EbpfProbeCheck};
    use probe_core::{CapabilityKind, CapabilityState, RuntimeMode};

    use super::*;

    #[test]
    fn capability_requires_tls_object_path_after_host_probe_passes() {
        let capability = capability(
            &AgentConfig::default(),
            &available_ebpf_host_report(),
            &procfs_socket_attribution_capability(RuntimeMode::Degraded),
        );

        assert_eq!(capability.kind, CapabilityKind::LibsslUprobe);
        assert_eq!(capability.mode, RuntimeMode::Unavailable);
        let reason = capability
            .reason
            .expect("missing TLS object path must explain the unavailable capability");
        assert!(reason.contains("tls.plaintext.libssl_uprobe_object_path is not configured"));
        assert!(reason.contains("btf_vmlinux=available"));
        assert!(reason.contains("bpffs=available"));
    }

    #[test]
    fn capability_reports_invalid_tls_object() -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("invalid-tls-object")?;
        let object = temp.join("invalid-tls.bpf.o");
        fs::write(&object, b"not an elf object")?;
        let mut config = AgentConfig::default();
        config.tls.plaintext.libssl_uprobe_object_path = Some(object);

        let capability = capability(
            &config,
            &available_ebpf_host_report(),
            &procfs_socket_attribution_capability(RuntimeMode::Degraded),
        );

        assert_eq!(capability.kind, CapabilityKind::LibsslUprobe);
        assert_eq!(capability.mode, RuntimeMode::Unavailable);
        let reason = capability
            .reason
            .expect("invalid TLS object must explain the unavailable capability");
        assert!(reason.contains("eBPF TLS plaintext object preflight via aya-obj failed"));
        assert!(reason.contains("failed to parse eBPF object"));
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn capability_stays_degraded_until_runtime_wiring_exists() {
        let capability = capability_from_object_report(
            available_tls_plaintext_object_report(),
            &procfs_socket_attribution_capability(RuntimeMode::Degraded),
        );

        assert_eq!(capability.kind, CapabilityKind::LibsslUprobe);
        assert_eq!(capability.mode, RuntimeMode::Degraded);
        let reason = capability
            .reason
            .expect("degraded TLS capability must explain the remaining runtime gap");
        assert!(reason.contains("eBPF TLS plaintext object preflight via aya-obj succeeded"));
        assert!(reason.contains("procfs socket attribution is usable"));
        assert!(reason.contains("dynamic attach lifecycle"));
        assert!(reason.contains("flow resolver runtime wiring"));
    }

    #[test]
    fn capability_requires_procfs_socket_attribution_after_tls_object_preflight() {
        let capability = capability_from_object_report(
            available_tls_plaintext_object_report(),
            &procfs_socket_attribution_capability(RuntimeMode::Unavailable),
        );

        assert_eq!(capability.kind, CapabilityKind::LibsslUprobe);
        assert_eq!(capability.mode, RuntimeMode::Unavailable);
        let reason = capability
            .reason
            .expect("missing procfs socket attribution must be reported");
        assert!(reason.contains("requires procfs_socket_attribution"));
        assert!(reason.contains("unavailable"));
    }

    fn procfs_socket_attribution_capability(mode: RuntimeMode) -> CapabilityState {
        match mode {
            RuntimeMode::Available => {
                CapabilityState::available(CapabilityKind::ProcfsSocketAttribution)
            }
            RuntimeMode::Degraded => CapabilityState::degraded(
                CapabilityKind::ProcfsSocketAttribution,
                "procfs socket attribution is degraded but usable",
            ),
            RuntimeMode::Unavailable => CapabilityState::unavailable(
                CapabilityKind::ProcfsSocketAttribution,
                "procfs socket attribution is unavailable",
            ),
        }
    }

    fn available_ebpf_host_report() -> EbpfHostProbeReport {
        EbpfHostProbeReport {
            linux: true,
            btf_vmlinux: EbpfProbeCheck::Available,
            bpffs: EbpfProbeCheck::Available,
            unprivileged_bpf: UnprivilegedBpfStatus::Disabled,
        }
    }

    fn available_tls_plaintext_object_report() -> EbpfObjectProbeReport {
        EbpfObjectProbeReport {
            object_path: PathBuf::from("/tmp/sssa-tls-plaintext.bpf.o"),
            object: EbpfProbeCheck::Available,
            contract: EbpfObjectContractReport {
                status: EbpfProbeCheck::Available,
                maps: Vec::new(),
                programs: Vec::new(),
            },
            programs: Vec::<EbpfObjectProgram>::new(),
            maps: Vec::<EbpfObjectMap>::new(),
        }
    }

    fn test_dir(name: &str) -> Result<PathBuf, std::io::Error> {
        let wall_time_unix_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        let path = std::env::temp_dir().join(format!(
            "sssa-probe-libssl-uprobe-capability-{name}-{}-{wall_time_unix_ns}",
            std::process::id()
        ));
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
        fs::create_dir_all(&path)?;
        Ok(path)
    }
}
