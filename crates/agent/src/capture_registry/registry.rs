use std::path::PathBuf;

use capture::{
    EbpfHostProbe, EbpfHostProbeConfig, EbpfHostProbeReport, LibpcapConfig, LibpcapProvider,
};
use ebpf_object::{EbpfObjectProbe, EbpfObjectProbeConfig, EbpfObjectProbeReport};
use probe_config::{AgentConfig, CaptureBackend};
use probe_core::{CapabilityKind, CapabilityState, RuntimeMode};
use runtime::{
    CaptureProviderBuilder, CaptureProviderDescriptor, PlatformProbeResults, ProviderRegistry,
};

pub fn default_provider_registry(
    config: &AgentConfig,
    connection_enforcement_capability: CapabilityState,
) -> ProviderRegistry {
    let procfs_socket_capabilities = attribution::ProcfsSocketResolver::new().capabilities();
    let procfs_socket_attribution =
        procfs_socket_attribution_capability(&procfs_socket_capabilities);
    ProviderRegistry::with_platform_probes(
        default_capture_provider_descriptors(config, procfs_socket_attribution),
        PlatformProbeResults::new(
            procfs_socket_capabilities,
            connection_enforcement_capability,
        ),
    )
}

pub fn libpcap_config_from_agent(config: &AgentConfig) -> LibpcapConfig {
    LibpcapConfig {
        interface: config.capture.libpcap.interface.clone(),
        bpf_filter: config.capture.libpcap.bpf_filter.clone(),
        snaplen: config.capture.libpcap.snaplen,
        promisc: config.capture.libpcap.promisc,
        immediate_mode: config.capture.libpcap.immediate_mode,
        read_timeout_ms: config.capture.libpcap.read_timeout_ms,
        buffer_size: config.capture.libpcap.buffer_size,
    }
}

fn default_capture_provider_descriptors(
    config: &AgentConfig,
    procfs_socket_attribution: CapabilityState,
) -> Vec<CaptureProviderDescriptor> {
    vec![
        CaptureProviderDescriptor::available(
            CaptureBackend::Replay,
            CaptureProviderBuilder::Replay,
        ),
        ebpf_provider_descriptor(
            EbpfHostProbe::probe(&EbpfHostProbeConfig::default()),
            config.capture.ebpf.object_path.as_ref(),
            procfs_socket_attribution,
        ),
        CaptureProviderDescriptor::available(
            CaptureBackend::PlaintextFeed,
            CaptureProviderBuilder::PlaintextFeed,
        ),
        libpcap_provider_descriptor(&libpcap_config_from_agent(config)),
    ]
}

fn ebpf_provider_descriptor(
    host: EbpfHostProbeReport,
    object_path: Option<&PathBuf>,
    procfs_socket_attribution: CapabilityState,
) -> CaptureProviderDescriptor {
    if !host.kernel_prerequisites_available() {
        return CaptureProviderDescriptor::unavailable(
            CaptureBackend::Ebpf,
            CaptureProviderBuilder::Unimplemented,
            format!("host prerequisites are not available: {}", host.summary()),
        );
    }

    let Some(object_path) = object_path else {
        return CaptureProviderDescriptor::unavailable(
            CaptureBackend::Ebpf,
            CaptureProviderBuilder::Unimplemented,
            format!(
                "capture.ebpf.object_path is not configured; host probe: {}",
                host.summary()
            ),
        );
    };

    let object = EbpfObjectProbe::probe(&EbpfObjectProbeConfig::process_observation(
        object_path.clone(),
    ));
    ebpf_provider_descriptor_from_object_report(object, procfs_socket_attribution)
}

fn ebpf_provider_descriptor_from_object_report(
    object: EbpfObjectProbeReport,
    procfs_socket_attribution: CapabilityState,
) -> CaptureProviderDescriptor {
    if !object.object_available() {
        return CaptureProviderDescriptor::unavailable(
            CaptureBackend::Ebpf,
            CaptureProviderBuilder::Unimplemented,
            format!(
                "eBPF object preflight via aya-obj failed: {}",
                object.summary()
            ),
        );
    }
    if !object.preflight_available() {
        return CaptureProviderDescriptor::unavailable(
            CaptureBackend::Ebpf,
            CaptureProviderBuilder::Unimplemented,
            format!(
                "eBPF object contract preflight via aya-obj failed: {}",
                object.summary()
            ),
        );
    }
    if procfs_socket_attribution.mode == RuntimeMode::Unavailable {
        return CaptureProviderDescriptor::unavailable(
            CaptureBackend::Ebpf,
            CaptureProviderBuilder::Ebpf,
            format!(
                "eBPF connect/close observation provider requires procfs_socket_attribution, but {}",
                procfs_socket_attribution
                    .reason
                    .as_deref()
                    .unwrap_or("procfs socket attribution is unavailable")
            ),
        );
    }

    CaptureProviderDescriptor::degraded(
        CaptureBackend::Ebpf,
        CaptureProviderBuilder::Ebpf,
        format!(
            "eBPF object preflight via aya-obj succeeded ({}), procfs socket attribution is usable, and the connect/close observation provider can emit connect observations and best-effort descriptor-close lifecycle events, but payload/lost-event conversion and complete kernel traffic capture are not implemented",
            object.summary(),
        ),
    )
    .allow_explicit_degraded()
}

fn procfs_socket_attribution_capability(capabilities: &[CapabilityState]) -> CapabilityState {
    capabilities
        .iter()
        .find(|state| state.kind == CapabilityKind::ProcfsSocketAttribution)
        .cloned()
        .unwrap_or_else(|| {
            CapabilityState::unavailable(
                CapabilityKind::ProcfsSocketAttribution,
                "procfs socket attribution probe returned no capability state",
            )
        })
}

fn libpcap_provider_descriptor(config: &LibpcapConfig) -> CaptureProviderDescriptor {
    match LibpcapProvider::probe(config) {
        Ok(()) => CaptureProviderDescriptor::available(
            CaptureBackend::Libpcap,
            CaptureProviderBuilder::Libpcap,
        ),
        Err(error) => CaptureProviderDescriptor::unavailable(
            CaptureBackend::Libpcap,
            CaptureProviderBuilder::Libpcap,
            error.to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use capture::UnprivilegedBpfStatus;
    use ebpf_object::{
        EbpfObjectContractCheck, EbpfObjectContractReport, EbpfObjectMap, EbpfObjectProbeReport,
        EbpfObjectProgram, EbpfProbeCheck,
    };
    use probe_core::{CapabilityKind, CapabilityState, RuntimeMode};

    use super::*;

    #[test]
    fn ebpf_provider_descriptor_keeps_host_probe_reason() {
        let descriptor = ebpf_provider_descriptor(
            EbpfHostProbeReport {
                linux: true,
                btf_vmlinux: EbpfProbeCheck::Available,
                bpffs: EbpfProbeCheck::Unavailable {
                    reason: "bpffs path /sys/fs/bpf does not exist".to_string(),
                },
                unprivileged_bpf: UnprivilegedBpfStatus::Disabled,
            },
            None,
            procfs_socket_attribution_capability_for_test(RuntimeMode::Degraded),
        );

        assert_eq!(descriptor.backend, CaptureBackend::Ebpf);
        assert_eq!(descriptor.builder, CaptureProviderBuilder::Unimplemented);
        assert_eq!(descriptor.mode, RuntimeMode::Unavailable);
        let reason = descriptor
            .reason
            .expect("eBPF descriptor should explain why it is unavailable");
        assert!(reason.contains("host prerequisites are not available"));
        assert!(reason.contains("btf_vmlinux=available"));
        assert!(reason.contains("bpffs path /sys/fs/bpf does not exist"));
        assert!(reason.contains("unprivileged_bpf=disabled"));
    }

    #[test]
    fn ebpf_provider_descriptor_requires_object_path_after_host_probe_passes() {
        let descriptor = ebpf_provider_descriptor(
            EbpfHostProbeReport {
                linux: true,
                btf_vmlinux: EbpfProbeCheck::Available,
                bpffs: EbpfProbeCheck::Available,
                unprivileged_bpf: UnprivilegedBpfStatus::Disabled,
            },
            None,
            procfs_socket_attribution_capability_for_test(RuntimeMode::Degraded),
        );

        assert_eq!(descriptor.backend, CaptureBackend::Ebpf);
        assert_eq!(descriptor.builder, CaptureProviderBuilder::Unimplemented);
        assert_eq!(descriptor.mode, RuntimeMode::Unavailable);
        let reason = descriptor
            .reason
            .expect("eBPF descriptor should explain why it is unavailable");
        assert!(reason.contains("capture.ebpf.object_path is not configured"));
        assert!(reason.contains("btf_vmlinux=available"));
        assert!(reason.contains("bpffs=available"));
    }

    #[test]
    fn ebpf_provider_descriptor_reports_invalid_aya_object()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("invalid-ebpf-object")?;
        let object = temp.join("invalid.bpf.o");
        fs::write(&object, b"not an elf object")?;
        let descriptor = ebpf_provider_descriptor(
            EbpfHostProbeReport {
                linux: true,
                btf_vmlinux: EbpfProbeCheck::Available,
                bpffs: EbpfProbeCheck::Available,
                unprivileged_bpf: UnprivilegedBpfStatus::Disabled,
            },
            Some(&object),
            procfs_socket_attribution_capability_for_test(RuntimeMode::Degraded),
        );

        assert_eq!(descriptor.backend, CaptureBackend::Ebpf);
        assert_eq!(descriptor.builder, CaptureProviderBuilder::Unimplemented);
        assert_eq!(descriptor.mode, RuntimeMode::Unavailable);
        let reason = descriptor
            .reason
            .expect("eBPF descriptor should explain why it is unavailable");
        assert!(reason.contains("eBPF object preflight via aya-obj failed"));
        assert!(reason.contains("failed to parse eBPF object"));
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn ebpf_provider_descriptor_reports_contract_preflight_failure() {
        let descriptor = ebpf_provider_descriptor_from_object_report(
            EbpfObjectProbeReport {
                object_path: PathBuf::from("/tmp/sssa-invalid-contract.bpf.o"),
                object: EbpfProbeCheck::Available,
                contract: EbpfObjectContractReport {
                    status: EbpfProbeCheck::Available,
                    maps: vec![EbpfObjectContractCheck {
                        name: "SSSA_EVENTS".to_string(),
                        check: EbpfProbeCheck::unavailable("missing eBPF map SSSA_EVENTS"),
                    }],
                    programs: Vec::new(),
                },
                programs: Vec::<EbpfObjectProgram>::new(),
                maps: Vec::<EbpfObjectMap>::new(),
            },
            procfs_socket_attribution_capability_for_test(RuntimeMode::Degraded),
        );

        assert_eq!(descriptor.backend, CaptureBackend::Ebpf);
        assert_eq!(descriptor.builder, CaptureProviderBuilder::Unimplemented);
        assert_eq!(descriptor.mode, RuntimeMode::Unavailable);
        let reason = descriptor
            .reason
            .expect("eBPF descriptor should explain why contract preflight failed");
        assert!(reason.contains("eBPF object contract preflight via aya-obj failed"));
        assert!(reason.contains("missing eBPF map SSSA_EVENTS"));
    }

    #[test]
    fn ebpf_provider_descriptor_exposes_degraded_observation_provider_after_object_preflight() {
        let descriptor = ebpf_provider_descriptor_from_object_report(
            EbpfObjectProbeReport {
                object_path: PathBuf::from("/tmp/sssa-valid-contract.bpf.o"),
                object: EbpfProbeCheck::Available,
                contract: EbpfObjectContractReport {
                    status: EbpfProbeCheck::Available,
                    maps: vec![EbpfObjectContractCheck {
                        name: "SSSA_EVENTS".to_string(),
                        check: EbpfProbeCheck::Available,
                    }],
                    programs: available_ebpf_lifecycle_program_checks(),
                },
                programs: Vec::<EbpfObjectProgram>::new(),
                maps: Vec::<EbpfObjectMap>::new(),
            },
            procfs_socket_attribution_capability_for_test(RuntimeMode::Degraded),
        );

        assert_eq!(descriptor.backend, CaptureBackend::Ebpf);
        assert_eq!(descriptor.builder, CaptureProviderBuilder::Ebpf);
        assert_eq!(descriptor.mode, RuntimeMode::Degraded);
        let reason = descriptor
            .reason
            .expect("eBPF descriptor should explain why capture provider is degraded");
        assert!(reason.contains("complete kernel traffic capture"));
        assert!(reason.contains("payload/lost-event conversion"));
        assert!(reason.contains("best-effort descriptor-close lifecycle events"));
        assert!(reason.contains("connect/close observation provider"));
        assert!(reason.contains("procfs socket attribution is usable"));
    }

    #[test]
    fn ebpf_provider_descriptor_requires_procfs_socket_attribution_after_object_preflight() {
        let descriptor = ebpf_provider_descriptor_from_object_report(
            EbpfObjectProbeReport {
                object_path: PathBuf::from("/tmp/sssa-valid-contract.bpf.o"),
                object: EbpfProbeCheck::Available,
                contract: EbpfObjectContractReport {
                    status: EbpfProbeCheck::Available,
                    maps: vec![EbpfObjectContractCheck {
                        name: "SSSA_EVENTS".to_string(),
                        check: EbpfProbeCheck::Available,
                    }],
                    programs: available_ebpf_lifecycle_program_checks(),
                },
                programs: Vec::<EbpfObjectProgram>::new(),
                maps: Vec::<EbpfObjectMap>::new(),
            },
            procfs_socket_attribution_capability_for_test(RuntimeMode::Unavailable),
        );

        assert_eq!(descriptor.backend, CaptureBackend::Ebpf);
        assert_eq!(descriptor.builder, CaptureProviderBuilder::Ebpf);
        assert_eq!(descriptor.mode, RuntimeMode::Unavailable);
        let reason = descriptor
            .reason
            .expect("eBPF descriptor should explain missing procfs socket attribution");
        assert!(reason.contains("requires procfs_socket_attribution"));
        assert!(reason.contains("unavailable"));
    }

    #[test]
    fn default_registry_keeps_connection_enforcement_unavailable_without_backend() {
        let registry = default_provider_registry(
            &AgentConfig::default(),
            CapabilityState::unavailable(
                CapabilityKind::ConnectionEnforcement,
                "connection-level enforcement backend is not configured",
            ),
        );
        let capabilities = registry.capability_matrix();

        assert_eq!(
            capabilities.mode(CapabilityKind::ConnectionEnforcement),
            RuntimeMode::Unavailable
        );
    }

    fn procfs_socket_attribution_capability_for_test(mode: RuntimeMode) -> CapabilityState {
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

    fn available_ebpf_lifecycle_program_checks() -> Vec<EbpfObjectContractCheck> {
        vec![
            EbpfObjectContractCheck {
                name: "sssa_sys_enter_connect".to_string(),
                check: EbpfProbeCheck::Available,
            },
            EbpfObjectContractCheck {
                name: "sssa_sys_enter_close".to_string(),
                check: EbpfProbeCheck::Available,
            },
        ]
    }

    fn test_dir(name: &str) -> Result<PathBuf, std::io::Error> {
        let wall_time_unix_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        let path = std::env::temp_dir().join(format!(
            "sssa-probe-capture-registry-{name}-{}-{wall_time_unix_ns}",
            std::process::id()
        ));
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
        fs::create_dir_all(&path)?;
        Ok(path)
    }
}
