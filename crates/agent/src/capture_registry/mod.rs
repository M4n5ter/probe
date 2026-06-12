use std::path::PathBuf;

use capture::{
    AyaEbpfObjectProbe, EbpfHostProbe, EbpfHostProbeConfig, EbpfHostProbeReport,
    EbpfObjectProbeConfig, LibpcapConfig, LibpcapProvider,
};
use probe_config::{AgentConfig, CaptureBackend};
use runtime::{CaptureProviderBuilder, CaptureProviderDescriptor, ProviderRegistry};

pub fn default_provider_registry(config: &AgentConfig) -> ProviderRegistry {
    ProviderRegistry::with_default_platform(default_capture_provider_descriptors(config))
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

fn default_capture_provider_descriptors(config: &AgentConfig) -> Vec<CaptureProviderDescriptor> {
    vec![
        CaptureProviderDescriptor::available(
            CaptureBackend::Replay,
            CaptureProviderBuilder::Replay,
        ),
        ebpf_provider_descriptor(
            EbpfHostProbe::probe(&EbpfHostProbeConfig::default()),
            config.capture.ebpf.object_path.as_ref(),
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

    let object = AyaEbpfObjectProbe::probe(&EbpfObjectProbeConfig::new(object_path.clone()));
    if !object.object_available() {
        return CaptureProviderDescriptor::unavailable(
            CaptureBackend::Ebpf,
            CaptureProviderBuilder::Unimplemented,
            format!("Aya object preflight failed: {}", object.summary()),
        );
    }

    CaptureProviderDescriptor::unavailable(
        CaptureBackend::Ebpf,
        CaptureProviderBuilder::Unimplemented,
        format!(
            "Aya object preflight succeeded ({}) but capture program attach and event reader are not implemented",
            object.summary()
        ),
    )
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

    use capture::{EbpfProbeCheck, UnprivilegedBpfStatus};
    use probe_core::RuntimeMode;

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
        );

        assert_eq!(descriptor.backend, CaptureBackend::Ebpf);
        assert_eq!(descriptor.builder, CaptureProviderBuilder::Unimplemented);
        assert_eq!(descriptor.mode, RuntimeMode::Unavailable);
        let reason = descriptor
            .reason
            .expect("eBPF descriptor should explain why it is unavailable");
        assert!(reason.contains("Aya object preflight failed"));
        assert!(reason.contains("failed to parse eBPF object"));
        fs::remove_dir_all(temp)?;
        Ok(())
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
