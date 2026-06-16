use super::{
    inventory::object_inventory,
    model::{
        EbpfObjectContractReport, EbpfObjectProbeConfig, EbpfObjectProbeReport,
        EbpfPreflightedObject, EbpfProbeCheck,
    },
    reader::read_ebpf_object_bytes,
};

pub struct EbpfObjectProbe;

impl EbpfObjectProbe {
    pub fn probe(config: &EbpfObjectProbeConfig) -> EbpfObjectProbeReport {
        Self::inspect(config).into_report()
    }

    pub fn preflight(
        config: &EbpfObjectProbeConfig,
    ) -> Result<EbpfPreflightedObject, Box<EbpfObjectProbeReport>> {
        match Self::inspect(config) {
            EbpfObjectInspection::Parsed { report, bytes } if report.preflight_available() => {
                Ok(EbpfPreflightedObject { report, bytes })
            }
            inspection => Err(Box::new(inspection.into_report())),
        }
    }

    fn inspect(config: &EbpfObjectProbeConfig) -> EbpfObjectInspection {
        let object_path = config.object_path.clone();
        match read_ebpf_object_bytes(&object_path).and_then(|bytes| {
            let (programs, maps) = object_inventory(&bytes)?;
            Ok((bytes, programs, maps))
        }) {
            Ok((bytes, programs, maps)) => {
                let contract =
                    EbpfObjectContractReport::from_inventory(&config.contract, &programs, &maps);
                EbpfObjectInspection::Parsed {
                    report: EbpfObjectProbeReport {
                        object_path,
                        object: EbpfProbeCheck::available(),
                        contract,
                        programs,
                        maps,
                    },
                    bytes,
                }
            }
            Err(error) => EbpfObjectInspection::Unavailable {
                report: EbpfObjectProbeReport {
                    object_path,
                    contract: EbpfObjectContractReport::unavailable(
                        "object inventory could not be built; expected eBPF contract could not be checked",
                    ),
                    object: EbpfProbeCheck::unavailable(error),
                    programs: Vec::new(),
                    maps: Vec::new(),
                },
            },
        }
    }
}

enum EbpfObjectInspection {
    Parsed {
        report: EbpfObjectProbeReport,
        bytes: Vec<u8>,
    },
    Unavailable {
        report: EbpfObjectProbeReport,
    },
}

impl EbpfObjectInspection {
    fn into_report(self) -> EbpfObjectProbeReport {
        match self {
            Self::Parsed { report, .. } | Self::Unavailable { report } => report,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use ebpf_abi::{
        EBPF_PROCESS_MAP_SPECS, EBPF_PROCESS_TRACEPOINT_SPECS, EBPF_TLS_EVENT_SCRATCH_MAP_NAME,
        EBPF_TLS_SSL_CLEAR_EXIT_PROGRAM_NAME, EBPF_TLS_SSL_SET_FD_PROGRAM_NAME,
    };
    use tempfile::tempdir;

    use super::super::{
        model::{
            EbpfObjectArtifact, EbpfObjectContract, EbpfObjectMapKind, EbpfObjectProbeConfig,
            EbpfObjectProgramKind,
        },
        object_fixture::{write_process_probe_ebpf_object, write_tls_plaintext_probe_ebpf_object},
        reader::MAX_EBPF_OBJECT_BYTES,
    };
    use super::*;

    #[test]
    fn object_probe_reports_missing_object() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let config = process_scaffold_config(temp.path().join("missing.bpf.o"));

        let report = EbpfObjectProbe::probe(&config);

        assert!(!report.object_available());
        assert!(!report.preflight_available());
        assert!(report.summary().contains("does not exist"));
        assert!(report.programs.is_empty());
        assert!(report.maps.is_empty());
        assert!(!report.contract.is_available());
        Ok(())
    }

    #[test]
    fn object_probe_reports_invalid_object() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let object = temp.path().join("invalid.bpf.o");
        fs::write(&object, b"not an elf object")?;
        let config = process_scaffold_config(object);

        let report = EbpfObjectProbe::probe(&config);

        assert!(!report.object_available());
        assert!(!report.preflight_available());
        assert!(report.summary().contains("failed to parse eBPF object"));
        assert!(report.programs.is_empty());
        assert!(report.maps.is_empty());
        assert!(!report.contract.is_available());
        Ok(())
    }

    #[test]
    fn object_probe_rejects_oversized_object_before_parse() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = tempdir()?;
        let object = temp.path().join("oversized.bpf.o");
        fs::File::create(&object)?.set_len(MAX_EBPF_OBJECT_BYTES + 1)?;
        let config = process_scaffold_config(object);

        let report = EbpfObjectProbe::probe(&config);

        assert!(!report.object_available());
        assert!(!report.preflight_available());
        assert!(report.summary().contains("too large"));
        assert!(report.programs.is_empty());
        assert!(report.maps.is_empty());
        assert!(!report.contract.is_available());
        Ok(())
    }

    #[test]
    fn object_probe_accepts_generated_scaffold_object() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let object = temp.path().join("scaffold.bpf.o");
        write_process_probe_ebpf_object(&object, None, EbpfObjectMapKind::Ringbuf)?;
        let config = EbpfObjectProbeConfig::process_observation(&object);

        let report = EbpfObjectProbe::probe(&config);

        assert!(report.object_available(), "{}", report.summary());
        assert!(report.preflight_available(), "{}", report.summary());
        assert_eq!(report.maps.len(), EBPF_PROCESS_MAP_SPECS.len());
        for expected in EBPF_PROCESS_MAP_SPECS {
            assert!(
                report.maps.iter().any(|map| {
                    map.name == expected.name && map.kind == EbpfObjectMapKind::from(expected.kind)
                }),
                "missing map {} in {:?}",
                expected.name,
                report.maps
            );
        }
        assert_eq!(report.programs.len(), EBPF_PROCESS_TRACEPOINT_SPECS.len());
        for expected in EBPF_PROCESS_TRACEPOINT_SPECS {
            let expected_section = expected.section_name().to_string();
            assert!(
                report.programs.iter().any(|program| {
                    program.name == expected.program_name
                        && program.section.as_deref() == Some(expected_section.as_str())
                }),
                "missing program {} in {:?}",
                expected.program_name,
                report.programs
            );
        }
        Ok(())
    }

    #[test]
    fn object_probe_accepts_generated_tls_plaintext_object()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let object = temp.path().join("tls-plaintext.bpf.o");
        write_tls_plaintext_probe_ebpf_object(&object)?;
        let config = EbpfObjectArtifact::TlsPlaintext.probe_config(&object);

        let report = EbpfObjectProbe::probe(&config);

        assert!(report.object_available(), "{}", report.summary());
        assert!(report.preflight_available(), "{}", report.summary());
        assert_eq!(report.maps.len(), 5);
        assert_eq!(report.programs.len(), 13);
        assert!(
            report.maps.iter().any(|map| {
                map.name == EBPF_TLS_EVENT_SCRATCH_MAP_NAME
                    && map.kind == EbpfObjectMapKind::PerCpuArray
            }),
            "{:?}",
            report.maps
        );
        assert!(
            report.programs.iter().any(|program| {
                program.name == EBPF_TLS_SSL_SET_FD_PROGRAM_NAME
                    && program.kind == EbpfObjectProgramKind::Uprobe
            }),
            "{:?}",
            report.programs
        );
        assert!(
            report.programs.iter().any(|program| {
                program.name == EBPF_TLS_SSL_CLEAR_EXIT_PROGRAM_NAME
                    && program.kind == EbpfObjectProgramKind::Uretprobe
            }),
            "{:?}",
            report.programs
        );
        Ok(())
    }

    #[test]
    fn process_observation_config_rejects_tls_plaintext_object()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let object = temp.path().join("tls-plaintext.bpf.o");
        write_tls_plaintext_probe_ebpf_object(&object)?;
        let config = EbpfObjectProbeConfig::process_observation(&object);

        let report = EbpfObjectProbe::probe(&config);

        assert!(report.object_available(), "{}", report.summary());
        assert!(!report.preflight_available());
        assert!(report.summary().contains("unexpected eBPF map"));
        assert!(report.summary().contains("unexpected eBPF program"));
        Ok(())
    }

    #[test]
    fn preflight_returns_same_hardened_object_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let object = temp.path().join("preflighted-scaffold.bpf.o");
        write_process_probe_ebpf_object(&object, None, EbpfObjectMapKind::Ringbuf)?;
        let config = EbpfObjectProbeConfig::process_observation(&object);

        let preflighted = EbpfObjectProbe::preflight(&config)
            .expect("generated scaffold object should pass contract preflight");

        assert!(preflighted.report.preflight_available());
        assert_eq!(preflighted.bytes(), fs::read(&object)?.as_slice());
        Ok(())
    }

    #[test]
    fn preflight_returns_report_for_contract_failure() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        for spec in EBPF_PROCESS_TRACEPOINT_SPECS {
            let object = temp
                .path()
                .join(format!("invalid-{:?}-contract.bpf.o", spec.role));
            let wrong_section = format!(
                "tracepoint/{}/wrong_{}",
                spec.category, spec.tracepoint_name
            );
            let expected_section = spec.section_name().to_string();
            write_process_probe_ebpf_object(
                &object,
                Some((spec.role, wrong_section.as_str())),
                EbpfObjectMapKind::Ringbuf,
            )?;
            let config = process_scaffold_config(&object);

            let report = EbpfObjectProbe::preflight(&config)
                .expect_err("wrong tracepoint section should fail contract preflight");

            assert!(report.object_available());
            assert!(!report.preflight_available());
            assert!(report.summary().contains(expected_section.as_str()));
        }
        Ok(())
    }

    #[test]
    fn object_probe_rejects_generated_object_with_wrong_section()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        for spec in EBPF_PROCESS_TRACEPOINT_SPECS {
            let object = temp
                .path()
                .join(format!("wrong-{:?}-section.bpf.o", spec.role));
            let wrong_section = format!(
                "tracepoint/{}/wrong_{}",
                spec.category, spec.tracepoint_name
            );
            let expected_section = spec.section_name().to_string();
            write_process_probe_ebpf_object(
                &object,
                Some((spec.role, wrong_section.as_str())),
                EbpfObjectMapKind::Ringbuf,
            )?;
            let config = process_scaffold_config(&object);

            let report = EbpfObjectProbe::probe(&config);

            assert!(report.object_available(), "{}", report.summary());
            assert!(!report.preflight_available());
            assert!(report.summary().contains(expected_section.as_str()));
        }
        Ok(())
    }

    fn process_scaffold_config(
        object_path: impl Into<std::path::PathBuf>,
    ) -> EbpfObjectProbeConfig {
        EbpfObjectProbeConfig::with_contract(
            object_path,
            EbpfObjectContract::process_probe_scaffold(),
        )
    }
}
