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

    use ebpf_abi::{EBPF_CONNECT_PROGRAM_NAME, EBPF_EVENTS_MAP_NAME};
    use tempfile::tempdir;

    use super::super::{
        contract::expected_tracepoint_section,
        model::{EbpfObjectMapKind, EbpfObjectProbeConfig},
        reader::MAX_EBPF_OBJECT_BYTES,
        test_support::write_minimal_ebpf_object,
    };
    use super::*;

    #[test]
    fn object_probe_reports_missing_object() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let config = EbpfObjectProbeConfig::new(temp.path().join("missing.bpf.o"));

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
        let config = EbpfObjectProbeConfig::new(object);

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
        let config = EbpfObjectProbeConfig::new(object);

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
        write_minimal_ebpf_object(
            &object,
            &expected_tracepoint_section(),
            EbpfObjectMapKind::Ringbuf,
        )?;
        let config = EbpfObjectProbeConfig::new(&object);

        let report = EbpfObjectProbe::probe(&config);

        assert!(report.object_available(), "{}", report.summary());
        assert!(report.preflight_available(), "{}", report.summary());
        assert_eq!(report.maps.len(), 1);
        assert_eq!(report.maps[0].name, EBPF_EVENTS_MAP_NAME);
        assert_eq!(report.maps[0].kind, EbpfObjectMapKind::Ringbuf);
        assert_eq!(report.programs.len(), 1);
        assert_eq!(report.programs[0].name, EBPF_CONNECT_PROGRAM_NAME);
        assert_eq!(
            report.programs[0].section.as_deref(),
            Some(expected_tracepoint_section().as_str())
        );
        Ok(())
    }

    #[test]
    fn preflight_returns_same_hardened_object_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let object = temp.path().join("preflighted-scaffold.bpf.o");
        write_minimal_ebpf_object(
            &object,
            &expected_tracepoint_section(),
            EbpfObjectMapKind::Ringbuf,
        )?;
        let config = EbpfObjectProbeConfig::new(&object);

        let preflighted = EbpfObjectProbe::preflight(&config)
            .expect("generated scaffold object should pass contract preflight");

        assert!(preflighted.report.preflight_available());
        assert_eq!(preflighted.bytes(), fs::read(&object)?.as_slice());
        Ok(())
    }

    #[test]
    fn preflight_returns_report_for_contract_failure() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let object = temp.path().join("invalid-contract.bpf.o");
        write_minimal_ebpf_object(
            &object,
            "tracepoint/syscalls/sys_exit_connect",
            EbpfObjectMapKind::Ringbuf,
        )?;
        let config = EbpfObjectProbeConfig::new(&object);

        let report = EbpfObjectProbe::preflight(&config)
            .expect_err("wrong tracepoint section should fail contract preflight");

        assert!(report.object_available());
        assert!(!report.preflight_available());
        assert!(
            report
                .summary()
                .contains("tracepoint/syscalls/sys_enter_connect")
        );
        Ok(())
    }

    #[test]
    fn object_probe_rejects_generated_object_with_wrong_section()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let object = temp.path().join("wrong-section.bpf.o");
        write_minimal_ebpf_object(
            &object,
            "tracepoint/syscalls/sys_exit_connect",
            EbpfObjectMapKind::Ringbuf,
        )?;
        let config = EbpfObjectProbeConfig::new(&object);

        let report = EbpfObjectProbe::probe(&config);

        assert!(report.object_available(), "{}", report.summary());
        assert!(!report.preflight_available());
        assert!(
            report
                .summary()
                .contains("tracepoint/syscalls/sys_enter_connect")
        );
        Ok(())
    }
}
