use ebpf_abi::{
    EBPF_CLOSE_PROGRAM_NAME, EBPF_CLOSE_TRACEPOINT_CATEGORY, EBPF_CLOSE_TRACEPOINT_NAME,
    EBPF_CONNECT_PROGRAM_NAME, EBPF_CONNECT_TRACEPOINT_CATEGORY, EBPF_CONNECT_TRACEPOINT_NAME,
    EBPF_EVENTS_MAP_NAME, EBPF_RING_BUFFER_BYTES,
};

use super::model::{
    EbpfExpectedMap, EbpfExpectedProgram, EbpfObjectContract, EbpfObjectContractCheck,
    EbpfObjectContractInventoryPolicy, EbpfObjectContractReport, EbpfObjectMap, EbpfObjectMapKind,
    EbpfObjectMapPinning, EbpfObjectProgram, EbpfObjectProgramKind, EbpfProbeCheck,
};

impl EbpfObjectContractReport {
    pub fn is_available(&self) -> bool {
        self.status.is_available()
            && self.maps.iter().all(EbpfObjectContractCheck::is_available)
            && self
                .programs
                .iter()
                .all(EbpfObjectContractCheck::is_available)
    }

    pub(super) fn from_inventory(
        contract: &EbpfObjectContract,
        programs: &[EbpfObjectProgram],
        maps: &[EbpfObjectMap],
    ) -> Self {
        let mut map_checks = contract
            .maps
            .iter()
            .map(|expected| expected_map_check(maps, expected))
            .collect::<Vec<_>>();

        let mut program_checks = contract
            .programs
            .iter()
            .map(|expected| expected_program_check(programs, expected))
            .collect::<Vec<_>>();
        if contract.inventory_policy == EbpfObjectContractInventoryPolicy::Strict {
            map_checks.extend(unexpected_map_checks(maps, contract));
            program_checks.extend(unexpected_program_checks(programs, contract));
        }

        Self {
            status: EbpfProbeCheck::available(),
            maps: map_checks,
            programs: program_checks,
        }
    }

    pub(super) fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            status: EbpfProbeCheck::unavailable(reason),
            maps: Vec::new(),
            programs: Vec::new(),
        }
    }

    pub fn summary(&self) -> String {
        if self.is_available() {
            return "available".to_string();
        }
        format!(
            "{}, {}",
            contract_check_summary("maps", &self.maps, &self.status),
            contract_check_summary("programs", &self.programs, &self.status)
        )
    }
}

impl EbpfObjectContract {
    pub fn new(maps: Vec<EbpfExpectedMap>, programs: Vec<EbpfExpectedProgram>) -> Self {
        Self {
            maps,
            programs,
            inventory_policy: EbpfObjectContractInventoryPolicy::RequiredOnly,
        }
    }

    pub fn with_inventory_policy(
        mut self,
        inventory_policy: EbpfObjectContractInventoryPolicy,
    ) -> Self {
        self.inventory_policy = inventory_policy;
        self
    }

    pub fn process_probe_scaffold() -> Self {
        Self {
            maps: vec![EbpfExpectedMap::ringbuf(
                EBPF_EVENTS_MAP_NAME,
                EBPF_RING_BUFFER_BYTES,
            )],
            programs: vec![
                EbpfExpectedProgram {
                    name: EBPF_CONNECT_PROGRAM_NAME.to_string(),
                    kind: EbpfObjectProgramKind::Tracepoint,
                    section: Some(expected_connect_tracepoint_section()),
                },
                EbpfExpectedProgram {
                    name: EBPF_CLOSE_PROGRAM_NAME.to_string(),
                    kind: EbpfObjectProgramKind::Tracepoint,
                    section: Some(expected_close_tracepoint_section()),
                },
            ],
            inventory_policy: EbpfObjectContractInventoryPolicy::RequiredOnly,
        }
    }
}

impl EbpfExpectedMap {
    pub fn ringbuf(name: impl Into<String>, byte_size: u32) -> Self {
        Self {
            name: name.into(),
            kind: EbpfObjectMapKind::Ringbuf,
            key_size: 0,
            value_size: 0,
            max_entries: byte_size,
            map_flags: 0,
            pinning: EbpfObjectMapPinning::None,
        }
    }
}

fn expected_map_check(
    maps: &[EbpfObjectMap],
    expected: &EbpfExpectedMap,
) -> EbpfObjectContractCheck {
    let check = match maps.iter().find(|map| map.name == expected.name) {
        Some(map) => {
            let mismatches = map_contract_mismatches(map, expected);
            if mismatches.is_empty() {
                EbpfProbeCheck::available()
            } else {
                EbpfProbeCheck::unavailable(format!(
                    "eBPF map {} violates contract: {}",
                    expected.name,
                    mismatches.join(", ")
                ))
            }
        }
        None => EbpfProbeCheck::unavailable(format!("missing eBPF map {}", expected.name)),
    };
    EbpfObjectContractCheck {
        name: expected.name.clone(),
        check,
    }
}

fn unexpected_map_checks(
    maps: &[EbpfObjectMap],
    contract: &EbpfObjectContract,
) -> Vec<EbpfObjectContractCheck> {
    maps.iter()
        .filter(|map| {
            !contract
                .maps
                .iter()
                .any(|expected| expected.name == map.name)
        })
        .map(|map| EbpfObjectContractCheck {
            name: map.name.clone(),
            check: EbpfProbeCheck::unavailable(format!("unexpected eBPF map {}", map.name)),
        })
        .collect()
}

fn unexpected_program_checks(
    programs: &[EbpfObjectProgram],
    contract: &EbpfObjectContract,
) -> Vec<EbpfObjectContractCheck> {
    programs
        .iter()
        .filter(|program| {
            !contract
                .programs
                .iter()
                .any(|expected| expected.name == program.name)
        })
        .map(|program| EbpfObjectContractCheck {
            name: program.name.clone(),
            check: EbpfProbeCheck::unavailable(format!("unexpected eBPF program {}", program.name)),
        })
        .collect()
}

fn map_contract_mismatches(map: &EbpfObjectMap, expected: &EbpfExpectedMap) -> Vec<String> {
    let mut mismatches = Vec::new();
    push_contract_mismatch(&mut mismatches, "kind", map.kind, expected.kind);
    push_contract_mismatch(&mut mismatches, "key_size", map.key_size, expected.key_size);
    push_contract_mismatch(
        &mut mismatches,
        "value_size",
        map.value_size,
        expected.value_size,
    );
    push_contract_mismatch(
        &mut mismatches,
        "max_entries",
        map.max_entries,
        expected.max_entries,
    );
    push_contract_mismatch(
        &mut mismatches,
        "map_flags",
        map.map_flags,
        expected.map_flags,
    );
    push_contract_mismatch(&mut mismatches, "pinning", map.pinning, expected.pinning);
    mismatches
}

fn push_contract_mismatch<T>(mismatches: &mut Vec<String>, field: &str, actual: T, expected: T)
where
    T: Copy + std::fmt::Debug + PartialEq,
{
    if actual != expected {
        mismatches.push(format!("{field} {actual:?} expected {expected:?}"));
    }
}

fn expected_program_check(
    programs: &[EbpfObjectProgram],
    expected: &EbpfExpectedProgram,
) -> EbpfObjectContractCheck {
    let check = match programs
        .iter()
        .find(|program| program.name == expected.name)
    {
        Some(program)
            if program.kind == expected.kind
                && expected
                    .section
                    .as_deref()
                    .is_none_or(|section| program.section.as_deref() == Some(section)) =>
        {
            EbpfProbeCheck::available()
        }
        Some(program) => EbpfProbeCheck::unavailable(format!(
            "eBPF program {} has kind {:?} and section {}, expected {:?} section {}",
            expected.name,
            program.kind,
            program.section.as_deref().unwrap_or("<unknown>"),
            expected.kind,
            expected.section.as_deref().unwrap_or("<any>")
        )),
        None => EbpfProbeCheck::unavailable(format!("missing eBPF program {}", expected.name)),
    };
    EbpfObjectContractCheck {
        name: expected.name.clone(),
        check,
    }
}

fn contract_check_summary(
    label: &str,
    checks: &[EbpfObjectContractCheck],
    status: &EbpfProbeCheck,
) -> String {
    if !status.is_available() {
        return format!("{label}={}", status.summary());
    }
    if checks.is_empty() {
        return format!("{label}=none");
    }
    let unavailable = checks
        .iter()
        .filter(|check| !check.is_available())
        .map(|check| format!("{}={}", check.name, check.check.summary()))
        .collect::<Vec<_>>();
    if unavailable.is_empty() {
        return format!("{label}=available");
    }
    format!("{label}={}", unavailable.join(","))
}

pub(super) fn expected_connect_tracepoint_section() -> String {
    format!("tracepoint/{EBPF_CONNECT_TRACEPOINT_CATEGORY}/{EBPF_CONNECT_TRACEPOINT_NAME}")
}

pub(super) fn expected_close_tracepoint_section() -> String {
    format!("tracepoint/{EBPF_CLOSE_TRACEPOINT_CATEGORY}/{EBPF_CLOSE_TRACEPOINT_NAME}")
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{
        contract_reason, contract_ringbuf_map, contract_tracepoint_program,
    };
    use super::*;

    #[test]
    fn object_contract_requires_ringbuf_map_and_lifecycle_tracepoint_programs() {
        let report = process_probe_contract_report(
            &required_process_probe_programs(),
            &[contract_ringbuf_map(EBPF_EVENTS_MAP_NAME)],
        );

        assert!(report.is_available());
        assert_eq!(report.summary(), "available");
    }

    #[test]
    fn object_contract_reports_missing_expected_names() {
        let report = process_probe_contract_report(
            &[contract_tracepoint_program(
                "different_program",
                &expected_connect_tracepoint_section(),
            )],
            &[contract_ringbuf_map("DIFFERENT_MAP")],
        );

        assert!(!report.is_available());
        assert!(report.summary().contains(EBPF_EVENTS_MAP_NAME));
        assert!(report.summary().contains(EBPF_CONNECT_PROGRAM_NAME));
        assert!(report.summary().contains(EBPF_CLOSE_PROGRAM_NAME));
    }

    #[test]
    fn object_contract_rejects_wrong_map_kind() {
        let mut map = contract_ringbuf_map(EBPF_EVENTS_MAP_NAME);
        map.kind = EbpfObjectMapKind::Other { value: 1 };
        let report = process_probe_contract_report(&required_process_probe_programs(), &[map]);

        assert!(!report.is_available());
        assert!(contract_reason(&report.maps, EBPF_EVENTS_MAP_NAME).contains("expected Ringbuf"));
    }

    #[test]
    fn object_contract_rejects_wrong_ringbuf_shape() {
        let mut map = contract_ringbuf_map(EBPF_EVENTS_MAP_NAME);
        map.max_entries = EBPF_RING_BUFFER_BYTES / 2;
        map.pinning = EbpfObjectMapPinning::ByName;
        let report = process_probe_contract_report(&required_process_probe_programs(), &[map]);

        let reason = contract_reason(&report.maps, EBPF_EVENTS_MAP_NAME);
        assert!(!report.is_available());
        assert!(reason.contains("max_entries"));
        assert!(reason.contains("pinning"));
    }

    #[test]
    fn object_contract_accepts_extra_inventory_by_default() {
        let mut programs = required_process_probe_programs();
        programs.push(contract_tracepoint_program(
            "unexpected_tracepoint",
            "tracepoint/syscalls/sys_exit",
        ));
        let report = process_probe_contract_report(
            &programs,
            &[
                contract_ringbuf_map(EBPF_EVENTS_MAP_NAME),
                contract_ringbuf_map("EXTRA_EVENTS"),
            ],
        );

        assert!(report.is_available());
    }

    #[test]
    fn object_contract_rejects_unexpected_extra_inventory_in_strict_mode() {
        let contract = EbpfObjectContract::process_probe_scaffold()
            .with_inventory_policy(EbpfObjectContractInventoryPolicy::Strict);
        let mut programs = required_process_probe_programs();
        programs.push(contract_tracepoint_program(
            "unexpected_tracepoint",
            "tracepoint/syscalls/sys_exit",
        ));
        let report = EbpfObjectContractReport::from_inventory(
            &contract,
            &programs,
            &[
                contract_ringbuf_map(EBPF_EVENTS_MAP_NAME),
                contract_ringbuf_map("EXTRA_EVENTS"),
            ],
        );

        assert!(!report.is_available());
        assert!(
            report
                .summary()
                .contains("unexpected eBPF map EXTRA_EVENTS")
        );
        assert!(
            report
                .summary()
                .contains("unexpected eBPF program unexpected_tracepoint")
        );
    }

    #[test]
    fn object_contract_rejects_wrong_program_kind() {
        for (program_name, section) in [
            (EBPF_CONNECT_PROGRAM_NAME, "kprobe/sssa_sys_enter_connect"),
            (EBPF_CLOSE_PROGRAM_NAME, "kprobe/sssa_sys_enter_close"),
        ] {
            let mut programs = required_process_probe_programs();
            replace_required_program(
                &mut programs,
                EbpfObjectProgram {
                    name: program_name.to_string(),
                    kind: EbpfObjectProgramKind::Unsupported,
                    section: Some(section.to_string()),
                },
            );
            let report = process_probe_contract_report(
                &programs,
                &[contract_ringbuf_map(EBPF_EVENTS_MAP_NAME)],
            );

            assert!(!report.is_available());
            assert!(
                contract_reason(&report.programs, program_name).contains("expected Tracepoint")
            );
        }
    }

    #[test]
    fn object_contract_rejects_wrong_tracepoint_section() {
        for (program_name, wrong_section, expected_section) in [
            (
                EBPF_CONNECT_PROGRAM_NAME,
                "tracepoint/syscalls/sys_exit_connect",
                "tracepoint/syscalls/sys_enter_connect",
            ),
            (
                EBPF_CLOSE_PROGRAM_NAME,
                "tracepoint/syscalls/sys_exit_close",
                "tracepoint/syscalls/sys_enter_close",
            ),
        ] {
            let mut programs = required_process_probe_programs();
            replace_required_program(
                &mut programs,
                contract_tracepoint_program(program_name, wrong_section),
            );
            let report = process_probe_contract_report(
                &programs,
                &[contract_ringbuf_map(EBPF_EVENTS_MAP_NAME)],
            );

            assert!(!report.is_available());
            assert!(contract_reason(&report.programs, program_name).contains(expected_section));
        }
    }

    #[test]
    fn object_contract_accepts_custom_expected_program() {
        let contract = EbpfObjectContract::new(
            vec![EbpfExpectedMap::ringbuf(
                "CUSTOM_EVENTS",
                EBPF_RING_BUFFER_BYTES,
            )],
            vec![EbpfExpectedProgram {
                name: "custom_tracepoint".to_string(),
                kind: EbpfObjectProgramKind::Tracepoint,
                section: Some("tracepoint/custom/event".to_string()),
            }],
        );
        let report = EbpfObjectContractReport::from_inventory(
            &contract,
            &[contract_tracepoint_program(
                "custom_tracepoint",
                "tracepoint/custom/event",
            )],
            &[contract_ringbuf_map("CUSTOM_EVENTS")],
        );

        assert!(report.is_available());
    }

    fn process_probe_contract_report(
        programs: &[EbpfObjectProgram],
        maps: &[EbpfObjectMap],
    ) -> EbpfObjectContractReport {
        EbpfObjectContractReport::from_inventory(
            &EbpfObjectContract::process_probe_scaffold(),
            programs,
            maps,
        )
    }

    fn required_process_probe_programs() -> Vec<EbpfObjectProgram> {
        vec![
            contract_tracepoint_program(
                EBPF_CONNECT_PROGRAM_NAME,
                &expected_connect_tracepoint_section(),
            ),
            contract_tracepoint_program(
                EBPF_CLOSE_PROGRAM_NAME,
                &expected_close_tracepoint_section(),
            ),
        ]
    }

    fn replace_required_program(
        programs: &mut [EbpfObjectProgram],
        replacement: EbpfObjectProgram,
    ) {
        let program = programs
            .iter_mut()
            .find(|program| program.name == replacement.name)
            .expect("required program should exist in test fixture");
        *program = replacement;
    }
}
