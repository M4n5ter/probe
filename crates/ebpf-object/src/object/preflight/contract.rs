use ebpf_abi::{
    EBPF_PROCESS_MAP_SPECS, EBPF_PROCESS_TRACEPOINT_SPECS, EBPF_TLS_LIBSSL_UPROBE_SPECS,
    EBPF_TLS_MAP_SPECS, EBPF_UPROBE_SECTION_NAME, EBPF_URETPROBE_SECTION_NAME,
    EbpfProcessTracepointSpec,
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
            maps: EBPF_PROCESS_MAP_SPECS
                .iter()
                .map(EbpfExpectedMap::from_abi_spec)
                .collect(),
            programs: EBPF_PROCESS_TRACEPOINT_SPECS
                .iter()
                .map(expected_process_tracepoint_program)
                .collect(),
            inventory_policy: EbpfObjectContractInventoryPolicy::RequiredOnly,
        }
    }

    pub fn tls_plaintext_uprobe() -> Self {
        Self {
            maps: EBPF_TLS_MAP_SPECS
                .iter()
                .map(EbpfExpectedMap::from_abi_spec)
                .collect(),
            programs: expected_tls_plaintext_programs(),
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

    fn from_abi_spec(spec: &ebpf_abi::EbpfMapSpec) -> Self {
        Self {
            name: spec.name.to_string(),
            kind: spec.kind.into(),
            key_size: spec.key_size,
            value_size: spec.value_size,
            max_entries: spec.max_entries,
            map_flags: spec.map_flags,
            pinning: EbpfObjectMapPinning::None,
        }
    }
}

fn expected_uprobe_program(name: &str) -> EbpfExpectedProgram {
    EbpfExpectedProgram {
        name: name.to_string(),
        kind: EbpfObjectProgramKind::Uprobe,
        section: Some(EBPF_UPROBE_SECTION_NAME.to_string()),
    }
}

fn expected_uretprobe_program(name: &str) -> EbpfExpectedProgram {
    EbpfExpectedProgram {
        name: name.to_string(),
        kind: EbpfObjectProgramKind::Uretprobe,
        section: Some(EBPF_URETPROBE_SECTION_NAME.to_string()),
    }
}

fn expected_tls_plaintext_programs() -> Vec<EbpfExpectedProgram> {
    let mut programs = Vec::new();
    for spec in EBPF_TLS_LIBSSL_UPROBE_SPECS {
        programs.push(expected_uprobe_program(spec.entry_program_name));
        if let Some(program_name) = spec.return_program_name {
            programs.push(expected_uretprobe_program(program_name));
        }
    }
    programs
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

#[cfg(test)]
pub(super) fn expected_connect_tracepoint_section() -> String {
    ebpf_abi::EbpfProcessTracepointRole::ConnectEnter
        .spec()
        .section_name()
        .to_string()
}

fn expected_process_tracepoint_program(spec: &EbpfProcessTracepointSpec) -> EbpfExpectedProgram {
    EbpfExpectedProgram {
        name: spec.program_name.to_string(),
        kind: EbpfObjectProgramKind::Tracepoint,
        section: Some(spec.section_name().to_string()),
    }
}

#[cfg(test)]
mod tests {
    use ebpf_abi::{EBPF_EVENTS_MAP_NAME, EBPF_RING_BUFFER_BYTES, EBPF_TLS_CALLS_MAP_NAME};

    use super::super::object_fixture::{
        contract_reason, contract_ringbuf_map, contract_tracepoint_program,
    };
    use super::*;

    #[test]
    fn object_contract_requires_process_probe_maps_and_tracepoint_programs() {
        let report = process_probe_contract_report(
            &required_process_probe_programs(),
            &required_process_probe_maps(),
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
        let summary = report.summary();
        let contract = EbpfObjectContract::process_probe_scaffold();
        for expected in &contract.maps {
            assert!(
                summary.contains(&expected.name),
                "summary {summary} should mention missing map {}",
                expected.name
            );
        }
        for expected in &contract.programs {
            assert!(
                summary.contains(&expected.name),
                "summary {summary} should mention missing program {}",
                expected.name
            );
        }
    }

    #[test]
    fn object_contract_rejects_wrong_map_kind() {
        let mut map = contract_ringbuf_map(EBPF_EVENTS_MAP_NAME);
        map.kind = EbpfObjectMapKind::Other { value: 1 };
        let mut maps = required_process_probe_maps();
        replace_required_map(&mut maps, map);
        let report = process_probe_contract_report(&required_process_probe_programs(), &maps);

        assert!(!report.is_available());
        assert!(contract_reason(&report.maps, EBPF_EVENTS_MAP_NAME).contains("expected Ringbuf"));
    }

    #[test]
    fn object_contract_rejects_wrong_ringbuf_shape() {
        let mut map = contract_ringbuf_map(EBPF_EVENTS_MAP_NAME);
        map.max_entries = EBPF_RING_BUFFER_BYTES / 2;
        map.pinning = EbpfObjectMapPinning::ByName;
        let mut maps = required_process_probe_maps();
        replace_required_map(&mut maps, map);
        let report = process_probe_contract_report(&required_process_probe_programs(), &maps);

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
        let mut maps = required_process_probe_maps();
        maps.push(contract_ringbuf_map("EXTRA_EVENTS"));
        let report = process_probe_contract_report(&programs, &maps);

        assert!(report.is_available());
    }

    #[test]
    fn tls_plaintext_contract_requires_uprobe_programs_and_state_maps() {
        let report = EbpfObjectContractReport::from_inventory(
            &EbpfObjectContract::tls_plaintext_uprobe(),
            &required_tls_plaintext_programs(),
            &required_tls_plaintext_maps(),
        );

        assert!(report.is_available(), "{}", report.summary());
        assert_eq!(report.summary(), "available");
    }

    #[test]
    fn tls_plaintext_contract_reports_missing_state_map() {
        let mut maps = required_tls_plaintext_maps();
        maps.retain(|map| map.name != EBPF_TLS_CALLS_MAP_NAME);
        let report = EbpfObjectContractReport::from_inventory(
            &EbpfObjectContract::tls_plaintext_uprobe(),
            &required_tls_plaintext_programs(),
            &maps,
        );

        assert!(!report.is_available());
        assert!(contract_reason(&report.maps, EBPF_TLS_CALLS_MAP_NAME).contains("missing"));
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
        let mut maps = required_process_probe_maps();
        maps.push(contract_ringbuf_map("EXTRA_EVENTS"));
        let report = EbpfObjectContractReport::from_inventory(&contract, &programs, &maps);

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
        for expected in EbpfObjectContract::process_probe_scaffold().programs {
            let mut programs = required_process_probe_programs();
            replace_required_program(
                &mut programs,
                EbpfObjectProgram {
                    name: expected.name.clone(),
                    kind: EbpfObjectProgramKind::Unsupported,
                    section: expected.section.clone(),
                },
            );
            let report = process_probe_contract_report(&programs, &required_process_probe_maps());

            assert!(!report.is_available());
            assert!(
                contract_reason(&report.programs, &expected.name).contains("expected Tracepoint")
            );
        }
    }

    #[test]
    fn object_contract_rejects_wrong_tracepoint_section() {
        for expected in EbpfObjectContract::process_probe_scaffold().programs {
            let mut programs = required_process_probe_programs();
            replace_required_program(
                &mut programs,
                contract_tracepoint_program(&expected.name, "tracepoint/wrong/event"),
            );
            let report = process_probe_contract_report(&programs, &required_process_probe_maps());

            assert!(!report.is_available());
            assert!(
                contract_reason(&report.programs, &expected.name)
                    .contains(expected.section.as_deref().expect("tracepoint section"))
            );
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
        EbpfObjectContract::process_probe_scaffold()
            .programs
            .iter()
            .map(contract_program_from_expected)
            .collect()
    }

    fn required_process_probe_maps() -> Vec<EbpfObjectMap> {
        EbpfObjectContract::process_probe_scaffold()
            .maps
            .iter()
            .map(contract_map_from_expected)
            .collect()
    }

    fn required_tls_plaintext_programs() -> Vec<EbpfObjectProgram> {
        EbpfObjectContract::tls_plaintext_uprobe()
            .programs
            .iter()
            .map(contract_program_from_expected)
            .collect()
    }

    fn required_tls_plaintext_maps() -> Vec<EbpfObjectMap> {
        EbpfObjectContract::tls_plaintext_uprobe()
            .maps
            .iter()
            .map(contract_map_from_expected)
            .collect()
    }

    fn contract_map_from_expected(expected: &EbpfExpectedMap) -> EbpfObjectMap {
        EbpfObjectMap {
            name: expected.name.clone(),
            kind: expected.kind,
            key_size: expected.key_size,
            value_size: expected.value_size,
            max_entries: expected.max_entries,
            map_flags: expected.map_flags,
            pinning: expected.pinning,
        }
    }

    fn contract_program_from_expected(expected: &EbpfExpectedProgram) -> EbpfObjectProgram {
        EbpfObjectProgram {
            name: expected.name.clone(),
            kind: expected.kind,
            section: expected.section.clone(),
        }
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

    fn replace_required_map(maps: &mut [EbpfObjectMap], replacement: EbpfObjectMap) {
        let map = maps
            .iter_mut()
            .find(|map| map.name == replacement.name)
            .expect("required map should exist in test fixture");
        *map = replacement;
    }
}
