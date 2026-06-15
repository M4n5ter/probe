use std::collections::{BTreeMap, HashSet};

use crate::{
    CaptureConfig, CaptureSelection, ConfigViolation, MAX_TLS_PLAINTEXT_RECONCILE_INTERVAL_MS,
    TlsConfig, TlsMaterialKind,
};

pub(crate) fn validate_tls(
    tls: &TlsConfig,
    capture: &CaptureConfig,
    violations: &mut Vec<ConfigViolation>,
) {
    validate_tls_materials(tls, violations);
    validate_plaintext_tls_material_refs(tls, violations);
    validate_plaintext_tls_provider_config(tls, violations);

    if capture.selection == CaptureSelection::PlaintextFeed {
        validate_plaintext_feed_selection(tls, violations);
    }
}

pub(crate) fn materials_by_id(tls: &TlsConfig) -> BTreeMap<&str, TlsMaterialKind> {
    tls.materials
        .iter()
        .filter_map(|material| material.id.as_deref().map(|id| (id, material.kind)))
        .collect()
}

pub(crate) fn validate_material_ref(
    field: impl Into<String>,
    reference: &str,
    expected_kind: TlsMaterialKind,
    materials_by_id: &BTreeMap<&str, TlsMaterialKind>,
    violations: &mut Vec<ConfigViolation>,
    subject: &str,
) {
    let field = field.into();
    if reference.trim().is_empty() {
        violations.push(ConfigViolation {
            field,
            reason: format!("{subject} reference cannot be empty"),
        });
        return;
    }
    match materials_by_id.get(reference).copied() {
        Some(kind) if kind == expected_kind => {}
        Some(kind) => violations.push(ConfigViolation {
            field,
            reason: format!(
                "{subject} ref {reference} has kind {kind:?}, expected {expected_kind:?}"
            ),
        }),
        None => violations.push(ConfigViolation {
            field,
            reason: format!("{subject} ref {reference} does not exist"),
        }),
    }
}

fn validate_tls_materials(tls: &TlsConfig, violations: &mut Vec<ConfigViolation>) {
    let mut ids = HashSet::new();
    for (index, material) in tls.materials.iter().enumerate() {
        if let Some(id) = &material.id {
            if id.trim().is_empty() {
                violations.push(ConfigViolation {
                    field: format!("tls.materials[{index}].id"),
                    reason: "TLS material id cannot be empty when set".to_string(),
                });
            } else if !ids.insert(id.as_str()) {
                violations.push(ConfigViolation {
                    field: format!("tls.materials[{index}].id"),
                    reason: "TLS material id must be unique".to_string(),
                });
            }
        }
        if material.path.as_os_str().is_empty() {
            violations.push(ConfigViolation {
                field: format!("tls.materials[{index}].path"),
                reason: "TLS material path cannot be empty".to_string(),
            });
        }
    }
}

fn validate_plaintext_tls_material_refs(tls: &TlsConfig, violations: &mut Vec<ConfigViolation>) {
    let materials_by_id = materials_by_id(tls);
    for reference in &tls.plaintext.key_log_refs {
        validate_material_ref(
            "tls.plaintext.key_log_refs",
            reference,
            TlsMaterialKind::KeyLogFile,
            &materials_by_id,
            violations,
            "TLS plaintext material",
        );
    }
    for reference in &tls.plaintext.session_secret_refs {
        validate_material_ref(
            "tls.plaintext.session_secret_refs",
            reference,
            TlsMaterialKind::SessionSecretFile,
            &materials_by_id,
            violations,
            "TLS plaintext material",
        );
    }
}

fn validate_plaintext_tls_provider_config(tls: &TlsConfig, violations: &mut Vec<ConfigViolation>) {
    if tls.plaintext.reconcile_interval_ms == 0 {
        violations.push(ConfigViolation {
            field: "tls.plaintext.reconcile_interval_ms".to_string(),
            reason: "TLS plaintext reconcile interval must be positive".to_string(),
        });
    }
    if tls.plaintext.reconcile_interval_ms > MAX_TLS_PLAINTEXT_RECONCILE_INTERVAL_MS {
        violations.push(ConfigViolation {
            field: "tls.plaintext.reconcile_interval_ms".to_string(),
            reason: format!(
                "TLS plaintext reconcile interval must be at most {MAX_TLS_PLAINTEXT_RECONCILE_INTERVAL_MS} ms"
            ),
        });
    }

    let Some(path) = &tls.plaintext.libssl_uprobe_object_path else {
        return;
    };
    if path.as_os_str().is_empty() {
        violations.push(ConfigViolation {
            field: "tls.plaintext.libssl_uprobe_object_path".to_string(),
            reason: "libssl uprobe eBPF object path cannot be empty".to_string(),
        });
    }
}

fn validate_plaintext_feed_selection(tls: &TlsConfig, violations: &mut Vec<ConfigViolation>) {
    if !tls.plaintext.enabled {
        return;
    }

    violations.push(ConfigViolation {
        field: "tls.plaintext.enabled".to_string(),
        reason: "plaintext_feed capture is the external plaintext source; disable tls.plaintext or select a TLS instrumentation backend"
            .to_string(),
    });
}
