use std::{
    collections::{BTreeMap, HashSet},
    path::Path,
};

use probe_io::{AllowedFileRootViolation, AllowedFileRootViolationKind, AllowedFileRoots};

use crate::{
    CaptureConfig, CaptureSelection, ConfigViolation, MAX_TLS_DECRYPT_HINT_REFRESH_INTERVAL_MS,
    MAX_TLS_PLAINTEXT_RECONCILE_INTERVAL_MS, TlsConfig, TlsMaterialKind,
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

pub(crate) fn validate_tls_material_registry(
    tls: &TlsConfig,
    violations: &mut Vec<ConfigViolation>,
) {
    validate_tls_materials(tls, violations);
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
    validate_tls_material_store(tls, violations);
    let allowed_roots = &tls.material_store.filesystem.allowed_roots;
    let allowed_root_policy = AllowedFileRoots::new(allowed_roots.clone()).ok();
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
        } else if !allowed_roots.is_empty()
            && let Some(allowed_root_policy) = &allowed_root_policy
        {
            validate_tls_material_path_under_allowed_roots(
                index,
                &material.path,
                allowed_root_policy,
                violations,
            );
        }
    }
}

fn validate_tls_material_store(tls: &TlsConfig, violations: &mut Vec<ConfigViolation>) {
    for violation in AllowedFileRoots::validate_paths(&tls.material_store.filesystem.allowed_roots)
    {
        violations.push(ConfigViolation {
            field: format!(
                "tls.material_store.filesystem.allowed_roots[{}]",
                violation.index
            ),
            reason: tls_material_root_violation_reason(&violation),
        });
    }
}

fn tls_material_root_violation_reason(violation: &AllowedFileRootViolation) -> String {
    match violation.kind {
        AllowedFileRootViolationKind::Empty => {
            "TLS material filesystem root cannot be empty".to_string()
        }
        AllowedFileRootViolationKind::Relative => {
            "TLS material filesystem root must be absolute".to_string()
        }
        AllowedFileRootViolationKind::RootDirectory => {
            "TLS material filesystem root cannot be /".to_string()
        }
        AllowedFileRootViolationKind::ParentComponent => {
            "TLS material filesystem root cannot contain parent directory components".to_string()
        }
        AllowedFileRootViolationKind::Duplicate => {
            "TLS material filesystem roots must be unique".to_string()
        }
    }
}

fn validate_tls_material_path_under_allowed_roots(
    index: usize,
    path: &Path,
    allowed_roots: &AllowedFileRoots,
    violations: &mut Vec<ConfigViolation>,
) {
    let field = format!("tls.materials[{index}].path");
    if !path.is_absolute() {
        violations.push(ConfigViolation {
            field,
            reason: "TLS material path must be absolute when filesystem roots are configured"
                .to_string(),
        });
        return;
    }
    if !allowed_roots.contains(path) {
        violations.push(ConfigViolation {
            field,
            reason: "TLS material path must be inside one configured filesystem root".to_string(),
        });
    }
}

fn validate_plaintext_tls_material_refs(tls: &TlsConfig, violations: &mut Vec<ConfigViolation>) {
    let materials_by_id = materials_by_id(tls);
    validate_plaintext_tls_material_ref_list(
        &tls.plaintext.decrypt_hints.key_log_refs,
        "tls.plaintext.decrypt_hints.key_log_refs",
        TlsMaterialKind::KeyLogFile,
        &materials_by_id,
        violations,
    );
    validate_plaintext_tls_material_ref_list(
        &tls.plaintext.decrypt_hints.session_secret_refs,
        "tls.plaintext.decrypt_hints.session_secret_refs",
        TlsMaterialKind::SessionSecretFile,
        &materials_by_id,
        violations,
    );
}

fn validate_plaintext_tls_material_ref_list(
    refs: &[String],
    field: &'static str,
    expected_kind: TlsMaterialKind,
    materials_by_id: &BTreeMap<&str, TlsMaterialKind>,
    violations: &mut Vec<ConfigViolation>,
) {
    let mut seen_refs = HashSet::new();
    for reference in refs {
        validate_material_ref(
            field,
            reference,
            expected_kind,
            materials_by_id,
            violations,
            "TLS plaintext material",
        );
        if !reference.trim().is_empty() && !seen_refs.insert(reference.as_str()) {
            violations.push(ConfigViolation {
                field: field.to_string(),
                reason: format!("TLS plaintext material ref {reference} is duplicated"),
            });
        }
    }
}

fn validate_plaintext_tls_provider_config(tls: &TlsConfig, violations: &mut Vec<ConfigViolation>) {
    if tls.plaintext.instrumentation.reconcile_interval_ms == 0 {
        violations.push(ConfigViolation {
            field: "tls.plaintext.instrumentation.reconcile_interval_ms".to_string(),
            reason: "TLS plaintext reconcile interval must be positive".to_string(),
        });
    }
    if tls.plaintext.instrumentation.reconcile_interval_ms > MAX_TLS_PLAINTEXT_RECONCILE_INTERVAL_MS
    {
        violations.push(ConfigViolation {
            field: "tls.plaintext.instrumentation.reconcile_interval_ms".to_string(),
            reason: format!(
                "TLS plaintext reconcile interval must be at most {MAX_TLS_PLAINTEXT_RECONCILE_INTERVAL_MS} ms"
            ),
        });
    }
    if tls.plaintext.decrypt_hints.refresh_interval_ms == 0 {
        violations.push(ConfigViolation {
            field: "tls.plaintext.decrypt_hints.refresh_interval_ms".to_string(),
            reason: "TLS decrypt hint refresh interval must be positive".to_string(),
        });
    }
    if tls.plaintext.decrypt_hints.refresh_interval_ms > MAX_TLS_DECRYPT_HINT_REFRESH_INTERVAL_MS {
        violations.push(ConfigViolation {
            field: "tls.plaintext.decrypt_hints.refresh_interval_ms".to_string(),
            reason: format!(
                "TLS decrypt hint refresh interval must be at most {MAX_TLS_DECRYPT_HINT_REFRESH_INTERVAL_MS} ms"
            ),
        });
    }

    let Some(path) = &tls.plaintext.instrumentation.libssl_uprobe_object_path else {
        return;
    };
    if path.as_os_str().is_empty() {
        violations.push(ConfigViolation {
            field: "tls.plaintext.instrumentation.libssl_uprobe_object_path".to_string(),
            reason: "libssl uprobe eBPF object path cannot be empty".to_string(),
        });
    }
}

fn validate_plaintext_feed_selection(tls: &TlsConfig, violations: &mut Vec<ConfigViolation>) {
    if !tls.plaintext.instrumentation.enabled {
        return;
    }

    violations.push(ConfigViolation {
        field: "tls.plaintext.instrumentation.enabled".to_string(),
        reason: "plaintext_feed capture is the external plaintext source; disable tls.plaintext.instrumentation or select a TLS instrumentation backend"
            .to_string(),
    });
}

#[cfg(test)]
mod tests {
    use crate::{AgentConfig, ConfigError, TlsMaterialConfig, TlsMaterialKind};

    #[test]
    fn duplicate_plaintext_decrypt_hint_refs_fail_validation() {
        let mut config = AgentConfig::default();
        config.tls.plaintext.decrypt_hints.key_log_refs =
            vec!["ssl-keys".to_string(), "ssl-keys".to_string()];
        config.tls.plaintext.decrypt_hints.session_secret_refs =
            vec!["session-secrets".to_string(), "session-secrets".to_string()];
        config.tls.materials = vec![
            TlsMaterialConfig {
                id: Some("ssl-keys".to_string()),
                kind: TlsMaterialKind::KeyLogFile,
                path: "/tmp/sslkeylog.log".into(),
            },
            TlsMaterialConfig {
                id: Some("session-secrets".to_string()),
                kind: TlsMaterialKind::SessionSecretFile,
                path: "/tmp/session-secrets.jsonl".into(),
            },
        ];

        let error = config
            .validate_basic()
            .expect_err("duplicate TLS plaintext decrypt hint refs must fail");
        let ConfigError::Validation(error) = error else {
            panic!("duplicate refs should produce a validation error");
        };

        assert_eq!(error.violations().len(), 2);
        assert!(error.violations().iter().any(|violation| {
            violation.field == "tls.plaintext.decrypt_hints.key_log_refs"
                && violation
                    .reason
                    .contains("TLS plaintext material ref ssl-keys is duplicated")
        }));
        assert!(error.violations().iter().any(|violation| {
            violation.field == "tls.plaintext.decrypt_hints.session_secret_refs"
                && violation
                    .reason
                    .contains("TLS plaintext material ref session-secrets is duplicated")
        }));
    }

    #[test]
    fn plaintext_decrypt_hint_refresh_interval_must_be_positive_and_bounded() {
        let mut config = AgentConfig::default();
        config.tls.plaintext.decrypt_hints.refresh_interval_ms = 0;

        let error = config
            .validate_basic()
            .expect_err("zero TLS decrypt hint refresh interval must fail");
        let ConfigError::Validation(error) = error else {
            panic!("invalid refresh interval should produce a validation error");
        };
        assert!(error.violations().iter().any(|violation| {
            violation.field == "tls.plaintext.decrypt_hints.refresh_interval_ms"
                && violation.reason.contains("must be positive")
        }));

        config.tls.plaintext.decrypt_hints.refresh_interval_ms =
            crate::MAX_TLS_DECRYPT_HINT_REFRESH_INTERVAL_MS + 1;
        let error = config
            .validate_basic()
            .expect_err("oversized TLS decrypt hint refresh interval must fail");
        let ConfigError::Validation(error) = error else {
            panic!("invalid refresh interval should produce a validation error");
        };
        assert!(error.violations().iter().any(|violation| {
            violation.field == "tls.plaintext.decrypt_hints.refresh_interval_ms"
                && violation.reason.contains("must be at most")
        }));
    }
}
