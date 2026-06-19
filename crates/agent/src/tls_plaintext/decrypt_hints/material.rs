use std::path::PathBuf;

use capture::{
    Tls13ApplicationDataDecryptor, Tls13DecryptError, TlsSessionSecretRecord, TlsSessionSecretStore,
};
use probe_config::TlsMaterialKind;
use runtime::TlsPlaintextMaterialPlan;
use thiserror::Error;

use crate::tls_material::{TlsMaterialFileStore, TlsMaterialFileStoreError};

#[derive(Debug)]
pub(crate) struct TlsSessionSecretMaterialSet {
    materials: Vec<TlsSessionSecretMaterial>,
}

impl TlsSessionSecretMaterialSet {
    pub(crate) fn materials(&self) -> &[TlsSessionSecretMaterial] {
        &self.materials
    }

    pub(crate) fn build_auto_binding_store(
        &self,
    ) -> Result<TlsSessionSecretStore, TlsDecryptHintError> {
        let mut records = Vec::new();
        for material in &self.materials {
            let mut material_records = Vec::new();
            for record in material.store.records() {
                if let Some(record) = live_auto_binding_record(material, record)? {
                    material_records.push(record);
                }
            }
            if material_records.is_empty() {
                return Err(TlsDecryptHintError::SessionSecretMaterialSet {
                    reason: format!(
                        "session_secret_refs material {} ({:?}) at {:?} does not contain any session_secret_file TLS 1.3 application traffic secret record usable by live auto-binding",
                        material.id, material.kind, material.path
                    ),
                });
            }
            records.extend(material_records);
        }
        TlsSessionSecretStore::from_time_qualified_lookup_records(records)
            .map_err(|source| TlsDecryptHintError::SessionSecretMaterialSet {
                reason: source.to_string(),
            })?
            .ok_or_else(|| TlsDecryptHintError::SessionSecretMaterialSet {
                reason: "session_secret_refs do not contain any TLS 1.3 application traffic secret record usable by live auto-binding".to_string(),
            })
    }
}

#[derive(Debug)]
pub(crate) struct TlsSessionSecretMaterial {
    pub(crate) id: String,
    pub(crate) kind: TlsMaterialKind,
    pub(crate) path: PathBuf,
    pub(crate) store: TlsSessionSecretStore,
}

pub(crate) fn load_tls_session_secret_materials(
    materials: &[TlsPlaintextMaterialPlan],
    file_store: &(impl TlsMaterialFileStore + ?Sized),
) -> Result<TlsSessionSecretMaterialSet, TlsDecryptHintError> {
    materials
        .iter()
        .map(|material| {
            let bytes = file_store
                .read_tls_material(&material.path)
                .map_err(|source| tls_session_secret_plan_material_error(material, source))?;
            decode_tls_session_secret_material(material, &bytes)
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|materials| TlsSessionSecretMaterialSet { materials })
}

pub(super) enum TlsSessionSecretMaterialLoad {
    Ready(TlsSessionSecretStore),
    Pending,
}

enum TlsSessionSecretMaterialSetLoad {
    Ready(TlsSessionSecretMaterialSet),
    Pending,
}

pub(super) fn load_tls_session_secret_auto_binding_material(
    materials: &[TlsPlaintextMaterialPlan],
    file_store: &(impl TlsMaterialFileStore + ?Sized),
) -> Result<TlsSessionSecretMaterialLoad, TlsDecryptHintError> {
    let TlsSessionSecretMaterialSetLoad::Ready(materials) =
        load_tls_session_secret_materials_if_available(materials, file_store)?
    else {
        return Ok(TlsSessionSecretMaterialLoad::Pending);
    };
    Ok(TlsSessionSecretMaterialLoad::Ready(
        materials.build_auto_binding_store()?,
    ))
}

fn load_tls_session_secret_materials_if_available(
    materials: &[TlsPlaintextMaterialPlan],
    file_store: &(impl TlsMaterialFileStore + ?Sized),
) -> Result<TlsSessionSecretMaterialSetLoad, TlsDecryptHintError> {
    let mut pending_material = false;
    let mut loaded_materials = Vec::new();
    for material in materials {
        let Some(loaded) = load_tls_session_secret_material_if_available(material, file_store)?
        else {
            pending_material = true;
            continue;
        };
        loaded_materials.push(loaded);
    }
    if pending_material {
        return Ok(TlsSessionSecretMaterialSetLoad::Pending);
    }
    Ok(TlsSessionSecretMaterialSetLoad::Ready(
        TlsSessionSecretMaterialSet {
            materials: loaded_materials,
        },
    ))
}

fn load_tls_session_secret_material_if_available(
    material: &TlsPlaintextMaterialPlan,
    file_store: &(impl TlsMaterialFileStore + ?Sized),
) -> Result<Option<TlsSessionSecretMaterial>, TlsDecryptHintError> {
    let bytes = match file_store.read_tls_material(&material.path) {
        Ok(bytes) => bytes,
        Err(TlsMaterialFileStoreError::NotFound) => return Ok(None),
        Err(source) => return Err(tls_session_secret_plan_material_error(material, source)),
    };
    if tls_session_secret_material_is_empty(&bytes) {
        return Ok(None);
    }
    Ok(Some(decode_tls_session_secret_material(material, &bytes)?))
}

fn decode_tls_session_secret_material(
    material: &TlsPlaintextMaterialPlan,
    bytes: &[u8],
) -> Result<TlsSessionSecretMaterial, TlsDecryptHintError> {
    let store = TlsSessionSecretStore::parse(bytes)
        .map_err(|source| tls_session_secret_plan_material_error(material, source))?;
    Ok(TlsSessionSecretMaterial {
        id: material.id.clone(),
        kind: material.kind,
        path: material.path.clone(),
        store,
    })
}

fn tls_session_secret_material_is_empty(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
}

fn live_auto_binding_record(
    material: &TlsSessionSecretMaterial,
    record: &TlsSessionSecretRecord,
) -> Result<Option<TlsSessionSecretRecord>, TlsDecryptHintError> {
    match Tls13ApplicationDataDecryptor::from_session_secret_record(record) {
        Ok(_) => Ok(Some(record.clone())),
        Err(
            Tls13DecryptError::UnsupportedProtocol { .. }
            | Tls13DecryptError::UnsupportedSecretKind { .. },
        ) => Ok(None),
        Err(source) => Err(tls_session_secret_material_error(
            &material.id,
            material.kind,
            &material.path,
            format!(
                "TLS session secret record for protocol {:?}, secret_kind {:?}, client_random {:?} cannot be used for live auto-binding: {source}",
                record.protocol(),
                record.secret_kind(),
                record.client_random()
            ),
        )),
    }
}

fn tls_session_secret_plan_material_error(
    material: &TlsPlaintextMaterialPlan,
    source: impl std::fmt::Display,
) -> TlsDecryptHintError {
    tls_session_secret_material_error(&material.id, material.kind, &material.path, source)
}

fn tls_session_secret_material_error(
    id: &str,
    kind: TlsMaterialKind,
    path: &std::path::Path,
    source: impl std::fmt::Display,
) -> TlsDecryptHintError {
    TlsDecryptHintError::SessionSecretMaterial {
        id: id.to_string(),
        kind,
        path: path.to_path_buf(),
        reason: source.to_string(),
    }
}

#[derive(Debug, Error)]
pub(crate) enum TlsDecryptHintError {
    #[error("TLS session secret material {id} ({kind:?}) at {path:?} is invalid: {reason}")]
    SessionSecretMaterial {
        id: String,
        kind: TlsMaterialKind,
        path: PathBuf,
        reason: String,
    },
    #[error("TLS session secret decrypt hints are invalid: {reason}")]
    SessionSecretMaterialSet { reason: String },
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        path::{Path, PathBuf},
    };

    use capture::TlsSessionSecretProtocol;
    use runtime::TlsPlaintextMaterialPlan;

    use super::*;
    use crate::tls_material::{TlsMaterialFileStore, TlsMaterialFileStoreError};

    #[test]
    fn multiple_session_secret_materials_are_merged() -> Result<(), Box<dyn std::error::Error>> {
        let first_path = PathBuf::from("/tmp/session-secrets-a.jsonl");
        let second_path = PathBuf::from("/tmp/session-secrets-b.jsonl");
        let material_plans = material_plans([
            ("session-secrets-a", first_path.as_path()),
            ("session-secrets-b", second_path.as_path()),
        ]);
        let store = MemoryTlsMaterialStore::default()
            .with_file(&first_path, valid_session_secret("00", "aa").into_bytes())
            .with_file(&second_path, valid_session_secret("11", "bb").into_bytes());

        let materials = load_tls_session_secret_materials(&material_plans, &store)
            .expect("session secret hints should load");
        let session_secrets = materials
            .build_auto_binding_store()
            .expect("configured records should build a live auto-binding store");

        assert_eq!(session_secrets.records().len(), 2);
        Ok(())
    }

    #[test]
    fn duplicate_loaded_session_secret_records_are_deduped()
    -> Result<(), Box<dyn std::error::Error>> {
        let first_path = PathBuf::from("/tmp/session-secrets-a.jsonl");
        let second_path = PathBuf::from("/tmp/session-secrets-b.jsonl");
        let material_plans = material_plans([
            ("session-secrets-a", first_path.as_path()),
            ("session-secrets-b", second_path.as_path()),
        ]);
        let material = valid_session_secret("00", "aa").into_bytes();
        let store = MemoryTlsMaterialStore::default()
            .with_file(&first_path, material.clone())
            .with_file(&second_path, material);

        let materials = load_tls_session_secret_materials(&material_plans, &store)
            .expect("duplicate exact records should load");
        let session_secrets = materials
            .build_auto_binding_store()
            .expect("configured records should build a live auto-binding store");

        assert_eq!(session_secrets.records().len(), 1);
        Ok(())
    }

    #[test]
    fn non_live_session_secret_records_do_not_enter_auto_binding_store()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = PathBuf::from("/tmp/session-secrets.jsonl");
        let material_plans = material_plans([("session-secrets", path.as_path())]);
        let material = format!(
            "{}\n{}",
            valid_session_secret("00", "aa"),
            tls12_master_secret("11", "bb")
        );
        let store = MemoryTlsMaterialStore::default().with_file(&path, material.into_bytes());

        let materials = load_tls_session_secret_materials(&material_plans, &store)?;
        let session_secrets = materials.build_auto_binding_store()?;

        assert_eq!(materials.materials()[0].store.records().len(), 2);
        assert_eq!(session_secrets.records().len(), 1);
        assert_eq!(
            session_secrets.records()[0].protocol(),
            TlsSessionSecretProtocol::Tls13
        );
        Ok(())
    }

    #[test]
    fn overlapping_session_secret_records_fail_closed_without_leaking_secret()
    -> Result<(), Box<dyn std::error::Error>> {
        let first_path = PathBuf::from("/tmp/session-secrets-a.jsonl");
        let second_path = PathBuf::from("/tmp/session-secrets-b.jsonl");
        let material_plans = material_plans([
            ("session-secrets-a", first_path.as_path()),
            ("session-secrets-b", second_path.as_path()),
        ]);
        let store = MemoryTlsMaterialStore::default()
            .with_file(
                &first_path,
                valid_session_secret_with_window("00", "aa", 10, 30).into_bytes(),
            )
            .with_file(
                &second_path,
                valid_session_secret_with_window("00", "bb", 20, 40).into_bytes(),
            );

        let materials = load_tls_session_secret_materials(&material_plans, &store)
            .expect("overlapping records are syntactically valid material");
        let error = materials
            .build_auto_binding_store()
            .expect_err("overlapping lookup windows should fail closed");

        let message = error.to_string();
        assert!(message.contains("overlapping TLS session secret records"));
        assert!(!message.contains(&"aa".repeat(32)));
        assert!(!message.contains(&"bb".repeat(32)));
        Ok(())
    }

    #[test]
    fn application_traffic_secret_without_cipher_suite_fails_live_auto_binding()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = PathBuf::from("/tmp/session-secrets.jsonl");
        let material_plans = material_plans([("session-secrets", path.as_path())]);
        let material = format!(
            r#"{{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"{}","secret":"{}"}}"#,
            "00".repeat(32),
            "aa".repeat(32),
        );
        let store = MemoryTlsMaterialStore::default().with_file(&path, material.into_bytes());

        let materials = load_tls_session_secret_materials(&material_plans, &store)
            .expect("missing cipher suite is syntactically valid material");
        let error = materials
            .build_auto_binding_store()
            .expect_err("live auto-binding requires cipher suite metadata");

        let message = error.to_string();
        assert!(message.contains("session-secrets"));
        assert!(message.contains("requires cipher_suite metadata"));
        assert!(!message.contains(&"aa".repeat(32)));
        Ok(())
    }

    #[test]
    fn session_secret_refs_without_live_application_material_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = PathBuf::from("/tmp/session-secrets.jsonl");
        let material_plans = material_plans([("session-secrets", path.as_path())]);
        let store = MemoryTlsMaterialStore::default()
            .with_file(&path, tls12_master_secret("00", "bb").into_bytes());

        let materials = load_tls_session_secret_materials(&material_plans, &store)
            .expect("non-live material is syntactically valid");
        let error = materials
            .build_auto_binding_store()
            .expect_err("non-live material must not enable the live wrapper");

        let message = error.to_string();
        assert!(message.contains("session_secret_file"));
        assert!(message.contains("usable by live auto-binding"));
        assert!(!message.contains(&"bb".repeat(48)));
        Ok(())
    }

    #[test]
    fn invalid_session_secret_material_error_does_not_leak_secret_value()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = PathBuf::from("/tmp/session-secrets.jsonl");
        let material_plans = material_plans([("session-secrets", path.as_path())]);
        let store = MemoryTlsMaterialStore::default().with_file(
            &path,
            br#"{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"0000000000000000000000000000000000000000000000000000000000000000","secret":"not-a-secret"}"#.to_vec(),
        );

        let error = load_tls_session_secret_materials(&material_plans, &store)
            .expect_err("invalid configured session secret material must fail");

        let message = error.to_string();
        assert!(message.contains("session-secrets"));
        assert!(!message.contains("not-a-secret"));
        Ok(())
    }

    #[derive(Default)]
    struct MemoryTlsMaterialStore {
        files: BTreeMap<PathBuf, Vec<u8>>,
    }

    impl MemoryTlsMaterialStore {
        fn with_file(mut self, path: &Path, bytes: Vec<u8>) -> Self {
            self.files.insert(path.to_path_buf(), bytes);
            self
        }
    }

    impl TlsMaterialFileStore for MemoryTlsMaterialStore {
        fn inspect_tls_material(&self, path: &Path) -> Result<(), TlsMaterialFileStoreError> {
            self.files
                .contains_key(path)
                .then_some(())
                .ok_or(TlsMaterialFileStoreError::NotFound)
        }

        fn read_tls_material(&self, path: &Path) -> Result<Vec<u8>, TlsMaterialFileStoreError> {
            self.files
                .get(path)
                .cloned()
                .ok_or(TlsMaterialFileStoreError::NotFound)
        }
    }

    fn material_plans<'a>(
        materials: impl IntoIterator<Item = (&'a str, &'a Path)>,
    ) -> Vec<TlsPlaintextMaterialPlan> {
        materials
            .into_iter()
            .map(|(id, path)| TlsPlaintextMaterialPlan {
                id: id.to_string(),
                kind: TlsMaterialKind::SessionSecretFile,
                path: path.to_path_buf(),
            })
            .collect()
    }

    fn valid_session_secret(client_random_byte: &str, secret_byte: &str) -> String {
        valid_session_secret_fields(client_random_byte, secret_byte, None)
    }

    fn valid_session_secret_with_window(
        client_random_byte: &str,
        secret_byte: &str,
        not_before_unix_ns: u64,
        not_after_unix_ns: u64,
    ) -> String {
        valid_session_secret_fields(
            client_random_byte,
            secret_byte,
            Some((not_before_unix_ns, not_after_unix_ns)),
        )
    }

    fn tls12_master_secret(client_random_byte: &str, secret_byte: &str) -> String {
        format!(
            r#"{{"protocol":"tls12","secret_kind":"master_secret","client_random":"{}","secret":"{}"}}"#,
            client_random_byte.repeat(32),
            secret_byte.repeat(48),
        )
    }

    fn valid_session_secret_fields(
        client_random_byte: &str,
        secret_byte: &str,
        window: Option<(u64, u64)>,
    ) -> String {
        let window = window.map_or_else(String::new, |(not_before, not_after)| {
            format!(r#","not_before_unix_ns":{not_before},"not_after_unix_ns":{not_after}"#)
        });
        format!(
            r#"{{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"{}","cipher_suite":"0x1301","secret":"{}"{window}}}"#,
            client_random_byte.repeat(32),
            secret_byte.repeat(32),
        )
    }
}
