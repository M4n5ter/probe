use std::path::PathBuf;

use capture::{
    TlsKeyLog, TlsSessionSecretKind, TlsSessionSecretProtocol, TlsSessionSecretRecord,
    TlsSessionSecretStore,
};
use probe_config::TlsMaterialKind;
use runtime::TlsPlaintextMaterialPlan;
use thiserror::Error;

use crate::tls_material::{TlsMaterialFileStore, TlsMaterialFileStoreError};

use super::plan::TlsSessionSecretAutoBindingMaterial;

#[derive(Debug)]
pub(crate) enum TlsSessionSecretMaterialLoad {
    Ready(TlsSessionSecretStore),
    Pending,
}

pub(crate) fn load_tls_session_secret_auto_binding_material(
    materials: &[TlsSessionSecretAutoBindingMaterial],
    file_store: &(impl TlsMaterialFileStore + ?Sized),
) -> Result<TlsSessionSecretMaterialLoad, TlsDecryptHintError> {
    let records = match load_tls_auto_binding_records_if_available(materials, file_store)? {
        TlsAutoBindingMaterialSetOutcome::Ready(records) => records,
        TlsAutoBindingMaterialSetOutcome::Pending => {
            return Ok(TlsSessionSecretMaterialLoad::Pending);
        }
    };
    let store = TlsSessionSecretStore::from_time_qualified_lookup_records(records)
        .map_err(|source| TlsDecryptHintError::MaterialSet {
            reason: source.to_string(),
        })?
        .ok_or_else(|| TlsDecryptHintError::MaterialSet {
            reason: "TLS decrypt hint refs do not contain any TLS 1.3 application traffic secret record usable by live auto-binding".to_string(),
        })?;
    Ok(TlsSessionSecretMaterialLoad::Ready(store))
}

enum TlsAutoBindingMaterialSetOutcome {
    Ready(Vec<TlsSessionSecretRecord>),
    Pending,
}

enum TlsAutoBindingMaterialOutcome {
    Ready(Vec<TlsSessionSecretRecord>),
    Pending(TlsAutoBindingMaterialPending),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlsAutoBindingMaterialPending {
    Blocking,
    Idle,
}

fn load_tls_auto_binding_records_if_available(
    materials: &[TlsSessionSecretAutoBindingMaterial],
    file_store: &(impl TlsMaterialFileStore + ?Sized),
) -> Result<TlsAutoBindingMaterialSetOutcome, TlsDecryptHintError> {
    let mut blocking_pending_material = false;
    let mut records = Vec::new();
    for material in materials {
        match load_tls_auto_binding_material_records_if_available(material, file_store)? {
            TlsAutoBindingMaterialOutcome::Ready(material_records) => {
                records.extend(material_records);
            }
            TlsAutoBindingMaterialOutcome::Pending(TlsAutoBindingMaterialPending::Blocking) => {
                blocking_pending_material = true;
            }
            TlsAutoBindingMaterialOutcome::Pending(TlsAutoBindingMaterialPending::Idle) => {}
        }
    }
    if blocking_pending_material || records.is_empty() {
        return Ok(TlsAutoBindingMaterialSetOutcome::Pending);
    }
    Ok(TlsAutoBindingMaterialSetOutcome::Ready(records))
}

fn load_tls_auto_binding_material_records_if_available(
    material: &TlsSessionSecretAutoBindingMaterial,
    file_store: &(impl TlsMaterialFileStore + ?Sized),
) -> Result<TlsAutoBindingMaterialOutcome, TlsDecryptHintError> {
    let Some(bytes) = read_tls_material_if_available(material, file_store)? else {
        return Ok(TlsAutoBindingMaterialOutcome::Pending(
            pending_kind_for_material(material),
        ));
    };
    let records = decode_tls_auto_binding_material_records(material, &bytes)?;
    if records.is_empty() {
        return Ok(TlsAutoBindingMaterialOutcome::Pending(
            pending_kind_for_material(material),
        ));
    }
    Ok(TlsAutoBindingMaterialOutcome::Ready(records))
}

fn pending_kind_for_material(
    material: &TlsSessionSecretAutoBindingMaterial,
) -> TlsAutoBindingMaterialPending {
    match material {
        TlsSessionSecretAutoBindingMaterial::KeyLog(_) => TlsAutoBindingMaterialPending::Idle,
        TlsSessionSecretAutoBindingMaterial::SessionSecret(_) => {
            TlsAutoBindingMaterialPending::Blocking
        }
    }
}

fn read_tls_material_if_available(
    material: &TlsSessionSecretAutoBindingMaterial,
    file_store: &(impl TlsMaterialFileStore + ?Sized),
) -> Result<Option<Vec<u8>>, TlsDecryptHintError> {
    let material_plan = material.plan();
    let bytes = match file_store.read_tls_material(&material_plan.path) {
        Ok(bytes) => bytes,
        Err(TlsMaterialFileStoreError::NotFound) => return Ok(None),
        Err(source) => {
            return Err(tls_session_secret_plan_material_error(
                material_plan,
                source,
            ));
        }
    };
    if tls_session_secret_material_is_empty(&bytes) {
        return Ok(None);
    }
    Ok(Some(bytes))
}

fn decode_tls_session_secret_material(
    material: &TlsPlaintextMaterialPlan,
    bytes: &[u8],
) -> Result<TlsSessionSecretStore, TlsDecryptHintError> {
    TlsSessionSecretStore::parse(bytes)
        .map_err(|source| tls_session_secret_plan_material_error(material, source))
}

fn tls_session_secret_material_is_empty(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
}

fn decode_tls_auto_binding_material_records(
    material: &TlsSessionSecretAutoBindingMaterial,
    bytes: &[u8],
) -> Result<Vec<TlsSessionSecretRecord>, TlsDecryptHintError> {
    match material {
        TlsSessionSecretAutoBindingMaterial::SessionSecret(material) => {
            decode_tls_session_secret_auto_binding_records(material, bytes)
        }
        TlsSessionSecretAutoBindingMaterial::KeyLog(material) => {
            decode_tls_key_log_auto_binding_records(material, bytes)
        }
    }
}

fn decode_tls_session_secret_auto_binding_records(
    material: &TlsPlaintextMaterialPlan,
    bytes: &[u8],
) -> Result<Vec<TlsSessionSecretRecord>, TlsDecryptHintError> {
    let store = decode_tls_session_secret_material(material, bytes)?;
    let mut records = Vec::new();
    for record in store.records() {
        if let Some(record) = live_auto_binding_record(record) {
            records.push(record);
        }
    }
    if records.is_empty() {
        return Err(TlsDecryptHintError::MaterialSet {
            reason: format!(
                "session_secret_refs material {} ({:?}) at {:?} does not contain any session_secret_file TLS 1.3 application traffic secret record usable by live auto-binding",
                material.id, material.kind, material.path
            ),
        });
    }
    Ok(records)
}

fn decode_tls_key_log_auto_binding_records(
    material: &TlsPlaintextMaterialPlan,
    bytes: &[u8],
) -> Result<Vec<TlsSessionSecretRecord>, TlsDecryptHintError> {
    let key_log = TlsKeyLog::parse_live_snapshot(bytes)
        .map_err(|source| tls_session_secret_plan_material_error(material, source))?;
    let Some(store) = TlsSessionSecretStore::from_tls_key_log(&key_log).map_err(|source| {
        tls_session_secret_material_error(
            &material.id,
            material.kind,
            &material.path,
            source.to_string(),
        )
    })?
    else {
        return Ok(Vec::new());
    };
    Ok(store.records().to_vec())
}

fn live_auto_binding_record(record: &TlsSessionSecretRecord) -> Option<TlsSessionSecretRecord> {
    if record.protocol() != TlsSessionSecretProtocol::Tls13 {
        return None;
    }
    if !matches!(
        record.secret_kind(),
        TlsSessionSecretKind::ClientApplicationTraffic
            | TlsSessionSecretKind::ServerApplicationTraffic
    ) {
        return None;
    }
    Some(record.clone())
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
    TlsDecryptHintError::Material {
        id: id.to_string(),
        kind,
        path: path.to_path_buf(),
        reason: source.to_string(),
    }
}

#[derive(Debug, Error)]
pub(crate) enum TlsDecryptHintError {
    #[error("TLS decrypt hint material {id} ({kind:?}) at {path:?} is invalid: {reason}")]
    Material {
        id: String,
        kind: TlsMaterialKind,
        path: PathBuf,
        reason: String,
    },
    #[error("TLS decrypt hints are invalid: {reason}")]
    MaterialSet { reason: String },
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
        let material_plans = auto_session_secret_material_plans([
            ("session-secrets-a", first_path.as_path()),
            ("session-secrets-b", second_path.as_path()),
        ]);
        let store = MemoryTlsMaterialStore::default()
            .with_file(&first_path, valid_session_secret("00", "aa").into_bytes())
            .with_file(&second_path, valid_session_secret("11", "bb").into_bytes());

        let session_secrets = ready_auto_binding_store(&material_plans, &store)
            .expect("configured records should build a live auto-binding store");

        assert_eq!(session_secrets.records().len(), 2);
        Ok(())
    }

    #[test]
    fn duplicate_loaded_session_secret_records_are_deduped()
    -> Result<(), Box<dyn std::error::Error>> {
        let first_path = PathBuf::from("/tmp/session-secrets-a.jsonl");
        let second_path = PathBuf::from("/tmp/session-secrets-b.jsonl");
        let material_plans = auto_session_secret_material_plans([
            ("session-secrets-a", first_path.as_path()),
            ("session-secrets-b", second_path.as_path()),
        ]);
        let material = valid_session_secret("00", "aa").into_bytes();
        let store = MemoryTlsMaterialStore::default()
            .with_file(&first_path, material.clone())
            .with_file(&second_path, material);

        let session_secrets = ready_auto_binding_store(&material_plans, &store)
            .expect("configured records should build a live auto-binding store");

        assert_eq!(session_secrets.records().len(), 1);
        Ok(())
    }

    #[test]
    fn non_live_session_secret_records_do_not_enter_auto_binding_store()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = PathBuf::from("/tmp/session-secrets.jsonl");
        let material_plans = session_secret_material_plans([("session-secrets", path.as_path())]);
        let auto_materials = auto_binding_materials_from_plans(material_plans.clone());
        let material = format!(
            "{}\n{}",
            valid_session_secret("00", "aa"),
            tls12_master_secret("11", "bb")
        );
        let decoded = TlsSessionSecretStore::parse(material.as_bytes())?;
        let store = MemoryTlsMaterialStore::default().with_file(&path, material.into_bytes());

        let session_secrets = ready_auto_binding_store(&auto_materials, &store)?;

        assert_eq!(decoded.records().len(), 2);
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
        let material_plans = auto_session_secret_material_plans([
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

        let error = load_tls_session_secret_auto_binding_material(&material_plans, &store)
            .expect_err("overlapping lookup windows should fail closed");

        let message = error.to_string();
        assert!(message.contains("overlapping TLS session secret records"));
        assert!(!message.contains(&"aa".repeat(32)));
        assert!(!message.contains(&"bb".repeat(32)));
        Ok(())
    }

    #[test]
    fn application_traffic_secret_without_cipher_suite_enters_auto_binding_store()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = PathBuf::from("/tmp/session-secrets.jsonl");
        let material_plans =
            auto_session_secret_material_plans([("session-secrets", path.as_path())]);
        let material = format!(
            r#"{{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"{}","secret":"{}"}}"#,
            "00".repeat(32),
            "aa".repeat(32),
        );
        let store = MemoryTlsMaterialStore::default().with_file(&path, material.into_bytes());

        let session_secrets = ready_auto_binding_store(&material_plans, &store)
            .expect("ServerHello can resolve missing cipher suite during binding");

        assert_eq!(session_secrets.records().len(), 1);
        assert!(session_secrets.records()[0].cipher_suite().is_none());
        Ok(())
    }

    #[test]
    fn session_secret_refs_without_live_application_material_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = PathBuf::from("/tmp/session-secrets.jsonl");
        let material_plans =
            auto_session_secret_material_plans([("session-secrets", path.as_path())]);
        let store = MemoryTlsMaterialStore::default()
            .with_file(&path, tls12_master_secret("00", "bb").into_bytes());

        let error = load_tls_session_secret_auto_binding_material(&material_plans, &store)
            .expect_err("non-live material must not enable the live wrapper");

        let message = error.to_string();
        assert!(message.contains("session_secret_file"));
        assert!(message.contains("usable by live auto-binding"));
        assert!(!message.contains(&"bb".repeat(48)));
        Ok(())
    }

    #[test]
    fn key_log_material_builds_auto_binding_records_without_static_cipher_suite()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = PathBuf::from("/tmp/sslkeylog.log");
        let material_plans = key_log_material_plans([("ssl-keys", path.as_path())]);
        let material = format!(
            "CLIENT_TRAFFIC_SECRET_0 {} {}\n",
            "00".repeat(32),
            "aa".repeat(32)
        );
        let store = MemoryTlsMaterialStore::default().with_file(&path, material.into_bytes());

        let TlsSessionSecretMaterialLoad::Ready(session_secrets) =
            load_tls_session_secret_auto_binding_material(&material_plans, &store)?
        else {
            panic!("key log traffic secret should be ready for live auto-binding");
        };

        assert_eq!(session_secrets.records().len(), 1);
        assert_eq!(
            session_secrets.records()[0].secret_kind(),
            capture::TlsSessionSecretKind::ClientApplicationTraffic
        );
        assert!(session_secrets.records()[0].cipher_suite().is_none());
        Ok(())
    }

    #[test]
    fn key_log_material_without_application_secret_keeps_auto_binding_pending()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = PathBuf::from("/tmp/sslkeylog.log");
        let material_plans = key_log_material_plans([("ssl-keys", path.as_path())]);
        let material = format!(
            "# SSL key log\nCLIENT_RANDOM {} {}\n",
            "00".repeat(32),
            "bb".repeat(48)
        );
        let store = MemoryTlsMaterialStore::default().with_file(&path, material.into_bytes());

        let loaded = load_tls_session_secret_auto_binding_material(&material_plans, &store)?;

        assert!(matches!(loaded, TlsSessionSecretMaterialLoad::Pending));
        Ok(())
    }

    #[test]
    fn idle_key_log_material_does_not_block_ready_key_log_material()
    -> Result<(), Box<dyn std::error::Error>> {
        let ready_path = PathBuf::from("/tmp/ready-sslkeylog.log");
        let idle_path = PathBuf::from("/tmp/idle-sslkeylog.log");
        let material_plans = key_log_material_plans([
            ("ready-ssl-keys", ready_path.as_path()),
            ("idle-ssl-keys", idle_path.as_path()),
        ]);
        let ready_material = format!(
            "CLIENT_TRAFFIC_SECRET_0 {} {}\n",
            "00".repeat(32),
            "aa".repeat(32)
        );
        let idle_material = format!("CLIENT_RANDOM {} {}\n", "11".repeat(32), "bb".repeat(48));
        let store = MemoryTlsMaterialStore::default()
            .with_file(&ready_path, ready_material.into_bytes())
            .with_file(&idle_path, idle_material.into_bytes());

        let TlsSessionSecretMaterialLoad::Ready(session_secrets) =
            load_tls_session_secret_auto_binding_material(&material_plans, &store)?
        else {
            panic!("ready key log material should not be blocked by an idle key log file");
        };

        assert_eq!(session_secrets.records().len(), 1);
        Ok(())
    }

    #[test]
    fn live_key_log_material_ignores_trailing_partial_line()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = PathBuf::from("/tmp/sslkeylog.log");
        let material_plans = key_log_material_plans([("ssl-keys", path.as_path())]);
        let material = format!(
            "CLIENT_TRAFFIC_SECRET_0 {} {}\nCLIENT_TRAFFIC_SECRET_0 {} aa",
            "00".repeat(32),
            "aa".repeat(32),
            "11".repeat(32)
        );
        let store = MemoryTlsMaterialStore::default().with_file(&path, material.into_bytes());

        let TlsSessionSecretMaterialLoad::Ready(session_secrets) =
            load_tls_session_secret_auto_binding_material(&material_plans, &store)?
        else {
            panic!("complete key log prefix should remain usable during append");
        };

        assert_eq!(session_secrets.records().len(), 1);
        assert_eq!(
            session_secrets.records()[0].secret().as_bytes(),
            vec![0xaa; 32]
        );
        Ok(())
    }

    #[test]
    fn pending_session_secret_material_blocks_ready_key_log_replacement()
    -> Result<(), Box<dyn std::error::Error>> {
        let key_log_path = PathBuf::from("/tmp/sslkeylog.log");
        let session_secret_path = PathBuf::from("/tmp/session-secrets.jsonl");
        let mut material_plans = key_log_material_plans([("ssl-keys", key_log_path.as_path())]);
        material_plans.extend(auto_session_secret_material_plans([(
            "session-secrets",
            session_secret_path.as_path(),
        )]));
        let key_log_material = format!(
            "CLIENT_TRAFFIC_SECRET_0 {} {}\n",
            "00".repeat(32),
            "aa".repeat(32)
        );
        let store = MemoryTlsMaterialStore::default()
            .with_file(&key_log_path, key_log_material.into_bytes())
            .with_file(&session_secret_path, b"\n".to_vec());

        let loaded = load_tls_session_secret_auto_binding_material(&material_plans, &store)?;

        assert!(matches!(loaded, TlsSessionSecretMaterialLoad::Pending));
        Ok(())
    }

    #[test]
    fn invalid_session_secret_material_error_does_not_leak_secret_value()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = PathBuf::from("/tmp/session-secrets.jsonl");
        let material_plans = session_secret_material_plans([("session-secrets", path.as_path())]);
        let store = MemoryTlsMaterialStore::default().with_file(
            &path,
            br#"{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"0000000000000000000000000000000000000000000000000000000000000000","secret":"not-a-secret"}"#.to_vec(),
        );
        let bytes = store.read_tls_material(&path)?;

        let error = decode_tls_session_secret_material(&material_plans[0], &bytes)
            .expect_err("invalid configured session secret material must fail");

        let message = error.to_string();
        assert!(message.contains("session-secrets"));
        assert!(!message.contains("not-a-secret"));
        Ok(())
    }

    fn ready_auto_binding_store(
        material_plans: &[TlsSessionSecretAutoBindingMaterial],
        store: &MemoryTlsMaterialStore,
    ) -> Result<TlsSessionSecretStore, TlsDecryptHintError> {
        match load_tls_session_secret_auto_binding_material(material_plans, store)? {
            TlsSessionSecretMaterialLoad::Ready(store) => Ok(store),
            TlsSessionSecretMaterialLoad::Pending => Err(TlsDecryptHintError::MaterialSet {
                reason: "test material unexpectedly remained pending".to_string(),
            }),
        }
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

    fn session_secret_material_plans<'a>(
        materials: impl IntoIterator<Item = (&'a str, &'a Path)>,
    ) -> Vec<TlsPlaintextMaterialPlan> {
        material_plans_with_kind(TlsMaterialKind::SessionSecretFile, materials)
    }

    fn auto_session_secret_material_plans<'a>(
        materials: impl IntoIterator<Item = (&'a str, &'a Path)>,
    ) -> Vec<TlsSessionSecretAutoBindingMaterial> {
        auto_binding_materials_from_plans(session_secret_material_plans(materials))
    }

    fn key_log_material_plans<'a>(
        materials: impl IntoIterator<Item = (&'a str, &'a Path)>,
    ) -> Vec<TlsSessionSecretAutoBindingMaterial> {
        material_plans_with_kind(TlsMaterialKind::KeyLogFile, materials)
            .into_iter()
            .map(TlsSessionSecretAutoBindingMaterial::KeyLog)
            .collect()
    }

    fn auto_binding_materials_from_plans(
        materials: Vec<TlsPlaintextMaterialPlan>,
    ) -> Vec<TlsSessionSecretAutoBindingMaterial> {
        materials
            .into_iter()
            .map(TlsSessionSecretAutoBindingMaterial::SessionSecret)
            .collect()
    }

    fn material_plans_with_kind<'a>(
        kind: TlsMaterialKind,
        materials: impl IntoIterator<Item = (&'a str, &'a Path)>,
    ) -> Vec<TlsPlaintextMaterialPlan> {
        materials
            .into_iter()
            .map(|(id, path)| TlsPlaintextMaterialPlan {
                id: id.to_string(),
                kind,
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
