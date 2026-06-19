use std::time::{Duration, Instant};

use capture::TlsSessionSecretStore;
use runtime::TlsPlaintextMaterialPlan;

use crate::tls_material::TlsMaterialFileStore;

use super::super::{
    material::{
        TlsDecryptHintError, TlsSessionSecretMaterialLoad,
        load_tls_session_secret_auto_binding_material,
    },
    runtime::{TlsDecryptHintRuntimeState, TlsSessionSecretRefreshRuntimeTransition},
};

pub(crate) struct TlsSessionSecretAutoBindingRuntime {
    initial_store: Option<TlsSessionSecretStore>,
    refresh: TlsSessionSecretMaterialRefresh,
    runtime_state: Option<TlsDecryptHintRuntimeState>,
}

impl TlsSessionSecretAutoBindingRuntime {
    pub(super) fn new(
        materials: Vec<TlsPlaintextMaterialPlan>,
        file_store: Box<dyn TlsMaterialFileStore>,
        refresh_interval: Duration,
        runtime_state: Option<TlsDecryptHintRuntimeState>,
    ) -> Result<Self, TlsDecryptHintError> {
        let initial_store =
            match load_tls_session_secret_auto_binding_material(&materials, file_store.as_ref())? {
                TlsSessionSecretMaterialLoad::Ready(store) => {
                    if let Some(runtime_state) = &runtime_state {
                        runtime_state.record_session_secret_refresh(
                            TlsSessionSecretRefreshRuntimeTransition::InitialReady,
                        );
                    }
                    Some(store)
                }
                TlsSessionSecretMaterialLoad::Pending => {
                    if let Some(runtime_state) = &runtime_state {
                        runtime_state.record_session_secret_refresh(
                            TlsSessionSecretRefreshRuntimeTransition::InitialPending,
                        );
                    }
                    None
                }
            };
        Ok(Self {
            initial_store,
            refresh: TlsSessionSecretMaterialRefresh::new(materials, file_store, refresh_interval),
            runtime_state,
        })
    }

    pub(super) fn into_parts(
        self,
    ) -> (
        Option<TlsSessionSecretStore>,
        TlsSessionSecretMaterialRefresh,
        Option<TlsDecryptHintRuntimeState>,
    ) {
        (self.initial_store, self.refresh, self.runtime_state)
    }

    #[cfg(test)]
    pub(super) fn defer_refresh_for_test(&mut self, delay: Duration) {
        self.refresh.next_refresh = Instant::now() + delay;
    }
}

pub(super) struct TlsSessionSecretMaterialRefresh {
    materials: Vec<TlsPlaintextMaterialPlan>,
    file_store: Box<dyn TlsMaterialFileStore>,
    refresh_interval: Duration,
    next_refresh: Instant,
}

impl TlsSessionSecretMaterialRefresh {
    fn new(
        materials: Vec<TlsPlaintextMaterialPlan>,
        file_store: Box<dyn TlsMaterialFileStore>,
        refresh_interval: Duration,
    ) -> Self {
        Self {
            materials,
            file_store,
            refresh_interval,
            next_refresh: Instant::now() + refresh_interval,
        }
    }

    pub(super) fn refresh_if_due(&mut self, now: Instant) -> TlsSessionSecretRefreshOutcome {
        if now < self.next_refresh {
            return TlsSessionSecretRefreshOutcome::NotDue;
        }
        self.next_refresh = now + self.refresh_interval;
        match load_tls_session_secret_auto_binding_material(
            &self.materials,
            self.file_store.as_ref(),
        ) {
            Ok(TlsSessionSecretMaterialLoad::Ready(store)) => {
                TlsSessionSecretRefreshOutcome::Ready(store)
            }
            Ok(TlsSessionSecretMaterialLoad::Pending) => TlsSessionSecretRefreshOutcome::Pending,
            Err(error) => {
                let reason = error.to_string();
                tracing::warn!(
                    target: "sssa_probe::tls_session_secret",
                    error = %reason,
                    "skipping TLS session-secret material refresh"
                );
                TlsSessionSecretRefreshOutcome::Failed { reason }
            }
        }
    }

    #[cfg(test)]
    pub(super) fn next_refresh(&self) -> Instant {
        self.next_refresh
    }

    #[cfg(test)]
    pub(super) fn force_due_for_test(&mut self) {
        self.next_refresh = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .unwrap_or_else(Instant::now);
    }
}

pub(super) enum TlsSessionSecretRefreshOutcome {
    NotDue,
    Pending,
    Ready(TlsSessionSecretStore),
    Failed { reason: String },
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, VecDeque},
        path::{Path, PathBuf},
        sync::{Arc, Mutex},
    };

    use probe_config::TlsMaterialKind;
    use runtime::TlsPlaintextMaterialPlan;

    use super::*;
    use crate::tls_material::TlsMaterialFileStoreError;

    #[test]
    fn runtime_session_secret_refresh_error_returns_no_store_until_later_material()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = PathBuf::from("/tmp/session-secrets.jsonl");
        let mut refresh = TlsSessionSecretMaterialRefresh::new(
            material_plans([("session-secrets", path.as_path())]),
            Box::new(ScriptedTlsMaterialStore::default().with_reads(
                &path,
                [
                    Ok(br#"{"#.to_vec()),
                    Ok(valid_session_secret("00", "aa").into_bytes()),
                ],
            )),
            Duration::from_millis(1),
        );

        let first_due = refresh.next_refresh();
        assert!(matches!(
            refresh.refresh_if_due(first_due),
            TlsSessionSecretRefreshOutcome::Failed { .. }
        ));

        let second_due = refresh.next_refresh();
        let refreshed = assert_ready_refresh(refresh.refresh_if_due(second_due));

        assert_eq!(refreshed.records().len(), 1);
        Ok(())
    }

    #[test]
    fn runtime_pending_session_secret_refresh_returns_no_store_until_later_material()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = PathBuf::from("/tmp/session-secrets.jsonl");
        let mut refresh = TlsSessionSecretMaterialRefresh::new(
            material_plans([("session-secrets", path.as_path())]),
            Box::new(ScriptedTlsMaterialStore::default().with_reads(
                &path,
                [
                    Ok(b"\n".to_vec()),
                    Ok(valid_session_secret("00", "aa").into_bytes()),
                ],
            )),
            Duration::from_millis(1),
        );

        let first_due = refresh.next_refresh();
        assert!(matches!(
            refresh.refresh_if_due(first_due),
            TlsSessionSecretRefreshOutcome::Pending
        ));

        let second_due = refresh.next_refresh();
        let refreshed = assert_ready_refresh(refresh.refresh_if_due(second_due));

        assert_eq!(refreshed.records().len(), 1);
        Ok(())
    }

    #[test]
    fn runtime_partial_session_secret_refresh_returns_no_store_until_all_refs_are_ready()
    -> Result<(), Box<dyn std::error::Error>> {
        let first_path = PathBuf::from("/tmp/session-secrets-a.jsonl");
        let second_path = PathBuf::from("/tmp/session-secrets-b.jsonl");
        let mut refresh = TlsSessionSecretMaterialRefresh::new(
            material_plans([
                ("session-secrets-a", first_path.as_path()),
                ("session-secrets-b", second_path.as_path()),
            ]),
            Box::new(
                ScriptedTlsMaterialStore::default()
                    .with_reads(
                        &first_path,
                        [
                            Ok(valid_session_secret("00", "aa").into_bytes()),
                            Ok(valid_session_secret("00", "aa").into_bytes()),
                        ],
                    )
                    .with_reads(
                        &second_path,
                        [
                            Ok(b"\n".to_vec()),
                            Ok(valid_session_secret("11", "bb").into_bytes()),
                        ],
                    ),
            ),
            Duration::from_millis(1),
        );

        let first_due = refresh.next_refresh();
        assert!(matches!(
            refresh.refresh_if_due(first_due),
            TlsSessionSecretRefreshOutcome::Pending
        ));

        let second_due = refresh.next_refresh();
        let refreshed = assert_ready_refresh(refresh.refresh_if_due(second_due));

        assert_eq!(refreshed.records().len(), 2);
        Ok(())
    }

    #[derive(Clone, Default)]
    struct ScriptedTlsMaterialStore {
        reads: MaterialReadScripts,
    }

    type MaterialReadScripts =
        Arc<Mutex<BTreeMap<PathBuf, VecDeque<Result<Vec<u8>, TlsMaterialFileStoreError>>>>>;

    impl ScriptedTlsMaterialStore {
        fn with_reads(
            self,
            path: &Path,
            reads: impl IntoIterator<Item = Result<Vec<u8>, TlsMaterialFileStoreError>>,
        ) -> Self {
            self.reads
                .lock()
                .expect("scripted material store lock should not be poisoned")
                .insert(path.to_path_buf(), reads.into_iter().collect());
            self
        }
    }

    impl TlsMaterialFileStore for ScriptedTlsMaterialStore {
        fn inspect_tls_material(&self, path: &Path) -> Result<(), TlsMaterialFileStoreError> {
            self.reads
                .lock()
                .expect("scripted material store lock should not be poisoned")
                .contains_key(path)
                .then_some(())
                .ok_or(TlsMaterialFileStoreError::NotFound)
        }

        fn read_tls_material(&self, path: &Path) -> Result<Vec<u8>, TlsMaterialFileStoreError> {
            let mut reads = self
                .reads
                .lock()
                .expect("scripted material store lock should not be poisoned");
            let Some(reads) = reads.get_mut(path) else {
                return Err(TlsMaterialFileStoreError::NotFound);
            };
            reads
                .pop_front()
                .unwrap_or(Err(TlsMaterialFileStoreError::NotFound))
        }
    }

    fn assert_ready_refresh(outcome: TlsSessionSecretRefreshOutcome) -> TlsSessionSecretStore {
        match outcome {
            TlsSessionSecretRefreshOutcome::Ready(store) => store,
            TlsSessionSecretRefreshOutcome::NotDue => panic!("refresh was not due"),
            TlsSessionSecretRefreshOutcome::Pending => panic!("refresh material was still pending"),
            TlsSessionSecretRefreshOutcome::Failed { .. } => {
                panic!("refresh material failed to parse")
            }
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
        format!(
            r#"{{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"{}","cipher_suite":"0x1301","secret":"{}"}}"#,
            client_random_byte.repeat(32),
            secret_byte.repeat(32),
        )
    }
}
