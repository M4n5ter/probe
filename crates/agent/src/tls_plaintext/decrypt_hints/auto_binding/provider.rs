use std::time::{Duration, Instant};

use capture::{CaptureError, CapturePoll, CaptureProvider, Tls13SessionSecretAutoBindingProvider};
use probe_core::CapabilityState;
use runtime::RuntimePlan;

use crate::tls_material::{FilesystemTlsMaterialStore, TlsMaterialFileStore};

use super::super::{
    material::TlsDecryptHintError,
    plan::TlsSessionSecretAutoBindingPlan,
    runtime::{TlsDecryptHintRuntimeState, TlsSessionSecretRefreshRuntimeTransition},
};
use super::refresh::{
    TlsSessionSecretAutoBindingRuntime, TlsSessionSecretMaterialRefresh,
    TlsSessionSecretRefreshOutcome,
};

pub(crate) fn build_tls_session_secret_auto_binding_with_runtime(
    plan: &RuntimePlan,
    runtime_state: Option<&TlsDecryptHintRuntimeState>,
) -> Result<TlsSessionSecretAutoBindingBuild, TlsDecryptHintError> {
    let file_store = FilesystemTlsMaterialStore::from_plan(&plan.tls_material_store);
    build_tls_session_secret_auto_binding_with_store_and_runtime(plan, file_store, runtime_state)
}

#[cfg(test)]
fn build_tls_session_secret_auto_binding_with_store(
    plan: &RuntimePlan,
    file_store: impl TlsMaterialFileStore + 'static,
) -> Result<TlsSessionSecretAutoBindingBuild, TlsDecryptHintError> {
    build_tls_session_secret_auto_binding_with_store_and_runtime(plan, file_store, None)
}

fn build_tls_session_secret_auto_binding_with_store_and_runtime(
    plan: &RuntimePlan,
    file_store: impl TlsMaterialFileStore + 'static,
    runtime_state: Option<&TlsDecryptHintRuntimeState>,
) -> Result<TlsSessionSecretAutoBindingBuild, TlsDecryptHintError> {
    match TlsSessionSecretAutoBindingPlan::for_runtime(plan) {
        TlsSessionSecretAutoBindingPlan::Disabled => {
            Ok(TlsSessionSecretAutoBindingBuild::NotConfigured)
        }
        TlsSessionSecretAutoBindingPlan::Enabled(materials) => Ok(
            TlsSessionSecretAutoBindingBuild::Enabled(TlsSessionSecretAutoBindingRuntime::new(
                materials.to_owned_materials(),
                Box::new(file_store),
                Duration::from_millis(plan.tls.plaintext.decrypt_hints.refresh_interval_ms),
                runtime_state.cloned(),
            )?),
        ),
    }
}

pub(crate) enum TlsSessionSecretAutoBindingBuild {
    NotConfigured,
    Enabled(TlsSessionSecretAutoBindingRuntime),
}

impl TlsSessionSecretAutoBindingBuild {
    pub(crate) fn wrap(self, primary: Box<dyn CaptureProvider>) -> Box<dyn CaptureProvider> {
        match self {
            Self::NotConfigured => primary,
            Self::Enabled(refresh) => Box::new(TlsSessionSecretRefreshingAutoBindingProvider::new(
                primary, refresh,
            )),
        }
    }
}

struct TlsSessionSecretRefreshingAutoBindingProvider {
    provider: Tls13SessionSecretAutoBindingProvider,
    refresh: TlsSessionSecretMaterialRefresh,
    runtime_state: Option<TlsDecryptHintRuntimeState>,
}

impl TlsSessionSecretRefreshingAutoBindingProvider {
    fn new(primary: Box<dyn CaptureProvider>, runtime: TlsSessionSecretAutoBindingRuntime) -> Self {
        let (initial_store, refresh, runtime_state) = runtime.into_parts();
        let provider = match initial_store {
            Some(store) => Tls13SessionSecretAutoBindingProvider::new(primary, store),
            None => Tls13SessionSecretAutoBindingProvider::new_pending(primary),
        };
        Self {
            provider,
            refresh,
            runtime_state,
        }
    }

    fn refresh_if_due(&mut self) -> Result<(), CaptureError> {
        match self.refresh.refresh_if_due(Instant::now()) {
            TlsSessionSecretRefreshOutcome::Ready(store) => {
                self.provider.replace_store(store);
                if let Some(runtime_state) = &self.runtime_state {
                    runtime_state.record_session_secret_refresh(
                        TlsSessionSecretRefreshRuntimeTransition::RefreshReady,
                    );
                }
            }
            TlsSessionSecretRefreshOutcome::Pending => {
                if let Some(runtime_state) = &self.runtime_state {
                    runtime_state.record_session_secret_refresh(
                        TlsSessionSecretRefreshRuntimeTransition::RefreshPending,
                    );
                }
            }
            TlsSessionSecretRefreshOutcome::Failed { reason } => {
                if let Some(runtime_state) = &self.runtime_state {
                    runtime_state.record_session_secret_refresh(
                        TlsSessionSecretRefreshRuntimeTransition::RefreshFailed { reason },
                    );
                }
            }
            TlsSessionSecretRefreshOutcome::NotDue => {}
        }
        Ok(())
    }

    #[cfg(test)]
    fn force_refresh_due(&mut self) {
        self.refresh.force_due_for_test();
    }
}

impl CaptureProvider for TlsSessionSecretRefreshingAutoBindingProvider {
    fn name(&self) -> &'static str {
        self.provider.name()
    }

    fn capabilities(&self) -> Vec<CapabilityState> {
        self.provider.capabilities()
    }

    fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
        self.refresh_if_due()?;
        self.provider.poll_next()
    }

    fn drain_before_handoff(&mut self) -> Result<CapturePoll, CaptureError> {
        self.provider.drain_before_handoff()
    }

    fn runtime_diagnostics(&mut self) -> capture::CaptureProviderRuntimeDiagnostics {
        self.provider.runtime_diagnostics()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, VecDeque},
        path::{Path, PathBuf},
        sync::{Arc, Mutex},
    };

    use capture::{
        CaptureError, CaptureEvent, CapturePoll, CapturedBytes, EnforcementEvidencePropagation,
        Tls13ApplicationDataDecryptor, Tls13SessionSecretHandshakeObservationKind,
        Tls13SessionSecretHandshakeObserver, TlsSessionSecretStore,
    };
    use probe_config::{AgentConfig, CaptureSelection, TlsMaterialConfig, TlsMaterialKind};
    use probe_core::{
        AddressPort, CapabilityKind, CapabilityState, CaptureOrigin, CaptureSource, Direction,
        EnforcementEvidence, FlowContext, FlowIdentity, ProcessContext, ProcessIdentity,
        RuntimeMode, Timestamp, TransportProtocol,
    };
    use runtime::{CaptureProviderBuilder, CaptureProviderDescriptor, ProviderRegistry};

    use super::super::super::runtime::TlsSessionSecretRefreshRuntimeMode;
    use super::*;
    use crate::tls_material::TlsMaterialFileStoreError;

    #[test]
    fn absent_session_secret_hints_keep_primary_provider() -> Result<(), Box<dyn std::error::Error>>
    {
        let plan = runtime_plan(AgentConfig::default())?;

        let provider = build_tls_session_secret_auto_binding_with_store(
            &plan,
            MemoryTlsMaterialStore::default(),
        )?
        .wrap(Box::new(NoopCaptureProvider));

        assert_eq!(provider.name(), "noop");
        assert!(provider.capabilities().is_empty());
        Ok(())
    }

    #[test]
    fn session_secret_hints_wrap_primary_provider() -> Result<(), Box<dyn std::error::Error>> {
        let path = PathBuf::from("/tmp/session-secrets.jsonl");
        let mut config = config_with_session_secret_material("session-secrets", &path);
        config.capture.selection = CaptureSelection::Libpcap;
        let plan = runtime_plan(config)?;
        let store = MemoryTlsMaterialStore::default()
            .with_file(&path, valid_session_secret("00", "aa").into_bytes());

        let provider = build_tls_session_secret_auto_binding_with_store(&plan, store)?
            .wrap(Box::new(NoopCaptureProvider));

        assert_eq!(provider.name(), "tls_session_secret_auto_binding");
        assert!(provider.capabilities().iter().any(|capability| {
            capability.kind == CapabilityKind::TlsSessionSecretRecordDecrypt
                && capability.mode == RuntimeMode::Degraded
        }));
        Ok(())
    }

    #[test]
    fn key_log_hints_wrap_primary_provider() -> Result<(), Box<dyn std::error::Error>> {
        let path = PathBuf::from("/tmp/sslkeylog.log");
        let mut config = config_with_key_log_material("ssl-keys", &path);
        config.capture.selection = CaptureSelection::Libpcap;
        let plan = runtime_plan(config)?;
        let store = MemoryTlsMaterialStore::default().with_file(
            &path,
            format!(
                "CLIENT_TRAFFIC_SECRET_0 {} {}\n",
                "00".repeat(32),
                "aa".repeat(32)
            )
            .into_bytes(),
        );

        let provider = build_tls_session_secret_auto_binding_with_store(&plan, store)?
            .wrap(Box::new(NoopCaptureProvider));

        assert_eq!(provider.name(), "tls_session_secret_auto_binding");
        assert!(provider.capabilities().iter().any(|capability| {
            capability.kind == CapabilityKind::TlsSessionSecretRecordDecrypt
                && capability.mode == RuntimeMode::Degraded
        }));
        Ok(())
    }

    #[test]
    fn empty_session_secret_file_keeps_live_auto_binding_enabled_for_refresh()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = PathBuf::from("/tmp/session-secrets.jsonl");
        let mut config = config_with_session_secret_material("session-secrets", &path);
        config.capture.selection = CaptureSelection::Libpcap;
        let plan = runtime_plan(config)?;
        let store = MemoryTlsMaterialStore::default().with_file(&path, b"\n\t\n".to_vec());

        let provider = build_tls_session_secret_auto_binding_with_store(&plan, store)?
            .wrap(Box::new(NoopCaptureProvider));

        assert_eq!(provider.name(), "tls_session_secret_auto_binding");
        Ok(())
    }

    #[test]
    fn live_auto_binding_refresh_does_not_partially_replace_active_store()
    -> Result<(), Box<dyn std::error::Error>> {
        let first_path = PathBuf::from("/tmp/session-secrets-a.jsonl");
        let second_path = PathBuf::from("/tmp/session-secrets-b.jsonl");
        let config = config_with_session_secret_materials([
            ("session-secrets-a", first_path.as_path()),
            ("session-secrets-b", second_path.as_path()),
        ]);
        let plan = runtime_plan(config)?;
        let fixture = SyntheticTls13AutoBindingFixture;
        fixture.validate()?;
        let runtime_state = TlsDecryptHintRuntimeState::for_plan(&plan);
        let store = ScriptedTlsMaterialStore::default()
            .with_reads(
                &first_path,
                [
                    Ok(fixture
                        .session_secret_material_jsonl(SHA256_TRAFFIC_SECRET)
                        .into_bytes()),
                    Ok(fixture
                        .session_secret_material_jsonl(&"ff".repeat(32))
                        .into_bytes()),
                ],
            )
            .with_reads(
                &second_path,
                [
                    Ok(valid_session_secret("11", "bb").into_bytes()),
                    Ok(b"\n".to_vec()),
                ],
            );
        let mut runtime = TlsSessionSecretAutoBindingRuntime::new(
            auto_binding_materials(&plan),
            Box::new(store),
            Duration::from_millis(1),
            Some(runtime_state.clone()),
        )?;
        runtime.defer_refresh_for_test(Duration::from_secs(60));
        let initial_refresh = runtime_state.snapshot().session_secret_refresh;
        assert_eq!(
            initial_refresh.mode,
            TlsSessionSecretRefreshRuntimeMode::Active
        );
        assert_eq!(initial_refresh.generation, 1);
        let mut provider = TlsSessionSecretRefreshingAutoBindingProvider::new(
            Box::new(VecCaptureProvider::new([
                CaptureEvent::Bytes(fixture.client_hello()),
                CaptureEvent::Bytes(fixture.application_record()),
            ])),
            runtime,
        );

        assert_next_provider_bytes(
            &mut provider,
            CaptureSource::Libpcap,
            fixture.client_hello_record().as_slice(),
        )?;
        provider.force_refresh_due();
        let bytes = assert_next_provider_bytes(
            &mut provider,
            CaptureSource::TlsSessionSecret,
            fixture.expected_plaintext().as_slice(),
        )?;

        assert!(bytes.degraded);
        let refresh = runtime_state.snapshot().session_secret_refresh;
        assert_eq!(refresh.mode, TlsSessionSecretRefreshRuntimeMode::Active);
        assert_eq!(refresh.generation, 1);
        assert_eq!(refresh.attempts, 1);
        assert_eq!(refresh.pending, 1);
        assert_eq!(refresh.failures, 0);
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn live_auto_binding_refresh_rejects_non_live_ref_without_replacing_active_store()
    -> Result<(), Box<dyn std::error::Error>> {
        let first_path = PathBuf::from("/tmp/session-secrets-a.jsonl");
        let second_path = PathBuf::from("/tmp/session-secrets-b.jsonl");
        let config = config_with_session_secret_materials([
            ("session-secrets-a", first_path.as_path()),
            ("session-secrets-b", second_path.as_path()),
        ]);
        let plan = runtime_plan(config)?;
        let fixture = SyntheticTls13AutoBindingFixture;
        fixture.validate()?;
        let runtime_state = TlsDecryptHintRuntimeState::for_plan(&plan);
        let store = ScriptedTlsMaterialStore::default()
            .with_reads(
                &first_path,
                [
                    Ok(fixture
                        .session_secret_material_jsonl(SHA256_TRAFFIC_SECRET)
                        .into_bytes()),
                    Ok(fixture
                        .session_secret_material_jsonl(&"ff".repeat(32))
                        .into_bytes()),
                ],
            )
            .with_reads(
                &second_path,
                [
                    Ok(valid_session_secret("11", "bb").into_bytes()),
                    Ok(tls12_master_secret("22", "cc").into_bytes()),
                ],
            );
        let mut runtime = TlsSessionSecretAutoBindingRuntime::new(
            auto_binding_materials(&plan),
            Box::new(store),
            Duration::from_millis(1),
            Some(runtime_state.clone()),
        )?;
        runtime.defer_refresh_for_test(Duration::from_secs(60));
        let mut provider = TlsSessionSecretRefreshingAutoBindingProvider::new(
            Box::new(VecCaptureProvider::new([
                CaptureEvent::Bytes(fixture.client_hello()),
                CaptureEvent::Bytes(fixture.application_record()),
            ])),
            runtime,
        );

        assert_next_provider_bytes(
            &mut provider,
            CaptureSource::Libpcap,
            fixture.client_hello_record().as_slice(),
        )?;
        provider.force_refresh_due();
        let bytes = assert_next_provider_bytes(
            &mut provider,
            CaptureSource::TlsSessionSecret,
            fixture.expected_plaintext().as_slice(),
        )?;

        assert!(bytes.degraded);
        let refresh = runtime_state.snapshot().session_secret_refresh;
        assert_eq!(refresh.mode, TlsSessionSecretRefreshRuntimeMode::Active);
        assert_eq!(refresh.generation, 1);
        assert_eq!(refresh.attempts, 1);
        assert_eq!(refresh.pending, 0);
        assert_eq!(refresh.failures, 1);
        assert!(
            refresh
                .last_failure
                .as_deref()
                .is_some_and(|error| error.contains("session_secret_file"))
        );
        assert!(provider.next()?.is_none());
        Ok(())
    }

    #[test]
    fn non_pending_session_secret_refs_without_live_material_still_fail_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = PathBuf::from("/tmp/session-secrets.jsonl");
        let mut config = config_with_session_secret_material("session-secrets", &path);
        config.capture.selection = CaptureSelection::Libpcap;
        let plan = runtime_plan(config)?;
        let store = MemoryTlsMaterialStore::default()
            .with_file(&path, tls12_master_secret("00", "bb").into_bytes());

        let error = match build_tls_session_secret_auto_binding_with_store(&plan, store) {
            Ok(_) => panic!("non-empty material without live app secrets must fail closed"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("session_secret_file"));
        Ok(())
    }

    #[test]
    fn plaintext_feed_capture_does_not_enable_session_secret_auto_binding()
    -> Result<(), Box<dyn std::error::Error>> {
        let path = PathBuf::from("/tmp/session-secrets.jsonl");
        let mut config = config_with_session_secret_material("session-secrets", &path);
        config.capture.selection = CaptureSelection::PlaintextFeed;
        config.capture.plaintext_feed.path = Some("/tmp/plaintext-feed.jsonl".into());
        let plan = runtime_plan(config)?;
        let store = MemoryTlsMaterialStore::default()
            .with_file(&path, tls12_master_secret("00", "bb").into_bytes());

        let provider = build_tls_session_secret_auto_binding_with_store(&plan, store)?
            .wrap(Box::new(NoopCaptureProvider));

        assert_eq!(provider.name(), "noop");
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
        fn inspect_tls_material(
            &self,
            _kind: TlsMaterialKind,
            path: &Path,
        ) -> Result<(), TlsMaterialFileStoreError> {
            self.files
                .contains_key(path)
                .then_some(())
                .ok_or(TlsMaterialFileStoreError::NotFound)
        }

        fn read_tls_material(
            &self,
            _kind: TlsMaterialKind,
            path: &Path,
        ) -> Result<Vec<u8>, TlsMaterialFileStoreError> {
            self.files
                .get(path)
                .cloned()
                .ok_or(TlsMaterialFileStoreError::NotFound)
        }
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
        fn inspect_tls_material(
            &self,
            _kind: TlsMaterialKind,
            path: &Path,
        ) -> Result<(), TlsMaterialFileStoreError> {
            self.reads
                .lock()
                .expect("scripted material store lock should not be poisoned")
                .contains_key(path)
                .then_some(())
                .ok_or(TlsMaterialFileStoreError::NotFound)
        }

        fn read_tls_material(
            &self,
            _kind: TlsMaterialKind,
            path: &Path,
        ) -> Result<Vec<u8>, TlsMaterialFileStoreError> {
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

    struct NoopCaptureProvider;

    impl CaptureProvider for NoopCaptureProvider {
        fn name(&self) -> &'static str {
            "noop"
        }

        fn capabilities(&self) -> Vec<CapabilityState> {
            Vec::new()
        }

        fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
            Ok(CapturePoll::Finished)
        }

        fn drain_before_handoff(&mut self) -> Result<CapturePoll, CaptureError> {
            Ok(CapturePoll::Finished)
        }
    }

    struct VecCaptureProvider {
        events: VecDeque<CaptureEvent>,
    }

    impl VecCaptureProvider {
        fn new(events: impl IntoIterator<Item = CaptureEvent>) -> Self {
            Self {
                events: events.into_iter().collect(),
            }
        }
    }

    impl CaptureProvider for VecCaptureProvider {
        fn name(&self) -> &'static str {
            "vec"
        }

        fn capabilities(&self) -> Vec<CapabilityState> {
            vec![CapabilityState::available(CapabilityKind::Libpcap)]
        }

        fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
            Ok(self
                .events
                .pop_front()
                .map(CapturePoll::event)
                .unwrap_or(CapturePoll::Finished))
        }

        fn drain_before_handoff(&mut self) -> Result<CapturePoll, CaptureError> {
            self.poll_next()
        }
    }

    fn assert_next_provider_bytes(
        provider: &mut impl CaptureProvider,
        source: CaptureSource,
        expected: &[u8],
    ) -> Result<CapturedBytes, Box<dyn std::error::Error>> {
        let Some(CaptureEvent::Bytes(bytes)) = provider.next()? else {
            panic!("expected bytes event");
        };
        assert_eq!(bytes.origin.source(), source);
        assert_eq!(bytes.bytes.as_ref(), expected);
        Ok(bytes)
    }

    fn config_with_session_secret_material(id: &str, path: &Path) -> AgentConfig {
        config_with_session_secret_materials([(id, path)])
    }

    fn config_with_key_log_material(id: &str, path: &Path) -> AgentConfig {
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Libpcap;
        config
            .tls
            .plaintext
            .decrypt_hints
            .key_log_refs
            .push(id.to_string());
        config.tls.materials.push(TlsMaterialConfig {
            id: Some(id.to_string()),
            kind: TlsMaterialKind::KeyLogFile,
            path: path.to_path_buf(),
        });
        config
    }

    fn config_with_session_secret_materials<'a>(
        materials: impl IntoIterator<Item = (&'a str, &'a Path)>,
    ) -> AgentConfig {
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Libpcap;
        for (id, path) in materials {
            config
                .tls
                .plaintext
                .decrypt_hints
                .session_secret_refs
                .push(id.to_string());
            config.tls.materials.push(TlsMaterialConfig {
                id: Some(id.to_string()),
                kind: TlsMaterialKind::SessionSecretFile,
                path: path.to_path_buf(),
            });
        }
        config
    }

    fn runtime_plan(config: AgentConfig) -> Result<RuntimePlan, runtime::RuntimeError> {
        let registry = ProviderRegistry::new(
            vec![
                CaptureProviderDescriptor::available(
                    probe_config::CaptureBackend::Libpcap,
                    CaptureProviderBuilder::Libpcap,
                ),
                CaptureProviderDescriptor::available(
                    probe_config::CaptureBackend::PlaintextFeed,
                    CaptureProviderBuilder::PlaintextFeed,
                ),
            ],
            Vec::new(),
        );
        RuntimePlan::build(config, &registry)
    }

    fn valid_session_secret(client_random_byte: &str, secret_byte: &str) -> String {
        valid_session_secret_fields(client_random_byte, secret_byte, None)
    }

    fn tls12_master_secret(client_random_byte: &str, secret_byte: &str) -> String {
        format!(
            r#"{{"protocol":"tls12","secret_kind":"master_secret","client_random":"{}","secret":"{}"}}"#,
            client_random_byte.repeat(32),
            secret_byte.repeat(48),
        )
    }

    fn auto_binding_materials(
        plan: &runtime::RuntimePlan,
    ) -> Vec<crate::tls_plaintext::decrypt_hints::plan::TlsSessionSecretAutoBindingMaterial> {
        TlsSessionSecretAutoBindingPlan::for_runtime(plan)
            .enabled_materials()
            .expect("test plan should enable live auto-binding")
            .to_owned_materials()
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

    const CLIENT_RANDOM_BYTES: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const SHA256_TRAFFIC_SECRET: &str =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
    const TLS13_VERSION: [u8; 2] = [0x03, 0x04];
    const TLS_LEGACY_RECORD_VERSION: [u8; 2] = [0x03, 0x03];
    const TLS_HANDSHAKE_CONTENT_TYPE: u8 = 0x16;
    const TLS_CLIENT_HELLO: u8 = 0x01;
    const SYNTHETIC_APPLICATION_RECORD: &[u8] = &[
        0x17, 0x03, 0x03, 0x00, 0x35, 0x62, 0x4d, 0xb3, 0x1e, 0x84, 0x42, 0x03, 0xee, 0xd7, 0x0e,
        0xd8, 0x95, 0x90, 0x7c, 0x1d, 0xba, 0x83, 0xb7, 0x98, 0x3b, 0xed, 0x37, 0xe4, 0x48, 0xfe,
        0xf6, 0x3e, 0x37, 0xa1, 0x91, 0x8f, 0xb3, 0xd2, 0x3e, 0x8e, 0xc8, 0x69, 0x65, 0x62, 0xf3,
        0x74, 0x4f, 0x95, 0x45, 0x35, 0x57, 0xcf, 0xf5, 0xfe, 0xc8, 0x55, 0xa1, 0xfe,
    ];

    #[derive(Debug, Clone, Copy)]
    struct SyntheticTls13AutoBindingFixture;

    impl SyntheticTls13AutoBindingFixture {
        fn validate(self) -> Result<(), Box<dyn std::error::Error>> {
            let material = self.session_secret_material_jsonl(SHA256_TRAFFIC_SECRET);
            let store = TlsSessionSecretStore::parse(material.as_bytes())?;
            let record = store
                .records()
                .first()
                .expect("synthetic TLS fixture should contain one record");
            assert_eq!(record.client_random().as_bytes(), &CLIENT_RANDOM_BYTES);
            self.validate_client_hello_random();
            let mut decryptor = Tls13ApplicationDataDecryptor::from_session_secret_record(record)?;
            let decrypted = decryptor.decrypt_next_record(SYNTHETIC_APPLICATION_RECORD)?;

            assert!(decrypted.content_type().is_application_data());
            assert_eq!(decrypted.plaintext(), self.expected_plaintext().as_slice());
            Ok(())
        }

        fn validate_client_hello_random(self) {
            let mut observer = Tls13SessionSecretHandshakeObserver::new();
            let observations =
                observer.push_capture_event(&CaptureEvent::Bytes(self.client_hello()));
            let [observation] = observations.as_slice() else {
                panic!("synthetic TLS fixture should produce exactly one ClientHello observation");
            };
            let Tls13SessionSecretHandshakeObservationKind::ClientHello { client_random } =
                observation.kind()
            else {
                panic!("synthetic TLS fixture should produce a ClientHello observation");
            };
            assert_eq!(client_random.as_bytes(), &CLIENT_RANDOM_BYTES);
        }

        fn session_secret_material_jsonl(self, secret: &str) -> String {
            format!(
                r#"{{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"{}","cipher_suite":"0x{TLS_AES_128_GCM_SHA256:04x}","secret":"{secret}"}}
"#,
                bytes_to_hex(&CLIENT_RANDOM_BYTES),
            )
        }

        fn client_hello(self) -> CapturedBytes {
            captured_bytes(Direction::Outbound, 0, self.client_hello_record())
        }

        fn application_record(self) -> CapturedBytes {
            captured_bytes(
                Direction::Outbound,
                self.client_hello_record().len() as u64,
                SYNTHETIC_APPLICATION_RECORD.to_vec(),
            )
        }

        fn client_hello_record(self) -> Vec<u8> {
            tls_handshake_record(TLS_CLIENT_HELLO, tls_client_hello_body())
        }

        fn expected_plaintext(self) -> Vec<u8> {
            b"GET /tls13 HTTP/1.1\r\nhost: e2e\r\n\r\n".to_vec()
        }
    }

    fn tls_client_hello_body() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&CLIENT_RANDOM_BYTES);
        body.push(0);
        body.extend_from_slice(&2_u16.to_be_bytes());
        body.extend_from_slice(&TLS_AES_128_GCM_SHA256.to_be_bytes());
        body.extend_from_slice(&[1, 0]);
        let extensions = supported_versions_client_extension();
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        body
    }

    fn supported_versions_client_extension() -> Vec<u8> {
        vec![
            0x00,
            0x2b,
            0x00,
            0x03,
            0x02,
            TLS13_VERSION[0],
            TLS13_VERSION[1],
        ]
    }

    fn tls_handshake_record(handshake_type: u8, body: Vec<u8>) -> Vec<u8> {
        let mut handshake = vec![
            handshake_type,
            ((body.len() >> 16) & 0xff) as u8,
            ((body.len() >> 8) & 0xff) as u8,
            (body.len() & 0xff) as u8,
        ];
        handshake.extend_from_slice(&body);
        tls_record(TLS_HANDSHAKE_CONTENT_TYPE, handshake)
    }

    fn tls_record(content_type: u8, payload: Vec<u8>) -> Vec<u8> {
        let mut record = vec![
            content_type,
            TLS_LEGACY_RECORD_VERSION[0],
            TLS_LEGACY_RECORD_VERSION[1],
            ((payload.len() >> 8) & 0xff) as u8,
            (payload.len() & 0xff) as u8,
        ];
        record.extend_from_slice(&payload);
        record
    }

    fn captured_bytes(direction: Direction, stream_offset: u64, bytes: Vec<u8>) -> CapturedBytes {
        CapturedBytes {
            timestamp: Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            flow: synthetic_flow(),
            origin: CaptureOrigin::from_source(CaptureSource::Libpcap),
            direction,
            stream_offset,
            bytes: bytes.into(),
            attribution_confidence: 100,
            degraded: true,
            degradation_reason: Some("synthetic TLS fixture".to_string()),
            enforcement_evidence: EnforcementEvidence::default(),
            enforcement_evidence_propagation: EnforcementEvidencePropagation::Event,
        }
    }

    fn synthetic_flow() -> FlowContext {
        let process = ProcessIdentity {
            pid: 1,
            tgid: 1,
            start_time_ticks: 1,
            boot_id: "test".to_string(),
            exe_path: "/bin/test".to_string(),
            cmdline_hash: "hash".to_string(),
            uid: 0,
            gid: 0,
            cgroup: None,
            systemd_service: None,
            container_id: None,
            runtime_hint: None,
        };
        let local = AddressPort {
            address: "127.0.0.1".to_string(),
            port: 40000,
        };
        let remote = AddressPort {
            address: "127.0.0.1".to_string(),
            port: 443,
        };
        FlowContext {
            id: FlowIdentity::stable(
                &process,
                &local,
                &remote,
                TransportProtocol::Tcp,
                1,
                Some(7),
            ),
            process: ProcessContext {
                identity: process,
                name: "test".to_string(),
                cmdline: vec!["test".to_string()],
            },
            local,
            remote,
            protocol: TransportProtocol::Tcp,
            start_monotonic_ns: 1,
            socket_cookie: Some(7),
            attribution_confidence: 100,
        }
    }

    fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    }
}
