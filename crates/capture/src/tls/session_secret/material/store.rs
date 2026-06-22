use std::collections::BTreeMap;

use serde::Serialize;
use thiserror::Error;

use crate::tls::{TlsMaterialLookup, TlsRandom, keylog::TlsKeyLog, resolve_lookup};

use super::{
    keylog_adapter::tls_key_log_entry_to_session_secret_record,
    record::{TlsSessionSecretKind, TlsSessionSecretProtocol, TlsSessionSecretRecord},
    wire::{TlsSessionSecretParseError, TlsSessionSecretRecordWire},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsSessionSecretStore {
    records: Vec<TlsSessionSecretRecord>,
}

impl TlsSessionSecretStore {
    pub fn parse(bytes: &[u8]) -> Result<Self, TlsSessionSecretParseError> {
        let content =
            std::str::from_utf8(bytes).map_err(|_| TlsSessionSecretParseError::invalid_utf8())?;
        let mut records = Vec::new();
        for (index, line) in content.lines().enumerate() {
            let line_number = index + 1;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            records
                .push(TlsSessionSecretRecordWire::parse(line_number, line)?.decode(line_number)?);
        }
        if records.is_empty() {
            return Err(TlsSessionSecretParseError::no_entries());
        }
        Ok(Self { records })
    }

    pub fn from_time_qualified_lookup_records(
        records: impl IntoIterator<Item = TlsSessionSecretRecord>,
    ) -> Result<Option<Self>, TlsSessionSecretLookupConflict> {
        let mut unique: Vec<TlsSessionSecretRecord> = Vec::new();
        for record in records {
            insert_lookup_unique_record(&mut unique, record)?;
        }
        Ok((!unique.is_empty()).then_some(Self { records: unique }))
    }

    pub fn from_tls_key_log(
        key_log: &TlsKeyLog,
    ) -> Result<Option<Self>, TlsSessionSecretLookupConflict> {
        Self::from_time_qualified_lookup_records(
            key_log
                .entries()
                .iter()
                .filter_map(tls_key_log_entry_to_session_secret_record),
        )
    }

    pub fn records(&self) -> &[TlsSessionSecretRecord] {
        &self.records
    }

    pub fn lookup(
        &self,
        protocol: TlsSessionSecretProtocol,
        secret_kind: TlsSessionSecretKind,
        client_random: &TlsRandom,
        at_wall_time_unix_ns: Option<u64>,
    ) -> TlsMaterialLookup<'_, TlsSessionSecretRecord> {
        resolve_lookup(self.records.iter().filter(|record| {
            record.protocol == protocol
                && record.secret_kind == secret_kind
                && record.client_random == *client_random
                && record.is_valid_at(at_wall_time_unix_ns)
        }))
    }

    pub fn summary(&self) -> TlsSessionSecretSummary {
        let mut protocol_counts = BTreeMap::<TlsSessionSecretProtocol, u64>::new();
        let mut secret_kind_counts = BTreeMap::<TlsSessionSecretKind, u64>::new();
        let mut secret_min_bytes = u64::MAX;
        let mut secret_max_bytes = 0_u64;

        for record in &self.records {
            *protocol_counts.entry(record.protocol).or_default() += 1;
            *secret_kind_counts.entry(record.secret_kind).or_default() += 1;
            let secret_bytes = record.secret.len() as u64;
            secret_min_bytes = secret_min_bytes.min(secret_bytes);
            secret_max_bytes = secret_max_bytes.max(secret_bytes);
        }

        TlsSessionSecretSummary {
            entries: self.records.len() as u64,
            protocols: protocol_counts
                .into_iter()
                .map(|(protocol, count)| TlsSessionSecretProtocolCount { protocol, count })
                .collect(),
            secret_kinds: secret_kind_counts
                .into_iter()
                .map(|(secret_kind, count)| TlsSessionSecretKindCount { secret_kind, count })
                .collect(),
            secret_min_bytes,
            secret_max_bytes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error(
    "overlapping TLS session secret records for protocol {protocol:?}, secret_kind {secret_kind:?}, client_random {client_random:?}"
)]
pub struct TlsSessionSecretLookupConflict {
    protocol: TlsSessionSecretProtocol,
    secret_kind: TlsSessionSecretKind,
    client_random: TlsRandom,
}

impl TlsSessionSecretLookupConflict {
    fn from_record(record: &TlsSessionSecretRecord) -> Self {
        Self {
            protocol: record.protocol,
            secret_kind: record.secret_kind,
            client_random: record.client_random,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsSessionSecretSummary {
    entries: u64,
    protocols: Vec<TlsSessionSecretProtocolCount>,
    secret_kinds: Vec<TlsSessionSecretKindCount>,
    secret_min_bytes: u64,
    secret_max_bytes: u64,
}

impl TlsSessionSecretSummary {
    pub fn parse(bytes: &[u8]) -> Result<Self, TlsSessionSecretParseError> {
        TlsSessionSecretStore::parse(bytes).map(|store| store.summary())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct TlsSessionSecretProtocolCount {
    protocol: TlsSessionSecretProtocol,
    count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct TlsSessionSecretKindCount {
    secret_kind: TlsSessionSecretKind,
    count: u64,
}

fn lookup_domains_overlap(left: &TlsSessionSecretRecord, right: &TlsSessionSecretRecord) -> bool {
    left.protocol == right.protocol
        && left.secret_kind == right.secret_kind
        && left.client_random == right.client_random
        && validity_windows_overlap(left, right)
}

fn insert_lookup_unique_record(
    unique: &mut Vec<TlsSessionSecretRecord>,
    record: TlsSessionSecretRecord,
) -> Result<(), TlsSessionSecretLookupConflict> {
    let mut candidate = record;
    loop {
        let Some(existing) = unique
            .iter()
            .position(|existing| lookup_domains_overlap(existing, &candidate))
        else {
            unique.push(candidate);
            return Ok(());
        };
        let existing = unique.remove(existing);
        let Some(merged) = merge_lookup_equivalent_records(&existing, &candidate) else {
            return Err(TlsSessionSecretLookupConflict::from_record(&candidate));
        };
        candidate = merged;
    }
}

fn merge_lookup_equivalent_records(
    left: &TlsSessionSecretRecord,
    right: &TlsSessionSecretRecord,
) -> Option<TlsSessionSecretRecord> {
    if left.protocol != right.protocol
        || left.secret_kind != right.secret_kind
        || left.client_random != right.client_random
        || left.secret != right.secret
    {
        return None;
    }

    Some(TlsSessionSecretRecord {
        protocol: left.protocol,
        secret_kind: left.secret_kind,
        client_random: left.client_random,
        server_random: merge_optional(left.server_random, right.server_random)?,
        cipher_suite: merge_optional(left.cipher_suite, right.cipher_suite)?,
        secret: left.secret.clone(),
        not_before_unix_ns: merge_not_before(left.not_before_unix_ns, right.not_before_unix_ns),
        not_after_unix_ns: merge_not_after(left.not_after_unix_ns, right.not_after_unix_ns),
    })
}

fn merge_optional<T: Copy + Eq>(left: Option<T>, right: Option<T>) -> Option<Option<T>> {
    match (left, right) {
        (Some(left), Some(right)) if left != right => None,
        (Some(value), _) | (_, Some(value)) => Some(Some(value)),
        (None, None) => Some(None),
    }
}

fn merge_not_before(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (None, _) | (_, None) => None,
    }
}

fn merge_not_after(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (None, _) | (_, None) => None,
    }
}

fn validity_windows_overlap(left: &TlsSessionSecretRecord, right: &TlsSessionSecretRecord) -> bool {
    record_ends_after_other_starts(left, right) && record_ends_after_other_starts(right, left)
}

fn record_ends_after_other_starts(
    left: &TlsSessionSecretRecord,
    right: &TlsSessionSecretRecord,
) -> bool {
    left.not_after_unix_ns.is_none_or(|left_end| {
        right
            .not_before_unix_ns
            .is_none_or(|right_start| left_end >= right_start)
    })
}

#[cfg(test)]
mod tests {
    use crate::tls::{
        TLS_RANDOM_BYTES, TlsMaterialLookup, TlsRandom, keylog::TlsKeyLog,
        session_secret::material::wire::TlsSessionSecretParseErrorKind,
    };

    use super::*;

    #[test]
    fn parses_jsonl_session_secret_file_and_summarizes_without_serializing_secret_bytes() {
        let client_random_a = "00".repeat(TLS_RANDOM_BYTES);
        let client_random_b = "11".repeat(TLS_RANDOM_BYTES);
        let server_random = "22".repeat(TLS_RANDOM_BYTES);
        let client_secret = "aa".repeat(32);
        let master_secret = "bb".repeat(48);
        let material = format!(
            r#"
{{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"{client_random_a}","server_random":"{server_random}","cipher_suite":"0x1301","secret":"{client_secret}","not_before_unix_ns":10,"not_after_unix_ns":20}}
{{"protocol":"tls12","secret_kind":"master_secret","client_random":"{client_random_b}","secret":"{master_secret}"}}
"#
        );

        let store =
            TlsSessionSecretStore::parse(material.as_bytes()).expect("valid session secret file");
        let summary = store.summary();

        assert_eq!(summary.entries, 2);
        assert_eq!(
            summary.protocols,
            vec![
                TlsSessionSecretProtocolCount {
                    protocol: TlsSessionSecretProtocol::Tls12,
                    count: 1
                },
                TlsSessionSecretProtocolCount {
                    protocol: TlsSessionSecretProtocol::Tls13,
                    count: 1
                }
            ]
        );
        assert_eq!(
            summary.secret_kinds,
            vec![
                TlsSessionSecretKindCount {
                    secret_kind: TlsSessionSecretKind::Master,
                    count: 1
                },
                TlsSessionSecretKindCount {
                    secret_kind: TlsSessionSecretKind::ClientApplicationTraffic,
                    count: 1
                }
            ]
        );
        assert_eq!(summary.secret_min_bytes, 32);
        assert_eq!(summary.secret_max_bytes, 48);
        let random = TlsRandom::from_hex(&client_random_a).expect("valid client random");
        let TlsMaterialLookup::Found(record) = store.lookup(
            TlsSessionSecretProtocol::Tls13,
            TlsSessionSecretKind::ClientApplicationTraffic,
            &random,
            Some(15),
        ) else {
            panic!("valid record by client random and time must be uniquely available");
        };
        assert_eq!(record.secret().as_bytes(), vec![0xaa; 32]);
        assert_eq!(record.cipher_suite().expect("cipher suite").code(), 0x1301);
        assert!(record.server_random().is_some());
        assert_eq!(
            store.lookup(
                TlsSessionSecretProtocol::Tls13,
                TlsSessionSecretKind::ClientApplicationTraffic,
                &random,
                Some(21),
            ),
            TlsMaterialLookup::Missing
        );
        assert!(!format!("{record:?}").contains(&client_secret));
    }

    #[test]
    fn lookup_reports_overlapping_validity_as_ambiguous() {
        let client_random = "00".repeat(TLS_RANDOM_BYTES);
        let material = format!(
            r#"
{{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"{client_random}","secret":"aa","not_before_unix_ns":10,"not_after_unix_ns":20}}
{{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"{client_random}","secret":"bb","not_before_unix_ns":15,"not_after_unix_ns":25}}
"#
        );
        let store =
            TlsSessionSecretStore::parse(material.as_bytes()).expect("valid session secret file");
        let random = TlsRandom::from_hex(&client_random).expect("valid client random");

        let lookup = store.lookup(
            TlsSessionSecretProtocol::Tls13,
            TlsSessionSecretKind::ClientApplicationTraffic,
            &random,
            Some(16),
        );

        assert_eq!(lookup, TlsMaterialLookup::Ambiguous { matches: 2 });
    }

    #[test]
    fn time_qualified_store_dedupes_exact_records_and_rejects_ambiguous_lookup_domain() {
        let client_random = "00".repeat(TLS_RANDOM_BYTES);
        let material = format!(
            r#"
{{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"{client_random}","secret":"aa","not_before_unix_ns":10,"not_after_unix_ns":20}}
{{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"{client_random}","secret":"bb","not_before_unix_ns":20,"not_after_unix_ns":30}}
"#
        );
        let store =
            TlsSessionSecretStore::parse(material.as_bytes()).expect("valid session secret file");

        let error =
            TlsSessionSecretStore::from_time_qualified_lookup_records(store.records().to_vec())
                .expect_err("overlapping lookup domains must be rejected");

        assert_eq!(
            error,
            TlsSessionSecretLookupConflict {
                protocol: TlsSessionSecretProtocol::Tls13,
                secret_kind: TlsSessionSecretKind::ClientApplicationTraffic,
                client_random: TlsRandom::from_hex(&client_random).expect("valid random"),
            }
        );
    }

    #[test]
    fn time_qualified_store_keeps_non_overlapping_records() {
        let client_random = "00".repeat(TLS_RANDOM_BYTES);
        let material = format!(
            r#"
{{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"{client_random}","secret":"aa","not_before_unix_ns":10,"not_after_unix_ns":20}}
{{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"{client_random}","secret":"aa","not_before_unix_ns":10,"not_after_unix_ns":20}}
{{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"{client_random}","secret":"cc","not_before_unix_ns":31,"not_after_unix_ns":40}}
{{"protocol":"tls13","secret_kind":"server_application_traffic_secret","client_random":"{client_random}","secret":"dd","not_before_unix_ns":10,"not_after_unix_ns":20}}
"#
        );
        let store =
            TlsSessionSecretStore::parse(material.as_bytes()).expect("valid session secret file");

        let lookup_unique = TlsSessionSecretStore::from_time_qualified_lookup_records(
            store.records().iter().cloned(),
        )
        .expect("non-overlapping lookup records should build a store")
        .expect("non-empty unique records should remain");

        assert_eq!(lookup_unique.records().len(), 3);
    }

    #[test]
    fn time_qualified_store_merges_lookup_equivalent_records_with_complementary_metadata() {
        let client_random = "00".repeat(TLS_RANDOM_BYTES);
        let secret = "aa".repeat(32);
        let key_log_material = format!("CLIENT_TRAFFIC_SECRET_0 {client_random} {secret}\n");
        let key_log = TlsKeyLog::parse(key_log_material.as_bytes()).expect("valid key log");
        let key_log_store = TlsSessionSecretStore::from_tls_key_log(&key_log)
            .expect("key log traffic secret should not conflict")
            .expect("key log should contain traffic secret material");
        let session_secret_material = format!(
            r#"{{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"{client_random}","cipher_suite":"0x1301","secret":"{secret}"}}"#
        );
        let session_secret_store = TlsSessionSecretStore::parse(session_secret_material.as_bytes())
            .expect("valid session secret file");

        let merged = TlsSessionSecretStore::from_time_qualified_lookup_records(
            key_log_store
                .records()
                .iter()
                .chain(session_secret_store.records())
                .cloned(),
        )
        .expect("equivalent material should merge")
        .expect("merged store should remain non-empty");

        assert_eq!(merged.records().len(), 1);
        assert_eq!(
            merged.records()[0]
                .cipher_suite()
                .expect("merged cipher suite")
                .code(),
            0x1301
        );
    }

    #[test]
    fn time_qualified_store_rechecks_conflicts_after_equivalent_record_merge_widens_window() {
        let client_random = "00".repeat(TLS_RANDOM_BYTES);
        let material = format!(
            r#"
{{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"{client_random}","secret":"aa","not_before_unix_ns":10,"not_after_unix_ns":20}}
{{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"{client_random}","secret":"bb","not_before_unix_ns":25,"not_after_unix_ns":35}}
{{"protocol":"tls13","secret_kind":"client_application_traffic_secret","client_random":"{client_random}","secret":"aa","not_before_unix_ns":20,"not_after_unix_ns":25}}
"#
        );
        let store =
            TlsSessionSecretStore::parse(material.as_bytes()).expect("valid session secret file");

        let error =
            TlsSessionSecretStore::from_time_qualified_lookup_records(store.records().to_vec())
                .expect_err("merged window must be rechecked against remaining records");

        assert_eq!(
            error,
            TlsSessionSecretLookupConflict {
                protocol: TlsSessionSecretProtocol::Tls13,
                secret_kind: TlsSessionSecretKind::ClientApplicationTraffic,
                client_random: TlsRandom::from_hex(&client_random).expect("valid random"),
            }
        );
    }

    #[test]
    fn key_log_application_traffic_entries_become_session_secret_records() {
        let client_random = "00".repeat(TLS_RANDOM_BYTES);
        let client_secret = "11".repeat(32);
        let server_secret = "22".repeat(32);
        let material = format!(
            "CLIENT_TRAFFIC_SECRET_0 {client_random} {client_secret}\nSERVER_TRAFFIC_SECRET_0 {client_random} {server_secret}\nCLIENT_RANDOM {client_random} {}\n",
            "33".repeat(48)
        );
        let key_log = TlsKeyLog::parse(material.as_bytes()).expect("valid key log");

        let store = TlsSessionSecretStore::from_tls_key_log(&key_log)
            .expect("key log traffic secrets should not conflict")
            .expect("key log should contain TLS 1.3 application secrets");

        assert_eq!(store.records().len(), 2);
        assert_eq!(
            store.records()[0].secret_kind(),
            TlsSessionSecretKind::ClientApplicationTraffic
        );
        assert_eq!(
            store.records()[1].secret_kind(),
            TlsSessionSecretKind::ServerApplicationTraffic
        );
        assert!(store.records().iter().all(|record| {
            record.protocol() == TlsSessionSecretProtocol::Tls13
                && record.client_random() == &TlsRandom::from_hex(&client_random).expect("random")
                && record.cipher_suite().is_none()
        }));
    }

    #[test]
    fn key_log_without_application_traffic_entries_produces_no_store() {
        let client_random = "00".repeat(TLS_RANDOM_BYTES);
        let material = format!("CLIENT_RANDOM {client_random} {}\n", "33".repeat(48));
        let key_log = TlsKeyLog::parse(material.as_bytes()).expect("valid key log");

        let store = TlsSessionSecretStore::from_tls_key_log(&key_log)
            .expect("non-application key log entries should not conflict");

        assert!(store.is_none());
    }

    #[test]
    fn rejects_empty_session_secret_file() {
        let error = TlsSessionSecretSummary::parse(b"\n\n")
            .expect_err("empty explicit session secret material must fail");

        assert_eq!(error.kind, TlsSessionSecretParseErrorKind::NoEntries);
    }
}
