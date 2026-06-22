use crate::tls::{
    TlsRandom,
    keylog::{TlsKeyLogEntry, TlsKeyLogLabel},
};

use super::record::TlsSessionSecretRecord;

pub(super) fn tls_key_log_entry_to_session_secret_record(
    entry: &TlsKeyLogEntry,
) -> Option<TlsSessionSecretRecord> {
    let client_random = TlsRandom::from_bytes(entry.context().try_into().ok()?);
    match entry.label() {
        TlsKeyLogLabel::ClientTrafficSecret0 => Some(
            TlsSessionSecretRecord::tls13_client_application_traffic_secret(
                client_random,
                entry.secret().clone(),
            ),
        ),
        TlsKeyLogLabel::ServerTrafficSecret0 => Some(
            TlsSessionSecretRecord::tls13_server_application_traffic_secret(
                client_random,
                entry.secret().clone(),
            ),
        ),
        TlsKeyLogLabel::Rsa
        | TlsKeyLogLabel::ClientRandom
        | TlsKeyLogLabel::ClientEarlyTrafficSecret
        | TlsKeyLogLabel::ClientHandshakeTrafficSecret
        | TlsKeyLogLabel::ServerHandshakeTrafficSecret
        | TlsKeyLogLabel::ExporterSecret
        | TlsKeyLogLabel::EarlyExporterSecret
        | TlsKeyLogLabel::Other(_) => None,
    }
}
