use serde::{Deserialize, Serialize};

use crate::tls::{TlsRandom, TlsSecret};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsSessionSecretRecord {
    pub(super) protocol: TlsSessionSecretProtocol,
    pub(super) secret_kind: TlsSessionSecretKind,
    pub(super) client_random: TlsRandom,
    pub(super) server_random: Option<TlsRandom>,
    pub(super) cipher_suite: Option<TlsCipherSuite>,
    pub(super) secret: TlsSecret,
    pub(super) not_before_unix_ns: Option<u64>,
    pub(super) not_after_unix_ns: Option<u64>,
}

impl TlsSessionSecretRecord {
    pub fn tls13_client_application_traffic_secret(
        client_random: TlsRandom,
        secret: TlsSecret,
    ) -> Self {
        Self::tls13_application_traffic_secret(
            TlsSessionSecretKind::ClientApplicationTraffic,
            client_random,
            secret,
        )
    }

    pub fn tls13_server_application_traffic_secret(
        client_random: TlsRandom,
        secret: TlsSecret,
    ) -> Self {
        Self::tls13_application_traffic_secret(
            TlsSessionSecretKind::ServerApplicationTraffic,
            client_random,
            secret,
        )
    }

    pub fn protocol(&self) -> TlsSessionSecretProtocol {
        self.protocol
    }

    pub fn secret_kind(&self) -> TlsSessionSecretKind {
        self.secret_kind
    }

    pub fn client_random(&self) -> &TlsRandom {
        &self.client_random
    }

    pub fn server_random(&self) -> Option<&TlsRandom> {
        self.server_random.as_ref()
    }

    pub fn cipher_suite(&self) -> Option<TlsCipherSuite> {
        self.cipher_suite
    }

    pub fn secret(&self) -> &TlsSecret {
        &self.secret
    }

    pub fn not_before_unix_ns(&self) -> Option<u64> {
        self.not_before_unix_ns
    }

    pub fn not_after_unix_ns(&self) -> Option<u64> {
        self.not_after_unix_ns
    }

    pub fn is_valid_at(&self, at_wall_time_unix_ns: Option<u64>) -> bool {
        let Some(at_wall_time_unix_ns) = at_wall_time_unix_ns else {
            return true;
        };
        self.not_before_unix_ns
            .is_none_or(|not_before| at_wall_time_unix_ns >= not_before)
            && self
                .not_after_unix_ns
                .is_none_or(|not_after| at_wall_time_unix_ns <= not_after)
    }

    fn tls13_application_traffic_secret(
        secret_kind: TlsSessionSecretKind,
        client_random: TlsRandom,
        secret: TlsSecret,
    ) -> Self {
        Self {
            protocol: TlsSessionSecretProtocol::Tls13,
            secret_kind,
            client_random,
            server_random: None,
            cipher_suite: None,
            secret,
            not_before_unix_ns: None,
            not_after_unix_ns: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TlsCipherSuite(u16);

impl TlsCipherSuite {
    pub(in crate::tls::session_secret) fn from_code(code: u16) -> Self {
        Self(code)
    }

    pub fn code(self) -> u16 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsSessionSecretProtocol {
    Tls12,
    Tls13,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TlsSessionSecretKind {
    #[serde(rename = "master_secret")]
    Master,
    #[serde(rename = "client_handshake_traffic_secret")]
    ClientHandshakeTraffic,
    #[serde(rename = "server_handshake_traffic_secret")]
    ServerHandshakeTraffic,
    #[serde(rename = "client_application_traffic_secret")]
    ClientApplicationTraffic,
    #[serde(rename = "server_application_traffic_secret")]
    ServerApplicationTraffic,
    #[serde(rename = "exporter_secret")]
    Exporter,
}

impl TlsSessionSecretKind {
    pub fn is_valid_for(self, protocol: TlsSessionSecretProtocol) -> bool {
        match protocol {
            TlsSessionSecretProtocol::Tls12 => matches!(self, Self::Master),
            TlsSessionSecretProtocol::Tls13 => matches!(
                self,
                Self::ClientHandshakeTraffic
                    | Self::ServerHandshakeTraffic
                    | Self::ClientApplicationTraffic
                    | Self::ServerApplicationTraffic
                    | Self::Exporter
            ),
        }
    }
}
