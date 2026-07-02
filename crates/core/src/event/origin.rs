use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureSource {
    EbpfSyscall,
    Libpcap,
    LibsslUprobe,
    TlsSessionSecret,
    ExternalPlaintextFeed,
    L7MitmPlaintext,
    L7MitmControlPlane,
    Replay,
    Mock,
}

impl CaptureSource {
    pub const ALL: [Self; 9] = [
        Self::EbpfSyscall,
        Self::Libpcap,
        Self::LibsslUprobe,
        Self::TlsSessionSecret,
        Self::ExternalPlaintextFeed,
        Self::L7MitmPlaintext,
        Self::L7MitmControlPlane,
        Self::Replay,
        Self::Mock,
    ];

    pub fn is_live_host_observation(self) -> bool {
        matches!(self, Self::EbpfSyscall | Self::Libpcap | Self::LibsslUprobe)
    }

    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::EbpfSyscall => "ebpf_syscall",
            Self::Libpcap => "libpcap",
            Self::LibsslUprobe => "libssl_uprobe",
            Self::TlsSessionSecret => "tls_session_secret",
            Self::ExternalPlaintextFeed => "external_plaintext_feed",
            Self::L7MitmPlaintext => "l7_mitm_plaintext",
            Self::L7MitmControlPlane => "l7_mitm_control_plane",
            Self::Replay => "replay",
            Self::Mock => "mock",
        }
    }

    pub const fn default_traffic_security(self) -> CaptureTrafficSecurity {
        match self {
            Self::LibsslUprobe | Self::TlsSessionSecret => CaptureTrafficSecurity::TlsDecrypted,
            Self::EbpfSyscall
            | Self::Libpcap
            | Self::ExternalPlaintextFeed
            | Self::L7MitmPlaintext
            | Self::L7MitmControlPlane
            | Self::Replay
            | Self::Mock => CaptureTrafficSecurity::Unknown,
        }
    }

    pub const fn allows_traffic_security(self, traffic_security: CaptureTrafficSecurity) -> bool {
        match self {
            Self::EbpfSyscall | Self::Libpcap | Self::L7MitmControlPlane => {
                matches!(traffic_security, CaptureTrafficSecurity::Unknown)
            }
            Self::LibsslUprobe | Self::TlsSessionSecret => {
                matches!(traffic_security, CaptureTrafficSecurity::TlsDecrypted)
            }
            Self::ExternalPlaintextFeed | Self::L7MitmPlaintext | Self::Replay | Self::Mock => true,
        }
    }

    pub const fn provider_kind(self) -> CaptureProviderKind {
        match self {
            Self::EbpfSyscall => CaptureProviderKind::Ebpf,
            Self::Libpcap => CaptureProviderKind::Libpcap,
            Self::LibsslUprobe | Self::TlsSessionSecret | Self::ExternalPlaintextFeed => {
                CaptureProviderKind::Plaintext
            }
            Self::L7MitmPlaintext | Self::L7MitmControlPlane => CaptureProviderKind::Interception,
            Self::Replay | Self::Mock => CaptureProviderKind::Replay,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureTrafficSecurity {
    #[default]
    Unknown,
    Cleartext,
    TlsDecrypted,
}

impl CaptureTrafficSecurity {
    pub const ALL: [Self; 3] = [Self::Unknown, Self::Cleartext, Self::TlsDecrypted];

    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Cleartext => "cleartext",
            Self::TlsDecrypted => "tls_decrypted",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureProviderKind {
    Replay,
    Ebpf,
    Libpcap,
    Plaintext,
    Interception,
}

impl CaptureProviderKind {
    pub const ALL: [Self; 5] = [
        Self::Replay,
        Self::Ebpf,
        Self::Libpcap,
        Self::Plaintext,
        Self::Interception,
    ];

    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Replay => "replay",
            Self::Ebpf => "ebpf",
            Self::Libpcap => "libpcap",
            Self::Plaintext => "plaintext",
            Self::Interception => "interception",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct CaptureOrigin {
    source: CaptureSource,
    provider: CaptureProviderKind,
    traffic_security: CaptureTrafficSecurity,
}

impl CaptureOrigin {
    pub const fn from_source(source: CaptureSource) -> Self {
        Self {
            source,
            provider: source.provider_kind(),
            traffic_security: source.default_traffic_security(),
        }
    }

    pub const fn source(self) -> CaptureSource {
        self.source
    }

    pub const fn provider(self) -> CaptureProviderKind {
        self.provider
    }

    pub const fn traffic_security(self) -> CaptureTrafficSecurity {
        self.traffic_security
    }

    pub fn with_traffic_security(self, traffic_security: CaptureTrafficSecurity) -> Self {
        assert!(
            self.source.allows_traffic_security(traffic_security),
            "capture source {} cannot carry traffic security {}",
            self.source.wire_name(),
            traffic_security.wire_name()
        );
        Self {
            source: self.source,
            provider: self.provider,
            traffic_security,
        }
    }
}

impl<'de> Deserialize<'de> for CaptureOrigin {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let parts = CaptureOriginParts::deserialize(deserializer)?;
        let expected_provider = parts.source.provider_kind();
        if parts.provider != expected_provider {
            return Err(serde::de::Error::custom(format!(
                "capture origin source {:?} requires provider {:?}, got {:?}",
                parts.source, expected_provider, parts.provider
            )));
        }
        let traffic_security = parts
            .traffic_security
            .unwrap_or_else(|| parts.source.default_traffic_security());
        if !parts.source.allows_traffic_security(traffic_security) {
            return Err(serde::de::Error::custom(format!(
                "capture origin source {:?} cannot carry traffic security {:?}",
                parts.source, traffic_security
            )));
        }
        Ok(Self {
            source: parts.source,
            provider: parts.provider,
            traffic_security,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureOriginParts {
    source: CaptureSource,
    provider: CaptureProviderKind,
    traffic_security: Option<CaptureTrafficSecurity>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Timestamp {
    pub monotonic_ns: u64,
    pub wall_time_unix_ns: i64,
}

#[cfg(test)]
mod tests {
    use super::{CaptureOrigin, CaptureProviderKind, CaptureSource, CaptureTrafficSecurity};

    #[test]
    fn live_host_observation_sources_exclude_replay_and_external_feeds() {
        assert!(CaptureSource::EbpfSyscall.is_live_host_observation());
        assert!(CaptureSource::Libpcap.is_live_host_observation());
        assert!(CaptureSource::LibsslUprobe.is_live_host_observation());
        assert!(!CaptureSource::TlsSessionSecret.is_live_host_observation());
        assert!(!CaptureSource::ExternalPlaintextFeed.is_live_host_observation());
        assert!(!CaptureSource::L7MitmPlaintext.is_live_host_observation());
        assert!(!CaptureSource::L7MitmControlPlane.is_live_host_observation());
        assert!(!CaptureSource::Replay.is_live_host_observation());
        assert!(!CaptureSource::Mock.is_live_host_observation());
    }

    #[test]
    fn capture_origin_derives_provider_from_source() {
        assert_eq!(
            CaptureOrigin::from_source(CaptureSource::LibsslUprobe).provider(),
            CaptureProviderKind::Plaintext
        );
        assert_eq!(
            CaptureOrigin::from_source(CaptureSource::EbpfSyscall).provider(),
            CaptureProviderKind::Ebpf
        );
        assert_eq!(
            CaptureOrigin::from_source(CaptureSource::L7MitmPlaintext).provider(),
            CaptureProviderKind::Interception
        );
        assert_eq!(
            CaptureOrigin::from_source(CaptureSource::L7MitmControlPlane).provider(),
            CaptureProviderKind::Interception
        );
    }

    #[test]
    fn capture_origin_derives_default_traffic_security_from_source() {
        assert_eq!(
            CaptureOrigin::from_source(CaptureSource::Libpcap).traffic_security(),
            CaptureTrafficSecurity::Unknown
        );
        assert_eq!(
            CaptureOrigin::from_source(CaptureSource::LibsslUprobe).traffic_security(),
            CaptureTrafficSecurity::TlsDecrypted
        );
        assert_eq!(
            CaptureOrigin::from_source(CaptureSource::L7MitmPlaintext).traffic_security(),
            CaptureTrafficSecurity::Unknown
        );
    }

    #[test]
    fn capture_origin_defaults_missing_traffic_security_from_source() {
        let libssl = serde_json::from_value::<CaptureOrigin>(serde_json::json!({
            "source": "libssl_uprobe",
            "provider": "plaintext"
        }))
        .expect("missing traffic security should use source default");
        assert_eq!(
            libssl.traffic_security(),
            CaptureTrafficSecurity::TlsDecrypted
        );

        let mitm = serde_json::from_value::<CaptureOrigin>(serde_json::json!({
            "source": "l7_mitm_plaintext",
            "provider": "interception"
        }))
        .expect("missing MITM traffic security should remain unknown");
        assert_eq!(mitm.traffic_security(), CaptureTrafficSecurity::Unknown);
    }

    #[test]
    fn capture_origin_rejects_invalid_traffic_security_for_source() {
        let result = serde_json::from_value::<CaptureOrigin>(serde_json::json!({
            "source": "libpcap",
            "provider": "libpcap",
            "traffic_security": "cleartext"
        }));

        assert!(result.is_err());
    }

    #[test]
    fn capture_provider_kind_round_trips_wire_name() -> Result<(), Box<dyn std::error::Error>> {
        for provider in CaptureProviderKind::ALL {
            assert_eq!(serde_json::to_value(provider)?, provider.wire_name());
        }
        Ok(())
    }

    #[test]
    fn capture_source_round_trips_wire_name() -> Result<(), Box<dyn std::error::Error>> {
        for source in CaptureSource::ALL {
            assert_eq!(serde_json::to_value(source)?, source.wire_name());
        }
        Ok(())
    }

    #[test]
    fn capture_traffic_security_round_trips_wire_name() -> Result<(), Box<dyn std::error::Error>> {
        for traffic_security in CaptureTrafficSecurity::ALL {
            assert_eq!(
                serde_json::to_value(traffic_security)?,
                traffic_security.wire_name()
            );
        }
        Ok(())
    }

    #[test]
    fn capture_origin_rejects_mismatched_provider_json() {
        let result = serde_json::from_value::<CaptureOrigin>(serde_json::json!({
            "source": "ebpf_syscall",
            "provider": "plaintext",
            "traffic_security": "unknown"
        }));

        assert!(result.is_err());
    }
}
