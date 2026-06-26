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
    pub fn is_live_host_observation(self) -> bool {
        matches!(self, Self::EbpfSyscall | Self::Libpcap | Self::LibsslUprobe)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureProviderKind {
    Replay,
    Ebpf,
    Libpcap,
    Plaintext,
    Interception,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct CaptureOrigin {
    source: CaptureSource,
    provider: CaptureProviderKind,
}

impl CaptureOrigin {
    pub const fn from_source(source: CaptureSource) -> Self {
        Self {
            source,
            provider: source.provider_kind(),
        }
    }

    pub const fn source(self) -> CaptureSource {
        self.source
    }

    pub const fn provider(self) -> CaptureProviderKind {
        self.provider
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
        Ok(Self {
            source: parts.source,
            provider: parts.provider,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureOriginParts {
    source: CaptureSource,
    provider: CaptureProviderKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Timestamp {
    pub monotonic_ns: u64,
    pub wall_time_unix_ns: i64,
}

#[cfg(test)]
mod tests {
    use super::{CaptureOrigin, CaptureProviderKind, CaptureSource};

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
    fn capture_origin_rejects_mismatched_provider_json() {
        let result = serde_json::from_value::<CaptureOrigin>(serde_json::json!({
            "source": "ebpf_syscall",
            "provider": "plaintext"
        }));

        assert!(result.is_err());
    }
}
