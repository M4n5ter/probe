use serde::{Deserialize, Deserializer, Serialize};

use crate::FlowContext;

use super::{CaptureOrigin, EventKind, Timestamp};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EventId(pub String);

impl EventId {
    pub fn stable(parts: impl IntoIterator<Item = impl AsRef<[u8]>>) -> Self {
        let mut hasher = blake3::Hasher::new();
        for part in parts {
            hasher.update(part.as_ref());
            hasher.update(&[0]);
        }
        Self(hasher.finalize().to_hex().to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct EventEnvelope {
    id: EventId,
    timestamp: Timestamp,
    subject: EventSubject,
    origin: CaptureOrigin,
    #[serde(skip_serializing_if = "Option::is_none")]
    provenance: Option<EventProvenance>,
    config_version: String,
    policy_version: Option<String>,
    degraded: bool,
    enforcement_evidence: EnforcementEvidence,
    kind: EventKind,
}

impl<'de> Deserialize<'de> for EventEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let parts = EventEnvelopeParts::deserialize(deserializer)?;
        if !subject_accepts_kind(&parts.subject, &parts.kind) {
            return Err(serde::de::Error::custom(format!(
                "event subject {:?} cannot carry event kind {}",
                parts.subject,
                parts.kind.event_type()
            )));
        }
        Ok(Self {
            id: parts.id,
            timestamp: parts.timestamp,
            subject: parts.subject,
            origin: parts.origin,
            provenance: parts.provenance,
            config_version: parts.config_version,
            policy_version: parts.policy_version,
            degraded: parts.degraded,
            enforcement_evidence: parts.enforcement_evidence,
            kind: parts.kind,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EventEnvelopeParts {
    id: EventId,
    timestamp: Timestamp,
    subject: EventSubject,
    origin: CaptureOrigin,
    provenance: Option<EventProvenance>,
    config_version: String,
    policy_version: Option<String>,
    degraded: bool,
    enforcement_evidence: EnforcementEvidence,
    kind: EventKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventSubject {
    Flow { flow: Box<FlowContext> },
    Provider,
}

impl<'de> Deserialize<'de> for EventSubject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        let subject_type = value
            .get("type")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| serde::de::Error::custom("event subject must include string type"))?;
        match subject_type {
            "flow" => {
                let parts =
                    EventSubjectFlowParts::deserialize(value).map_err(serde::de::Error::custom)?;
                Ok(Self::Flow { flow: parts.flow })
            }
            "provider" => {
                EventSubjectProviderParts::deserialize(value).map_err(serde::de::Error::custom)?;
                Ok(Self::Provider)
            }
            other => Err(serde::de::Error::custom(format!(
                "unknown event subject type: {other}"
            ))),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EventSubjectFlowParts {
    #[serde(rename = "type")]
    _subject_type: EventSubjectFlowType,
    flow: Box<FlowContext>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EventSubjectProviderParts {
    #[serde(rename = "type")]
    _subject_type: EventSubjectProviderType,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum EventSubjectFlowType {
    Flow,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum EventSubjectProviderType {
    Provider,
}

impl EventSubject {
    pub fn flow(&self) -> Option<&FlowContext> {
        match self {
            Self::Flow { flow } => Some(flow.as_ref()),
            Self::Provider => None,
        }
    }

    fn stable_identity_bytes(&self) -> Vec<u8> {
        match self {
            Self::Flow { flow } => {
                let mut bytes = b"flow".to_vec();
                bytes.push(0);
                bytes.extend_from_slice(flow.id.0.as_bytes());
                bytes
            }
            Self::Provider => b"provider".to_vec(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EnforcementEvidence {
    #[default]
    DestructiveAllowed,
    ObservationOnly {
        reason: ObservationOnlyReason,
        #[serde(skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationOnlyReason {
    EbpfSyscallPayloadSnapshot,
    EbpfUnresolvedFlow,
    EbpfProcessLifecycleBoundary,
    ProviderCaptureLoss,
}

impl EnforcementEvidence {
    pub fn observation_only(reason: ObservationOnlyReason) -> Self {
        Self::ObservationOnly {
            reason,
            detail: None,
        }
    }

    pub fn observation_only_with_detail(
        reason: ObservationOnlyReason,
        detail: impl Into<String>,
    ) -> Self {
        let detail = detail.into();
        Self::ObservationOnly {
            reason,
            detail: (!detail.is_empty()).then_some(detail),
        }
    }

    pub fn destructive_enforcement_rejection_reason(&self) -> Option<&'static str> {
        match self {
            Self::DestructiveAllowed => None,
            Self::ObservationOnly { reason, .. } => Some(reason.description()),
        }
    }

    fn stable_identity_bytes(&self) -> &'static [u8] {
        match self {
            Self::DestructiveAllowed => b"destructive_allowed",
            Self::ObservationOnly { reason, .. } => reason.wire_name().as_bytes(),
        }
    }
}

impl ObservationOnlyReason {
    pub fn description(self) -> &'static str {
        match self {
            Self::EbpfSyscallPayloadSnapshot => {
                "eBPF syscall payload snapshot cannot prove complete socket payload or application consumption"
            }
            Self::EbpfUnresolvedFlow => {
                "eBPF observation could not be resolved to a strong flow identity"
            }
            Self::EbpfProcessLifecycleBoundary => {
                "eBPF process lifecycle boundary invalidated payload observation continuity"
            }
            Self::ProviderCaptureLoss => {
                "capture provider reported lost observations; destructive enforcement cannot rely on this event"
            }
        }
    }

    fn wire_name(self) -> &'static str {
        match self {
            Self::EbpfSyscallPayloadSnapshot => "ebpf_syscall_payload_snapshot",
            Self::EbpfUnresolvedFlow => "ebpf_unresolved_flow",
            Self::EbpfProcessLifecycleBoundary => "ebpf_process_lifecycle_boundary",
            Self::ProviderCaptureLoss => "provider_capture_loss",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventProvenance {
    pub ingress_sequence: u64,
    pub emission: EventEmission,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EventEmission {
    Primary {
        index: u64,
    },
    Policy {
        trigger_index: u64,
        policy_index: u64,
        output_index: u64,
        stage: PolicyEmissionStage,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEmissionStage {
    RuntimeError,
    Output,
    EnforcementDecision,
}

impl EventProvenance {
    pub fn primary(ingress_sequence: u64, index: u64) -> Self {
        Self {
            ingress_sequence,
            emission: EventEmission::Primary { index },
        }
    }

    pub fn policy(
        trigger: &Self,
        policy_index: u64,
        output_index: u64,
        stage: PolicyEmissionStage,
    ) -> Self {
        Self {
            ingress_sequence: trigger.ingress_sequence,
            emission: EventEmission::Policy {
                trigger_index: trigger.primary_index(),
                policy_index,
                output_index,
                stage,
            },
        }
    }

    pub fn primary_index(&self) -> u64 {
        match self.emission {
            EventEmission::Primary { index } => index,
            EventEmission::Policy { trigger_index, .. } => trigger_index,
        }
    }
}

impl EventEnvelope {
    fn new(
        timestamp: Timestamp,
        subject: EventSubject,
        origin: CaptureOrigin,
        config_version: impl Into<String>,
        kind: EventKind,
    ) -> Self {
        assert!(
            subject_accepts_kind(&subject, &kind),
            "event subject {:?} cannot carry event kind {}",
            subject,
            kind.event_type()
        );
        let config_version = config_version.into();
        let degraded = kind.is_degraded();
        let enforcement_evidence = EnforcementEvidence::default();
        let id = Self::stable_id(EventIdentityParts {
            timestamp,
            subject: &subject,
            origin,
            provenance: None,
            config_version: &config_version,
            policy_version: None,
            enforcement_evidence: &enforcement_evidence,
            kind: &kind,
        });
        Self {
            id,
            timestamp,
            subject,
            origin,
            provenance: None,
            config_version,
            policy_version: None,
            degraded,
            enforcement_evidence,
            kind,
        }
    }

    pub fn from_policy_emission(
        timestamp: Timestamp,
        trigger: &Self,
        policy_version: impl Into<String>,
        policy_index: u64,
        output_index: u64,
        stage: PolicyEmissionStage,
        kind: EventKind,
    ) -> Self {
        assert!(
            kind_is_policy_emission(&kind),
            "policy emission cannot carry event kind {}",
            kind.event_type()
        );
        let trigger_provenance = trigger
            .provenance()
            .expect("policy emission trigger must carry provenance");
        Self::new(
            timestamp,
            trigger.subject.clone(),
            trigger.origin,
            trigger.config_version.clone(),
            kind,
        )
        .with_policy_version(policy_version)
        .with_degraded(trigger.degraded)
        .with_enforcement_evidence(trigger.enforcement_evidence.clone())
        .with_provenance(EventProvenance::policy(
            trigger_provenance,
            policy_index,
            output_index,
            stage,
        ))
    }

    pub fn from_flow(
        timestamp: Timestamp,
        flow: FlowContext,
        origin: CaptureOrigin,
        config_version: impl Into<String>,
        kind: EventKind,
    ) -> Self {
        assert!(
            kind_is_primary_flow_event(&kind),
            "flow event constructor cannot carry event kind {}",
            kind.event_type()
        );
        Self::new(
            timestamp,
            EventSubject::Flow {
                flow: Box::new(flow),
            },
            origin,
            config_version,
            kind,
        )
    }

    pub fn from_provider(
        timestamp: Timestamp,
        origin: CaptureOrigin,
        config_version: impl Into<String>,
        kind: EventKind,
    ) -> Self {
        Self::new(
            timestamp,
            EventSubject::Provider,
            origin,
            config_version,
            kind,
        )
    }

    pub fn flow(&self) -> Option<&FlowContext> {
        self.subject.flow()
    }

    pub fn id(&self) -> &EventId {
        &self.id
    }

    pub fn timestamp(&self) -> Timestamp {
        self.timestamp
    }

    pub fn subject(&self) -> &EventSubject {
        &self.subject
    }

    pub fn origin(&self) -> CaptureOrigin {
        self.origin
    }

    pub fn provenance(&self) -> Option<&EventProvenance> {
        self.provenance.as_ref()
    }

    pub fn config_version(&self) -> &str {
        &self.config_version
    }

    pub fn policy_version(&self) -> Option<&str> {
        self.policy_version.as_deref()
    }

    pub fn degraded(&self) -> bool {
        self.degraded
    }

    pub fn enforcement_evidence(&self) -> &EnforcementEvidence {
        &self.enforcement_evidence
    }

    pub fn kind(&self) -> &EventKind {
        &self.kind
    }

    pub fn with_policy_version(mut self, policy_version: impl Into<String>) -> Self {
        self.policy_version = Some(policy_version.into());
        self.recompute_id();
        self
    }

    pub fn with_provenance(mut self, provenance: EventProvenance) -> Self {
        self.provenance = Some(provenance);
        self.recompute_id();
        self
    }

    pub fn with_degraded(mut self, degraded: bool) -> Self {
        self.degraded = self.degraded || degraded;
        self
    }

    pub fn with_enforcement_evidence(mut self, evidence: EnforcementEvidence) -> Self {
        self.enforcement_evidence = evidence;
        self.recompute_id();
        self
    }

    fn recompute_id(&mut self) {
        self.id = Self::stable_id(EventIdentityParts {
            timestamp: self.timestamp,
            subject: &self.subject,
            origin: self.origin,
            provenance: self.provenance.as_ref(),
            config_version: &self.config_version,
            policy_version: self.policy_version.as_deref(),
            enforcement_evidence: &self.enforcement_evidence,
            kind: &self.kind,
        });
    }

    fn stable_id(parts: EventIdentityParts<'_>) -> EventId {
        let origin_fingerprint = serde_json::to_vec(&parts.origin)
            .unwrap_or_else(|_| format!("{:?}", parts.origin).into_bytes());
        let subject_fingerprint = parts.subject.stable_identity_bytes();
        let monotonic_ns = parts
            .provenance
            .map_or(parts.timestamp.monotonic_ns, |_| 0)
            .to_be_bytes();
        let provenance_fingerprint = parts
            .provenance
            .map(|value| serde_json::to_vec(value).unwrap_or_else(|_| format!("{value:?}").into()))
            .unwrap_or_default();
        let identity_mode = if parts.provenance.is_some() {
            b"ingress_provenance".as_slice()
        } else {
            b"timestamp".as_slice()
        };
        let kind_fingerprint = serde_json::to_vec(parts.kind)
            .unwrap_or_else(|_| format!("{:?}", parts.kind).into_bytes());
        EventId::stable([
            subject_fingerprint.as_slice(),
            parts.config_version.as_bytes(),
            parts.policy_version.unwrap_or_default().as_bytes(),
            origin_fingerprint.as_slice(),
            parts.kind.event_type().as_str().as_bytes(),
            identity_mode,
            monotonic_ns.as_slice(),
            provenance_fingerprint.as_slice(),
            parts.enforcement_evidence.stable_identity_bytes(),
            kind_fingerprint.as_slice(),
        ])
    }
}

struct EventIdentityParts<'a> {
    timestamp: Timestamp,
    subject: &'a EventSubject,
    origin: CaptureOrigin,
    provenance: Option<&'a EventProvenance>,
    config_version: &'a str,
    policy_version: Option<&'a str>,
    enforcement_evidence: &'a EnforcementEvidence,
    kind: &'a EventKind,
}

fn subject_accepts_kind(subject: &EventSubject, kind: &EventKind) -> bool {
    matches!(
        (subject, kind),
        (EventSubject::Provider, EventKind::CaptureLoss(_))
            | (EventSubject::Provider, EventKind::L7MitmAudit(_))
            | (EventSubject::Flow { .. }, EventKind::ConnectionOpened)
            | (EventSubject::Flow { .. }, EventKind::ConnectionClosed)
            | (EventSubject::Flow { .. }, EventKind::HttpRequestHeaders(_))
            | (EventSubject::Flow { .. }, EventKind::HttpResponseHeaders(_))
            | (EventSubject::Flow { .. }, EventKind::HttpBodyChunk(_))
            | (EventSubject::Flow { .. }, EventKind::SseEvent(_))
            | (EventSubject::Flow { .. }, EventKind::WebSocketHandoff(_))
            | (EventSubject::Flow { .. }, EventKind::WebSocketFrame(_))
            | (EventSubject::Flow { .. }, EventKind::WebSocketMessage(_))
            | (EventSubject::Flow { .. }, EventKind::OpaqueStream(_))
            | (EventSubject::Flow { .. }, EventKind::Gap(_))
            | (EventSubject::Flow { .. }, EventKind::ProtocolError(_))
            | (EventSubject::Flow { .. }, EventKind::PolicyAlert(_))
            | (EventSubject::Flow { .. }, EventKind::PolicyVerdict(_))
            | (EventSubject::Flow { .. }, EventKind::PolicyRuntimeError(_))
            | (EventSubject::Flow { .. }, EventKind::EnforcementDecision(_))
    )
}

fn kind_is_primary_flow_event(kind: &EventKind) -> bool {
    matches!(
        kind,
        EventKind::ConnectionOpened
            | EventKind::ConnectionClosed
            | EventKind::HttpRequestHeaders(_)
            | EventKind::HttpResponseHeaders(_)
            | EventKind::HttpBodyChunk(_)
            | EventKind::SseEvent(_)
            | EventKind::WebSocketHandoff(_)
            | EventKind::WebSocketFrame(_)
            | EventKind::WebSocketMessage(_)
            | EventKind::OpaqueStream(_)
            | EventKind::Gap(_)
            | EventKind::ProtocolError(_)
    )
}

fn kind_is_policy_emission(kind: &EventKind) -> bool {
    matches!(
        kind,
        EventKind::PolicyAlert(_)
            | EventKind::PolicyVerdict(_)
            | EventKind::PolicyRuntimeError(_)
            | EventKind::EnforcementDecision(_)
    )
}

#[cfg(test)]
mod tests {
    use crate::{
        Action, AddressPort, CaptureLoss, CaptureOrigin, CaptureSource, Direction, DomainEvent,
        EnforcementEvidence, EventEnvelope, EventKind, EventProvenance, FlowContext, FlowIdentity,
        HttpHeaders, ObservationOnlyReason, ProcessContext, ProcessIdentity, Timestamp,
        TransportProtocol,
    };

    #[test]
    fn event_id_changes_when_event_payload_changes() {
        let first = request_event(CaptureSource::Replay, "/first");
        let second = request_event(CaptureSource::Replay, "/second");

        assert_ne!(first.id, second.id);
    }

    #[test]
    fn event_id_changes_when_capture_source_changes() {
        let replay = request_event(CaptureSource::Replay, "/same");
        let mock = request_event(CaptureSource::Mock, "/same");

        assert_ne!(replay.id, mock.id);
    }

    #[test]
    fn event_id_changes_when_capture_provider_changes() {
        let ebpf = request_event_with_origin(
            CaptureOrigin::from_source(CaptureSource::EbpfSyscall),
            "/same",
        );
        let plaintext = request_event_with_origin(
            CaptureOrigin::from_source(CaptureSource::LibsslUprobe),
            "/same",
        );

        assert_ne!(ebpf.id, plaintext.id);
    }

    #[test]
    fn provider_subject_capture_loss_has_no_flow_or_nested_scope_in_json() {
        let envelope = EventEnvelope::from_provider(
            Timestamp {
                monotonic_ns: 7,
                wall_time_unix_ns: 1,
            },
            CaptureOrigin::from_source(CaptureSource::EbpfSyscall),
            "test",
            EventKind::CaptureLoss(CaptureLoss {
                lost_events: 3,
                reason: "lost".to_string(),
            }),
        );

        let value = serde_json::to_value(&envelope).expect("event envelope must serialize");

        assert_eq!(value["subject"]["type"], "provider");
        assert!(value.get("flow").is_none());
        assert_eq!(value["origin"]["provider"], "ebpf");
        assert_eq!(value["kind"]["type"], "capture_loss");
        assert_eq!(value["kind"]["lost_events"], 3);
        assert!(value["kind"].get("scope").is_none());
    }

    #[test]
    #[should_panic(expected = "event subject")]
    fn provider_subject_rejects_flow_event_kind() {
        let _ = EventEnvelope::from_provider(
            Timestamp {
                monotonic_ns: 7,
                wall_time_unix_ns: 1,
            },
            CaptureOrigin::from_source(CaptureSource::EbpfSyscall),
            "test",
            EventKind::HttpRequestHeaders(HttpHeaders {
                direction: Direction::Outbound,
                stream_sequence: 1,
                method: Some("GET".to_string()),
                target: Some("/".to_string()),
                status: None,
                reason: None,
                version: "HTTP/1.1".to_string(),
                headers: Vec::new(),
            }),
        );
    }

    #[test]
    #[should_panic(expected = "flow event constructor")]
    fn flow_subject_rejects_provider_event_kind() {
        let _ = EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: 7,
                wall_time_unix_ns: 1,
            },
            demo_flow(),
            CaptureOrigin::from_source(CaptureSource::EbpfSyscall),
            "test",
            EventKind::CaptureLoss(CaptureLoss {
                lost_events: 1,
                reason: "lost".to_string(),
            }),
        );
    }

    #[test]
    #[should_panic(expected = "flow event constructor")]
    fn flow_constructor_rejects_policy_event_kind() {
        let _ = EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: 7,
                wall_time_unix_ns: 1,
            },
            demo_flow(),
            CaptureOrigin::from_source(CaptureSource::EbpfSyscall),
            "test",
            EventKind::PolicyAlert(DomainEvent {
                name: "audit".to_string(),
                severity: Action::Alert,
                message: "secondary".to_string(),
                metadata: serde_json::Value::Null,
            }),
        );
    }

    #[test]
    fn event_envelope_deserialization_rejects_invalid_subject_kind() {
        let mut provider_http =
            serde_json::to_value(request_event(CaptureSource::EbpfSyscall, "/same"))
                .expect("event envelope must serialize");
        provider_http["subject"] = serde_json::json!({ "type": "provider" });

        let mut flow_capture_loss = serde_json::to_value(EventEnvelope::from_provider(
            Timestamp {
                monotonic_ns: 7,
                wall_time_unix_ns: 1,
            },
            CaptureOrigin::from_source(CaptureSource::EbpfSyscall),
            "test",
            EventKind::CaptureLoss(CaptureLoss {
                lost_events: 1,
                reason: "lost".to_string(),
            }),
        ))
        .expect("event envelope must serialize");
        flow_capture_loss["subject"] = serde_json::json!({
            "type": "flow",
            "flow": demo_flow(),
        });

        assert!(serde_json::from_value::<EventEnvelope>(provider_http).is_err());
        assert!(serde_json::from_value::<EventEnvelope>(flow_capture_loss).is_err());
    }

    #[test]
    fn event_envelope_deserialization_rejects_unknown_shape_fields() {
        let mut top_level =
            serde_json::to_value(request_event(CaptureSource::EbpfSyscall, "/same"))
                .expect("event envelope must serialize");
        top_level["flow"] = serde_json::json!(demo_flow());
        top_level["source"] = serde_json::json!("ebpf_syscall");
        top_level["provider"] = serde_json::json!("ebpf");

        let mut subject = serde_json::to_value(EventEnvelope::from_provider(
            Timestamp {
                monotonic_ns: 7,
                wall_time_unix_ns: 1,
            },
            CaptureOrigin::from_source(CaptureSource::EbpfSyscall),
            "test",
            EventKind::CaptureLoss(CaptureLoss {
                lost_events: 1,
                reason: "lost".to_string(),
            }),
        ))
        .expect("event envelope must serialize");
        subject["subject"]["flow"] = serde_json::json!(demo_flow());

        let mut origin = serde_json::to_value(request_event(CaptureSource::EbpfSyscall, "/same"))
            .expect("event envelope must serialize");
        origin["origin"]["unexpected"] = serde_json::json!(true);

        let mut kind = serde_json::to_value(request_event(CaptureSource::EbpfSyscall, "/same"))
            .expect("event envelope must serialize");
        kind["kind"]["unexpected"] = serde_json::json!(true);

        assert!(serde_json::from_value::<EventEnvelope>(top_level).is_err());
        assert!(serde_json::from_value::<EventEnvelope>(subject).is_err());
        assert!(serde_json::from_value::<EventEnvelope>(origin).is_err());
        assert!(serde_json::from_value::<EventEnvelope>(kind).is_err());
    }

    #[test]
    fn event_id_changes_when_policy_version_changes() {
        let first = request_event(CaptureSource::Replay, "/same").with_policy_version("policy@1");
        let second = request_event(CaptureSource::Replay, "/same").with_policy_version("policy@2");

        assert_ne!(first.id, second.id);
    }

    #[test]
    fn event_id_changes_when_enforcement_evidence_changes() {
        let first = request_event(CaptureSource::Replay, "/same");
        let second = request_event(CaptureSource::Replay, "/same").with_enforcement_evidence(
            EnforcementEvidence::observation_only(
                ObservationOnlyReason::EbpfSyscallPayloadSnapshot,
            ),
        );

        assert_ne!(first.id, second.id);
    }

    #[test]
    fn event_id_uses_stable_enforcement_evidence_reason_not_detail() {
        let first = request_event(CaptureSource::Replay, "/same").with_enforcement_evidence(
            EnforcementEvidence::observation_only_with_detail(
                ObservationOnlyReason::EbpfSyscallPayloadSnapshot,
                "first detail",
            ),
        );
        let second = request_event(CaptureSource::Replay, "/same").with_enforcement_evidence(
            EnforcementEvidence::observation_only_with_detail(
                ObservationOnlyReason::EbpfSyscallPayloadSnapshot,
                "second detail",
            ),
        );
        let third = request_event(CaptureSource::Replay, "/same").with_enforcement_evidence(
            EnforcementEvidence::observation_only(ObservationOnlyReason::EbpfUnresolvedFlow),
        );

        assert_eq!(first.id, second.id);
        assert_ne!(first.id, third.id);
        assert!(
            !first
                .enforcement_evidence
                .destructive_enforcement_rejection_reason()
                .is_some_and(|reason| reason.contains("first detail"))
        );
    }

    #[test]
    fn event_id_uses_provenance_instead_of_timestamp_when_present() {
        let first = request_event_at(CaptureSource::Replay, "/same", 1)
            .with_provenance(EventProvenance::primary(42, 3));
        let second = request_event_at(CaptureSource::Replay, "/same", 99)
            .with_provenance(EventProvenance::primary(42, 3));

        assert_eq!(first.id, second.id);
    }

    #[test]
    fn event_id_changes_when_provenance_primary_index_changes() {
        let first = request_event(CaptureSource::Replay, "/same")
            .with_provenance(EventProvenance::primary(42, 3));
        let second = request_event(CaptureSource::Replay, "/same")
            .with_provenance(EventProvenance::primary(42, 4));

        assert_ne!(first.id, second.id);
    }

    #[test]
    fn event_envelope_defaults_to_destructive_allowed_evidence() {
        let event = request_event(CaptureSource::Replay, "/same");

        assert_eq!(
            event.enforcement_evidence,
            EnforcementEvidence::DestructiveAllowed
        );
        assert!(
            event
                .enforcement_evidence
                .destructive_enforcement_rejection_reason()
                .is_none()
        );
    }

    #[test]
    fn event_envelope_rejects_missing_enforcement_evidence() {
        let mut value = serde_json::to_value(request_event(CaptureSource::Replay, "/same"))
            .expect("event envelope must serialize");
        value
            .as_object_mut()
            .expect("event envelope must serialize as an object")
            .remove("enforcement_evidence");

        let result = serde_json::from_value::<EventEnvelope>(value);

        assert!(result.is_err());
    }

    fn request_event(source: CaptureSource, target: &str) -> EventEnvelope {
        request_event_at(source, target, 1)
    }

    fn request_event_at(source: CaptureSource, target: &str, monotonic_ns: u64) -> EventEnvelope {
        request_event_with_origin_at(CaptureOrigin::from_source(source), target, monotonic_ns)
    }

    fn request_event_with_origin(origin: CaptureOrigin, target: &str) -> EventEnvelope {
        request_event_with_origin_at(origin, target, 1)
    }

    fn request_event_with_origin_at(
        origin: CaptureOrigin,
        target: &str,
        monotonic_ns: u64,
    ) -> EventEnvelope {
        EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns,
                wall_time_unix_ns: 1,
            },
            demo_flow(),
            origin,
            "test",
            EventKind::HttpRequestHeaders(HttpHeaders {
                direction: Direction::Outbound,
                stream_sequence: 1,
                method: Some("GET".to_string()),
                target: Some(target.to_string()),
                status: None,
                reason: None,
                version: "HTTP/1.1".to_string(),
                headers: Vec::new(),
            }),
        )
    }

    fn demo_flow() -> FlowContext {
        let process = ProcessIdentity {
            pid: 1,
            tgid: 1,
            start_time_ticks: 1,
            boot_id: "boot".to_string(),
            exe_path: "/usr/bin/demo".to_string(),
            cmdline_hash: "hash".to_string(),
            uid: 1000,
            gid: 1000,
            cgroup: None,
            systemd_service: None,
            container_id: None,
            runtime_hint: None,
        };
        let local = AddressPort {
            address: "127.0.0.1".to_string(),
            port: 50_000,
        };
        let remote = AddressPort {
            address: "127.0.0.1".to_string(),
            port: 80,
        };
        FlowContext {
            id: FlowIdentity::stable(&process, &local, &remote, TransportProtocol::Tcp, 1, None),
            process: ProcessContext {
                identity: process,
                name: "demo".to_string(),
                cmdline: vec!["demo".to_string()],
            },
            local,
            remote,
            protocol: TransportProtocol::Tcp,
            start_monotonic_ns: 1,
            socket_cookie: None,
            attribution_confidence: 100,
        }
    }
}
