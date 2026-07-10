use std::{fmt, mem, num::NonZeroU128};

pub const SELECTOR_VALUE_COST_HARD_LIMIT: usize = 4096;
pub const SELECTOR_VALUE_EVIDENCE_HARD_LIMIT: usize = 512;
pub const SELECTOR_ATOM_SIZE_HARD_LIMIT: usize = 1024;

/// A fixed-size canonical handle whose equality and proof encoding have declared upper bounds.
/// Implementations must report conservative bounds; compilation rejects zero or oversized values.
pub trait SelectorValue: Copy + fmt::Debug + Eq + Send + Sync + 'static {
    /// Upper-bound work units for one equality comparison.
    const COMPARISON_COST: usize;

    /// Upper bound for the canonical encoded value included in one proof operand.
    const EVIDENCE_BYTES: usize;
}

pub trait TargetVocabulary: Copy + fmt::Debug + Eq + Send + Sync + 'static {
    type Workload: SelectorValue;
    type Process: SelectorValue;
    type Cgroup: SelectorValue;
    type Container: SelectorValue;
    type Service: SelectorValue;
    type NetworkNamespace: SelectorValue;
    type Executable: SelectorValue;
    type Endpoint: SelectorValue;
    type TransportProtocol: SelectorValue;
    type Direction: SelectorValue;

    fn process_executable(process: &Self::Process) -> &Self::Executable;
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FactProvenanceId(NonZeroU128);

impl FactProvenanceId {
    pub fn new(value: u128) -> Result<Self, FactProvenanceIdError> {
        NonZeroU128::new(value)
            .map(Self)
            .ok_or(FactProvenanceIdError)
    }

    pub const fn get(self) -> u128 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FactProvenanceIdError;

impl fmt::Display for FactProvenanceIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("target fact provenance identifier must be non-zero")
    }
}

impl std::error::Error for FactProvenanceIdError {}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EndpointSide {
    Local,
    Remote,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AtomKind {
    Workload,
    Process,
    Cgroup,
    Container,
    Service,
    NetworkNamespace,
    Executable,
    LocalEndpoint,
    RemoteEndpoint,
    TransportProtocol,
    Direction,
}

impl AtomKind {
    pub const ALL: [Self; 11] = [
        Self::Workload,
        Self::Process,
        Self::Cgroup,
        Self::Container,
        Self::Service,
        Self::NetworkNamespace,
        Self::Executable,
        Self::LocalEndpoint,
        Self::RemoteEndpoint,
        Self::TransportProtocol,
        Self::Direction,
    ];

    pub const fn required_field(self) -> TargetField {
        match self {
            Self::Workload => TargetField::Workload,
            Self::Process => TargetField::Process,
            Self::Cgroup => TargetField::Cgroup,
            Self::Container => TargetField::Container,
            Self::Service => TargetField::Service,
            Self::NetworkNamespace => TargetField::NetworkNamespace,
            Self::Executable => TargetField::Process,
            Self::LocalEndpoint => TargetField::LocalEndpoint,
            Self::RemoteEndpoint => TargetField::RemoteEndpoint,
            Self::TransportProtocol => TargetField::TransportProtocol,
            Self::Direction => TargetField::Direction,
        }
    }

    pub(crate) const fn proves_target_scope(self) -> bool {
        matches!(
            self,
            Self::Workload
                | Self::Process
                | Self::Cgroup
                | Self::Container
                | Self::Service
                | Self::NetworkNamespace
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetAtom<V: TargetVocabulary> {
    Workload(V::Workload),
    Process(V::Process),
    Cgroup(V::Cgroup),
    Container(V::Container),
    Service(V::Service),
    NetworkNamespace(V::NetworkNamespace),
    Executable(V::Executable),
    Endpoint {
        side: EndpointSide,
        endpoint: V::Endpoint,
    },
    TransportProtocol(V::TransportProtocol),
    Direction(V::Direction),
}

impl<V: TargetVocabulary> TargetAtom<V> {
    pub const fn kind(&self) -> AtomKind {
        match self {
            Self::Workload(_) => AtomKind::Workload,
            Self::Process(_) => AtomKind::Process,
            Self::Cgroup(_) => AtomKind::Cgroup,
            Self::Container(_) => AtomKind::Container,
            Self::Service(_) => AtomKind::Service,
            Self::NetworkNamespace(_) => AtomKind::NetworkNamespace,
            Self::Executable(_) => AtomKind::Executable,
            Self::Endpoint {
                side: EndpointSide::Local,
                ..
            } => AtomKind::LocalEndpoint,
            Self::Endpoint {
                side: EndpointSide::Remote,
                ..
            } => AtomKind::RemoteEndpoint,
            Self::TransportProtocol(_) => AtomKind::TransportProtocol,
            Self::Direction(_) => AtomKind::Direction,
        }
    }

    pub fn resource_cost(&self) -> Result<AtomResourceCost, SelectorValueContractError> {
        if mem::size_of::<Self>() > SELECTOR_ATOM_SIZE_HARD_LIMIT {
            return Err(SelectorValueContractError::AtomRepresentationTooLarge {
                size: mem::size_of::<Self>(),
                hard_limit: SELECTOR_ATOM_SIZE_HARD_LIMIT,
            });
        }
        match self {
            Self::Workload(_) => value_resource_cost::<V::Workload>(),
            Self::Process(_) => value_resource_cost::<V::Process>(),
            Self::Cgroup(_) => value_resource_cost::<V::Cgroup>(),
            Self::Container(_) => value_resource_cost::<V::Container>(),
            Self::Service(_) => value_resource_cost::<V::Service>(),
            Self::NetworkNamespace(_) => value_resource_cost::<V::NetworkNamespace>(),
            Self::Executable(_) => value_resource_cost::<V::Executable>(),
            Self::Endpoint { .. } => value_resource_cost::<V::Endpoint>(),
            Self::TransportProtocol(_) => value_resource_cost::<V::TransportProtocol>(),
            Self::Direction(_) => value_resource_cost::<V::Direction>(),
        }
    }

    pub(crate) fn evaluate(&self, facts: &TargetFacts<V>) -> AtomEvaluation<V> {
        let field = self.kind().required_field();
        let observed = match self {
            Self::Workload(_) => facts
                .workload
                .as_ref()
                .map(|fact| fact.map(TargetAtom::Workload)),
            Self::Process(_) => facts
                .process
                .as_ref()
                .map(|fact| fact.map(TargetAtom::Process)),
            Self::Cgroup(_) => facts
                .cgroup
                .as_ref()
                .map(|fact| fact.map(TargetAtom::Cgroup)),
            Self::Container(_) => facts
                .container
                .as_ref()
                .map(|fact| fact.map(TargetAtom::Container)),
            Self::Service(_) => facts
                .service
                .as_ref()
                .map(|fact| fact.map(TargetAtom::Service)),
            Self::NetworkNamespace(_) => facts
                .network_namespace
                .as_ref()
                .map(|fact| fact.map(TargetAtom::NetworkNamespace)),
            Self::Executable(_) => facts.process.as_ref().map(|fact| ObservedTargetFact {
                value: TargetAtom::Executable(*V::process_executable(&fact.value)),
                provenance: fact.provenance,
            }),
            Self::Endpoint {
                side: EndpointSide::Local,
                ..
            } => facts
                .local_endpoint
                .as_ref()
                .map(|fact| ObservedTargetFact {
                    value: TargetAtom::Endpoint {
                        side: EndpointSide::Local,
                        endpoint: fact.value,
                    },
                    provenance: fact.provenance,
                }),
            Self::Endpoint {
                side: EndpointSide::Remote,
                ..
            } => facts
                .remote_endpoint
                .as_ref()
                .map(|fact| ObservedTargetFact {
                    value: TargetAtom::Endpoint {
                        side: EndpointSide::Remote,
                        endpoint: fact.value,
                    },
                    provenance: fact.provenance,
                }),
            Self::TransportProtocol(_) => facts
                .transport_protocol
                .as_ref()
                .map(|fact| fact.map(TargetAtom::TransportProtocol)),
            Self::Direction(_) => facts
                .direction
                .as_ref()
                .map(|fact| fact.map(TargetAtom::Direction)),
        };
        let matching = match observed.as_ref() {
            Some(actual) if actual.value == *self => AtomMatch::Match,
            Some(_) => AtomMatch::NoMatch,
            None => AtomMatch::Unknown(field),
        };
        AtomEvaluation {
            matching,
            evidence: AtomEvidence {
                expected: *self,
                observed,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TargetField {
    Workload,
    Process,
    Cgroup,
    Container,
    Service,
    NetworkNamespace,
    LocalEndpoint,
    RemoteEndpoint,
    TransportProtocol,
    Direction,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservedTargetFact<V: TargetVocabulary> {
    value: TargetAtom<V>,
    provenance: FactProvenanceId,
}

impl<V: TargetVocabulary> ObservedTargetFact<V> {
    pub const fn value(&self) -> &TargetAtom<V> {
        &self.value
    }

    pub const fn provenance(&self) -> FactProvenanceId {
        self.provenance
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AtomEvidence<V: TargetVocabulary> {
    expected: TargetAtom<V>,
    observed: Option<ObservedTargetFact<V>>,
}

impl<V: TargetVocabulary> AtomEvidence<V> {
    pub const fn expected(&self) -> &TargetAtom<V> {
        &self.expected
    }

    pub fn observed(&self) -> Option<&ObservedTargetFact<V>> {
        self.observed.as_ref()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetFacts<V: TargetVocabulary> {
    workload: Option<Observed<V::Workload>>,
    process: Option<Observed<V::Process>>,
    cgroup: Option<Observed<V::Cgroup>>,
    container: Option<Observed<V::Container>>,
    service: Option<Observed<V::Service>>,
    network_namespace: Option<Observed<V::NetworkNamespace>>,
    local_endpoint: Option<Observed<V::Endpoint>>,
    remote_endpoint: Option<Observed<V::Endpoint>>,
    transport_protocol: Option<Observed<V::TransportProtocol>>,
    direction: Option<Observed<V::Direction>>,
}

impl<V: TargetVocabulary> TargetFacts<V> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_workload(mut self, value: V::Workload, provenance: FactProvenanceId) -> Self {
        self.workload = Some(Observed::new(value, provenance));
        self
    }

    pub fn with_process(mut self, value: V::Process, provenance: FactProvenanceId) -> Self {
        self.process = Some(Observed::new(value, provenance));
        self
    }

    pub fn with_cgroup(mut self, value: V::Cgroup, provenance: FactProvenanceId) -> Self {
        self.cgroup = Some(Observed::new(value, provenance));
        self
    }

    pub fn with_container(mut self, value: V::Container, provenance: FactProvenanceId) -> Self {
        self.container = Some(Observed::new(value, provenance));
        self
    }

    pub fn with_service(mut self, value: V::Service, provenance: FactProvenanceId) -> Self {
        self.service = Some(Observed::new(value, provenance));
        self
    }

    pub fn with_network_namespace(
        mut self,
        value: V::NetworkNamespace,
        provenance: FactProvenanceId,
    ) -> Self {
        self.network_namespace = Some(Observed::new(value, provenance));
        self
    }

    pub fn with_local_endpoint(mut self, value: V::Endpoint, provenance: FactProvenanceId) -> Self {
        self.local_endpoint = Some(Observed::new(value, provenance));
        self
    }

    pub fn with_remote_endpoint(
        mut self,
        value: V::Endpoint,
        provenance: FactProvenanceId,
    ) -> Self {
        self.remote_endpoint = Some(Observed::new(value, provenance));
        self
    }

    pub fn with_transport_protocol(
        mut self,
        value: V::TransportProtocol,
        provenance: FactProvenanceId,
    ) -> Self {
        self.transport_protocol = Some(Observed::new(value, provenance));
        self
    }

    pub fn with_direction(mut self, value: V::Direction, provenance: FactProvenanceId) -> Self {
        self.direction = Some(Observed::new(value, provenance));
        self
    }
}

impl<V: TargetVocabulary> Default for TargetFacts<V> {
    fn default() -> Self {
        Self {
            workload: None,
            process: None,
            cgroup: None,
            container: None,
            service: None,
            network_namespace: None,
            local_endpoint: None,
            remote_endpoint: None,
            transport_protocol: None,
            direction: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Observed<T> {
    value: T,
    provenance: FactProvenanceId,
}

impl<T> Observed<T> {
    const fn new(value: T, provenance: FactProvenanceId) -> Self {
        Self { value, provenance }
    }

    fn map<V: TargetVocabulary>(
        &self,
        map: impl FnOnce(T) -> TargetAtom<V>,
    ) -> ObservedTargetFact<V>
    where
        T: Copy,
    {
        ObservedTargetFact {
            value: map(self.value),
            provenance: self.provenance,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AtomMatch {
    Match,
    NoMatch,
    Unknown(TargetField),
}

pub(crate) struct AtomEvaluation<V: TargetVocabulary> {
    pub(crate) matching: AtomMatch,
    pub(crate) evidence: AtomEvidence<V>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AtomResourceCost {
    comparison_units: usize,
    value_evidence_bytes: usize,
}

impl AtomResourceCost {
    pub const fn comparison_units(self) -> usize {
        self.comparison_units
    }

    pub const fn value_evidence_bytes(self) -> usize {
        self.value_evidence_bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectorValueContractError {
    ZeroComparisonCost,
    ComparisonCostTooLarge {
        cost: usize,
        hard_limit: usize,
    },
    ZeroEvidenceBytes,
    EvidenceTooLarge {
        bytes: usize,
        hard_limit: usize,
    },
    EvidenceSmallerThanRepresentation {
        evidence_bytes: usize,
        representation_bytes: usize,
    },
    AtomRepresentationTooLarge {
        size: usize,
        hard_limit: usize,
    },
}

impl fmt::Display for SelectorValueContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroComparisonCost => {
                formatter.write_str("selector value comparison cost must be non-zero")
            }
            Self::ComparisonCostTooLarge { cost, hard_limit } => write!(
                formatter,
                "selector value comparison cost {cost} exceeds hard limit {hard_limit}"
            ),
            Self::ZeroEvidenceBytes => {
                formatter.write_str("selector value evidence size must be non-zero")
            }
            Self::EvidenceTooLarge { bytes, hard_limit } => write!(
                formatter,
                "selector value evidence size {bytes} exceeds hard limit {hard_limit}"
            ),
            Self::EvidenceSmallerThanRepresentation {
                evidence_bytes,
                representation_bytes,
            } => write!(
                formatter,
                "selector value evidence size {evidence_bytes} is smaller than its {representation_bytes}-byte representation"
            ),
            Self::AtomRepresentationTooLarge { size, hard_limit } => write!(
                formatter,
                "selector atom representation size {size} exceeds hard limit {hard_limit}"
            ),
        }
    }
}

impl std::error::Error for SelectorValueContractError {}

fn value_resource_cost<T: SelectorValue>() -> Result<AtomResourceCost, SelectorValueContractError> {
    if T::COMPARISON_COST == 0 {
        return Err(SelectorValueContractError::ZeroComparisonCost);
    }
    if T::COMPARISON_COST > SELECTOR_VALUE_COST_HARD_LIMIT {
        return Err(SelectorValueContractError::ComparisonCostTooLarge {
            cost: T::COMPARISON_COST,
            hard_limit: SELECTOR_VALUE_COST_HARD_LIMIT,
        });
    }
    if T::EVIDENCE_BYTES == 0 {
        return Err(SelectorValueContractError::ZeroEvidenceBytes);
    }
    if T::EVIDENCE_BYTES > SELECTOR_VALUE_EVIDENCE_HARD_LIMIT {
        return Err(SelectorValueContractError::EvidenceTooLarge {
            bytes: T::EVIDENCE_BYTES,
            hard_limit: SELECTOR_VALUE_EVIDENCE_HARD_LIMIT,
        });
    }
    if T::EVIDENCE_BYTES < mem::size_of::<T>() {
        return Err(
            SelectorValueContractError::EvidenceSmallerThanRepresentation {
                evidence_bytes: T::EVIDENCE_BYTES,
                representation_bytes: mem::size_of::<T>(),
            },
        );
    }
    Ok(AtomResourceCost {
        comparison_units: T::COMPARISON_COST,
        value_evidence_bytes: T::EVIDENCE_BYTES,
    })
}
