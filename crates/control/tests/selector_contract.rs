use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::{Arc, Barrier},
};

use control::{
    AtomEvaluationCost, AtomKind, AtomSupport, CaptureDecision, CaptureSelector, CompileError,
    EndpointSide, EnforcementDecision, EnforcementSelector, FactProvenanceId, MatchOutcome,
    Predicate, PredicateBudget, PredicateKey, PredicateName, PredicateNamespace, PredicateRef,
    PredicateRegistry, PredicateRegistryError, PredicateRegistryRevision, QuerySelector,
    QueryUnknownPolicy, SelectorKind, SelectorValue, TargetAtom, TargetFacts, TargetField,
    TargetVocabulary, TraceNodeKind, UnknownMatchReason, atom_support,
};

#[test]
fn selector_compilers_emit_auditable_proofs_and_apply_distinct_unknown_policy() {
    let registry = PredicateRegistry::<TestVocabulary>::new(revision(1));
    let snapshot = registry.snapshot().expect("registry snapshot");
    let workload = Workload(41);
    let remote = Endpoint {
        address: "192.0.2.10".parse().expect("IP address"),
        port: 443,
    };
    let predicate = Predicate::all(
        Predicate::atom(TargetAtom::Workload(workload)),
        vec![Predicate::negate(Predicate::negate(Predicate::atom(
            TargetAtom::Endpoint {
                side: EndpointSide::Remote,
                endpoint: remote,
            },
        )))],
    );

    let query = QuerySelector::compile(predicate.clone(), &snapshot, PredicateBudget::default())
        .expect("query selector");
    let capture =
        CaptureSelector::compile(predicate.clone(), &snapshot, PredicateBudget::default())
            .expect("capture selector");
    let enforcement =
        EnforcementSelector::compile(predicate, &snapshot, PredicateBudget::default())
            .expect("enforcement selector");

    let workload_provenance = provenance(101);
    let endpoint_provenance = provenance(102);
    let matching = TargetFacts::new()
        .with_workload(workload, workload_provenance)
        .with_remote_endpoint(remote, endpoint_provenance);
    let query_match = query.evaluate(&matching, QueryUnknownPolicy::Exclude);
    let capture_match = capture.evaluate(&matching);
    let enforcement_match = enforcement.evaluate(&matching);
    assert!(query_match.is_included());
    assert!(capture_match.is_admitted());
    assert!(enforcement_match.is_selected());
    assert_eq!(query_match.evaluation().outcome(), MatchOutcome::Match);
    assert_eq!(query_match.evaluation().registry_revision(), revision(1));
    assert_eq!(
        query_match.evaluation().trace(),
        capture_match.evaluation().trace()
    );
    assert_eq!(
        query_match.evaluation().trace(),
        enforcement_match.evaluation().trace()
    );

    let trace = query_match.evaluation().trace();
    assert_eq!(trace.len(), 5);
    assert_eq!(
        (trace[0].node_id(), trace[0].parent_id(), trace[0].depth()),
        (1, Some(0), 2)
    );
    assert_atom_evidence(
        trace[0].kind(),
        &TargetAtom::Workload(workload),
        Some((&TargetAtom::Workload(workload), workload_provenance)),
    );
    assert_eq!(
        (trace[1].node_id(), trace[1].parent_id(), trace[1].depth()),
        (4, Some(3), 4)
    );
    assert_atom_evidence(
        trace[1].kind(),
        &TargetAtom::Endpoint {
            side: EndpointSide::Remote,
            endpoint: remote,
        },
        Some((
            &TargetAtom::Endpoint {
                side: EndpointSide::Remote,
                endpoint: remote,
            },
            endpoint_provenance,
        )),
    );
    assert!(matches!(trace[2].kind(), TraceNodeKind::Not));
    assert_eq!((trace[2].node_id(), trace[2].parent_id()), (3, Some(2)));
    assert!(matches!(trace[3].kind(), TraceNodeKind::Not));
    assert_eq!((trace[3].node_id(), trace[3].parent_id()), (2, Some(0)));
    assert!(matches!(trace[4].kind(), TraceNodeKind::All));
    assert_eq!((trace[4].node_id(), trace[4].parent_id()), (0, None));

    let missing_endpoint = TargetFacts::new().with_workload(workload, workload_provenance);
    let query_unknown = query.evaluate(&missing_endpoint, QueryUnknownPolicy::Include);
    let capture_unknown = capture.evaluate(&missing_endpoint);
    let enforcement_unknown = enforcement.evaluate(&missing_endpoint);
    let expected = MatchOutcome::Unknown(UnknownMatchReason::MissingField(
        TargetField::RemoteEndpoint,
    ));
    assert!(query_unknown.is_included());
    assert!(matches!(capture_unknown, CaptureDecision::RejectUnknown(_)));
    assert!(matches!(
        enforcement_unknown,
        EnforcementDecision::RejectUnknown(_)
    ));
    assert_eq!(query_unknown.evaluation().outcome(), expected);
    assert_eq!(capture_unknown.evaluation().outcome(), expected);
    assert_eq!(enforcement_unknown.evaluation().outcome(), expected);
    assert_atom_evidence(
        query_unknown.evaluation().trace()[1].kind(),
        &TargetAtom::Endpoint {
            side: EndpointSide::Remote,
            endpoint: remote,
        },
        None,
    );

    assert!(
        !query
            .evaluate(&missing_endpoint, QueryUnknownPolicy::Exclude)
            .is_included()
    );
    let mismatch = TargetFacts::new()
        .with_workload(workload, workload_provenance)
        .with_remote_endpoint(
            Endpoint {
                address: "192.0.2.11".parse().expect("IP address"),
                port: 443,
            },
            endpoint_provenance,
        );
    assert_eq!(
        query
            .evaluate(&mismatch, QueryUnknownPolicy::Include)
            .evaluation()
            .outcome(),
        MatchOutcome::NoMatch
    );
    assert!(matches!(
        capture.evaluate(&mismatch),
        CaptureDecision::RejectNoMatch(_)
    ));
    assert!(matches!(
        enforcement.evaluate(&mismatch),
        EnforcementDecision::RejectNoMatch(_)
    ));
}

#[test]
fn registry_namespaces_reload_atomically_and_compiled_plans_pin_revisions() {
    let registry = PredicateRegistry::<TestVocabulary>::new(revision(1));
    let blue = key("tenant/blue", "frontend");
    let green = key("tenant/green", "frontend");
    registry
        .replace(
            revision(1),
            revision(2),
            BTreeMap::from([
                (
                    blue.clone(),
                    Predicate::atom(TargetAtom::Workload(Workload(10))),
                ),
                (
                    green.clone(),
                    Predicate::atom(TargetAtom::Workload(Workload(20))),
                ),
            ]),
            PredicateBudget::default(),
        )
        .expect("registry reload");
    let revision_two = registry.snapshot().expect("revision two");
    assert_eq!(revision_two.len(), 2);
    assert!(revision_two.predicate(&blue).is_some());
    assert!(revision_two.predicate(&green).is_some());

    let old_plan = QuerySelector::compile(
        Predicate::reference(PredicateRef::new(blue.clone(), revision(2))),
        &revision_two,
        PredicateBudget::default(),
    )
    .expect("old plan");
    registry
        .replace(
            revision(2),
            revision(3),
            BTreeMap::from([
                (
                    blue.clone(),
                    Predicate::atom(TargetAtom::Workload(Workload(30))),
                ),
                (green, Predicate::atom(TargetAtom::Workload(Workload(20)))),
            ]),
            PredicateBudget::default(),
        )
        .expect("registry reload");

    assert_eq!(old_plan.registry_revision(), revision(2));
    assert!(
        old_plan
            .evaluate(
                &TargetFacts::new().with_workload(Workload(10), provenance(1)),
                QueryUnknownPolicy::Exclude,
            )
            .is_included()
    );

    let revision_three = registry.snapshot().expect("revision three");
    let new_plan = QuerySelector::compile(
        Predicate::reference(PredicateRef::new(blue.clone(), revision(3))),
        &revision_three,
        PredicateBudget::default(),
    )
    .expect("new plan");
    assert!(
        new_plan
            .evaluate(
                &TargetFacts::new().with_workload(Workload(30), provenance(2)),
                QueryUnknownPolicy::Exclude,
            )
            .is_included()
    );

    let stale = QuerySelector::compile(
        Predicate::reference(PredicateRef::new(blue, revision(2))),
        &revision_three,
        PredicateBudget::default(),
    );
    assert!(matches!(stale, Err(CompileError::StaleReference { .. })));

    let conflict = registry.replace(
        revision(2),
        revision(4),
        BTreeMap::new(),
        PredicateBudget::default(),
    );
    assert!(matches!(
        conflict,
        Err(PredicateRegistryError::RevisionConflict {
            expected,
            actual
        }) if expected == revision(2) && actual == revision(3)
    ));
    assert_eq!(
        registry.snapshot().expect("snapshot").revision(),
        revision(3)
    );
}

#[test]
fn concurrent_registry_reloads_publish_exactly_one_candidate() {
    let registry = Arc::new(PredicateRegistry::<TestVocabulary>::new(revision(1)));
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for value in [10, 20] {
        let registry = Arc::clone(&registry);
        let barrier = Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            registry.replace(
                revision(1),
                revision(2),
                BTreeMap::from([(
                    key("test", "winner"),
                    Predicate::atom(TargetAtom::Workload(Workload(value))),
                )]),
                PredicateBudget::default(),
            )
        }));
    }
    barrier.wait();

    let results = workers
        .into_iter()
        .map(|worker| worker.join().expect("reload worker"))
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(PredicateRegistryError::RevisionConflict { .. })))
            .count(),
        1
    );
    assert_eq!(
        registry.snapshot().expect("snapshot").revision(),
        revision(2)
    );
}

#[test]
fn registry_and_compilers_reject_cycles_exhaustion_and_unsafe_scope() {
    let registry = PredicateRegistry::<TestVocabulary>::new(revision(1));
    let left = key("test", "left");
    let right = key("test", "right");
    let cycle = registry.replace(
        revision(1),
        revision(2),
        BTreeMap::from([
            (
                left.clone(),
                Predicate::reference(PredicateRef::new(right.clone(), revision(2))),
            ),
            (
                right,
                Predicate::reference(PredicateRef::new(left, revision(2))),
            ),
        ]),
        PredicateBudget::default(),
    );
    assert!(matches!(
        cycle,
        Err(PredicateRegistryError::InvalidPredicate {
            source: CompileError::ReferenceCycle { .. },
            ..
        })
    ));
    assert_eq!(
        registry.snapshot().expect("snapshot").revision(),
        revision(1)
    );

    let snapshot = registry.snapshot().expect("snapshot");
    let depth_limited = QuerySelector::compile(
        Predicate::negate(Predicate::negate(Predicate::negate(Predicate::atom(
            TargetAtom::Workload(Workload(1)),
        )))),
        &snapshot,
        budget(16, 3, 16),
    );
    assert!(matches!(
        depth_limited,
        Err(CompileError::DepthBudgetExceeded { max: 3 })
    ));

    let size_limited = QuerySelector::compile(
        Predicate::any(
            Predicate::atom(TargetAtom::Workload(Workload(1))),
            vec![
                Predicate::atom(TargetAtom::Workload(Workload(2))),
                Predicate::atom(TargetAtom::Workload(Workload(3))),
            ],
        ),
        &snapshot,
        budget(3, 16, 16),
    );
    assert!(matches!(
        size_limited,
        Err(CompileError::NodeBudgetExceeded { max: 3 })
    ));

    let endpoint_only = Predicate::atom(TargetAtom::Endpoint {
        side: EndpointSide::Remote,
        endpoint: Endpoint {
            address: "198.51.100.2".parse().expect("IP address"),
            port: 80,
        },
    });
    let capture =
        CaptureSelector::compile(endpoint_only.clone(), &snapshot, PredicateBudget::default());
    assert!(matches!(
        capture,
        Err(CompileError::MissingPositiveTargetScope {
            selector: SelectorKind::Capture
        })
    ));

    let alternative_scope = CaptureSelector::compile(
        Predicate::any(
            Predicate::atom(TargetAtom::Workload(Workload(1))),
            vec![endpoint_only],
        ),
        &snapshot,
        PredicateBudget::default(),
    );
    assert!(matches!(
        alternative_scope,
        Err(CompileError::MissingPositiveTargetScope {
            selector: SelectorKind::Capture
        })
    ));

    let excluded_scope = CaptureSelector::compile(
        Predicate::negate(Predicate::atom(TargetAtom::Workload(Workload(1)))),
        &snapshot,
        PredicateBudget::default(),
    );
    assert!(matches!(
        excluded_scope,
        Err(CompileError::MissingPositiveTargetScope {
            selector: SelectorKind::Capture
        })
    ));
    CaptureSelector::compile(
        Predicate::negate(Predicate::negate(Predicate::atom(TargetAtom::Workload(
            Workload(1),
        )))),
        &snapshot,
        PredicateBudget::default(),
    )
    .expect("double negation preserves positive scope");

    let unsupported = EnforcementSelector::compile(
        Predicate::all(
            Predicate::atom(TargetAtom::Workload(Workload(1))),
            vec![Predicate::atom(TargetAtom::Executable(Executable(7)))],
        ),
        &snapshot,
        PredicateBudget::default(),
    );
    assert!(matches!(
        unsupported,
        Err(CompileError::UnsupportedAtom {
            selector: SelectorKind::Enforcement,
            atom: AtomKind::Executable
        })
    ));
}

#[test]
fn reference_graphs_fail_closed_and_large_shared_subgraphs_remain_bounded() {
    let registry = PredicateRegistry::<TestVocabulary>::new(revision(1));
    let first = key("test", "first");
    let second = key("test", "second");
    let third = key("test", "third");
    let missing = key("test", "missing");

    let missing_target = registry.replace(
        revision(1),
        revision(2),
        BTreeMap::from([(
            first.clone(),
            Predicate::reference(PredicateRef::new(missing, revision(2))),
        )]),
        PredicateBudget::default(),
    );
    assert!(matches!(
        missing_target,
        Err(PredicateRegistryError::InvalidPredicate {
            source: CompileError::MissingReference { .. },
            ..
        })
    ));

    let shared = key("test", "shared");
    let mut predicates = BTreeMap::from([
        (
            first.clone(),
            Predicate::reference(PredicateRef::new(second.clone(), revision(2))),
        ),
        (
            second,
            Predicate::reference(PredicateRef::new(third.clone(), revision(2))),
        ),
        (
            third,
            Predicate::reference(PredicateRef::new(shared.clone(), revision(2))),
        ),
        (
            shared.clone(),
            Predicate::any(
                Predicate::atom(TargetAtom::Workload(Workload(0))),
                (1..512)
                    .map(|value| Predicate::atom(TargetAtom::Workload(Workload(value))))
                    .collect(),
            ),
        ),
    ]);
    for alias in 0..512 {
        predicates.insert(
            key("alias", &format!("shared-{alias}")),
            Predicate::reference(PredicateRef::new(shared.clone(), revision(2))),
        );
    }
    registry
        .replace(
            revision(1),
            revision(2),
            predicates,
            PredicateBudget::default(),
        )
        .expect("shared registry graph");

    let exhausted = QuerySelector::compile(
        Predicate::reference(PredicateRef::new(first, revision(2))),
        &registry.snapshot().expect("snapshot"),
        budget(1024, 16, 2),
    );
    assert!(matches!(
        exhausted,
        Err(CompileError::ReferenceBudgetExceeded { max: 2 })
    ));
}

#[test]
fn long_reference_chains_fail_before_exhausting_the_thread_stack() {
    let registry = PredicateRegistry::<TestVocabulary>::new(revision(1));
    let chain_length = 2048;
    let mut predicates = BTreeMap::new();
    for index in 0..chain_length {
        let current = key("chain", &format!("node-{index}"));
        let predicate = if index + 1 == chain_length {
            Predicate::atom(TargetAtom::Workload(Workload(1)))
        } else {
            Predicate::reference(PredicateRef::new(
                key("chain", &format!("node-{}", index + 1)),
                revision(2),
            ))
        };
        predicates.insert(current, predicate);
    }

    let result = registry.replace(revision(1), revision(2), predicates, budget(4096, 64, 4096));
    assert!(matches!(
        result,
        Err(PredicateRegistryError::InvalidPredicate {
            source: CompileError::DepthBudgetExceeded { max: 64 },
            ..
        })
    ));
}

#[test]
fn compiler_enforces_declared_comparison_and_proof_byte_budgets() {
    let registry = PredicateRegistry::<TestVocabulary>::new(revision(1));
    let snapshot = registry.snapshot().expect("snapshot");
    let predicate = Predicate::all(
        Predicate::atom(TargetAtom::Workload(Workload(1))),
        vec![Predicate::atom(TargetAtom::Workload(Workload(2)))],
    );

    let comparison_limited = QuerySelector::compile(
        predicate.clone(),
        &snapshot,
        PredicateBudget::new(16, 16, 16, 4, 8 * 1024 * 1024).expect("budget"),
    );
    assert!(matches!(
        comparison_limited,
        Err(CompileError::EvaluationCostBudgetExceeded { max: 4 })
    ));

    let proof_limited = QuerySelector::compile(
        predicate,
        &snapshot,
        PredicateBudget::new(16, 16, 16, 64, 1567).expect("budget"),
    );
    assert!(matches!(
        proof_limited,
        Err(CompileError::ProofBytesBudgetExceeded { max: 1567 })
    ));
}

#[test]
fn compiler_rejects_vocabulary_values_without_a_bounded_evidence_contract() {
    let registry = PredicateRegistry::<OversizedVocabulary>::new(revision(1));
    let snapshot = registry.snapshot().expect("snapshot");
    let result = QuerySelector::compile(
        Predicate::atom(TargetAtom::Workload(OversizedValue([0; 513]))),
        &snapshot,
        PredicateBudget::default(),
    );

    assert!(matches!(
        result,
        Err(CompileError::InvalidAtomContract {
            atom: AtomKind::Workload,
            source: control::SelectorValueContractError::EvidenceTooLarge {
                bytes: 513,
                hard_limit: 512
            }
        })
    ));
}

#[test]
fn atom_support_matrix_is_explicit_for_every_selector_kind() {
    for atom in AtomKind::ALL {
        assert_eq!(
            atom_support(SelectorKind::Query, atom),
            AtomSupport::Supported {
                required_field: atom.required_field(),
                cost: AtomEvaluationCost::DeclaredConstant,
            }
        );
        assert_eq!(
            atom_support(SelectorKind::Capture, atom),
            AtomSupport::Supported {
                required_field: atom.required_field(),
                cost: AtomEvaluationCost::DeclaredConstant,
            }
        );
        let enforcement = atom_support(SelectorKind::Enforcement, atom);
        if atom == AtomKind::Executable {
            assert_eq!(enforcement, AtomSupport::Unsupported);
        } else {
            assert_eq!(
                enforcement,
                AtomSupport::Supported {
                    required_field: atom.required_field(),
                    cost: AtomEvaluationCost::DeclaredConstant,
                }
            );
        }
    }
}

#[test]
fn every_typed_atom_preserves_its_observed_value_and_provenance() {
    let registry = PredicateRegistry::<TestVocabulary>::new(revision(1));
    let snapshot = registry.snapshot().expect("snapshot");
    let process = Process {
        id: 2,
        executable: Executable(7),
    };
    let local = Endpoint {
        address: "127.0.0.1".parse().expect("IP address"),
        port: 8080,
    };
    let remote = Endpoint {
        address: "192.0.2.20".parse().expect("IP address"),
        port: 443,
    };
    let facts = TargetFacts::new()
        .with_workload(Workload(1), provenance(1))
        .with_process(process, provenance(2))
        .with_cgroup(Cgroup(3), provenance(3))
        .with_container(Container(4), provenance(4))
        .with_service(Service(5), provenance(5))
        .with_network_namespace(NetworkNamespace(6), provenance(6))
        .with_local_endpoint(local, provenance(7))
        .with_remote_endpoint(remote, provenance(8))
        .with_transport_protocol(TransportProtocol(9), provenance(9))
        .with_direction(Direction(10), provenance(10));
    let atoms = [
        (TargetAtom::Workload(Workload(1)), provenance(1)),
        (TargetAtom::Process(process), provenance(2)),
        (TargetAtom::Cgroup(Cgroup(3)), provenance(3)),
        (TargetAtom::Container(Container(4)), provenance(4)),
        (TargetAtom::Service(Service(5)), provenance(5)),
        (
            TargetAtom::NetworkNamespace(NetworkNamespace(6)),
            provenance(6),
        ),
        (TargetAtom::Executable(Executable(7)), provenance(2)),
        (
            TargetAtom::Endpoint {
                side: EndpointSide::Local,
                endpoint: local,
            },
            provenance(7),
        ),
        (
            TargetAtom::Endpoint {
                side: EndpointSide::Remote,
                endpoint: remote,
            },
            provenance(8),
        ),
        (
            TargetAtom::TransportProtocol(TransportProtocol(9)),
            provenance(9),
        ),
        (TargetAtom::Direction(Direction(10)), provenance(10)),
    ];

    for (atom, expected_provenance) in atoms {
        let selector =
            QuerySelector::compile(Predicate::atom(atom), &snapshot, PredicateBudget::default())
                .expect("query selector");
        let decision = selector.evaluate(&facts, QueryUnknownPolicy::Exclude);
        assert_eq!(decision.evaluation().outcome(), MatchOutcome::Match);
        assert_eq!(decision.evaluation().trace().len(), 1);
        assert_atom_evidence(
            decision.evaluation().trace()[0].kind(),
            &atom,
            Some((&atom, expected_provenance)),
        );
    }
}

fn assert_atom_evidence(
    kind: &TraceNodeKind<TestVocabulary>,
    expected: &TargetAtom<TestVocabulary>,
    observed: Option<(&TargetAtom<TestVocabulary>, FactProvenanceId)>,
) {
    let TraceNodeKind::Atom(evidence) = kind else {
        panic!("expected atom trace");
    };
    assert_eq!(evidence.expected(), expected);
    match (evidence.observed(), observed) {
        (Some(actual), Some((expected_value, expected_provenance))) => {
            assert_eq!(actual.value(), expected_value);
            assert_eq!(actual.provenance(), expected_provenance);
        }
        (None, None) => {}
        (actual, expected) => panic!("observed evidence mismatch: {actual:?} != {expected:?}"),
    }
}

fn revision(value: u64) -> PredicateRegistryRevision {
    PredicateRegistryRevision::new(value).expect("registry revision")
}

fn key(namespace: &str, name: &str) -> PredicateKey {
    PredicateKey::new(
        PredicateNamespace::new(namespace).expect("predicate namespace"),
        PredicateName::new(name).expect("predicate name"),
    )
}

fn provenance(value: u128) -> FactProvenanceId {
    FactProvenanceId::new(value).expect("fact provenance")
}

fn budget(nodes: usize, depth: usize, references: usize) -> PredicateBudget {
    PredicateBudget::new(nodes, depth, references, 65_536, 8 * 1024 * 1024)
        .expect("predicate budget")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TestVocabulary;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Workload(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Process {
    id: u64,
    executable: Executable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Cgroup(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Container(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Service(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NetworkNamespace(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Executable(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Endpoint {
    address: IpAddr,
    port: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TransportProtocol(u8);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Direction(u8);

macro_rules! selector_values {
    ($($value:ty),+ $(,)?) => {
        $(
            impl SelectorValue for $value {
                const COMPARISON_COST: usize = 1;
                const EVIDENCE_BYTES: usize = std::mem::size_of::<Self>();
            }
        )+
    };
}

selector_values!(
    Workload,
    Process,
    Cgroup,
    Container,
    Service,
    NetworkNamespace,
    Executable,
    Endpoint,
    TransportProtocol,
    Direction,
);

impl TargetVocabulary for TestVocabulary {
    type Workload = Workload;
    type Process = Process;
    type Cgroup = Cgroup;
    type Container = Container;
    type Service = Service;
    type NetworkNamespace = NetworkNamespace;
    type Executable = Executable;
    type Endpoint = Endpoint;
    type TransportProtocol = TransportProtocol;
    type Direction = Direction;

    fn process_executable(process: &Self::Process) -> &Self::Executable {
        &process.executable
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OversizedVocabulary;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OversizedValue([u8; 513]);

impl SelectorValue for OversizedValue {
    const COMPARISON_COST: usize = 1;
    const EVIDENCE_BYTES: usize = 513;
}

impl TargetVocabulary for OversizedVocabulary {
    type Workload = OversizedValue;
    type Process = Process;
    type Cgroup = Cgroup;
    type Container = Container;
    type Service = Service;
    type NetworkNamespace = NetworkNamespace;
    type Executable = Executable;
    type Endpoint = Endpoint;
    type TransportProtocol = TransportProtocol;
    type Direction = Direction;

    fn process_executable(process: &Self::Process) -> &Self::Executable {
        &process.executable
    }
}
