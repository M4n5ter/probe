use attribution::proof::{
    AdmissionDecision, AdmissionPolicy, AdmissionPolicyParts, AdmissionRejection,
    AttributionBudget, AttributionBudgetSpec, AttributionConfidence, AttributionConfidenceGrant,
    AttributionEngine, AttributionError, AttributionGapReason, AttributionJoinRule,
    AttributionResource, AttributionScope, AttributionSnapshot, AttributionSnapshotAuthority,
    AttributionSnapshotError, AttributionSnapshotParts, AttributionSource, AuthorizationStatus,
    CalibratedInterval, CalibratedValidity, CandidateSourceSnapshot, CaptureGrant,
    CapturePrincipal, CaptureSubjectScope, CompletenessAllowance, CorrelationCandidate,
    CorrelationCandidateParts, CoverageCursor, CoverageWindow, DirectJoinKey, DirectSocketFact,
    FactProvenance, HostAuthorizationContext, HostCaptureAuthority, HostCaptureAuthorizationParts,
    HostCaptureGrant, MonotonicInstant, PacketFingerprint, PacketObservation, PayloadAccess,
    RetentionLimit, SelectionAttestationParts, SelectionAuthority, SnapshotVerificationError,
    SocketRole, SourceCoverage, SourceIdentity, SourceLoss, SourceSequence, SourceSequenceRange,
    StageRelation, TargetBinding, TargetSelection, TimeInterval, ValidityInterval,
};
use probe_core::{
    AttributionEvidenceId, AuthorizationAuditId, AuthorizationId, AuthorizationIssuerId,
    AuthorizationNonce, BootId, CaptureSelectorDigest, CaptureStageId, CgroupId,
    ClockCalibrationId, FlowId, NetworkNamespaceId, ObservationIntentId, ProcessId, Revision,
    SelectionProofId, SocketId, SourceEpochId, SourceInstanceId, SubjectId, WorkloadId,
};

#[test]
fn direct_packet_join_requires_complete_source_and_current_selection() {
    let harness = Harness::new(7);
    let snapshot = harness.snapshot(
        vec![direct_fact(direct_spec(binding(10, 20), 30, 2))],
        Vec::new(),
        complete_coverages(Vec::new()),
    );

    let claim = harness
        .attribute(packet(), &snapshot)
        .expect("direct attribution");

    assert_eq!(claim.confidence(), AttributionConfidence::Proven);
    assert_eq!(claim.binding(), Some(binding(10, 20)));
    assert_eq!(
        claim.proof_basis().rule(),
        AttributionJoinRule::DirectPacketFingerprint
    );
    assert_eq!(claim.proof_basis().socket(), Some(socket_id(30)));
    assert_eq!(claim.proof_basis().matching_candidate_count(), 1);
    assert_eq!(claim.proof_basis().completeness().len(), 1);
    assert!(claim.proof_basis().limitations().is_empty());

    let decision = policy(false, None).decide(claim, selected(binding(10, 20)));
    assert!(matches!(
        decision,
        AdmissionDecision::AdmitTarget { selection, .. }
            if selection.proof() == selection_proof_id(9)
                && selection.revision() == revision(7)
    ));
}

#[test]
fn direct_source_loss_downgrades_to_inferred_and_cannot_use_host_fallback() {
    let harness = Harness::new(7);
    let losses = vec![SourceLoss::new(interval(96, 100), evidence_id(13))];
    let snapshot = harness.snapshot(
        vec![direct_fact(direct_spec(binding(10, 20), 30, 2))],
        Vec::new(),
        complete_coverages(losses),
    );
    let claim = harness
        .attribute(packet(), &snapshot)
        .expect("incomplete direct attribution");

    assert_eq!(claim.confidence(), AttributionConfidence::Inferred);
    assert_eq!(claim.binding(), Some(binding(10, 20)));
    assert_eq!(
        claim.proof_basis().rule(),
        AttributionJoinRule::IncompleteDirectPacketFingerprint
    );
    assert!(
        claim
            .proof_basis()
            .limitations()
            .contains(&AttributionGapReason::SourceIncomplete(
                AttributionSource::SocketLifecycle
            ))
    );

    let host = host_context(
        host_grant(true, true, true, requested_grant()),
        CaptureSubjectScope::Host,
        AuthorizationStatus::Active,
        interval(90, 120),
    );
    assert!(matches!(
        policy(false, Some(host)).decide(
            claim,
            TargetSelection::NotSelected {
                revision: revision(7)
            }
        ),
        AdmissionDecision::Reject {
            reason: AdmissionRejection::InferredDisabled,
            ..
        }
    ));
}

#[test]
fn conflicting_and_temporally_incoherent_direct_facts_fail_closed() {
    let harness = Harness::new(7);
    let conflicting = harness.snapshot(
        vec![
            direct_fact(direct_spec(binding(10, 20), 30, 2)),
            direct_fact(direct_spec(binding(11, 21), 31, 3)),
        ],
        Vec::new(),
        complete_coverages(Vec::new()),
    );
    let claim = harness
        .attribute(packet(), &conflicting)
        .expect("conflicting direct attribution");
    assert_eq!(claim.confidence(), AttributionConfidence::Unknown);
    assert_eq!(claim.proof_basis().matching_candidate_count(), 2);
    assert_eq!(
        claim.proof_basis().limitations(),
        &[AttributionGapReason::ConflictingDirectBindings]
    );

    let mut incoherent = direct_spec(binding(10, 20), 30, 2);
    incoherent.validity = ValidityInterval::new(interval(90, 110), interval(103, 110))
        .expect("partial direct validity");
    let snapshot = harness.snapshot(
        vec![direct_fact(incoherent)],
        Vec::new(),
        complete_coverages(Vec::new()),
    );
    let claim = harness
        .attribute(packet(), &snapshot)
        .expect("incoherent direct attribution");
    assert_eq!(claim.confidence(), AttributionConfidence::Unknown);
    assert!(
        claim
            .proof_basis()
            .limitations()
            .contains(&AttributionGapReason::DirectFactWindowMismatch)
    );
}

#[test]
fn signed_candidate_corpus_produces_auditable_unique_correlation() {
    let harness = Harness::new(7);
    let snapshot = harness.snapshot(
        Vec::new(),
        vec![candidate(established(binding(10, 20), 30, 1, 2))],
        complete_coverages(Vec::new()),
    );

    let claim = harness
        .attribute(packet(), &snapshot)
        .expect("closed-world attribution");

    assert_eq!(claim.confidence(), AttributionConfidence::CorrelatedUnique);
    assert_eq!(claim.binding(), Some(binding(10, 20)));
    assert_eq!(
        claim.proof_basis().rule(),
        AttributionJoinRule::ClosedWorldFlowCorrelation
    );
    assert_eq!(
        claim.proof_basis().candidate_set(),
        snapshot.candidate_set()
    );
    assert_eq!(
        claim.proof_basis().snapshot_digest(),
        snapshot.snapshot_digest()
    );
    assert_eq!(claim.proof_basis().universe_candidate_count(), 1);
    assert_eq!(claim.proof_basis().matching_candidate_count(), 1);
    assert_eq!(claim.proof_basis().completeness().len(), 3);
    assert!(claim.proof_basis().limitations().is_empty());
}

#[test]
fn source_loss_and_lagging_watermark_prevent_closed_world_correlation() {
    let harness = Harness::new(7);
    let candidate = candidate(established(binding(10, 20), 30, 1, 2));
    let lossy = harness.snapshot(
        Vec::new(),
        vec![candidate],
        complete_coverages(vec![SourceLoss::new(interval(96, 100), evidence_id(13))]),
    );
    let claim = harness
        .attribute(packet(), &lossy)
        .expect("lossy correlation");
    assert_eq!(claim.confidence(), AttributionConfidence::Inferred);
    assert!(
        claim
            .proof_basis()
            .limitations()
            .contains(&AttributionGapReason::SourceIncomplete(
                AttributionSource::SocketLifecycle
            ))
    );

    let mut coverages = complete_coverages(Vec::new());
    coverages[0] = coverage(
        AttributionSource::SocketLifecycle,
        socket_source(),
        10,
        CoverageWindow::new(
            interval(70, 130),
            interval(80, 100),
            MonotonicInstant::from_nanos(100),
        )
        .expect("lagging coverage"),
        Vec::new(),
    );
    let lagging = harness.snapshot(Vec::new(), vec![candidate], coverages);
    let claim = harness
        .attribute(packet(), &lagging)
        .expect("lagging correlation");
    assert_eq!(claim.confidence(), AttributionConfidence::Inferred);
}

#[test]
fn completeness_proof_claims_only_the_exact_loss_free_query_interval() {
    let harness = Harness::new(7);
    let snapshot = harness.snapshot(
        Vec::new(),
        vec![candidate(established(binding(10, 20), 30, 1, 2))],
        complete_coverages(vec![SourceLoss::new(interval(110, 115), evidence_id(13))]),
    );
    let claim = harness
        .attribute(packet(), &snapshot)
        .expect("loss-free query interval");

    assert_eq!(claim.confidence(), AttributionConfidence::CorrelatedUnique);
    let socket_proof = claim
        .proof_basis()
        .completeness()
        .iter()
        .find(|proof| proof.source() == AttributionSource::SocketLifecycle)
        .expect("socket completeness proof");
    assert_eq!(socket_proof.proven_interval(), interval(95, 107));
    assert_eq!(socket_proof.source_complete_interval(), interval(80, 120));
}

#[test]
fn unsupported_socket_role_stage_relation_and_partial_window_block_uniqueness() {
    let harness = Harness::new(7);
    let valid = candidate(established(binding(10, 20), 30, 1, 2));
    let listener = candidate(CandidateSpec {
        binding: binding(11, 21),
        socket: socket_id(31),
        role: SocketRole::Listener,
        evidence: evidence_id(3),
        sequence: 2,
        ..established(binding(10, 20), 30, 1, 2)
    });
    let claim = harness
        .attribute(
            packet(),
            &harness.snapshot(
                Vec::new(),
                vec![valid, listener],
                complete_coverages(Vec::new()),
            ),
        )
        .expect("listener competitor");
    assert_eq!(claim.confidence(), AttributionConfidence::Unknown);
    assert!(claim.proof_basis().limitations().contains(
        &AttributionGapReason::UnsupportedSocketRole(SocketRole::Listener)
    ));

    let translated = candidate(CandidateSpec {
        observed_scope: other_scope(),
        observed_flow: flow_id(2),
        stage_relation: StageRelation::Translated {
            topology_evidence: evidence_id(14),
        },
        binding: binding(11, 21),
        socket: socket_id(31),
        evidence: evidence_id(3),
        sequence: 2,
        ..established(binding(10, 20), 30, 1, 2)
    });
    let claim = harness
        .attribute(
            packet(),
            &harness.snapshot(
                Vec::new(),
                vec![valid, translated],
                complete_coverages(Vec::new()),
            ),
        )
        .expect("translated competitor");
    assert!(
        claim
            .proof_basis()
            .limitations()
            .contains(&AttributionGapReason::UnsupportedStageRelation)
    );

    let partial = candidate(CandidateSpec {
        binding: binding(11, 21),
        socket: socket_id(31),
        validity: ValidityInterval::new(interval(90, 110), interval(100, 110))
            .expect("partial candidate validity"),
        evidence: evidence_id(3),
        sequence: 2,
        ..established(binding(10, 20), 30, 1, 2)
    });
    let claim = harness
        .attribute(
            packet(),
            &harness.snapshot(
                Vec::new(),
                vec![valid, partial],
                complete_coverages(Vec::new()),
            ),
        )
        .expect("partial competitor");
    assert!(
        claim
            .proof_basis()
            .limitations()
            .contains(&AttributionGapReason::CandidateWindowMismatch)
    );
}

#[test]
fn foreign_authority_cannot_substitute_an_internally_consistent_crop() {
    let trusted = Harness::new(7);
    let candidates = vec![
        candidate(established(binding(10, 20), 30, 1, 2)),
        candidate(established(binding(11, 21), 31, 2, 3)),
    ];
    let full = trusted.snapshot(Vec::new(), candidates, complete_coverages(Vec::new()));
    let claim = trusted
        .attribute(packet(), &full)
        .expect("trusted ambiguous snapshot");
    assert_eq!(claim.confidence(), AttributionConfidence::Unknown);
    assert_eq!(claim.proof_basis().matching_candidate_count(), 2);

    let foreign = Harness::new(8);
    let cropped = foreign.snapshot(
        Vec::new(),
        vec![candidate(established(binding(10, 20), 30, 1, 2))],
        complete_coverages(Vec::new()),
    );
    assert!(matches!(
        trusted.engine().bind(&cropped),
        Err(AttributionError::SnapshotVerification(
            SnapshotVerificationError::AuthenticationFailed
        ))
    ));
}

#[test]
fn malformed_same_stage_candidate_is_rejected_before_sealing() {
    let authority = authority(7);
    let candidate = candidate(CandidateSpec {
        observed_scope: other_scope(),
        ..established(binding(10, 20), 30, 1, 2)
    });
    assert_eq!(
        authority.seal(snapshot_parts(
            Vec::new(),
            vec![candidate],
            complete_coverages(Vec::new())
        )),
        Err(AttributionSnapshotError::SameStageScopeMismatch)
    );
}

#[test]
fn snapshot_requires_one_source_owner_and_canonicalizes_loss_facts() {
    let authority = authority(7);
    let mut duplicate_source = complete_coverages(Vec::new());
    let process_window = duplicate_source[1].window();
    duplicate_source.push(coverage(
        AttributionSource::ProcessLifecycle,
        SourceIdentity::new(source_instance_id(30), source_epoch_id(1)),
        30,
        process_window,
        vec![SourceLoss::new(interval(96, 100), evidence_id(30))],
    ));
    assert!(matches!(
        authority.seal(snapshot_parts(
            Vec::new(),
            vec![candidate(established(binding(10, 20), 30, 1, 2))],
            duplicate_source,
        )),
        Err(AttributionSnapshotError::DuplicateCoverageSource {
            source: AttributionSource::ProcessLifecycle,
            ..
        })
    ));

    let first = SourceLoss::new(interval(110, 112), evidence_id(13));
    let second = SourceLoss::new(interval(113, 115), evidence_id(14));
    let ordered = authority
        .seal(snapshot_parts(
            Vec::new(),
            vec![candidate(established(binding(10, 20), 30, 1, 2))],
            complete_coverages(vec![first, second]),
        ))
        .expect("ordered loss snapshot");
    let reordered = authority
        .seal(snapshot_parts(
            Vec::new(),
            vec![candidate(established(binding(10, 20), 30, 1, 2))],
            complete_coverages(vec![second, first, second]),
        ))
        .expect("reordered loss snapshot");
    assert_eq!(ordered.snapshot_digest(), reordered.snapshot_digest());
}

#[test]
fn pid_reuse_history_is_excluded_from_classification_and_proof_memory() {
    let harness = Harness::new(7);
    let current = candidate(CandidateSpec {
        validity: ValidityInterval::exact(interval(95, 110)),
        ..established(binding(10, 21), 31, 31, 50)
    });
    let current_only = harness.snapshot(Vec::new(), vec![current], complete_coverages(Vec::new()));
    let baseline = harness
        .attribute(packet(), &current_only)
        .expect("current attribution");
    let proof_budget = baseline.proof_memory_bytes().expect("proof memory size");

    let mut candidates = (1_u64..=30)
        .map(|sequence| {
            candidate(CandidateSpec {
                validity: ValidityInterval::exact(interval(0, 94)),
                max_error_ns: 100,
                ..established(
                    binding(100 + sequence, 200 + sequence),
                    100 + sequence,
                    sequence,
                    10 + sequence,
                )
            })
        })
        .collect::<Vec<_>>();
    candidates.push(current);
    let snapshot = harness.snapshot(Vec::new(), candidates, complete_coverages(Vec::new()));
    let claim = harness
        .attribute(packet(), &snapshot)
        .expect("PID reuse attribution");

    assert_eq!(claim.confidence(), AttributionConfidence::CorrelatedUnique);
    assert_eq!(claim.binding(), Some(binding(10, 21)));
    assert_eq!(claim.proof_basis().fact_provenance().len(), 2);
    assert_eq!(claim.proof_memory_bytes(), Some(proof_budget));

    let mut spec = budget_spec();
    spec.max_proof_memory_bytes = proof_budget;
    let limited = AttributionEngine::new(
        AttributionBudget::new(spec).expect("history proof budget"),
        harness.authority.verifier(),
    );
    assert!(
        limited
            .bind(&snapshot)
            .expect("history snapshot binding")
            .attribute(packet())
            .is_ok()
    );
}

#[test]
fn foreign_direct_fact_axes_do_not_contaminate_a_valid_direct_join() {
    let harness = Harness::new(7);
    let valid = direct_fact(direct_spec(binding(10, 20), 30, 2));
    let mut foreign = Vec::new();

    let mut spec = direct_spec(binding(11, 21), 31, 3);
    spec.scope = AttributionScope::new(boot_id(2), netns_id(1), stage_id(1));
    foreign.push(direct_fact(spec));
    let mut spec = direct_spec(binding(11, 21), 32, 4);
    spec.scope = AttributionScope::new(boot_id(1), netns_id(2), stage_id(1));
    foreign.push(direct_fact(spec));
    let mut spec = direct_spec(binding(11, 21), 33, 5);
    spec.scope = AttributionScope::new(boot_id(1), netns_id(1), stage_id(2));
    foreign.push(direct_fact(spec));
    let mut spec = direct_spec(binding(11, 21), 34, 6);
    spec.fingerprint = PacketFingerprint::new([2; 32]).expect("foreign fingerprint");
    foreign.push(direct_fact(spec));
    let mut spec = direct_spec(binding(11, 21), 35, 7);
    spec.flow = flow_id(2);
    foreign.push(direct_fact(spec));
    foreign.push(valid);

    let snapshot = harness.snapshot(foreign, Vec::new(), complete_coverages(Vec::new()));
    let claim = harness
        .attribute(packet(), &snapshot)
        .expect("foreign-axis direct attribution");
    assert_eq!(claim.confidence(), AttributionConfidence::Proven);
    assert_eq!(claim.binding(), Some(binding(10, 20)));
}

#[test]
fn selection_attestation_binds_authority_intent_selector_grant_and_target() {
    let claim = direct_claim();
    let trusted = trusted_selection_authority();

    let foreign = SelectionAuthority::new([22; 32]).expect("foreign selection authority");
    assert_rejected(
        policy(false, None).decide(
            claim.clone(),
            selected_with(&foreign, selection_parts(binding(10, 20))),
        ),
        AdmissionRejection::SelectionProofUntrusted,
    );
    assert_rejected(
        policy(false, None).decide(
            claim.clone(),
            selected_with(
                &trusted,
                SelectionAttestationParts {
                    observation_intent: observation_intent_id(2),
                    ..selection_parts(binding(10, 20))
                },
            ),
        ),
        AdmissionRejection::SelectionIntentMismatch,
    );
    assert_rejected(
        policy(false, None).decide(
            claim.clone(),
            selected_with(
                &trusted,
                SelectionAttestationParts {
                    selector: capture_selector_digest(2),
                    ..selection_parts(binding(10, 20))
                },
            ),
        ),
        AdmissionRejection::SelectionSelectorMismatch,
    );
    assert!(matches!(
        policy(false, None).decide(
            claim.clone(),
            selected_with(
                &trusted,
                SelectionAttestationParts {
                    revision: revision(6),
                    ..selection_parts(binding(10, 20))
                },
            ),
        ),
        AdmissionDecision::Reject {
            reason: AdmissionRejection::SelectionRevisionMismatch { .. },
            ..
        }
    ));
    assert_rejected(
        policy(false, None).decide(claim.clone(), selected(binding(11, 21))),
        AdmissionRejection::SelectionBindingMismatch,
    );
    assert_rejected(
        policy(false, None).decide(
            claim.clone(),
            selected_with(
                &trusted,
                SelectionAttestationParts {
                    scope: other_scope(),
                    ..selection_parts(binding(10, 20))
                },
            ),
        ),
        AdmissionRejection::SelectionScopeMismatch,
    );
    let metadata_only = CaptureGrant::new(
        PayloadAccess::MetadataOnly,
        CompletenessAllowance::RequireComplete,
        RetentionLimit::new(30, 1024).expect("metadata retention"),
    );
    assert_rejected(
        policy(false, None).decide(
            claim.clone(),
            selected_with(
                &trusted,
                SelectionAttestationParts {
                    grant: metadata_only,
                    ..selection_parts(binding(10, 20))
                },
            ),
        ),
        AdmissionRejection::SelectionGrantMismatch,
    );
    assert_rejected(
        policy(false, None).decide(
            claim,
            selected_with(
                &trusted,
                SelectionAttestationParts {
                    valid_during: interval(0, 104),
                    ..selection_parts(binding(10, 20))
                },
            ),
        ),
        AdmissionRejection::SelectionExpired,
    );
}

#[test]
fn host_authorization_requires_trusted_scope_grant_and_current_live_state() {
    let unknown = unknown_claim();
    let capabilities = host_grant(false, false, true, requested_grant());
    let valid = host_context(
        capabilities,
        CaptureSubjectScope::User(1000),
        AuthorizationStatus::Active,
        interval(90, 120),
    );
    let decision = policy(false, Some(valid)).decide(unknown.clone(), unknown_selection());
    assert!(decision.is_admitted());
    assert_eq!(decision.grant(), Some(requested_grant()));

    let revoked = host_context(
        capabilities,
        CaptureSubjectScope::User(1000),
        AuthorizationStatus::Revoked,
        interval(90, 120),
    );
    assert!(matches!(
        policy(false, Some(revoked)).decide(unknown.clone(), unknown_selection()),
        AdmissionDecision::Reject {
            reason: AdmissionRejection::HostAuthorizationRevoked,
            ..
        }
    ));
    let stale = host_context(
        capabilities,
        CaptureSubjectScope::User(1000),
        AuthorizationStatus::Active,
        interval(90, 104),
    );
    assert!(matches!(
        policy(false, Some(stale)).decide(unknown.clone(), unknown_selection()),
        AdmissionDecision::Reject {
            reason: AdmissionRejection::HostAuthorizationStateStale,
            ..
        }
    ));
    let wrong_subject = host_context(
        capabilities,
        CaptureSubjectScope::User(2000),
        AuthorizationStatus::Active,
        interval(90, 120),
    );
    assert!(matches!(
        policy(false, Some(wrong_subject)).decide(unknown.clone(), unknown_selection()),
        AdmissionDecision::Reject {
            reason: AdmissionRejection::HostSubjectMismatch,
            ..
        }
    ));
    let wrong_capability = host_context(
        host_grant(true, false, false, requested_grant()),
        CaptureSubjectScope::Host,
        AuthorizationStatus::Active,
        interval(90, 120),
    );
    assert!(matches!(
        policy(false, Some(wrong_capability)).decide(unknown.clone(), unknown_selection()),
        AdmissionDecision::Reject {
            reason: AdmissionRejection::HostGrantDenied,
            ..
        }
    ));

    let trusted = trusted_host_authority();
    let foreign = HostCaptureAuthority::new(issuer_id(1), [32; 32]).expect("foreign authority");
    let foreign_context = host_context_with(
        &foreign,
        valid_host_spec(capabilities, CaptureSubjectScope::User(1000)),
    );
    assert_rejected(
        policy(false, Some(foreign_context)).decide(unknown.clone(), unknown_selection()),
        AdmissionRejection::HostAuthorizationUntrusted,
    );

    let wrong_intent = host_context_with(
        &trusted,
        HostContextSpec {
            observation_intent: observation_intent_id(2),
            ..valid_host_spec(capabilities, CaptureSubjectScope::User(1000))
        },
    );
    assert_rejected(
        policy(false, Some(wrong_intent)).decide(unknown.clone(), unknown_selection()),
        AdmissionRejection::HostIntentMismatch,
    );
    let wrong_scope = host_context_with(
        &trusted,
        HostContextSpec {
            attribution_scope: other_scope(),
            ..valid_host_spec(capabilities, CaptureSubjectScope::User(1000))
        },
    );
    assert_rejected(
        policy(false, Some(wrong_scope)).decide(unknown.clone(), unknown_selection()),
        AdmissionRejection::HostScopeMismatch,
    );
    let expired = host_context_with(
        &trusted,
        HostContextSpec {
            valid_during: interval(0, 104),
            ..valid_host_spec(capabilities, CaptureSubjectScope::User(1000))
        },
    );
    assert_rejected(
        policy(false, Some(expired)).decide(unknown.clone(), unknown_selection()),
        AdmissionRejection::HostAuthorizationExpired,
    );
    assert_rejected(
        policy_with_state(false, Some(valid), Some(revision(10)))
            .decide(unknown.clone(), unknown_selection()),
        AdmissionRejection::HostAuthorizationStateMismatch,
    );

    let restricted_capture = CaptureGrant::new(
        PayloadAccess::FullPayload,
        CompletenessAllowance::AllowIncomplete,
        RetentionLimit::new(30, 2048).expect("restricted retention"),
    );
    let restricted = host_context_with(
        &trusted,
        valid_host_spec(
            host_grant(false, false, true, restricted_capture),
            CaptureSubjectScope::User(1000),
        ),
    );
    assert_rejected(
        policy(false, Some(restricted)).decide(unknown.clone(), unknown_selection()),
        AdmissionRejection::HostGrantDenied,
    );

    let alternate = host_context_with(
        &trusted,
        HostContextSpec {
            observation_intent: observation_intent_id(2),
            ..valid_host_spec(capabilities, CaptureSubjectScope::User(1000))
        },
    );
    let mismatched = HostAuthorizationContext::new(valid.authorization(), alternate.liveness());
    assert_rejected(
        policy(false, Some(mismatched)).decide(unknown, unknown_selection()),
        AdmissionRejection::HostAuthorizationStateMismatch,
    );
}

#[test]
fn budget_limits_use_cardinality_and_actual_proof_memory() {
    let harness = Harness::new(7);
    let snapshot = harness.snapshot(
        Vec::new(),
        vec![
            candidate(established(binding(10, 20), 30, 1, 2)),
            candidate(established(binding(11, 21), 31, 2, 3)),
        ],
        complete_coverages(Vec::new()),
    );
    let mut spec = budget_spec();
    spec.max_candidates = 1;
    let limited = AttributionEngine::new(
        AttributionBudget::new(spec).expect("candidate budget"),
        harness.authority.verifier(),
    );
    assert!(matches!(
        limited.bind(&snapshot),
        Err(AttributionError::InputLimitExceeded {
            resource: AttributionResource::Candidates,
            actual: 2,
            max: 1
        })
    ));

    let small_snapshot = harness.snapshot(
        Vec::new(),
        vec![candidate(established(binding(10, 20), 30, 1, 2))],
        complete_coverages(Vec::new()),
    );
    let small_claim = harness
        .attribute(packet(), &small_snapshot)
        .expect("small proof");
    let small_proof_bytes = small_claim.proof_memory_bytes().expect("small proof bytes");
    let mut spec = budget_spec();
    spec.max_proof_memory_bytes = small_proof_bytes;
    let limited = AttributionEngine::new(
        AttributionBudget::new(spec).expect("proof budget"),
        harness.authority.verifier(),
    );
    assert!(
        limited
            .bind(&small_snapshot)
            .expect("small snapshot binding")
            .attribute(packet())
            .is_ok()
    );

    let larger_snapshot = harness.snapshot(
        Vec::new(),
        vec![
            candidate(established(binding(10, 20), 30, 1, 2)),
            candidate(established(binding(10, 20), 30, 2, 3)),
        ],
        complete_coverages(Vec::new()),
    );
    assert!(matches!(
        limited
            .bind(&larger_snapshot)
            .expect("larger snapshot binding")
            .attribute(packet()),
        Err(AttributionError::ProofMemoryBudgetExceeded { max, required })
            if max == small_proof_bytes && required > max
    ));
}

struct Harness {
    authority: AttributionSnapshotAuthority,
}

impl Harness {
    fn new(key_byte: u8) -> Self {
        Self {
            authority: authority(key_byte),
        }
    }

    fn engine(&self) -> AttributionEngine {
        AttributionEngine::new(
            AttributionBudget::new(budget_spec()).expect("attribution budget"),
            self.authority.verifier(),
        )
    }

    fn attribute(
        &self,
        packet: PacketObservation,
        snapshot: &AttributionSnapshot,
    ) -> Result<attribution::proof::AttributionClaim, AttributionError> {
        self.engine().bind(snapshot)?.attribute(packet)
    }

    fn snapshot(
        &self,
        direct_facts: Vec<DirectSocketFact>,
        candidates: Vec<CorrelationCandidate>,
        coverages: Vec<SourceCoverage>,
    ) -> AttributionSnapshot {
        self.authority
            .seal(snapshot_parts(direct_facts, candidates, coverages))
            .expect("attribution snapshot")
    }
}

fn authority(key_byte: u8) -> AttributionSnapshotAuthority {
    AttributionSnapshotAuthority::new([key_byte; 32]).expect("snapshot authority")
}

fn snapshot_parts(
    direct_facts: Vec<DirectSocketFact>,
    candidates: Vec<CorrelationCandidate>,
    coverages: Vec<SourceCoverage>,
) -> AttributionSnapshotParts {
    AttributionSnapshotParts {
        scope: scope(),
        flow: flow_id(1),
        candidate_source: CandidateSourceSnapshot::new(
            socket_source(),
            sequence_range(),
            evidence_id(9),
        ),
        direct_facts,
        candidates,
        coverages,
    }
}

fn direct_claim() -> attribution::proof::AttributionClaim {
    let harness = Harness::new(7);
    let snapshot = harness.snapshot(
        vec![direct_fact(direct_spec(binding(10, 20), 30, 2))],
        Vec::new(),
        complete_coverages(Vec::new()),
    );
    harness
        .attribute(packet(), &snapshot)
        .expect("direct claim")
}

fn unknown_claim() -> attribution::proof::AttributionClaim {
    let harness = Harness::new(7);
    let snapshot = harness.snapshot(Vec::new(), Vec::new(), complete_coverages(Vec::new()));
    harness
        .attribute(packet(), &snapshot)
        .expect("unknown claim")
}

fn budget_spec() -> AttributionBudgetSpec {
    AttributionBudgetSpec {
        max_direct_facts: 32,
        max_candidates: 32,
        max_coverages: 16,
        max_loss_intervals: 32,
        max_proof_memory_bytes: 64 * 1024,
        max_clock_error_ns: 10,
        correlation_slack_ns: 5,
    }
}

fn packet() -> PacketObservation {
    PacketObservation::new(
        subject_id(1),
        CapturePrincipal::new(1000, Some(cgroup_id(1))),
        scope(),
        fingerprint(),
        flow_id(1),
        CalibratedInterval::new(interval(100, 102), calibration_id(1), 1),
        provenance(1, packet_source(), 1),
    )
}

#[derive(Clone, Copy)]
struct DirectSpec {
    scope: AttributionScope,
    fingerprint: PacketFingerprint,
    flow: FlowId,
    binding: TargetBinding,
    socket: SocketId,
    validity: ValidityInterval,
    observed: TimeInterval,
    evidence: AttributionEvidenceId,
    calibration: ClockCalibrationId,
    max_error_ns: u64,
    sequence: u64,
}

fn direct_spec(binding: TargetBinding, socket: u64, evidence: u64) -> DirectSpec {
    DirectSpec {
        scope: scope(),
        fingerprint: fingerprint(),
        flow: flow_id(1),
        binding,
        socket: socket_id(socket),
        validity: ValidityInterval::exact(interval(90, 110)),
        observed: interval(100, 102),
        evidence: evidence_id(evidence),
        calibration: calibration_id(evidence),
        max_error_ns: 1,
        sequence: evidence,
    }
}

fn direct_fact(spec: DirectSpec) -> DirectSocketFact {
    DirectSocketFact::new(
        spec.scope,
        DirectJoinKey::new(spec.fingerprint, spec.flow),
        spec.socket,
        spec.binding,
        spec.validity,
        CalibratedInterval::new(spec.observed, spec.calibration, spec.max_error_ns),
        FactProvenance::new(
            spec.evidence,
            socket_source(),
            source_sequence(spec.sequence),
        ),
    )
}

#[derive(Clone, Copy)]
struct CandidateSpec {
    observed_scope: AttributionScope,
    observed_flow: FlowId,
    stage_relation: StageRelation,
    binding: TargetBinding,
    socket: SocketId,
    role: SocketRole,
    validity: ValidityInterval,
    evidence: AttributionEvidenceId,
    calibration: ClockCalibrationId,
    max_error_ns: u64,
    sequence: u64,
}

fn established(binding: TargetBinding, socket: u64, sequence: u64, evidence: u64) -> CandidateSpec {
    CandidateSpec {
        observed_scope: scope(),
        observed_flow: flow_id(1),
        stage_relation: StageRelation::SameCaptureStage,
        binding,
        socket: socket_id(socket),
        role: SocketRole::EstablishedStream,
        validity: ValidityInterval::exact(interval(90, 110)),
        evidence: evidence_id(evidence),
        calibration: calibration_id(evidence),
        max_error_ns: 1,
        sequence,
    }
}

fn candidate(spec: CandidateSpec) -> CorrelationCandidate {
    CorrelationCandidate::new(CorrelationCandidateParts {
        observed_scope: spec.observed_scope,
        observed_flow: spec.observed_flow,
        stage_relation: spec.stage_relation,
        socket: spec.socket,
        binding: spec.binding,
        role: spec.role,
        valid_during: CalibratedValidity::new(spec.validity, spec.calibration, spec.max_error_ns),
        provenance: FactProvenance::new(
            spec.evidence,
            socket_source(),
            source_sequence(spec.sequence),
        ),
    })
}

fn complete_coverages(socket_losses: Vec<SourceLoss>) -> Vec<SourceCoverage> {
    let complete = CoverageWindow::new(
        interval(70, 130),
        interval(80, 120),
        MonotonicInstant::from_nanos(120),
    )
    .expect("complete coverage window");
    vec![
        coverage(
            AttributionSource::SocketLifecycle,
            socket_source(),
            10,
            complete,
            socket_losses,
        ),
        coverage(
            AttributionSource::ProcessLifecycle,
            process_source(),
            11,
            complete,
            Vec::new(),
        ),
        coverage(
            AttributionSource::CaptureTopology,
            topology_source(),
            12,
            complete,
            Vec::new(),
        ),
    ]
}

fn coverage(
    source: AttributionSource,
    source_identity: SourceIdentity,
    evidence: u64,
    window: CoverageWindow,
    losses: Vec<SourceLoss>,
) -> SourceCoverage {
    SourceCoverage::new(
        source,
        scope(),
        CoverageCursor::new(source_identity, sequence_range(), evidence_id(evidence)),
        window,
        losses,
    )
}

fn policy(
    allow_inferred: bool,
    authorization: Option<HostAuthorizationContext>,
) -> AdmissionPolicy {
    let active_host_state_revision =
        authorization.map(|context| context.liveness().state_revision());
    policy_with_state(allow_inferred, authorization, active_host_state_revision)
}

fn selected(binding: TargetBinding) -> TargetSelection {
    selected_with(&trusted_selection_authority(), selection_parts(binding))
}

fn unknown_selection() -> TargetSelection {
    TargetSelection::Unknown {
        revision: revision(7),
    }
}

fn host_context(
    grant: HostCaptureGrant,
    subject_scope: CaptureSubjectScope,
    status: AuthorizationStatus,
    fresh_during: TimeInterval,
) -> HostAuthorizationContext {
    host_context_with(
        &trusted_host_authority(),
        HostContextSpec {
            observation_intent: observation_intent_id(1),
            subject_scope,
            attribution_scope: scope(),
            grant,
            authorization_revision: revision(8),
            state_revision: revision(9),
            status,
            valid_during: interval(0, 200),
            fresh_during,
        },
    )
}

fn policy_with_state(
    allow_inferred: bool,
    authorization: Option<HostAuthorizationContext>,
    active_host_state_revision: Option<Revision>,
) -> AdmissionPolicy {
    AdmissionPolicy::new(AdmissionPolicyParts {
        observation_intent: observation_intent_id(1),
        selector: capture_selector_digest(1),
        active_selection_revision: revision(7),
        requested_grant: requested_grant(),
        decision_time: MonotonicInstant::from_nanos(105),
        allow_inferred,
        selection_verifier: trusted_selection_authority().verifier(),
        host_verifier: trusted_host_authority().verifier(),
        active_host_state_revision,
        host_authorization: authorization,
    })
}

fn selected_with(
    authority: &SelectionAuthority,
    parts: SelectionAttestationParts,
) -> TargetSelection {
    TargetSelection::Selected(Box::new(authority.attest(parts)))
}

fn selection_parts(binding: TargetBinding) -> SelectionAttestationParts {
    SelectionAttestationParts {
        observation_intent: observation_intent_id(1),
        selector: capture_selector_digest(1),
        binding,
        scope: scope(),
        proof: selection_proof_id(9),
        revision: revision(7),
        grant: requested_grant(),
        valid_during: interval(0, 200),
    }
}

#[derive(Clone, Copy)]
struct HostContextSpec {
    observation_intent: ObservationIntentId,
    subject_scope: CaptureSubjectScope,
    attribution_scope: AttributionScope,
    grant: HostCaptureGrant,
    authorization_revision: Revision,
    state_revision: Revision,
    status: AuthorizationStatus,
    valid_during: TimeInterval,
    fresh_during: TimeInterval,
}

fn valid_host_spec(grant: HostCaptureGrant, subject_scope: CaptureSubjectScope) -> HostContextSpec {
    HostContextSpec {
        observation_intent: observation_intent_id(1),
        subject_scope,
        attribution_scope: scope(),
        grant,
        authorization_revision: revision(8),
        state_revision: revision(9),
        status: AuthorizationStatus::Active,
        valid_during: interval(0, 200),
        fresh_during: interval(90, 120),
    }
}

fn host_context_with(
    authority: &HostCaptureAuthority,
    spec: HostContextSpec,
) -> HostAuthorizationContext {
    let authorization = authority
        .authorize(HostCaptureAuthorizationParts {
            authorization: authorization_id(1),
            issuer: authority.issuer(),
            observation_intent: spec.observation_intent,
            nonce: authorization_nonce(1),
            audit: authorization_audit_id(1),
            subject_scope: spec.subject_scope,
            attribution_scope: spec.attribution_scope,
            grant: spec.grant,
            revision: spec.authorization_revision,
            valid_during: spec.valid_during,
        })
        .expect("host authorization");
    let liveness = authority
        .issue_liveness(
            authorization,
            spec.state_revision,
            spec.status,
            spec.fresh_during,
        )
        .expect("host authorization state");
    HostAuthorizationContext::new(authorization, liveness)
}

fn trusted_selection_authority() -> SelectionAuthority {
    SelectionAuthority::new([21; 32]).expect("selection authority")
}

fn trusted_host_authority() -> HostCaptureAuthority {
    HostCaptureAuthority::new(issuer_id(1), [31; 32]).expect("host capture authority")
}

fn requested_grant() -> CaptureGrant {
    CaptureGrant::new(
        PayloadAccess::FullPayload,
        CompletenessAllowance::AllowIncomplete,
        RetentionLimit::new(60, 4096).expect("retention limit"),
    )
}

fn host_grant(
    attributed: bool,
    inferred: bool,
    unknown: bool,
    maximum_capture: CaptureGrant,
) -> HostCaptureGrant {
    HostCaptureGrant::new(
        AttributionConfidenceGrant::new(attributed, inferred, unknown).expect("confidence grant"),
        maximum_capture,
    )
}

fn assert_rejected(decision: AdmissionDecision, expected: AdmissionRejection) {
    assert!(
        matches!(decision, AdmissionDecision::Reject { reason, .. } if reason == expected),
        "expected admission rejection {expected:?}, got {decision:?}"
    );
}

fn provenance(evidence: u64, source: SourceIdentity, sequence: u64) -> FactProvenance {
    FactProvenance::new(evidence_id(evidence), source, source_sequence(sequence))
}

fn packet_source() -> SourceIdentity {
    SourceIdentity::new(source_instance_id(1), source_epoch_id(1))
}

fn socket_source() -> SourceIdentity {
    SourceIdentity::new(source_instance_id(2), source_epoch_id(1))
}

fn process_source() -> SourceIdentity {
    SourceIdentity::new(source_instance_id(3), source_epoch_id(1))
}

fn topology_source() -> SourceIdentity {
    SourceIdentity::new(source_instance_id(4), source_epoch_id(1))
}

fn source_sequence(value: u64) -> SourceSequence {
    SourceSequence::new(value).expect("source sequence")
}

fn sequence_range() -> SourceSequenceRange {
    SourceSequenceRange::new(source_sequence(1), source_sequence(100))
        .expect("source sequence range")
}

fn scope() -> AttributionScope {
    AttributionScope::new(boot_id(1), netns_id(1), stage_id(1))
}

fn other_scope() -> AttributionScope {
    AttributionScope::new(boot_id(1), netns_id(2), stage_id(2))
}

fn fingerprint() -> PacketFingerprint {
    PacketFingerprint::new([1; 32]).expect("packet fingerprint")
}

fn binding(workload: u64, process: u64) -> TargetBinding {
    TargetBinding::new(Some(workload_id(workload)), Some(process_id(process))).expect("binding")
}

fn interval(start: u64, end: u64) -> TimeInterval {
    TimeInterval::new(
        MonotonicInstant::from_nanos(start),
        MonotonicInstant::from_nanos(end),
    )
    .expect("time interval")
}

fn revision(value: u64) -> Revision {
    Revision::new(value).expect("revision")
}

fn id_bytes(value: u64) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[8..].copy_from_slice(&value.to_be_bytes());
    bytes
}

macro_rules! id_helpers {
    ($($function:ident => $type:ty),+ $(,)?) => {
        $(
            fn $function(value: u64) -> $type {
                <$type>::new(id_bytes(value)).expect("canonical test identifier")
            }
        )+
    };
}

id_helpers!(
    authorization_audit_id => AuthorizationAuditId,
    authorization_id => AuthorizationId,
    authorization_nonce => AuthorizationNonce,
    boot_id => BootId,
    calibration_id => ClockCalibrationId,
    cgroup_id => CgroupId,
    evidence_id => AttributionEvidenceId,
    flow_id => FlowId,
    issuer_id => AuthorizationIssuerId,
    netns_id => NetworkNamespaceId,
    observation_intent_id => ObservationIntentId,
    process_id => ProcessId,
    selection_proof_id => SelectionProofId,
    socket_id => SocketId,
    source_epoch_id => SourceEpochId,
    source_instance_id => SourceInstanceId,
    stage_id => CaptureStageId,
    subject_id => SubjectId,
    workload_id => WorkloadId,
);

fn capture_selector_digest(value: u64) -> CaptureSelectorDigest {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    CaptureSelectorDigest::new(bytes).expect("capture selector digest")
}
