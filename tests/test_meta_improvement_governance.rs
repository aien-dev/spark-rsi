use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};
use spark_rsi::ledger::{BlockType, ImprovementLedger};
use spark_rsi::meta::{
    AbForkEvaluator, CandidateTier, MetaBenchmarkMetrics, TierGovernance,
    TrueRsiEvaluator,
};
use spark_rsi::models::{ImprovementProposal, ProposalKind};
use std::fs;
use std::path::Path;

#[test]
fn test_tier_classification_and_immutable_containment() {
    let target_proposal = ImprovementProposal {
        id: "prop-target-01".to_string(),
        title: "Clean documentation".to_string(),
        description: "Remove unslop from docs".to_string(),
        target_file: "README.md".to_string(),
        proposed_patch: "# Cleaned".to_string(),
        kind: ProposalKind::UnslopSanitization,
        created_at: "2026-09-19T00:00:00Z".to_string(),
        sandbox_path: None,
        operator_signature: None,
    };
    assert_eq!(
        TierGovernance::classify_proposal(&target_proposal),
        CandidateTier::Tier1Target
    );

    let engine_proposal = ImprovementProposal {
        id: "prop-engine-01".to_string(),
        title: "Optimize KV scheduler in propose subsystem".to_string(),
        description: "Speed up proposal generation".to_string(),
        target_file: "src/propose/mod.rs".to_string(),
        proposed_patch: "pub fn fast_gen() {}".to_string(),
        kind: ProposalKind::Optimization,
        created_at: "2026-09-19T00:00:00Z".to_string(),
        sandbox_path: None,
        operator_signature: None,
    };
    assert_eq!(
        TierGovernance::classify_proposal(&engine_proposal),
        CandidateTier::Tier2Engine
    );

    // Verify immutable containment boundaries for Tier 2
    assert!(TierGovernance::validate_tier2_candidate_boundaries("src/propose/mod.rs").is_ok());
    assert!(TierGovernance::validate_tier2_candidate_boundaries("src/daemon.rs").is_ok());
    assert!(TierGovernance::validate_tier2_candidate_boundaries("src/graph/mod.rs").is_ok());

    // Attempts to modify tests, scoring rules, containment, or holdouts must fail closed
    assert!(TierGovernance::validate_tier2_candidate_boundaries("tests/integration_tests.rs").is_err());
    assert!(TierGovernance::validate_tier2_candidate_boundaries("src/evaluator/layers/correctness.rs").is_err());
    assert!(TierGovernance::validate_tier2_candidate_boundaries("src/isolation/container.rs").is_err());
    assert!(TierGovernance::validate_tier2_candidate_boundaries(".rsi/holdouts/suite1.json").is_err());
    assert!(TierGovernance::validate_tier2_candidate_boundaries("CONSTITUTION.md").is_err());
    assert!(TierGovernance::validate_tier2_candidate_boundaries("LICENSE").is_err());
}

#[test]
fn test_operator_cryptographic_authorization_requirement() {
    let operator_signing_key = SigningKey::from_bytes(&[55u8; 32].into()).unwrap();
    let operator_verifying_key = operator_signing_key.verifying_key();

    let patch = "pub fn autonomous_engine_upgrade() {}";
    let patch_digest = Sha256::digest(patch.as_bytes());
    let sig: Signature = operator_signing_key.sign(&patch_digest);
    let valid_sig_hex = hex::encode(sig.to_bytes());

    let authorized_proposal = ImprovementProposal {
        id: "meta-auth-01".to_string(),
        title: "Autonomous Engine Upgrade".to_string(),
        description: "Self-improvement patch signed by hardware TPM vault".to_string(),
        target_file: "src/observe.rs".to_string(),
        proposed_patch: patch.to_string(),
        kind: ProposalKind::MetaEngineImprovement,
        created_at: "2026-09-19T00:00:00Z".to_string(),
        sandbox_path: None,
        operator_signature: Some(valid_sig_hex),
    };

    let parent_metrics = MetaBenchmarkMetrics::new(10.0, 0.85, 1.0, 400.0, 4096);
    let candidate_metrics = MetaBenchmarkMetrics::new(12.5, 0.90, 1.25, 360.0, 4096);

    let res = AbForkEvaluator::evaluate_tier2_candidate(
        Path::new("."),
        Path::new("."),
        &authorized_proposal,
        &parent_metrics,
        &candidate_metrics,
        Some(&operator_verifying_key),
        1.0,
        None,
    );
    assert!(res.is_ok(), "Authorized Tier 2 proposal must succeed");

    // Missing signature must fail closed
    let mut unsigned_proposal = authorized_proposal.clone();
    unsigned_proposal.operator_signature = None;
    let err_unsigned = AbForkEvaluator::evaluate_tier2_candidate(
        Path::new("."),
        Path::new("."),
        &unsigned_proposal,
        &parent_metrics,
        &candidate_metrics,
        Some(&operator_verifying_key),
        1.0,
        None,
    );
    assert!(err_unsigned.is_err());
    assert!(err_unsigned.unwrap_err().contains("Missing operator cryptographic signature"));

    // Forged signature must fail closed
    let mut forged_proposal = authorized_proposal.clone();
    forged_proposal.operator_signature = Some("00".repeat(64));
    let err_forged = AbForkEvaluator::evaluate_tier2_candidate(
        Path::new("."),
        Path::new("."),
        &forged_proposal,
        &parent_metrics,
        &candidate_metrics,
        Some(&operator_verifying_key),
        1.0,
        None,
    );
    assert!(err_forged.is_err());
    assert!(err_forged.is_err());
}

#[test]
fn test_ab_fork_evaluation_engine_n_judges_engine_n_plus_1() {
    let operator_signing_key = SigningKey::from_bytes(&[99u8; 32].into()).unwrap();
    let operator_verifying_key = operator_signing_key.verifying_key();

    let patch = "pub fn speedup() {}";
    let patch_digest = Sha256::digest(patch.as_bytes());
    let sig: Signature = operator_signing_key.sign(&patch_digest);

    let proposal = ImprovementProposal {
        id: "meta-ab-01".to_string(),
        title: "Speedup Proposal".to_string(),
        description: "Dynamic telemetry bottleneck repair".to_string(),
        target_file: "src/propose/mod.rs".to_string(),
        proposed_patch: patch.to_string(),
        kind: ProposalKind::MetaEngineImprovement,
        created_at: "2026-09-19T00:00:00Z".to_string(),
        sandbox_path: None,
        operator_signature: Some(hex::encode(sig.to_bytes())),
    };

    let parent_metrics = MetaBenchmarkMetrics::new(10.0, 0.80, 1.0, 500.0, 4096);

    // Scenario A: Candidate regresses on latency by 20% -> Rejected
    let regressed_candidate = MetaBenchmarkMetrics::new(10.0, 0.80, 1.0, 600.0, 4096);
    let res_regressed = AbForkEvaluator::evaluate_tier2_candidate(
        Path::new("."),
        Path::new("."),
        &proposal,
        &parent_metrics,
        &regressed_candidate,
        Some(&operator_verifying_key),
        1.0,
        None,
    ).unwrap();
    assert_eq!(res_regressed.overall_classification, "REJECTED");
    assert!(!res_regressed.self_capability_improvement.passed);

    // Scenario B: Candidate accelerates discovery rate by 30% -> MetaCandidate
    let amplified_candidate = MetaBenchmarkMetrics::new(13.0, 0.85, 1.3, 450.0, 4096);
    let res_amplified = AbForkEvaluator::evaluate_tier2_candidate(
        Path::new("."),
        Path::new("."),
        &proposal,
        &parent_metrics,
        &amplified_candidate,
        Some(&operator_verifying_key),
        1.0,
        None,
    ).unwrap();
    assert_eq!(res_amplified.overall_classification, "META_CANDIDATE");
    assert!(res_amplified.novel_discovery.passed);
    assert!(res_amplified.self_capability_improvement.passed);
    assert!(!res_amplified.recursive_persistence.passed); // Downstream evidence pending
}

#[test]
fn test_three_criteria_true_rsi_lifecycle_and_ledger_compounding() {
    let tmp = tempfile::tempdir().unwrap();
    let rsi_root = tmp.path().join(".rsi");
    fs::create_dir_all(&rsi_root).unwrap();

    let ledger = ImprovementLedger::open(&rsi_root).expect("Ledger initialization failed");

    // 1. Record generation N (MetaCandidate) promotion block
    let meta_block = ledger.append_block(
        BlockType::Promotion,
        "{\"candidate\": \"engine-gen-01\", \"classification\": \"META_CANDIDATE\"}".to_string(),
        Vec::new(),
    ).expect("MetaCandidate promotion block append");

    // 2. Record downstream generation N+1 cycle evaluation block
    let downstream_block = ledger.append_block(
        BlockType::Evaluation,
        "{\"cycle_id\": \"cycle-02\", \"throughput_gain_pct\": 18.5}".to_string(),
        Vec::new(),
    ).expect("Downstream evaluation block append");

    // 3. Evaluate Three Criteria with downstream evidence
    let c1 = TrueRsiEvaluator::evaluate_criterion_1_novel_discovery(
        "Identified unencoded KV cache contention under concurrency",
        true,
        &["static_heuristic", "hardcoded_rule"],
    );
    assert!(c1.passed, "Criterion 1 NovelDiscovery must pass");

    let c2 = TrueRsiEvaluator::evaluate_criterion_2_self_capability_improvement(
        true,
        "Discovery rate improved +22.5%, cycle latency -11.0%",
    );
    assert!(c2.passed, "Criterion 2 SelfCapabilityImprovement must pass");

    let c3 = TrueRsiEvaluator::evaluate_criterion_3_recursive_persistence(
        Some(&meta_block.block_hash),
        Some("cycle-02"),
        Some(&downstream_block.block_hash),
        Some("Downstream generation N+1 utilized lock-free cache primitive from N to resolve cycle-02 bottleneck"),
    );
    assert!(c3.0.passed, "Criterion 3 RecursivePersistence must pass");

    let verdict = TrueRsiEvaluator::evaluate_full(c1, c2, c3);
    assert_eq!(verdict.overall_classification, "TRUE_RSI");
    assert!(verdict.evidence_payload.is_some());

    // 4. Record append-only PromotionEvidence block in cryptographic ledger
    let evidence_payload = verdict.evidence_payload.unwrap();
    let evidence_block = ledger.append_promotion_evidence(&evidence_payload)
        .expect("Appending promotion evidence to ledger failed");

    assert_eq!(evidence_block.block_type, BlockType::PromotionEvidence);

    // 5. Cryptographically audit ledger integrity
    let signing_key = SigningKey::from_bytes(&[88u8; 32].into()).unwrap();
    let verifying_key = signing_key.verifying_key();
    let _ = ledger.checkpoint(Some(&signing_key));

    let audit = ledger.verify_chain_integrity(Some(&verifying_key)).expect("Ledger audit failed");
    assert!(audit.chain_valid, "Cryptographic ledger hash chain must be valid");
    assert_eq!(audit.total_blocks, 4); // Genesis (0) + Promotion (1) + Evaluation (2) + PromotionEvidence (3)
}
