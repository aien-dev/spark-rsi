use p256::ecdsa::SigningKey;
use spark_rsi::ledger::ImprovementLedger;
use spark_rsi::soak::{
    AdmittedMetaCandidate, CycleCandidateRecord, CycleRecord, EngineNSnapshot,
    HypothesisQuarantineTracker, SoakConfig, SoakRunManifest, SoakRunner, ThermalSnapshot,
};
use std::fs;

#[test]
fn test_hypothesis_quarantine_exhaustion_after_3_failures() {
    let mut tracker = HypothesisQuarantineTracker::new();
    let node = "Propose";
    let problem = "High latency on Propose: betweenness centrality bottleneck";

    assert!(!tracker.is_exhausted(node, problem));

    // Failure 1
    let newly_exhausted_1 = tracker.record_failure(node, problem, "Compilation error in Jail 1");
    assert!(!newly_exhausted_1);
    assert!(!tracker.is_exhausted(node, problem));

    // Failure 2
    let newly_exhausted_2 = tracker.record_failure(node, problem, "Invariants failed");
    assert!(!newly_exhausted_2);
    assert!(!tracker.is_exhausted(node, problem));

    // Failure 3: Triggers quarantine exhaustion
    let newly_exhausted_3 = tracker.record_failure(node, problem, "Blind judge non-inferiority exceeded");
    assert!(newly_exhausted_3);
    assert!(tracker.is_exhausted(node, problem));

    let exhausted = tracker.exhausted_list();
    assert_eq!(exhausted.len(), 1);

    // Success resets exhaustion
    tracker.record_success(node, problem);
    assert!(!tracker.is_exhausted(node, problem));
    assert!(tracker.exhausted_list().is_empty());
}

#[test]
fn test_thermal_snapshot_and_engine_snapshot() {
    let thermal = ThermalSnapshot::capture();
    if let Some(ref t) = thermal {
        assert!(!t.timestamp.is_empty());
    }

    let engine_n = EngineNSnapshot {
        commit_sha: "abc123def456".to_string(),
        evaluator_version: "0.1.0".to_string(),
        holdout_bundle_digest: "sha256:holdouts-bundle-v1".to_string(),
        builder_digest: "sha256:spark-rsi-builder-pinned".to_string(),
        max_model: "atlas-lightning-omni".to_string(),
        cortex_snapshot_ref: "2026-09-19T00:00:00Z".to_string(),
        operator_verifying_key: Some("04aabbcc...".to_string()),
    };

    assert_eq!(engine_n.commit_sha, "abc123def456");
    assert_eq!(engine_n.max_model, "atlas-lightning-omni");
}

#[test]
fn test_soak_manifest_serialization_and_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let manifest_path = tmp.path().join("soak_manifest.json");

    let engine_n = EngineNSnapshot {
        commit_sha: "test-sha".to_string(),
        evaluator_version: "0.1.0".to_string(),
        holdout_bundle_digest: "digest-1".to_string(),
        builder_digest: "digest-2".to_string(),
        max_model: "atlas-lightning-omni".to_string(),
        cortex_snapshot_ref: "now".to_string(),
        operator_verifying_key: None,
    };

    let manifest = SoakRunManifest {
        manifest_version: "1.0.0".to_string(),
        run_id: "soak-test-01".to_string(),
        started_at: "2026-09-19T20:00:00Z".to_string(),
        completed_at: "2026-09-19T20:30:00Z".to_string(),
        engine_n_snapshot: engine_n,
        cycles: vec![CycleRecord {
            cycle_index: 1,
            cycle_id: "soak-c01".to_string(),
            bottleneck_node: "Propose".to_string(),
            hypothesis_id: "hypo-01".to_string(),
            hypothesis_problem: "High latency".to_string(),
            candidates: vec![CycleCandidateRecord {
                candidate_id: "cand-01".to_string(),
                candidate_index: 1,
                target_file: "src/propose/hypothesis.rs".to_string(),
                proposed_patch_digest: "digest".to_string(),
                compilation_passed: true,
                invariants_passed: true,
                judge_admitted: true,
                primary_metric_name: "latency_delta_pct".to_string(),
                primary_metric_value: -5.2,
                rejection_reason: None,
                ledger_block_hash: Some("blockhash01".to_string()),
            }],
            winning_candidate_id: Some("cand-01".to_string()),
            merkle_checkpoint_hash: Some("merkleroot01".to_string()),
            thermal_before: None,
            thermal_after: None,
            cortex_receipt_id: Some("receipt-01".to_string()),
            status: "COMPLETED".to_string(),
        }],
        admitted_candidates: vec![AdmittedMetaCandidate {
            candidate_id: "cand-01".to_string(),
            ledger_block_hash: "blockhash01".to_string(),
            staging_dir: ".rsi/admitted/blockhash01".to_string(),
            patch_digest: "patchdigest01".to_string(),
            criteria_1_novel_discovery: true,
            criteria_2_self_capability_gain: true,
            classification: "META_CANDIDATE".to_string(),
        }],
        exhausted_hypotheses: vec![],
        final_merkle_checkpoint: Some("merkleroot01".to_string()),
        total_candidates_evaluated: 1,
        total_candidates_admitted: 1,
        preflight_passed: true,
        overall_status: "SUCCESS".to_string(),
    };

    manifest.save_to_file(&manifest_path).expect("Failed to save manifest");
    assert!(manifest_path.exists());

    let raw = fs::read_to_string(&manifest_path).unwrap();
    let loaded: SoakRunManifest = serde_json::from_str(&raw).unwrap();
    assert_eq!(loaded.run_id, "soak-test-01");
    assert_eq!(loaded.cycles.len(), 1);
    assert_eq!(loaded.admitted_candidates.len(), 1);
    assert_eq!(loaded.overall_status, "SUCCESS");
}

#[tokio::test]
async fn test_soak_preflight_fails_closed_without_valid_key() {
    let tmp = tempfile::tempdir().unwrap();
    let rsi_dir = tmp.path().join(".rsi");
    fs::create_dir_all(&rsi_dir).unwrap();

    let mut config = SoakConfig::default();
    config.target_repo = tmp.path().display().to_string();
    config.rsi_root = ".rsi".to_string();
    config.signing_key_hex = None;

    let res = SoakRunner::run_batch(&config).await;
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(err.contains("signing_key_hex"));
}

#[tokio::test]
async fn test_soak_preflight_fails_closed_missing_holdouts() {
    let tmp = tempfile::tempdir().unwrap();
    let rsi_dir = tmp.path().join(".rsi");
    fs::create_dir_all(&rsi_dir).unwrap();
    fs::write(
        tmp.path().join("Cargo.toml"),
        "[package]\nname = \"test\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ).unwrap();

    let _ledger = ImprovementLedger::open(&rsi_dir).unwrap();

    let sk = SigningKey::from_bytes(&[77u8; 32].into()).unwrap();
    let sk_hex = hex::encode(sk.to_bytes());

    let mut config = SoakConfig::default();
    config.target_repo = tmp.path().display().to_string();
    config.rsi_root = ".rsi".to_string();
    config.signing_key_hex = Some(sk_hex);
    config.holdouts_dir = Some(tmp.path().join("non_existent_holdouts").display().to_string());

    let res = SoakRunner::run_batch(&config).await;
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(err.contains("Preflight"));
    assert!(err.contains("holdouts"));
}
