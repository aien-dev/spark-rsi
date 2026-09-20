use p256::ecdsa::{SigningKey, VerifyingKey};
use rusqlite::Connection;
use spark_rsi::daemon::RsiEngine;
use spark_rsi::evaluator::EvaluationMetricsSummary;
use spark_rsi::evaluator::EvaluationReceipt;
use spark_rsi::ledger::{BlockType, ImprovementLedger, LedgerBlock, PromotionEvidencePayload};
use spark_rsi::models::RsiConfig;
use std::fs;
use std::process::Command;

#[test]
fn test_ledger_genesis_initialization_and_monotonic_chaining() {
    let tmp = tempfile::tempdir().unwrap();
    let rsi_root = tmp.path().join(".rsi");

    let ledger = ImprovementLedger::open(&rsi_root).expect("Failed to open ledger");

    // 1. Verify Genesis block invariants
    let genesis = ledger
        .latest_block()
        .unwrap()
        .expect("Genesis block must exist");
    assert_eq!(genesis.sequence, 0);
    assert_eq!(genesis.block_type, BlockType::Genesis);
    assert_eq!(genesis.prev_block_hash, LedgerBlock::GENESIS_PREV_HASH);
    assert!(genesis.verify_integrity().is_ok());

    // 2. Append sequential blocks
    for i in 1..=5 {
        let payload = format!("{{\"step\": {}}}", i);
        let block = ledger
            .append_block(BlockType::Evaluation, payload, Vec::new())
            .expect("Append block failed");
        assert_eq!(block.sequence, i as u64);
        assert!(block.verify_integrity().is_ok());
    }

    // 3. Verify monotonic chaining across all 6 blocks
    let blocks = ledger.all_blocks().expect("Failed to query all blocks");
    assert_eq!(blocks.len(), 6);

    for i in 1..blocks.len() {
        assert_eq!(blocks[i].sequence, i as u64);
        assert_eq!(blocks[i].prev_block_hash, blocks[i - 1].block_hash);
    }

    let report = ledger
        .verify_chain_integrity(None)
        .expect("Audit must pass");
    assert_eq!(report.total_blocks, 6);
    assert!(report.chain_valid);
}

#[test]
fn test_ledger_detects_sqlite_payload_tampering() {
    let tmp = tempfile::tempdir().unwrap();
    let rsi_root = tmp.path().join(".rsi");

    let ledger = ImprovementLedger::open(&rsi_root).unwrap();
    ledger
        .append_block(
            BlockType::Evaluation,
            "{\"original\": true}".to_string(),
            Vec::new(),
        )
        .unwrap();

    // Adversarial attack: modify payload_json directly in SQLite
    let db_path = rsi_root.join("ledger.db");
    let conn = Connection::open(&db_path).unwrap();
    conn.execute(
        "UPDATE blocks SET payload_json = '{\"tampered\": true}' WHERE sequence = 1",
        [],
    )
    .unwrap();

    let audit_res = ledger.verify_chain_integrity(None);
    assert!(
        audit_res.is_err(),
        "Audit must fail when payload is tampered"
    );
    let err_msg = audit_res.err().unwrap();
    assert!(
        err_msg.contains("Payload digest mismatch at sequence 1"),
        "Expected payload digest error, got: {}",
        err_msg
    );
}

#[test]
fn test_ledger_detects_hash_chain_discontinuity() {
    let tmp = tempfile::tempdir().unwrap();
    let rsi_root = tmp.path().join(".rsi");

    let ledger = ImprovementLedger::open(&rsi_root).unwrap();
    ledger
        .append_block(
            BlockType::Evaluation,
            "{\"block\": 1}".to_string(),
            Vec::new(),
        )
        .unwrap();
    ledger
        .append_block(
            BlockType::Promotion,
            "{\"block\": 2}".to_string(),
            Vec::new(),
        )
        .unwrap();

    // Adversarial attack: break prev_block_hash pointer
    let db_path = rsi_root.join("ledger.db");
    let conn = Connection::open(&db_path).unwrap();
    conn.execute(
        "UPDATE blocks SET prev_block_hash = '1111111111111111111111111111111111111111111111111111111111111111' WHERE sequence = 2",
        [],
    )
    .unwrap();

    let audit_res = ledger.verify_chain_integrity(None);
    assert!(audit_res.is_err(), "Audit must fail on broken hash chain");
    let err_msg = audit_res.err().unwrap();
    assert!(
        err_msg.contains("Hash chain broken at sequence 2"),
        "Expected chain break error, got: {}",
        err_msg
    );
}

#[test]
fn test_content_addressed_blob_store_and_tamper_detection() {
    let tmp = tempfile::tempdir().unwrap();
    let rsi_root = tmp.path().join(".rsi");

    let ledger = ImprovementLedger::open(&rsi_root).unwrap();
    let raw_metrics = b"{\"p95_latency_us\": 1420.5, \"peak_rss_mb\": 412}";

    let receipt = EvaluationReceipt {
        cycle_id: "cycle-blob-01".to_string(),
        candidate_id: "cand-blob-01".to_string(),
        parent_id: "parent-blob-00".to_string(),
        evaluated_at: chrono::Utc::now().to_rfc3339(),
        evaluator_version: "1.0.0".to_string(),
        passed_all_hard_invariants: true,
        passed_statistical_gates: true,
        admitted: true,
        layer_results: Vec::new(),
        metrics_summary: Some(EvaluationMetricsSummary {
            latency_delta_pct: -5.2,
            p_value: 0.001,
            p95_ci_upper_degradation_pct: 0.2,
            p99_ci_upper_degradation_pct: 0.4,
            rss_growth_pct: 0.1,
            candidate_resident_mb: 412,
        }),
        receipt_digest: "digest-test-01".to_string(),
        signature: None,
    };

    let block = ledger
        .append_evaluation(&receipt, Some(raw_metrics))
        .unwrap();
    assert_eq!(block.blob_hashes.len(), 1);
    let blob_hash = &block.blob_hashes[0];

    // Blob must exist in .rsi/blobs/<sha256>
    assert!(ledger.blob_store().has_blob(blob_hash));
    let read_back = ledger.blob_store().get_blob(blob_hash).unwrap();
    assert_eq!(read_back, raw_metrics);

    // Chain integrity passes
    let report = ledger.verify_chain_integrity(None).unwrap();
    assert_eq!(report.total_blobs, 1);

    // Adversarial attack: mutate physical blob file on disk
    let blob_path = rsi_root.join("blobs").join(blob_hash);
    fs::write(&blob_path, b"{\"tampered_metric\": 99999}").unwrap();

    // Audit must catch corrupt blob
    let audit_fail = ledger.verify_chain_integrity(None);
    assert!(audit_fail.is_err());
    let err_msg = audit_fail.err().unwrap();
    assert!(err_msg.contains("missing or corrupted"));
}

#[test]
fn test_merkle_root_computation_and_ecdsa_signature_verification() {
    let tmp = tempfile::tempdir().unwrap();
    let rsi_root = tmp.path().join(".rsi");

    let ledger = ImprovementLedger::open(&rsi_root).unwrap();

    let signing_key = SigningKey::from_bytes(&[88u8; 32].into()).unwrap();
    let verifying_key = VerifyingKey::from(&signing_key);

    let attacker_key = SigningKey::from_bytes(&[99u8; 32].into()).unwrap();
    let attacker_verifying_key = VerifyingKey::from(&attacker_key);

    for i in 1..=4 {
        ledger
            .append_block(
                BlockType::Evaluation,
                format!("{{\"eval\": {}}}", i),
                Vec::new(),
            )
            .unwrap();
    }

    // 1. Create signed checkpoint
    let checkpoint = ledger.checkpoint(Some(&signing_key)).unwrap();
    assert!(checkpoint.signature.is_some());
    assert!(checkpoint.verify_signature(&verifying_key));
    assert!(!checkpoint.verify_signature(&attacker_verifying_key));

    // 2. Audit with authorized verifying key
    let report = ledger.verify_chain_integrity(Some(&verifying_key)).unwrap();
    assert!(report.checkpoint_verified);
    assert!(report.signature_verified);

    // 3. Audit with attacker key must fail signature verification
    let audit_fail = ledger.verify_chain_integrity(Some(&attacker_verifying_key));
    assert!(audit_fail.is_err());
    let err_msg = audit_fail.err().unwrap();
    assert!(err_msg.contains("signature verification failed"));
}

#[test]
fn test_promotion_evidence_true_rsi_compounding() {
    let tmp = tempfile::tempdir().unwrap();
    let rsi_root = tmp.path().join(".rsi");

    let ledger = ImprovementLedger::open(&rsi_root).unwrap();

    // 1. Record generation N (MetaCandidate)
    let meta_block = ledger
        .append_block(
            BlockType::Promotion,
            "{\"candidate\": \"gen-01\", \"classification\": \"META_CANDIDATE\"}".to_string(),
            Vec::new(),
        )
        .unwrap();

    // 2. Record downstream generation N+1
    let downstream_block = ledger
        .append_block(
            BlockType::Evaluation,
            "{\"cycle_id\": \"cycle-02\", \"delta_pct\": -12.4}".to_string(),
            Vec::new(),
        )
        .unwrap();

    // 3. Append append-only PromotionEvidence record proving True RSI Criterion 3
    let evidence_payload = PromotionEvidencePayload {
        meta_candidate_block_hash: meta_block.block_hash.clone(),
        downstream_cycle_id: "cycle-02".to_string(),
        downstream_ledger_block_hash: downstream_block.block_hash.clone(),
        capability_improvement_proof: "Downstream generation N+1 resolved scheduler bottleneck using primitive introduced in N".to_string(),
        final_classification: "TRUE_RSI".to_string(),
    };

    let evidence_block = ledger
        .append_promotion_evidence(&evidence_payload)
        .expect("Appending promotion evidence failed");

    assert_eq!(evidence_block.block_type, BlockType::PromotionEvidence);
    assert_eq!(evidence_block.sequence, 3);
    assert!(evidence_block.payload_json.contains("TRUE_RSI"));

    let report = ledger.verify_chain_integrity(None).unwrap();
    assert_eq!(report.total_blocks, 4);
    assert!(report.chain_valid);
}

#[tokio::test]
async fn test_daemon_run_cycle_records_provenance_to_ledger() {
    let tmp = tempfile::tempdir().unwrap();
    let repo_dir = tmp.path().join("repo");
    let sandbox_dir = tmp.path().join("sandbox");
    fs::create_dir_all(&repo_dir).unwrap();

    // Init git repo
    let _ = Command::new("git")
        .args(["init", "-b", "main"])
        .current_dir(&repo_dir)
        .output();
    let _ = Command::new("git")
        .args(["config", "user.name", "Test Operator"])
        .current_dir(&repo_dir)
        .output();
    let _ = Command::new("git")
        .args(["config", "user.email", "operator@test.local"])
        .current_dir(&repo_dir)
        .output();

    let readme = repo_dir.join("README.md");
    fs::write(&readme, "# Provenance Test\n\nWe build, fix, finish, and optimize systems with love, honor, and discipline\u{2014}unslop clean.\n").unwrap();

    let exe = spark_rsi::actor::judge::find_executable(std::path::Path::new("."))
        .expect("spark-rsi executable must exist");
    fs::copy(&exe, repo_dir.join("spark-rsi")).unwrap();

    let _ = Command::new("git")
        .args(["add", "."])
        .current_dir(&repo_dir)
        .output();
    let _ = Command::new("git")
        .args(["commit", "-m", "initial commit"])
        .current_dir(&repo_dir)
        .output();

    let rsi_root = repo_dir.join(".rsi");
    let holdouts = rsi_root.join("holdouts");
    std::fs::create_dir_all(&holdouts).unwrap();
    for s in spark_rsi::actor::judge::HoldoutSuite::builtin_suites() {
        s.save_to_dir(&holdouts).unwrap();
    }
    let signing_key = p256::ecdsa::SigningKey::from_bytes(&[88u8; 32].into()).unwrap();
    let signing_key_hex = hex::encode(signing_key.to_bytes());

    let config = RsiConfig {
        target_repo: repo_dir.to_str().unwrap().to_string(),
        cortex_url: "http://127.0.0.1:18080".to_string(),
        cortex_space: "atlas-memory".to_string(),
        mojo_kernel_path: "mojo/balance_bin".to_string(),
        loop_interval_secs: 60,
        sandbox_root: sandbox_dir.to_str().unwrap().to_string(),
        rsi_root: ".rsi".to_string(),
        holdouts_dir: None,
        signing_key_hex: Some(signing_key_hex),
        require_latency_improvement: false,
        non_inferiority_margin: Some(250.0),
        max_url: "http://127.0.0.1:9".to_string(),
        ..Default::default()
    };

    let result = RsiEngine::run_cycle(&config)
        .await
        .expect("run_cycle failed");
    assert!(result.success);
    assert!(result.proposal.is_some());
    assert!(result.generation.is_some());
    assert!(
        result.ledger_block.is_some(),
        "Ledger block must be emitted upon promotion"
    );

    // Verify ledger database exists and contains provenance records
    let ledger = ImprovementLedger::open(&rsi_root).expect("Failed to open generated ledger");
    let blocks = ledger.all_blocks().expect("Failed to query blocks");
    assert!(
        blocks.len() >= 2,
        "Ledger must contain Genesis and Promotion blocks"
    );

    let audit = ledger
        .verify_chain_integrity(None)
        .expect("Chain audit failed");
    assert!(audit.chain_valid);
}
