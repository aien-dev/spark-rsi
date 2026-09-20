use spark_rsi::balance::BalanceKernel;
use spark_rsi::models::{ProposalKind, RsiConfig};
use spark_rsi::observe::{calculate_soul_tension, observe_codebase};
use spark_rsi::propose::ProposalGenerator;
use spark_rsi::verifier::InvariantVerifier;
use std::fs;
use std::path::Path;

#[test]
fn test_mojo_balance_kernel_scalar() {
    let kernel_path = "mojo/balance_bin";
    let verdict =
        BalanceKernel::evaluate(12.0, 10.0, Some(kernel_path)).expect("Evaluation should succeed");
    assert_eq!(verdict.verdict, "balanced");
    assert!(verdict.score > 0.7);
}

#[test]
fn test_mojo_balance_kernel_simd() {
    let kernel_path = "mojo/balance_bin";
    let drive_vec = [10.0, 8.0, 7.0, 9.0];
    let human_vec = [9.0, 8.0, 8.0, 8.0];
    let verdict = BalanceKernel::evaluate_simd(drive_vec, human_vec, Some(kernel_path))
        .expect("SIMD evaluation should succeed");
    assert_eq!(verdict.verdict, "balanced");
    assert_eq!(verdict.drive, 34.0);
    assert_eq!(verdict.humanity, 33.0);
}

#[test]
fn test_soul_tension_analysis() {
    let sample = "We build, fix, finish, and solve problems with love, community, and discipline.";
    let tension = calculate_soul_tension(sample);
    assert!(tension.drive_score >= 4.0);
    assert!(tension.humanity_score >= 3.0);
    assert_eq!(tension.state, "Balanced");
}

#[test]
fn test_invariant_unslop_enforcement() {
    let clean_text = "Standard engineering documentation without banned elements.";
    let (clean, em, en, bw, tr) = InvariantVerifier::verify_unslop_text(clean_text);
    assert!(clean);
    assert_eq!(em, 0);
    assert_eq!(en, 0);
    assert!(bw.is_empty());
    assert!(tr.is_empty());

    let em_dash_text = "Violation \u{2014} here.";
    let (clean, em, _, _, _) = InvariantVerifier::verify_unslop_text(em_dash_text);
    assert!(!clean);
    assert_eq!(em, 1);

    let buzzword_text = "We will delve into the tapestry of software.";
    let (clean, _, _, bw, _) = InvariantVerifier::verify_unslop_text(buzzword_text);
    assert!(!clean);
    assert_eq!(bw.len(), 2);
}

#[test]
fn test_invariant_secret_scanner() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let safe_file = temp_dir.path().join("config.json");
    fs::write(&safe_file, "{\"setting\": true}").expect("write safe file");

    let (clean, leaks) = InvariantVerifier::scan_dir_for_secrets(temp_dir.path());
    assert!(clean);
    assert!(leaks.is_empty());

    let env_file = temp_dir.path().join(".env");
    fs::write(&env_file, "SECRET=compromised").expect("write env file");

    let (clean, leaks) = InvariantVerifier::scan_dir_for_secrets(temp_dir.path());
    assert!(!clean);
    assert_eq!(leaks.len(), 1);
}

#[test]
fn test_proposal_staging_in_sandbox() {
    let temp_repo = tempfile::tempdir().expect("temp repo");
    let temp_sandbox = tempfile::tempdir().expect("temp sandbox");

    let file_path = temp_repo.path().join("test_file.txt");
    fs::write(&file_path, "original content").expect("write original");

    let mut proposal = ProposalGenerator::create_proposal(
        "update file",
        "update content in sandbox",
        "test_file.txt",
        "improved content",
        ProposalKind::Optimization,
    );

    let staged_path =
        ProposalGenerator::stage_in_sandbox(&mut proposal, temp_repo.path(), temp_sandbox.path())
            .expect("stage should succeed");

    assert!(staged_path.exists());
    let staged_file = staged_path.join("test_file.txt");
    let content = fs::read_to_string(&staged_file).expect("read staged");
    assert_eq!(content, "improved content");
}

#[test]
fn test_codebase_observation_current_repo() {
    let repo_path = Path::new(".");
    let telemetry = observe_codebase(repo_path).expect("telemetry should succeed");
    assert!(!telemetry.git_branch.is_empty());
    assert!(telemetry.tests_passing);
}

#[tokio::test]
async fn test_rsi_cycle_execution() {
    let tmp = tempfile::tempdir().unwrap();
    let rsi_root = tmp.path().join(".rsi");
    std::fs::create_dir_all(&rsi_root).unwrap();

    // Initialize Improvement Ledger
    spark_rsi::ledger::ImprovementLedger::open(&rsi_root).expect("ledger init");

    // Initialize Holdouts
    let holdouts = rsi_root.join("holdouts");
    std::fs::create_dir_all(&holdouts).unwrap();
    for s in spark_rsi::actor::judge::HoldoutSuite::builtin_suites() {
        s.save_to_dir(&holdouts).unwrap();
    }

    // P-256 signing key
    let signing_key = p256::ecdsa::SigningKey::from_bytes(&[88u8; 32].into()).unwrap();
    let signing_key_hex = hex::encode(signing_key.to_bytes());

    let config = RsiConfig {
        target_repo: ".".to_string(),
        cortex_url: "http://127.0.0.1:18080".to_string(),
        cortex_space: "atlas-memory".to_string(),
        mojo_kernel_path: "mojo/balance_bin".to_string(),
        loop_interval_secs: 60,
        sandbox_root: tmp.path().join("sandbox").display().to_string(),
        rsi_root: rsi_root.display().to_string(),
        holdouts_dir: Some(holdouts.display().to_string()),
        signing_key_hex: Some(signing_key_hex),
        require_latency_improvement: false,
        canary_target: 3,
        max_url: "http://127.0.0.1:9999/v1".to_string(),
        non_inferiority_margin: Some(150.0),
        ..Default::default()
    };

    let result = spark_rsi::daemon::RsiEngine::run_cycle(&config)
        .await
        .expect("cycle should execute");

    assert!(result.elapsed_ms >= 0.0);
    assert!(result.balance.is_some());
    let balance = result.balance.unwrap();
    assert_eq!(balance.verdict, "balanced");
}

#[tokio::test]
async fn test_rsi_cycle_missing_holdouts_fails_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let rsi_root = tmp.path().join(".rsi");
    std::fs::create_dir_all(&rsi_root).unwrap();
    spark_rsi::ledger::ImprovementLedger::open(&rsi_root).unwrap();

    let signing_key = p256::ecdsa::SigningKey::from_bytes(&[88u8; 32].into()).unwrap();
    let signing_key_hex = hex::encode(signing_key.to_bytes());

    let config = RsiConfig {
        target_repo: ".".to_string(),
        rsi_root: rsi_root.display().to_string(),
        holdouts_dir: Some(
            tmp.path()
                .join("nonexistent_holdouts")
                .display()
                .to_string(),
        ),
        signing_key_hex: Some(signing_key_hex),
        ..Default::default()
    };

    let res = spark_rsi::daemon::RsiEngine::run_cycle(&config).await;
    assert!(res.is_err(), "Missing holdouts must fail closed");
    assert!(res.err().unwrap().contains("Missing holdouts"));
}

#[tokio::test]
async fn test_rsi_cycle_missing_signer_fails_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let rsi_root = tmp.path().join(".rsi");
    std::fs::create_dir_all(&rsi_root).unwrap();
    spark_rsi::ledger::ImprovementLedger::open(&rsi_root).unwrap();

    let holdouts = rsi_root.join("holdouts");
    std::fs::create_dir_all(&holdouts).unwrap();

    let config = RsiConfig {
        target_repo: ".".to_string(),
        rsi_root: rsi_root.display().to_string(),
        holdouts_dir: Some(holdouts.display().to_string()),
        signing_key_hex: None,
        ..Default::default()
    };

    let res = spark_rsi::daemon::RsiEngine::run_cycle(&config).await;
    assert!(res.is_err(), "Missing signer must fail closed");
    assert!(res
        .err()
        .unwrap()
        .contains("Missing cryptographic signing key"));
}

#[tokio::test]
async fn test_production_loop_end_to_end_with_candidate() {
    let tmp = tempfile::tempdir().unwrap();
    let rsi_root = tmp.path().join(".rsi");
    std::fs::create_dir_all(&rsi_root).unwrap();

    let ledger = spark_rsi::ledger::ImprovementLedger::open(&rsi_root).expect("ledger init");

    // Initialize Holdouts
    let holdouts = rsi_root.join("holdouts");
    std::fs::create_dir_all(&holdouts).unwrap();
    for s in spark_rsi::actor::judge::HoldoutSuite::builtin_suites() {
        s.save_to_dir(&holdouts).unwrap();
    }

    // P-256 signing key
    let signing_key = p256::ecdsa::SigningKey::from_bytes(&[88u8; 32].into()).unwrap();
    let signing_key_hex = hex::encode(signing_key.to_bytes());

    // Create an isolated target repo with an unslop defect
    let test_repo = tmp.path().join("test_repo");
    std::fs::create_dir_all(&test_repo).unwrap();

    // Copy complete source tree to test_repo including Cargo.lock, README.md, docs, mojo
    std::process::Command::new("cp")
        .args(&[
            "-r",
            "Cargo.toml",
            "Cargo.lock",
            "README.md",
            "src",
            "mojo",
            "docs",
            test_repo.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    if let Some(exe) = spark_rsi::actor::judge::find_executable(std::path::Path::new(".")) {
        let _ = std::fs::copy(&exe, test_repo.join("spark-rsi"));
    } else {
        let _ = std::fs::copy(
            "/tmp/spark-rsi-target/release/spark-rsi",
            test_repo.join("spark-rsi"),
        );
    }

    // Initialize git in test_repo
    let _ = std::process::Command::new("git")
        .arg("init")
        .current_dir(&test_repo)
        .output();
    let _ = std::process::Command::new("git")
        .args(&["config", "user.name", "AIEN"])
        .current_dir(&test_repo)
        .output();
    let _ = std::process::Command::new("git")
        .args(&["config", "user.email", "aien@dgx-spark.local"])
        .current_dir(&test_repo)
        .output();

    // Inject an unslop violation into docs/PHILOSOPHY.md
    let phil_path = test_repo.join("docs").join("PHILOSOPHY.md");
    let mut phil_content = std::fs::read_to_string(&phil_path).unwrap();
    phil_content.push_str("\n# Injected Standard \u{2014} unslop violation to sanitize\n");
    std::fs::write(&phil_path, phil_content).unwrap();

    let _ = std::process::Command::new("git")
        .args(&["add", "."])
        .current_dir(&test_repo)
        .output();
    let _ = std::process::Command::new("git")
        .args(&["commit", "-m", "initial commit"])
        .current_dir(&test_repo)
        .output();

    let config = RsiConfig {
        target_repo: test_repo.display().to_string(),
        cortex_url: "http://127.0.0.1:18080".to_string(),
        cortex_space: "atlas-memory".to_string(),
        mojo_kernel_path: "mojo/balance_bin".to_string(),
        loop_interval_secs: 60,
        sandbox_root: tmp.path().join("sandbox").display().to_string(),
        rsi_root: rsi_root.display().to_string(),
        holdouts_dir: Some(holdouts.display().to_string()),
        signing_key_hex: Some(signing_key_hex),
        require_latency_improvement: false,
        canary_target: 5,
        max_url: "http://127.0.0.1:9999/v1".to_string(),
        non_inferiority_margin: Some(150.0),
        ..Default::default()
    };

    let result = spark_rsi::daemon::RsiEngine::run_cycle(&config)
        .await
        .expect("cycle should execute");

    assert!(result.success, "Production cycle must succeed");
    assert!(
        result.proposal.is_some(),
        "Unslop candidate proposal must be generated"
    );
    let prop = result.proposal.unwrap();
    assert_eq!(
        prop.kind,
        spark_rsi::models::ProposalKind::UnslopSanitization
    );

    assert!(result.invariants.is_some(), "Invariants must be verified");
    assert!(result.invariants.unwrap().passed, "Invariants must pass");

    assert!(result.balance.is_some(), "Balance kernel must be evaluated");
    assert_eq!(result.balance.unwrap().verdict, "balanced");

    assert!(
        result.receipt.is_some(),
        "BlindJudge receipt must be present"
    );
    assert!(
        result.receipt.unwrap().admitted,
        "BlindJudge must admit the candidate"
    );

    assert!(
        result.generation.is_some(),
        "Supervisor generation info must be present"
    );
    let gen = result.generation.unwrap();
    assert_eq!(gen.state, spark_rsi::supervisor::GenerationState::Durable);
    assert_eq!(gen.canary_transactions, 5);

    assert!(
        result.ledger_block.is_some(),
        "Ledger block must be present"
    );
    let blk = result.ledger_block.unwrap();
    assert_eq!(blk.block_type, spark_rsi::ledger::BlockType::Promotion);

    assert!(
        result.ratification.is_some(),
        "Ratification must be recorded"
    );

    // Verify ledger audit report
    let audit = ledger
        .verify_chain_integrity(Some(&signing_key.verifying_key()))
        .expect("ledger audit");
    assert!(
        audit.chain_valid,
        "Ledger chain must be cryptographically valid"
    );
    assert!(
        audit.total_blocks >= 2,
        "Ledger must have evaluation and promotion blocks"
    );
}
