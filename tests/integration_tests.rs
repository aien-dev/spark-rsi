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
    let verdict = BalanceKernel::evaluate(12.0, 10.0, Some(kernel_path)).expect("Evaluation should succeed");
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

    let staged_path = ProposalGenerator::stage_in_sandbox(&mut proposal, temp_repo.path(), temp_sandbox.path())
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
    let config = RsiConfig {
        target_repo: ".".to_string(),
        cortex_url: "http://127.0.0.1:18080".to_string(),
        cortex_space: "atlas-memory".to_string(),
        mojo_kernel_path: "mojo/balance_bin".to_string(),
        loop_interval_secs: 60,
        sandbox_root: "/tmp/spark-rsi-test-sandbox".to_string(),
    };

    let result = spark_rsi::daemon::RsiEngine::run_cycle(&config)
        .await
        .expect("cycle should execute");

    assert!(result.elapsed_ms >= 0.0);
    assert!(result.balance.is_some());
    let balance = result.balance.unwrap();
    assert_eq!(balance.verdict, "balanced");
}
