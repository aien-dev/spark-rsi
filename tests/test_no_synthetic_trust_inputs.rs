use p256::ecdsa::{SigningKey, VerifyingKey};
use spark_rsi::actor::judge::{find_executable, run_paired_benchmarks, BlindJudge, HoldoutSuite};
use spark_rsi::isolation::CandidateJailRunner;
use spark_rsi::supervisor::{GenerationState, HostSupervisor};
use std::fs;
use std::path::Path;

#[test]
fn test_jailed_execution_blocks_network_and_host_leaks() {
    let exe = find_executable(Path::new(".")).expect("spark-rsi executable must exist");
    let runner = CandidateJailRunner::new(&exe);

    // 1. Verify candidate execution inside jail returns valid deterministic response
    let (success, stdout, _) = runner
        .execute(&["holdout", "check_unicode_dashes"])
        .expect("Jail execution failed");
    assert!(success);
    assert_eq!(stdout.trim(), "DASHES_PROHIBITED");

    // 2. Verify Bubblewrap args contain mandatory isolation parameters
    let args = runner.build_bwrap_args(&["holdout", ""]);
    assert!(args.contains(&"--unshare-net".to_string()), "Jail missing --unshare-net");
    assert!(args.contains(&"--unshare-user".to_string()), "Jail missing --unshare-user");
    assert!(args.contains(&"--unshare-pid".to_string()), "Jail missing --unshare-pid");
    assert!(args.contains(&"--die-with-parent".to_string()), "Jail missing --die-with-parent");
}

#[test]
fn test_judge_fails_closed_without_protected_holdouts_or_authorized_key() {
    let tmp = tempfile::tempdir().unwrap();
    let holdouts = tmp.path().join("holdouts");
    let outputs = tmp.path().join("eval_outputs");
    let candidate = tmp.path().join("cand");
    let parent = tmp.path().join("parent");
    fs::create_dir_all(&candidate).unwrap();
    fs::create_dir_all(&parent).unwrap();

    let exe = find_executable(Path::new(".")).expect("spark-rsi executable must exist");
    fs::copy(&exe, candidate.join("spark-rsi")).unwrap();
    fs::copy(&exe, parent.join("spark-rsi")).unwrap();

    // Failure Case 1: Missing holdouts directory fails closed
    let signing_key = SigningKey::from_bytes(&[44u8; 32].into()).unwrap();
    let judge_no_holdouts = BlindJudge::new(holdouts.clone(), outputs.clone())
        .with_signing_key(signing_key.clone());
    let res1 = judge_no_holdouts.evaluate_cycle("c1", "cand1", "parent0", &candidate, &parent);
    assert!(res1.is_err(), "Judge must fail closed when holdouts dir does not exist");
    assert!(res1.unwrap_err().contains("Holdouts directory does not exist"));

    // Failure Case 2: Empty holdouts directory fails closed
    fs::create_dir_all(&holdouts).unwrap();
    let res2 = judge_no_holdouts.evaluate_cycle("c2", "cand2", "parent0", &candidate, &parent);
    assert!(res2.is_err(), "Judge must fail closed when holdouts dir is empty");
    assert!(res2.unwrap_err().contains("No valid holdout suites found"));

    // Populate valid holdout suites
    for suite in HoldoutSuite::builtin_suites() {
        suite.save_to_dir(&holdouts).unwrap();
    }

    // Failure Case 3: Missing signing key fails closed (zero fallback to static seed)
    let judge_no_key = BlindJudge::new(holdouts.clone(), outputs.clone());
    let res3 = judge_no_key.evaluate_cycle("c3", "cand3", "parent0", &candidate, &parent);
    assert!(res3.is_err(), "Judge must fail closed without authorized signing key");
    assert!(res3.unwrap_err().contains("signing key"));

    // Failure Case 4: Missing candidate binary in paired benchmarks fails closed (zero fallback to synthetic hash loop)
    let empty_dir = tmp.path().join("empty_binary_dir");
    fs::create_dir_all(&empty_dir).unwrap();
    let bench_res = run_paired_benchmarks(&empty_dir, &candidate, 10);
    assert!(bench_res.is_err(), "Paired benchmark must fail closed without compiled binaries");
    assert!(bench_res.unwrap_err().contains("executable binary not found"));
}

#[test]
fn test_paired_benchmarks_capture_real_child_process_metrics_without_markers() {
    let tmp = tempfile::tempdir().unwrap();
    let candidate = tmp.path().join("cand");
    let parent = tmp.path().join("parent");
    fs::create_dir_all(&candidate).unwrap();
    fs::create_dir_all(&parent).unwrap();

    let exe = find_executable(Path::new(".")).expect("spark-rsi executable must exist");
    fs::copy(&exe, candidate.join("spark-rsi")).unwrap();
    fs::copy(&exe, parent.join("spark-rsi")).unwrap();

    // Plant synthetic speedup marker in candidate
    fs::write(candidate.join(".rsi_speedup"), "0.10").unwrap();

    let (p_lats, c_lats, p_ru, c_ru) = run_paired_benchmarks(&parent, &candidate, 30)
        .expect("Paired benchmark must execute real child processes");

    assert_eq!(p_lats.len(), 30);
    assert_eq!(c_lats.len(), 30);

    // Verify latencies are genuine measured positive non-zero numbers
    for lat in &p_lats {
        assert!(*lat > 50.0, "Latency must be real elapsed microseconds: {}", lat);
    }
    for lat in &c_lats {
        assert!(*lat > 50.0, "Latency must be real elapsed microseconds: {}", lat);
    }

    // Core invariant: .rsi_speedup (0.10) must NOT artificially scale candidate latency by 10x
    let p_mean: f64 = p_lats.iter().sum::<f64>() / 30.0;
    let c_mean: f64 = c_lats.iter().sum::<f64>() / 30.0;
    let ratio = c_mean / p_mean;
    assert!(
        ratio > 0.50 && ratio < 2.0,
        "Marker file bypassed measurement: ratio was {:.4} (p_mean={}, c_mean={})",
        ratio, p_mean, c_mean
    );

    // Verify child rusage metrics are captured
    assert!(p_ru.max_rss_kb > 0, "Parent RSS must be non-zero");
    assert!(c_ru.max_rss_kb > 0, "Candidate RSS must be non-zero");
}

#[test]
fn test_end_to_end_unmocked_lifecycle_admission_and_supervisor_rollback() {
    let tmp = tempfile::tempdir().unwrap();
    let rsi_root = tmp.path().join(".rsi");
    let holdouts = rsi_root.join("holdouts");
    let outputs = rsi_root.join("eval_outputs");
    let candidate = tmp.path().join("cand");
    let parent = tmp.path().join("parent");
    fs::create_dir_all(&candidate).unwrap();
    fs::create_dir_all(&parent).unwrap();

    let exe = find_executable(Path::new(".")).expect("spark-rsi executable must exist");
    fs::copy(&exe, candidate.join("spark-rsi")).unwrap();
    fs::copy(&exe, parent.join("spark-rsi")).unwrap();

    // Seed protected holdouts
    for suite in HoldoutSuite::builtin_suites() {
        suite.save_to_dir(&holdouts).unwrap();
    }

    let signing_key = SigningKey::from_bytes(&[55u8; 32].into()).unwrap();
    let verifying_key = VerifyingKey::from(&signing_key);

    let judge = BlindJudge::new(holdouts, outputs.clone())
        .with_signing_key(signing_key)
        .with_non_inferiority_margin(500.0);

    // 1. Evaluate candidate
    let receipt = judge
        .evaluate_cycle("cycle-e2e-01", "cand-e2e-01", "parent-e2e-00", &candidate, &parent)
        .expect("Evaluation cycle failed");

    assert!(receipt.admitted, "Clean candidate must be admitted");
    assert!(receipt.passed_all_hard_invariants);
    assert!(receipt.passed_statistical_gates);
    assert!(receipt.verify_digest());
    assert!(receipt.signature.is_some());
    assert!(receipt.verify_signature(&verifying_key));

    // 2. Route admitted candidate into HostSupervisor
    let supervisor = HostSupervisor::new(&rsi_root, 49_152);

    // Stage parent generation first
    supervisor
        .stage_generation("gen-parent-00", &parent, "parent-digest-00")
        .expect("Parent staging failed");
    supervisor
        .atomic_symlink_swap("gen-parent-00")
        .expect("Initial parent symlink swap failed");

    // Stage admitted candidate generation
    let mut gen_info = supervisor
        .stage_generation("gen-e2e-01", &candidate, &receipt.receipt_digest)
        .expect("Candidate staging failed");
    assert_eq!(gen_info.state, GenerationState::Staged);

    // Atomic symlink swap to point to candidate
    supervisor
        .atomic_symlink_swap("gen-e2e-01")
        .expect("Candidate symlink swap failed");
    let active_link = fs::read_link(rsi_root.join("active")).unwrap();
    assert!(active_link.to_string_lossy().contains("gen-e2e-01"));

    // Canary testing: transaction success transitions toward Durable
    let s1 = supervisor
        .record_canary_transaction(&mut gen_info, true, 1000, 10, 1_000_000, 0.0)
        .expect("Canary update failed");
    assert_eq!(s1, GenerationState::CanaryActive);

    // Simulate regression alert triggering automated rollback
    let _ = supervisor.record_canary_transaction(&mut gen_info, false, 1000, 10, 1_000_000, 0.0);
    assert_eq!(gen_info.state, GenerationState::Reverting);

    // Supervisor executes atomic rollback to parent
    let rollback_res = supervisor.rollback_to_parent("gen-parent-00", None, None);
    assert!(rollback_res.is_ok(), "Supervisor rollback failed");
    let reverted_link = fs::read_link(rsi_root.join("active")).unwrap();
    assert!(reverted_link.to_string_lossy().contains("gen-parent-00"));
}

#[tokio::test]
async fn test_daemon_run_cycle_promotes_via_host_supervisor() {
    use spark_rsi::daemon::RsiEngine;
    use spark_rsi::models::RsiConfig;
    use std::process::Command;

    let tmp = tempfile::tempdir().unwrap();
    let repo_dir = tmp.path().join("repo");
    let sandbox_dir = tmp.path().join("sandbox");
    fs::create_dir_all(&repo_dir).unwrap();

    // Initialize git repository
    let _ = Command::new("git").args(["init", "-b", "main"]).current_dir(&repo_dir).output();
    let _ = Command::new("git").args(["config", "user.name", "Test Operator"]).current_dir(&repo_dir).output();
    let _ = Command::new("git").args(["config", "user.email", "operator@test.local"]).current_dir(&repo_dir).output();

    // Write a README with an em-dash to trigger ProposalGenerator
    let readme = repo_dir.join("README.md");
    fs::write(&readme, "# Test Repo\n\nWe build, fix, finish, and optimize systems with love, honor, and discipline\u{2014}with an em dash.\n").unwrap();

    let exe = find_executable(Path::new(".")).expect("spark-rsi executable must exist");
    fs::copy(&exe, repo_dir.join("spark-rsi")).unwrap();

    let _ = Command::new("git").args(["add", "."]).current_dir(&repo_dir).output();
    let _ = Command::new("git").args(["commit", "-m", "initial commit"]).current_dir(&repo_dir).output();

    let rsi_root = repo_dir.join(".rsi");
    let holdouts = rsi_root.join("holdouts");
    std::fs::create_dir_all(&holdouts).unwrap();
    for s in HoldoutSuite::builtin_suites() {
        s.save_to_dir(&holdouts).unwrap();
    }
    let signing_key = SigningKey::from_bytes(&[88u8; 32].into()).unwrap();
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

    let result = RsiEngine::run_cycle(&config).await.expect("run_cycle failed");

    assert!(result.success, "Cycle should succeed");
    assert!(result.proposal.is_some(), "Proposal should be generated for em dash unslop");
    assert!(result.generation.is_some(), "Candidate promotion must execute through Host Supervisor");

    let gen = result.generation.unwrap();
    assert!(gen.state == GenerationState::Durable || gen.state == GenerationState::CanaryActive);

    // Verify atomic active symlink was created by HostSupervisor
    let active_link = fs::read_link(rsi_root.join("active")).expect("Active symlink must exist");
    assert!(active_link.to_string_lossy().contains(&gen.generation_id));
    assert!(gen.installed_path.exists());
}
