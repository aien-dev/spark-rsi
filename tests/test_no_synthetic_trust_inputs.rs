use p256::ecdsa::{SigningKey, VerifyingKey};
use spark_rsi::actor::judge::{find_executable, run_paired_benchmarks, BlindJudge, HoldoutSuite};
use spark_rsi::canary::{CanaryWorkloadManifest, SealedObservationLog};
use spark_rsi::daemon::RsiEngine;
use spark_rsi::isolation::CandidateJailRunner;
use spark_rsi::ledger::ImprovementLedger;
use spark_rsi::models::{ProposalKind, RsiConfig};
use spark_rsi::supervisor::{GenerationState, HostSupervisor};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[allow(dead_code)]
mod canary_fixture;

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
    assert!(
        args.contains(&"--unshare-net".to_string()),
        "Jail missing --unshare-net"
    );
    assert!(
        args.contains(&"--unshare-user".to_string()),
        "Jail missing --unshare-user"
    );
    assert!(
        args.contains(&"--unshare-pid".to_string()),
        "Jail missing --unshare-pid"
    );
    assert!(
        args.contains(&"--die-with-parent".to_string()),
        "Jail missing --die-with-parent"
    );
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
    let judge_no_holdouts =
        BlindJudge::new(holdouts.clone(), outputs.clone()).with_signing_key(signing_key.clone());
    let res1 = judge_no_holdouts.evaluate_cycle("c1", "cand1", "parent0", &candidate, &parent);
    assert!(
        res1.is_err(),
        "Judge must fail closed when holdouts dir does not exist"
    );
    assert!(res1
        .unwrap_err()
        .contains("Holdouts directory does not exist"));

    // Failure Case 2: Empty holdouts directory fails closed
    fs::create_dir_all(&holdouts).unwrap();
    let res2 = judge_no_holdouts.evaluate_cycle("c2", "cand2", "parent0", &candidate, &parent);
    assert!(
        res2.is_err(),
        "Judge must fail closed when holdouts dir is empty"
    );
    assert!(res2.unwrap_err().contains("No valid holdout suites found"));

    // Populate valid holdout suites
    for suite in HoldoutSuite::builtin_suites() {
        suite.save_to_dir(&holdouts).unwrap();
    }

    // Failure Case 3: Missing signing key fails closed (zero fallback to static seed)
    let judge_no_key = BlindJudge::new(holdouts.clone(), outputs.clone());
    let res3 = judge_no_key.evaluate_cycle("c3", "cand3", "parent0", &candidate, &parent);
    assert!(
        res3.is_err(),
        "Judge must fail closed without authorized signing key"
    );
    assert!(res3.unwrap_err().contains("signing key"));

    // Failure Case 4: Missing candidate binary in paired benchmarks fails closed (zero fallback to synthetic hash loop)
    let empty_dir = tmp.path().join("empty_binary_dir");
    fs::create_dir_all(&empty_dir).unwrap();
    let bench_res = run_paired_benchmarks(&empty_dir, &candidate, 10);
    assert!(
        bench_res.is_err(),
        "Paired benchmark must fail closed without compiled binaries"
    );
    assert!(bench_res
        .unwrap_err()
        .contains("executable binary not found"));
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
        assert!(
            *lat > 50.0,
            "Latency must be real elapsed microseconds: {}",
            lat
        );
    }
    for lat in &c_lats {
        assert!(
            *lat > 50.0,
            "Latency must be real elapsed microseconds: {}",
            lat
        );
    }

    // Core invariant: .rsi_speedup (0.10) must NOT artificially scale candidate latency by 10x
    let p_mean: f64 = p_lats.iter().sum::<f64>() / 30.0;
    let c_mean: f64 = c_lats.iter().sum::<f64>() / 30.0;
    let ratio = c_mean / p_mean;
    assert!(
        ratio > 0.50 && ratio < 2.0,
        "Marker file bypassed measurement: ratio was {:.4} (p_mean={}, c_mean={})",
        ratio,
        p_mean,
        c_mean
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
        .evaluate_cycle(
            "cycle-e2e-01",
            "cand-e2e-01",
            "parent-e2e-00",
            &candidate,
            &parent,
        )
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

    // Worker self-reports are diagnostics: however many clean ones arrive, the generation stays
    // on probation. Only a sealed supervisor-driven observation log can reach admission.
    for _ in 0..25 {
        let state = supervisor
            .record_canary_transaction(&mut gen_info, true, 1000, 1_000_000, 0.0)
            .expect("Canary update failed");
        assert_eq!(state, GenerationState::CanaryActive);
    }
    assert_ne!(gen_info.state, GenerationState::Durable);

    // A reported failure still triggers the early safety revert
    let failed = supervisor.record_canary_transaction(&mut gen_info, false, 1000, 1_000_000, 0.0);
    assert!(failed.is_err());
    assert_eq!(gen_info.state, GenerationState::Reverting);

    // Supervisor executes atomic rollback to parent
    let rollback_res = supervisor.rollback_to_parent("gen-parent-00", None, None);
    assert!(rollback_res.is_ok(), "Supervisor rollback failed");
    let reverted_link = fs::read_link(rsi_root.join("active")).unwrap();
    assert!(reverted_link.to_string_lossy().contains("gen-parent-00"));
}

// ---------------------------------------------------------------------------------------------
// Daemon-level canary admission. The target repository is built from fixtures/canary-target and
// the daemon drives the real fixture executable through the supervisor. No test here lets a
// worker self-report success into admission.
// ---------------------------------------------------------------------------------------------

static FIXTURE_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The build jail is the only thing that builds the candidate. Without bubblewrap there is no
/// jail, so the daemon tests cannot run and say so. Set RSI_REQUIRE_BUILD_JAIL=1 to make a
/// missing jail a failure instead of a skip.
fn build_jail_available() -> bool {
    let ok = Command::new("bwrap")
        .args([
            "--unshare-user",
            "--unshare-pid",
            "--unshare-net",
            "--ro-bind",
            "/usr",
            "/usr",
            "--ro-bind",
            "/lib",
            "/lib",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "/usr/bin/true",
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !ok {
        assert!(
            std::env::var_os("RSI_REQUIRE_BUILD_JAIL").is_none(),
            "RSI_REQUIRE_BUILD_JAIL is set but bubblewrap cannot run here"
        );
        eprintln!(
            "SKIPPED: bubblewrap cannot run in this environment, so the build jail is unavailable"
        );
    }
    ok
}

fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("git runs");
    assert!(out.status.success(), "git {:?} failed", args);
}

/// A target repository: the fixture crate, a README with an em dash so the unslop proposal
/// exists, the pinned workload under `.rsi/canary`, holdouts and a signing key. With
/// `with_adapter` false the adapter manifest is left out.
struct Target {
    _tmp: tempfile::TempDir,
    repo: PathBuf,
    config: RsiConfig,
}

fn make_target(with_adapter: bool, pin: Option<&str>) -> Target {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    let sandbox = tmp.path().join("sandbox");
    let fx = canary_fixture::fixture_dir();
    fs::create_dir_all(repo.join("src")).unwrap();
    for f in ["Cargo.toml", "Cargo.lock"] {
        fs::copy(fx.join(f), repo.join(f)).unwrap();
    }
    fs::copy(fx.join("src/main.rs"), repo.join("src/main.rs")).unwrap();
    if with_adapter {
        fs::copy(
            fx.join("canary-adapter.toml"),
            repo.join("canary-adapter.toml"),
        )
        .unwrap();
    }
    fs::write(
        repo.join("README.md"),
        "# Target\n\nWe build, fix, finish, and optimize systems with love, honor, and discipline\u{2014}with an em dash.\n",
    )
    .unwrap();
    // The judge's paired benchmarks need the engine executable in the tree.
    let exe = find_executable(Path::new(".")).expect("spark-rsi executable must exist");
    fs::copy(&exe, repo.join("spark-rsi")).unwrap();
    fs::write(repo.join(".gitignore"), "target\n").unwrap();
    git(&repo, &["init", "-b", "main"]);
    git(&repo, &["config", "user.name", "Test Operator"]);
    git(&repo, &["config", "user.email", "operator@test.local"]);
    git(&repo, &["add", "."]);
    git(&repo, &["commit", "-m", "initial commit"]);

    let rsi_root = repo.join(".rsi");
    let holdouts = rsi_root.join("holdouts");
    fs::create_dir_all(&holdouts).unwrap();
    for s in HoldoutSuite::builtin_suites() {
        s.save_to_dir(&holdouts).unwrap();
    }
    let workload = rsi_root.join("canary/workload.json");
    fs::create_dir_all(workload.parent().unwrap()).unwrap();
    fs::copy(fx.join("workload.json"), &workload).unwrap();
    let digest = CanaryWorkloadManifest::load(&workload).unwrap().digest;

    let signing_key = SigningKey::from_bytes(&[88u8; 32].into()).unwrap();
    let config = RsiConfig {
        target_repo: repo.to_str().unwrap().to_string(),
        cortex_url: "http://127.0.0.1:18080".to_string(),
        cortex_space: "atlas-memory".to_string(),
        loop_interval_secs: 60,
        sandbox_root: sandbox.to_str().unwrap().to_string(),
        rsi_root: ".rsi".to_string(),
        holdouts_dir: None,
        signing_key_hex: Some(hex::encode(signing_key.to_bytes())),
        require_latency_improvement: false,
        non_inferiority_margin: Some(250.0),
        model_url: "http://127.0.0.1:9".to_string(),
        canary_target: 10,
        canary_workload_sha256: Some(pin.map(str::to_string).unwrap_or(digest)),
        ..Default::default()
    };
    Target {
        _tmp: tmp,
        repo,
        config,
    }
}

fn ledger_payloads(repo: &Path) -> Vec<String> {
    ImprovementLedger::open(&repo.join(".rsi"))
        .unwrap()
        .all_blocks()
        .unwrap()
        .into_iter()
        .map(|b| b.payload_json)
        .collect()
}

fn commitment(payloads: &[String]) -> Option<serde_json::Value> {
    payloads.iter().find_map(|p| {
        let v: serde_json::Value = serde_json::from_str(p).ok()?;
        v.get("canary_commitment").cloned()
    })
}

#[tokio::test]
async fn daemon_cycle_with_a_correct_fixture_reaches_the_later_gates() {
    if !build_jail_available() {
        return;
    }
    let _guard = FIXTURE_ENV_LOCK.lock().await;
    std::env::remove_var("RSI_CANARY_FIXTURE_MODE");
    let t = make_target(true, None);

    let result = RsiEngine::run_cycle(&t.config).await.expect("run_cycle");
    assert!(result.proposal.is_some(), "the em dash makes a proposal");
    let canary = result.canary.expect("canary summary");
    assert!(canary.applicable && canary.eligible, "{:?}", canary);
    let binding = canary.identity_binding_digest.clone().expect("identity");
    assert_eq!(binding.len(), 64);

    // The sealed log: ten supervisor-verified observations, all qualifying.
    let log_path = t.repo.join(format!(
        ".rsi/canary/observations/{}.jsonl",
        result.proposal.as_ref().unwrap().id
    ));
    let sealed = SealedObservationLog::load(&log_path).expect("sealed log verifies");
    assert_eq!(sealed.seal.observation_count, 10);
    assert_eq!(sealed.seal.qualifying_count, 10);
    assert_eq!(
        canary.log_digest.as_deref(),
        Some(sealed.seal.log_digest.as_str())
    );

    // The ledger holds the commitment, bound to the identity and the sealed log.
    let payloads = ledger_payloads(&t.repo);
    let c = commitment(&payloads).expect("canary_commitment block in the ledger");
    assert_eq!(c["identity_binding_digest"], binding.as_str());
    assert_eq!(c["log_digest"], sealed.seal.log_digest.as_str());
    assert_eq!(c["qualifying_count"], 10);
    assert_eq!(c["observation_count"], 10);
    assert_eq!(c["rejection_count"], 0);
    assert_eq!(
        c["workload_digest"],
        canary.workload_digest.as_deref().unwrap()
    );
    assert!(c["adapter_manifest_digest"].as_str().unwrap().len() == 64);
    assert!(canary.commitment_block_hash.is_some());

    // Quota admission passed, the envelope ran and is recorded as a reference evaluation, and
    // the promotion gate decided.
    let quota = canary.quota.expect("quota decision");
    assert!(quota.admitted, "{:?}", quota);
    assert_eq!(quota.counted, Some(10));
    assert_eq!(quota.target, 10);
    assert!(canary.envelope.expect("envelope decision").passed);
    assert!(canary
        .envelope_note
        .expect("envelope note")
        .contains("DeterministicReferenceBackend"));
    let gate = canary.promotion_gate.expect("promotion gate decision");
    // The in-process judge signs with the daemon's own key and binds no version 2 receipt, so
    // the gate refuses in this cut (issue #35). Nothing becomes durable.
    assert!(!gate.passed, "{:?}", gate);
    assert!(!result.success);
    assert!(result.generation.is_none());
    assert!(fs::read_link(t.repo.join(".rsi/active")).is_err());
    assert!(payloads
        .iter()
        .any(|p| p.contains("DeterministicReferenceBackend")));
}

#[tokio::test]
async fn daemon_cycle_with_a_wrong_answering_fixture_is_refused_and_rolled_back() {
    if !build_jail_available() {
        return;
    }
    let _guard = FIXTURE_ENV_LOCK.lock().await;
    std::env::set_var("RSI_CANARY_FIXTURE_MODE", "wrong_answer");
    let t = make_target(true, None);
    let outcome = RsiEngine::run_cycle(&t.config).await;
    std::env::remove_var("RSI_CANARY_FIXTURE_MODE");
    let result = outcome.expect("run_cycle");

    let canary = result.canary.expect("canary summary");
    let quota = canary.quota.expect("quota decision");
    assert!(!quota.admitted, "{:?}", quota);
    assert!(quota.refusal.is_some());
    assert!(
        canary.envelope.is_none(),
        "the envelope runs only after the quota"
    );
    assert!(canary.promotion_gate.is_none());
    assert!(!result.success);
    assert!(result.generation.is_none(), "nothing becomes durable");
    assert!(fs::read_link(t.repo.join(".rsi/active")).is_err());
    assert!(fs::read_link(t.repo.join(".rsi/active.sock")).is_err());

    let payloads = ledger_payloads(&t.repo);
    assert!(
        commitment(&payloads).is_some(),
        "the commitment precedes admission"
    );
    assert!(
        payloads
            .iter()
            .any(|p| p.contains("\"reason\"") && p.contains("rolled_back_at")),
        "a rollback block records the reason"
    );
}

#[tokio::test]
async fn daemon_cycle_refuses_a_target_without_an_adapter_before_any_worker_starts() {
    let _guard = FIXTURE_ENV_LOCK.lock().await;
    let t = make_target(false, None);
    let result = RsiEngine::run_cycle(&t.config).await.expect("run_cycle");

    let canary = result.canary.expect("canary summary");
    assert!(canary.applicable);
    assert!(!canary.eligible);
    assert!(canary.refusal.unwrap().contains("not eligible for canary"));
    assert!(
        result.proposal.is_some(),
        "the judge ran, the canary refused"
    );
    assert!(!result.success);
    assert!(canary.quota.is_none() && canary.log_digest.is_none());
    assert!(result.generation.is_none());
    assert!(
        !t.repo.join(".rsi/canary/observations").exists(),
        "no worker started, so no observation log exists"
    );
    assert!(!t.repo.join(".rsi/workers").exists());
    assert!(ledger_payloads(&t.repo)
        .iter()
        .any(|p| p.contains("not eligible for canary")));
}

#[tokio::test]
async fn daemon_cycle_refuses_a_mismatched_or_missing_workload_pin() {
    let _guard = FIXTURE_ENV_LOCK.lock().await;
    let wrong = "0".repeat(64);
    let t = make_target(true, Some(&wrong));
    let err = RsiEngine::run_cycle(&t.config).await.unwrap_err();
    assert!(err.contains("canary workload refused"), "{}", err);
    assert!(err.contains("pinned digest"), "{}", err);
    assert!(!t.repo.join(".rsi/canary/observations").exists());

    // Unpinned fails closed in production mode.
    let mut unpinned = make_target(true, None);
    unpinned.config.canary_workload_sha256 = None;
    let err = RsiEngine::run_cycle(&unpinned.config).await.unwrap_err();
    assert!(err.contains("must pin the canary workload"), "{}", err);
}

#[tokio::test]
async fn exemption_is_explicit_configuration_and_never_covers_executable_changes() {
    // Default policy: nothing is exempt, so a documentation-like proposal in a tree that ships
    // an adapter is still canary-applicable.
    let _guard = FIXTURE_ENV_LOCK.lock().await;
    let t = make_target(false, None);
    assert!(t.config.canary_exempt_kinds.is_empty());
    let result = RsiEngine::run_cycle(&t.config).await.expect("run_cycle");
    assert!(result.canary.expect("summary").applicable);

    // Listing the kind exempts it only when nothing executable is involved. This tree ships no
    // adapter and its engine executable is already present, so the change is exempt by
    // configuration. The exemption skips the canary only: the envelope and the promotion gate
    // still decide, and the gate still refuses.
    let mut listed = make_target(false, None);
    listed.config.canary_exempt_kinds = vec![ProposalKind::UnslopSanitization];
    let result = RsiEngine::run_cycle(&listed.config)
        .await
        .expect("run_cycle");
    let canary = result.canary.expect("summary");
    assert!(!canary.applicable);
    assert!(canary.exemption.is_some());
    assert!(canary.quota.is_none() && canary.log_digest.is_none());
    assert!(canary.envelope.expect("envelope still runs").passed);
    assert!(!canary.promotion_gate.expect("gate still decides").passed);
    assert!(!result.success && result.generation.is_none());
    assert!(!listed.repo.join(".rsi/canary/observations").exists());

    // A tree that declares an adapter is executable: listing the kind exempts nothing. The
    // unpinned workload stops the cycle, which proves canary admission was required.
    let mut executable = make_target(true, None);
    executable.config.canary_exempt_kinds = vec![ProposalKind::UnslopSanitization];
    executable.config.canary_workload_sha256 = None;
    let err = RsiEngine::run_cycle(&executable.config).await.unwrap_err();
    assert!(err.contains("must pin the canary workload"), "{}", err);
}
