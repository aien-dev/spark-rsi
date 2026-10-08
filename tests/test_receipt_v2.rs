//! Version 2 evaluation receipts (docs/RECEIPT-V2.md): the signed score binds the exact change,
//! holdout set, policy and evaluator, and promotion refuses anything else.

use p256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};
use spark_rsi::actor::judge::{
    strict_changed_paths, BlindJudge, EvaluationPolicy, HoldoutSuite, V2Request,
};
use spark_rsi::evaluator::layers::LayerResult;
use spark_rsi::evaluator::{EvaluationMetricsSummary, EvaluationReceipt, ReceiptBindingV2};
use spark_rsi::promotion_gate::{check_v2_promotion, PromotionSubject};
use std::fs;
use std::path::Path;

const README: &[u8] = b"A plain readme for the candidate.\n";

fn key(seed: u8) -> SigningKey {
    SigningKey::from_slice(&[seed; 32]).unwrap()
}

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn layer(name: &str, passed: bool, score: f64) -> LayerResult {
    LayerResult {
        layer_name: name.to_string(),
        is_hard_invariant: true,
        passed,
        score,
        summary: format!("{} summary", name),
        violations: Vec::new(),
    }
}

fn base_receipt() -> EvaluationReceipt {
    EvaluationReceipt {
        cycle_id: "cycle-v2".to_string(),
        candidate_id: "cand-v2".to_string(),
        parent_id: "parent-v2".to_string(),
        evaluated_at: "2026-10-08T22:00:00Z".to_string(),
        evaluator_version: "1.0.0".to_string(),
        passed_all_hard_invariants: true,
        passed_statistical_gates: true,
        admitted: true,
        layer_results: vec![
            layer("correctness", true, 1.0),
            layer("security", true, 1.0),
        ],
        metrics_summary: Some(EvaluationMetricsSummary {
            latency_delta_pct: -1.0,
            p_value: 0.01,
            p95_ci_upper_degradation_pct: 0.5,
            p99_ci_upper_degradation_pct: 0.7,
            rss_growth_pct: 0.1,
            candidate_resident_mb: 12,
        }),
        receipt_digest: String::new(),
        signature: None,
        format_version: 1,
        binding: None,
    }
}

fn binding(holdout_set_sha256: &str, policy_sha256: &str) -> ReceiptBindingV2 {
    ReceiptBindingV2 {
        subject_path: "README.md".to_string(),
        subject_sha256: sha(README),
        holdout_set_sha256: holdout_set_sha256.to_string(),
        holdouts_total: 4,
        holdouts_passed: 4,
        policy_sha256: policy_sha256.to_string(),
        evaluator_binary_sha256: sha(b"judge-binary"),
    }
}

fn v2_receipt(judge: &SigningKey, holdout: &str, policy: &str) -> EvaluationReceipt {
    let mut r = base_receipt();
    r.bind_and_sign_v2(binding(holdout, policy), judge).unwrap();
    r
}

fn policy_json(holdout_set_sha256: &str) -> String {
    serde_json::json!({
        "policy_id": "vac-m5-test",
        "holdout_set_sha256": holdout_set_sha256,
        "min_holdout_pass_ratio": 1.0,
        "require_admitted": true,
        "allowed_targets": ["README.md"],
        "protected_paths": ["holdouts", "policy", ".rsi"],
    })
    .to_string()
}

fn write_policy(dir: &Path, holdout_set_sha256: &str) -> (String, String) {
    let path = dir.join("policy.json");
    let text = policy_json(holdout_set_sha256);
    fs::write(&path, &text).unwrap();
    (path.to_string_lossy().to_string(), sha(text.as_bytes()))
}

fn pub_hex(k: &SigningKey) -> String {
    hex::encode(k.verifying_key().to_sec1_point(false).as_bytes())
}

// ---------------------------------------------------------------- receipt format

#[test]
fn v2_round_trip_verifies_for_promotion() {
    let judge = key(7);
    let h = sha(b"holdouts");
    let p = sha(b"policy");
    let r = v2_receipt(&judge, &h, &p);
    assert_eq!(r.format_version, 2);
    assert!(r.verify_signature(judge.verifying_key()));
    r.verify_for_promotion(judge.verifying_key(), &sha(README), &p, &h)
        .unwrap();
    // Survives a JSON round trip unchanged.
    let back: EvaluationReceipt =
        serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
    assert_eq!(back, r);
    back.verify_for_promotion(judge.verifying_key(), &sha(README), &p, &h)
        .unwrap();
}

#[test]
fn v1_receipts_still_verify_but_never_promote() {
    let judge = key(7);
    let mut r = base_receipt();
    r.receipt_digest = EvaluationReceipt::compute_digest(
        &r.cycle_id,
        &r.candidate_id,
        &r.parent_id,
        r.admitted,
        &r.layer_results,
    );
    r.sign(&judge);
    assert!(
        r.verify_signature(judge.verifying_key()),
        "history stays verifiable"
    );
    let err = r
        .verify_for_promotion(judge.verifying_key(), &sha(README), "p", "h")
        .unwrap_err();
    assert!(err.contains("not sufficient"), "{}", err);
}

#[test]
fn old_records_without_new_fields_load_as_version_1() {
    let judge = key(7);
    let mut r = base_receipt();
    r.receipt_digest = EvaluationReceipt::compute_digest(
        &r.cycle_id,
        &r.candidate_id,
        &r.parent_id,
        r.admitted,
        &r.layer_results,
    );
    r.sign(&judge);
    let mut v = serde_json::to_value(&r).unwrap();
    v.as_object_mut().unwrap().remove("format_version");
    v.as_object_mut().unwrap().remove("binding");
    let old: EvaluationReceipt = serde_json::from_value(v).unwrap();
    assert_eq!(old.format_version, 1);
    assert!(old.binding.is_none());
    assert!(old.verify_signature(judge.verifying_key()));
}

#[test]
fn format_and_binding_must_agree() {
    let judge = key(7);
    // A version 2 receipt relabelled as version 1 keeps its binding: refused.
    let mut r = v2_receipt(&judge, "h", "p");
    r.format_version = 1;
    assert!(!r.verify_signature(judge.verifying_key()));
    // A version 2 receipt with the binding stripped: refused.
    let mut r = v2_receipt(&judge, "h", "p");
    r.binding = None;
    assert!(!r.verify_signature(judge.verifying_key()));
    // Unknown versions: refused.
    let mut r = v2_receipt(&judge, "h", "p");
    r.format_version = 3;
    assert!(!r.verify_signature(judge.verifying_key()));
}

#[test]
fn substituted_change_is_refused() {
    let judge = key(7);
    let r = v2_receipt(&judge, "h", "p");
    let other = sha(b"A different change.\n");
    let err = r
        .verify_for_promotion(judge.verifying_key(), &other, "p", "h")
        .unwrap_err();
    assert!(err.contains("not the change being promoted"), "{}", err);
    // Rewriting the bound subject digest to match breaks the signature.
    let mut forged = r.clone();
    forged.binding.as_mut().unwrap().subject_sha256 = other.clone();
    assert!(forged
        .verify_for_promotion(judge.verifying_key(), &other, "p", "h")
        .is_err());
}

#[test]
fn substituted_scores_are_refused() {
    let judge = key(7);
    let base = v2_receipt(&judge, "h", "p");
    let mutations: Vec<(&str, Box<dyn Fn(&mut EvaluationReceipt)>)> = vec![
        ("layer score", Box::new(|r| r.layer_results[0].score = 0.5)),
        (
            "layer passed",
            Box::new(|r| r.layer_results[1].passed = false),
        ),
        (
            "hard flag",
            Box::new(|r| r.layer_results[0].is_hard_invariant = false),
        ),
        (
            "violations",
            Box::new(|r| r.layer_results[0].violations.push("x".into())),
        ),
        (
            "summary",
            Box::new(|r| r.layer_results[0].summary.push('!')),
        ),
        (
            "layer dropped",
            Box::new(|r| {
                r.layer_results.pop();
            }),
        ),
        ("admitted", Box::new(|r| r.admitted = !r.admitted)),
        (
            "statistical gates",
            Box::new(|r| r.passed_statistical_gates = false),
        ),
        (
            "hard invariants",
            Box::new(|r| r.passed_all_hard_invariants = false),
        ),
        (
            "holdouts passed",
            Box::new(|r| r.binding.as_mut().unwrap().holdouts_passed = 3),
        ),
        (
            "holdouts total",
            Box::new(|r| r.binding.as_mut().unwrap().holdouts_total = 5),
        ),
        (
            "metrics",
            Box::new(|r| r.metrics_summary.as_mut().unwrap().p_value = 0.5),
        ),
        ("metrics removed", Box::new(|r| r.metrics_summary = None)),
        ("evaluated at", Box::new(|r| r.evaluated_at.push('Z'))),
        (
            "evaluator version",
            Box::new(|r| r.evaluator_version = "9".into()),
        ),
        (
            "evaluator binary",
            Box::new(|r| r.binding.as_mut().unwrap().evaluator_binary_sha256 = sha(b"other")),
        ),
        (
            "subject path",
            Box::new(|r| r.binding.as_mut().unwrap().subject_path = "src/lib.rs".into()),
        ),
        (
            "candidate id",
            Box::new(|r| r.candidate_id = "cand-other".into()),
        ),
    ];
    for (what, m) in mutations {
        let mut r = base.clone();
        m(&mut r);
        assert!(
            !r.verify_signature(judge.verifying_key()),
            "changing {} must break the signature",
            what
        );
        // Recomputing the digest does not help without the judge key.
        r.receipt_digest = r.compute_digest_v2().unwrap();
        assert!(
            !r.verify_signature(judge.verifying_key()),
            "changing {} and re-digesting must still fail",
            what
        );
    }
}

#[test]
fn wrong_signing_key_is_refused() {
    let judge = key(7);
    let proposer = key(9);
    // Signed by the proposer instead of the judge.
    let r = v2_receipt(&proposer, "h", "p");
    let err = r
        .verify_for_promotion(judge.verifying_key(), &sha(README), "p", "h")
        .unwrap_err();
    assert!(err.contains("signature"), "{}", err);
}

#[test]
fn altered_policy_or_holdouts_are_refused() {
    let judge = key(7);
    let r = v2_receipt(&judge, "h", "p");
    assert!(r
        .verify_for_promotion(judge.verifying_key(), &sha(README), "p-altered", "h")
        .unwrap_err()
        .contains("policy"));
    assert!(r
        .verify_for_promotion(judge.verifying_key(), &sha(README), "p", "h-altered")
        .unwrap_err()
        .contains("holdout"));
}

#[test]
fn not_admitted_is_refused() {
    let judge = key(7);
    let mut r = base_receipt();
    r.admitted = false;
    r.bind_and_sign_v2(binding("h", "p"), &judge).unwrap();
    assert!(r
        .verify_for_promotion(judge.verifying_key(), &sha(README), "p", "h")
        .unwrap_err()
        .contains("did not admit"));
}

// ---------------------------------------------------------------- promotion gate

#[test]
fn promotion_gate_accepts_bound_receipt_and_refuses_everything_else() {
    let tmp = tempfile::tempdir().unwrap();
    let judge = key(7);
    let daemon = key(9);
    let holdout = sha(b"holdouts");
    let (policy_path, policy_sha) = write_policy(tmp.path(), &holdout);
    let r = v2_receipt(&judge, &holdout, &policy_sha);
    let jk = pub_hex(&judge);
    let subject_sha = sha(README);
    let subject = PromotionSubject::same("README.md", &subject_sha);

    check_v2_promotion(
        &r,
        Some(&jk),
        daemon.verifying_key(),
        Some(&policy_path),
        &subject,
    )
    .unwrap();

    // Missing judge key, missing policy: fail closed.
    assert!(check_v2_promotion(
        &r,
        None,
        daemon.verifying_key(),
        Some(&policy_path),
        &subject
    )
    .unwrap_err()
    .contains("fails closed"));
    assert!(
        check_v2_promotion(&r, Some(&jk), daemon.verifying_key(), None, &subject)
            .unwrap_err()
            .contains("fails closed")
    );
    // The judge key must not be the promoter's own key.
    assert!(check_v2_promotion(
        &r,
        Some(&jk),
        judge.verifying_key(),
        Some(&policy_path),
        &subject
    )
    .unwrap_err()
    .contains("separate"));
    // Pinned key is someone else's: signature refused.
    let wrong = pub_hex(&key(11));
    assert!(check_v2_promotion(
        &r,
        Some(&wrong),
        daemon.verifying_key(),
        Some(&policy_path),
        &subject
    )
    .is_err());
    // Substituted change.
    assert!(check_v2_promotion(
        &r,
        Some(&jk),
        daemon.verifying_key(),
        Some(&policy_path),
        &PromotionSubject::same("README.md", &sha(b"other bytes"))
    )
    .is_err());
    // The receipt covers README.md; the change replaces another file with the same bytes.
    assert!(check_v2_promotion(
        &r,
        Some(&jk),
        daemon.verifying_key(),
        Some(&policy_path),
        &PromotionSubject::same("src/lib.rs", &subject_sha)
    )
    .unwrap_err()
    .contains("covers README.md"));
    // The staged bytes on disk differ from the change's bytes.
    let other = sha(b"staged bytes");
    assert!(check_v2_promotion(
        &r,
        Some(&jk),
        daemon.verifying_key(),
        Some(&policy_path),
        &PromotionSubject {
            path: "README.md",
            content_sha256: &subject_sha,
            disk_sha256: &other,
        }
    )
    .unwrap_err()
    .contains("staged README.md"));
    // The operator's policy file changes after the evaluation: refused.
    fs::write(
        &policy_path,
        policy_json(&holdout).replace("vac-m5-test", "vac-m5-edited"),
    )
    .unwrap();
    assert!(check_v2_promotion(
        &r,
        Some(&jk),
        daemon.verifying_key(),
        Some(&policy_path),
        &subject
    )
    .unwrap_err()
    .contains("policy"));
}

#[test]
fn promotion_gate_refuses_below_threshold_and_v1() {
    let tmp = tempfile::tempdir().unwrap();
    let judge = key(7);
    let daemon = key(9);
    let holdout = sha(b"holdouts");
    let (policy_path, policy_sha) = write_policy(tmp.path(), &holdout);
    let mut r = base_receipt();
    let mut b = binding(&holdout, &policy_sha);
    b.holdouts_passed = 3;
    r.bind_and_sign_v2(b, &judge).unwrap();
    let jk = pub_hex(&judge);
    assert!(check_v2_promotion(
        &r,
        Some(&jk),
        daemon.verifying_key(),
        Some(&policy_path),
        &PromotionSubject::same("README.md", &sha(README))
    )
    .unwrap_err()
    .contains("threshold"));

    let mut v1 = base_receipt();
    v1.receipt_digest = EvaluationReceipt::compute_digest(
        &v1.cycle_id,
        &v1.candidate_id,
        &v1.parent_id,
        v1.admitted,
        &v1.layer_results,
    );
    v1.sign(&judge);
    assert!(check_v2_promotion(
        &v1,
        Some(&jk),
        daemon.verifying_key(),
        Some(&policy_path),
        &PromotionSubject::same("README.md", &sha(README))
    )
    .unwrap_err()
    .contains("not sufficient"));
}

#[test]
fn policy_that_waives_admission_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("p.json");
    fs::write(
        &path,
        policy_json(&sha(b"h")).replace("\"require_admitted\":true", "\"require_admitted\":false"),
    )
    .unwrap();
    assert!(EvaluationPolicy::load(&path)
        .unwrap_err()
        .contains("require_admitted"));
    fs::write(&path, policy_json(&sha(b"h")).replace("1.0", "0.0")).unwrap();
    assert!(EvaluationPolicy::load(&path).is_err());
    fs::write(&path, r#"{"policy_id":"x"}"#).unwrap();
    assert!(EvaluationPolicy::load(&path).is_err());
}

// ---------------------------------------------------------------- holdout set

fn holdout_dir(tmp: &Path) -> std::path::PathBuf {
    let dir = tmp.join("holdouts");
    for s in HoldoutSuite::builtin_suites() {
        s.save_to_dir(&dir).unwrap();
    }
    dir
}

#[test]
fn holdout_set_digest_is_stable_and_content_bound() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = holdout_dir(tmp.path());
    let (suites, d1) = HoldoutSuite::load_strict(&dir).unwrap();
    assert_eq!(suites.len(), 2);
    let (_, d2) = HoldoutSuite::load_strict(&dir).unwrap();
    assert_eq!(d1, d2);
    // Editing one expected answer changes the digest.
    let f = dir.join("HOLD-INV-001.json");
    let text = fs::read_to_string(&f)
        .unwrap()
        .replace("EMPTY_OK", "EMPTY_OK2");
    fs::write(&f, text).unwrap();
    let (_, d3) = HoldoutSuite::load_strict(&dir).unwrap();
    assert_ne!(d1, d3);
}

#[test]
fn incomplete_or_corrupted_holdouts_are_rejected() {
    type Breaker = Box<dyn Fn(&Path)>;
    let breakers: Vec<(&str, Breaker)> = vec![
        (
            "corrupted file",
            Box::new(|d| fs::write(d.join("HOLD-INV-001.json"), "{not json").unwrap()),
        ),
        (
            "truncated file",
            Box::new(|d| {
                let f = d.join("HOLD-INV-001.json");
                let t = fs::read_to_string(&f).unwrap();
                fs::write(&f, &t[..t.len() / 2]).unwrap();
            }),
        ),
        (
            "empty suite",
            Box::new(|d| {
                fs::write(
                    d.join("EMPTY.json"),
                    r#"{"suite_id":"E","name":"E","cases":[]}"#,
                )
                .unwrap()
            }),
        ),
        (
            "missing expected output",
            Box::new(|d| {
                fs::write(
                d.join("BAD.json"),
                r#"{"suite_id":"B","name":"B","cases":[{"id":"B-1","name":"b","input":"x","expected_output":"","category":"c"}]}"#,
            )
            .unwrap()
            }),
        ),
        (
            "duplicate case id",
            Box::new(|d| {
                fs::copy(
                    d.join("HOLD-INV-001.json"),
                    d.join("HOLD-INV-001-copy.json"),
                )
                .unwrap();
            }),
        ),
        (
            "stray non-json file",
            Box::new(|d| fs::write(d.join("notes.txt"), "x").unwrap()),
        ),
        (
            "subdirectory",
            Box::new(|d| fs::create_dir(d.join("more")).unwrap()),
        ),
        (
            "symlink",
            Box::new(|d| {
                std::os::unix::fs::symlink(d.join("HOLD-INV-001.json"), d.join("link.json"))
                    .unwrap()
            }),
        ),
        (
            "all files removed",
            Box::new(|d| {
                for e in fs::read_dir(d).unwrap() {
                    fs::remove_file(e.unwrap().path()).unwrap();
                }
            }),
        ),
        (
            "directory missing",
            Box::new(|d| fs::remove_dir_all(d).unwrap()),
        ),
    ];
    for (what, brk) in breakers {
        let tmp = tempfile::tempdir().unwrap();
        let dir = holdout_dir(tmp.path());
        brk(&dir);
        assert!(
            HoldoutSuite::load_strict(&dir).is_err(),
            "{} must fail closed",
            what
        );
        assert!(
            HoldoutSuite::load_from_dir(&dir).is_err(),
            "{} (v1 loader)",
            what
        );
    }
}

// ---------------------------------------------------------------- judge, end to end

struct Trees {
    _tmp: tempfile::TempDir,
    root: std::path::PathBuf,
    parent: std::path::PathBuf,
    candidate: std::path::PathBuf,
    holdouts: std::path::PathBuf,
}

fn trees() -> Trees {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let exe = Path::new(env!("CARGO_BIN_EXE_spark-rsi"));
    let parent = root.join("parent");
    let candidate = root.join("candidate");
    for t in [&parent, &candidate] {
        fs::create_dir_all(t.join("bin")).unwrap();
        fs::copy(exe, t.join("bin/spark-rsi")).unwrap();
    }
    fs::write(parent.join("README.md"), b"The old readme.\n").unwrap();
    fs::write(candidate.join("README.md"), README).unwrap();
    let holdouts = holdout_dir(&root);
    Trees {
        _tmp: tmp,
        root,
        parent,
        candidate,
        holdouts,
    }
}

fn v2_judge(t: &Trees, policy_holdout_digest: &str, subject: &str) -> (BlindJudge, String, String) {
    let (policy_path, policy_sha) = write_policy(&t.root, policy_holdout_digest);
    let (policy, loaded_sha) = EvaluationPolicy::load(Path::new(&policy_path)).unwrap();
    assert_eq!(loaded_sha, policy_sha);
    let mut judge = BlindJudge::new(t.holdouts.clone(), t.root.join("out"))
        .with_signing_key(key(7))
        .with_non_inferiority_margin(1000.0)
        .with_executable("bin/spark-rsi".into(), false)
        .with_v2(V2Request {
            subject_path: subject.to_string(),
            policy,
            policy_sha256: policy_sha.clone(),
        });
    judge.require_build_verification = false;
    (judge, policy_path, policy_sha)
}

#[test]
fn judge_signs_v2_bound_to_subject_policy_and_holdouts() {
    let t = trees();
    fs::create_dir_all(t.root.join("out")).unwrap();
    let (_, holdout_digest) = HoldoutSuite::load_strict(&t.holdouts).unwrap();
    let (judge, policy_path, policy_sha) = v2_judge(&t, &holdout_digest, "README.md");
    let r = judge
        .evaluate_cycle("cyc-v2", "cand", "par", &t.candidate, &t.parent)
        .unwrap();
    let b = r.binding.clone().expect("v2 binding");
    assert_eq!(r.format_version, 2);
    assert_eq!(b.subject_path, "README.md");
    assert_eq!(b.subject_sha256, sha(README));
    assert_eq!(b.holdout_set_sha256, holdout_digest);
    assert_eq!(b.policy_sha256, policy_sha);
    assert_eq!(b.holdouts_total, 4);
    assert_eq!(b.holdouts_passed, 4);
    assert_eq!(b.evaluator_binary_sha256.len(), 64);
    assert!(
        r.admitted,
        "candidate should be admitted: {:?}",
        r.layer_results
    );
    check_v2_promotion(
        &r,
        Some(&pub_hex(&key(7))),
        key(9).verifying_key(),
        Some(&policy_path),
        &PromotionSubject::same("README.md", &sha(README)),
    )
    .unwrap();
}

#[test]
fn judge_refuses_holdout_set_that_differs_from_policy() {
    let t = trees();
    let (judge, _, _) = v2_judge(&t, &sha(b"some other holdout set"), "README.md");
    let err = judge
        .evaluate_cycle("c", "cand", "par", &t.candidate, &t.parent)
        .unwrap_err();
    assert!(err.contains("does not match the policy"), "{}", err);
}

#[test]
fn judge_refuses_subject_outside_policy_or_protected() {
    let t = trees();
    let (_, holdout_digest) = HoldoutSuite::load_strict(&t.holdouts).unwrap();
    for subject in [
        "src/lib.rs",
        "../README.md",
        "/etc/passwd",
        "holdouts/x.json",
    ] {
        let (judge, _, _) = v2_judge(&t, &holdout_digest, subject);
        assert!(
            judge
                .evaluate_cycle("c", "cand", "par", &t.candidate, &t.parent)
                .is_err(),
            "subject {} must be refused",
            subject
        );
    }
}

#[test]
fn judge_refuses_candidate_that_changes_more_than_the_subject() {
    let t = trees();
    let (_, holdout_digest) = HoldoutSuite::load_strict(&t.holdouts).unwrap();
    // A hidden build-config change rides along with the subject.
    fs::create_dir_all(t.candidate.join(".cargo")).unwrap();
    fs::write(t.candidate.join(".cargo/config.toml"), "[build]\n").unwrap();
    let (judge, _, _) = v2_judge(&t, &holdout_digest, "README.md");
    let err = judge
        .evaluate_cycle("c", "cand", "par", &t.candidate, &t.parent)
        .unwrap_err();
    assert!(err.contains("exactly the subject"), "{}", err);
}

#[test]
fn judge_refuses_incomplete_holdouts() {
    let t = trees();
    let (_, holdout_digest) = HoldoutSuite::load_strict(&t.holdouts).unwrap();
    fs::write(t.holdouts.join("HOLD-STY-002.json"), "{").unwrap();
    let (judge, _, _) = v2_judge(&t, &holdout_digest, "README.md");
    let err = judge
        .evaluate_cycle("c", "cand", "par", &t.candidate, &t.parent)
        .unwrap_err();
    assert!(err.contains("corrupt"), "{}", err);
}

#[test]
fn strict_diff_sees_dotfiles_and_skips_only_git_and_target() {
    let t = trees();
    assert_eq!(
        strict_changed_paths(&t.parent, &t.candidate).unwrap(),
        vec!["README.md".to_string()]
    );
    fs::create_dir_all(t.candidate.join("target/release")).unwrap();
    fs::write(t.candidate.join("target/release/x"), "x").unwrap();
    fs::create_dir_all(t.candidate.join(".git")).unwrap();
    fs::write(t.candidate.join(".git/HEAD"), "x").unwrap();
    assert_eq!(
        strict_changed_paths(&t.parent, &t.candidate).unwrap().len(),
        1
    );
    fs::write(t.candidate.join(".env"), "x").unwrap();
    assert_eq!(
        strict_changed_paths(&t.parent, &t.candidate).unwrap().len(),
        2
    );
}

#[test]
fn strict_diff_refuses_nested_git_entries() {
    let t = trees();
    fs::create_dir_all(t.candidate.join("src")).unwrap();
    fs::write(t.candidate.join("src/.git"), "gitdir: elsewhere").unwrap();
    let err = strict_changed_paths(&t.parent, &t.candidate).unwrap_err();
    assert!(err.contains("nested .git"), "{}", err);
}

#[test]
fn judge_refuses_an_executable_the_tree_comparison_cannot_cover() {
    let t = trees();
    let (_, holdout_digest) = HoldoutSuite::load_strict(&t.holdouts).unwrap();
    // A prebuilt program under the skipped target directory.
    for tree in [&t.parent, &t.candidate] {
        fs::create_dir_all(tree.join("target/release")).unwrap();
        fs::copy(
            tree.join("bin/spark-rsi"),
            tree.join("target/release/spark-rsi"),
        )
        .unwrap();
    }
    let (judge, _, _) = v2_judge(&t, &holdout_digest, "README.md");
    let judge = judge.with_executable("target/release/spark-rsi".into(), false);
    let err = judge
        .evaluate_cycle("c", "cand", "par", &t.candidate, &t.parent)
        .unwrap_err();
    assert!(err.contains("tree comparison covers"), "{}", err);
    // No named executable: the judge never searches the trees for one.
    let (mut judge, _, _) = v2_judge(&t, &holdout_digest, "README.md");
    judge.executable = None;
    let err = judge
        .evaluate_cycle("c", "cand", "par", &t.candidate, &t.parent)
        .unwrap_err();
    assert!(err.contains("names its executable"), "{}", err);
}

#[test]
fn policy_paths_must_be_clean() {
    let tmp = tempfile::tempdir().unwrap();
    let digest = sha(b"holdouts");
    for (field, value) in [
        ("protected_paths", serde_json::json!(["./src"])),
        ("protected_paths", serde_json::json!(["/"])),
        ("protected_paths", serde_json::json!([""])),
        ("allowed_targets", serde_json::json!(["../README.md"])),
        ("allowed_targets", serde_json::json!([])),
    ] {
        let mut p: serde_json::Value = serde_json::from_str(&policy_json(&digest)).unwrap();
        p[field] = value.clone();
        let path = tmp.path().join("p.json");
        fs::write(&path, p.to_string()).unwrap();
        assert!(
            EvaluationPolicy::load(&path).is_err(),
            "{} = {} must be refused",
            field,
            value
        );
    }
}

/// The judge builds candidate code inside a sandbox: a file outside the tree (standing in for the
/// judge's signing key) cannot be read at build time, so `include_str!` of it fails the build.
#[test]
fn judge_build_cannot_read_files_outside_the_tree() {
    let probe = std::process::Command::new("bwrap")
        .args([
            "--unshare-user",
            "--unshare-net",
            "--ro-bind",
            "/",
            "/",
            "true",
        ])
        .status();
    if !probe.is_ok_and(|s| s.success()) {
        eprintln!("SKIP: bubblewrap cannot create a user namespace on this host");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let secret = tmp.path().join("judge.key");
    fs::write(&secret, "not-for-candidates").unwrap();
    let crate_toml =
        "[package]\nname = \"probe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[workspace]\n";
    let lock = "version = 4\n\n[[package]]\nname = \"probe\"\nversion = \"0.1.0\"\n";
    let parent = tmp.path().join("parent");
    let candidate = tmp.path().join("candidate");
    for (tree, main) in [
        (&parent, "fn main() {}\n".to_string()),
        (
            &candidate,
            format!(
                "const K: &str = include_str!({:?});\nfn main() {{ println!(\"{{}}\", K); }}\n",
                secret
            ),
        ),
    ] {
        fs::create_dir_all(tree.join("src")).unwrap();
        fs::write(tree.join("Cargo.toml"), crate_toml).unwrap();
        fs::write(tree.join("Cargo.lock"), lock).unwrap();
        fs::write(tree.join("src/main.rs"), main).unwrap();
    }
    // Outside the sandbox the candidate builds (the include works), so the refusal below is the
    // sandbox and not a broken fixture.
    let plain = std::process::Command::new("cargo")
        .args(["build", "--release", "--offline", "--locked", "-q"])
        .env("CARGO_TARGET_DIR", tmp.path().join("plain-target"))
        .current_dir(&candidate)
        .status()
        .unwrap();
    assert!(plain.success(), "control build outside the sandbox failed");

    let holdouts = holdout_dir(tmp.path());
    let mut judge = BlindJudge::new(holdouts, tmp.path().join("out"))
        .with_signing_key(key(7))
        .with_executable("probe".into(), true);
    judge.require_build_verification = false;
    let err = judge
        .evaluate_cycle("c", "cand", "par", &candidate, &parent)
        .unwrap_err();
    assert!(err.contains("candidate build failed"), "{}", err);
    assert!(err.contains("judge.key"), "{}", err);
}
