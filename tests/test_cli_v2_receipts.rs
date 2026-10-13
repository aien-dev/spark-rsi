//! The CLI path writes version 2 receipts (issue #35). Pre-registered rows:
//!
//! 1. `spark-rsi judge` with `--policy-file` and `--subject-path` prints a version 2 receipt bound
//!    to that subject, policy and holdout set, and the promotion gate accepts it.
//! 2. The policy may come from `RSI_JUDGE_POLICY_FILE` instead: configured once, version 2 is the
//!    default for every run.
//! 3. A malformed policy file is refused: non-zero exit, the error names the policy, and no
//!    receipt is printed. It is never ignored in favour of a version 1 receipt.
//! 4. A policy without a subject is refused rather than downgraded to version 1.
//! 5. `cycle` and `daemon` refuse a malformed judge policy or judge public key at startup,
//!    before any cycle runs.

use p256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};
use spark_rsi::actor::judge::HoldoutSuite;
use spark_rsi::evaluator::EvaluationReceipt;
use spark_rsi::promotion_gate::{check_v2_promotion, PromotionSubject};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const README: &[u8] = b"A plain readme for the candidate.\n";

fn key(seed: u8) -> SigningKey {
    SigningKey::from_slice(&[seed; 32]).unwrap()
}

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn pub_hex(k: &SigningKey) -> String {
    hex::encode(k.verifying_key().to_sec1_point(false).as_bytes())
}

fn bin() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_spark-rsi"))
}

struct Trees {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    parent: PathBuf,
    candidate: PathBuf,
    holdouts: PathBuf,
}

fn trees() -> Trees {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    let parent = root.join("parent");
    let candidate = root.join("candidate");
    for t in [&parent, &candidate] {
        fs::create_dir_all(t.join("bin")).unwrap();
        fs::copy(bin(), t.join("bin/spark-rsi")).unwrap();
    }
    fs::write(parent.join("README.md"), b"The old readme.\n").unwrap();
    fs::write(candidate.join("README.md"), README).unwrap();
    let holdouts = root.join("holdouts");
    for s in HoldoutSuite::builtin_suites() {
        s.save_to_dir(&holdouts).unwrap();
    }
    fs::create_dir_all(root.join("out")).unwrap();
    Trees {
        _tmp: tmp,
        root,
        parent,
        candidate,
        holdouts,
    }
}

/// Writes the operator policy pinning the trees' holdout set; returns its path and digest.
fn write_policy(t: &Trees) -> (PathBuf, String) {
    let (_, holdout_digest) = HoldoutSuite::load_strict(&t.holdouts).unwrap();
    let text = serde_json::json!({
        "policy_id": "cli-v2-test",
        "holdout_set_sha256": holdout_digest,
        "min_holdout_pass_ratio": 1.0,
        "require_admitted": true,
        "allowed_targets": ["README.md"],
        "protected_paths": ["holdouts", "policy", ".rsi"],
    })
    .to_string();
    let path = t.root.join("policy.json");
    fs::write(&path, &text).unwrap();
    (path, sha(text.as_bytes()))
}

/// `spark-rsi judge` over the trees with the judge key; `extra` adds the version 2 arguments.
fn judge_cmd(t: &Trees) -> Command {
    let mut cmd = Command::new(bin());
    cmd.env_remove("RSI_JUDGE_POLICY_FILE")
        .env_remove("RSI_JUDGE_SIGNING_KEY")
        .arg("judge")
        .args(["--cycle-id", "cyc-cli", "--candidate-id", "cand"])
        .args(["--parent-id", "par"])
        .arg("--candidate-path")
        .arg(&t.candidate)
        .arg("--parent-path")
        .arg(&t.parent)
        .arg("--holdouts-dir")
        .arg(&t.holdouts)
        .arg("--output-dir")
        .arg(t.root.join("out"))
        .args(["--signing-key-hex", &hex::encode([7u8; 32])])
        .args(["--non-inferiority-margin-pct", "1000"])
        .args(["--executable", "bin/spark-rsi"]);
    cmd
}

fn receipt_of(out: &Output) -> EvaluationReceipt {
    assert!(
        out.status.success(),
        "judge failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("stdout is one receipt")
}

fn assert_v2_for(r: &EvaluationReceipt, policy_path: &Path, policy_sha: &str) {
    assert_eq!(r.format_version, 2, "CLI must write a version 2 receipt");
    let b = r.binding.as_ref().expect("version 2 binding");
    assert_eq!(b.subject_path, "README.md");
    assert_eq!(b.subject_sha256, sha(README));
    assert_eq!(b.policy_sha256, policy_sha);
    assert!(
        r.admitted,
        "candidate should be admitted: {:?}",
        r.layer_results
    );
    check_v2_promotion(
        r,
        Some(&pub_hex(&key(7))),
        key(9).verifying_key(),
        Some(policy_path.to_str().unwrap()),
        &PromotionSubject::same("par", "README.md", &sha(README)),
    )
    .unwrap();
}

#[test]
fn cli_judge_with_policy_file_writes_a_v2_receipt() {
    let t = trees();
    let (policy, policy_sha) = write_policy(&t);
    let out = judge_cmd(&t)
        .arg("--policy-file")
        .arg(&policy)
        .args(["--subject-path", "README.md"])
        .output()
        .unwrap();
    assert_v2_for(&receipt_of(&out), &policy, &policy_sha);
}

#[test]
fn cli_judge_takes_the_policy_from_the_environment() {
    let t = trees();
    let (policy, policy_sha) = write_policy(&t);
    let out = judge_cmd(&t)
        .env("RSI_JUDGE_POLICY_FILE", &policy)
        .args(["--subject-path", "README.md"])
        .output()
        .unwrap();
    assert_v2_for(&receipt_of(&out), &policy, &policy_sha);
}

fn assert_refused(out: &Output, needle: &str) {
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "must be refused, stderr: {}", stderr);
    assert!(
        stderr.contains(needle),
        "stderr must name {:?}, got: {}",
        needle,
        stderr
    );
    assert!(
        serde_json::from_slice::<EvaluationReceipt>(&out.stdout).is_err(),
        "no receipt may be printed when the policy is refused"
    );
}

#[test]
fn cli_judge_refuses_a_malformed_policy_file() {
    let t = trees();
    let bad = t.root.join("bad-policy.json");
    fs::write(&bad, b"{ \"policy_id\": \"half").unwrap();
    let out = judge_cmd(&t)
        .arg("--policy-file")
        .arg(&bad)
        .args(["--subject-path", "README.md"])
        .output()
        .unwrap();
    assert_refused(&out, "policy");

    let out = judge_cmd(&t)
        .env("RSI_JUDGE_POLICY_FILE", &bad)
        .args(["--subject-path", "README.md"])
        .output()
        .unwrap();
    assert_refused(&out, "policy");
}

#[test]
fn cli_judge_refuses_a_policy_without_a_subject() {
    let t = trees();
    let (policy, _) = write_policy(&t);
    let out = judge_cmd(&t)
        .arg("--policy-file")
        .arg(&policy)
        .output()
        .unwrap();
    assert_refused(&out, "subject");
    let out = judge_cmd(&t)
        .env("RSI_JUDGE_POLICY_FILE", &policy)
        .output()
        .unwrap();
    assert_refused(&out, "subject");
}

#[test]
fn cycle_and_daemon_refuse_a_malformed_judge_policy_or_key_at_startup() {
    let t = trees();
    let bad = t.root.join("bad-policy.json");
    fs::write(&bad, b"not json").unwrap();
    let (good, _) = write_policy(&t);
    for sub in ["cycle", "daemon"] {
        let run = |args: &[&std::ffi::OsStr]| {
            Command::new(bin())
                .env_remove("RSI_JUDGE_POLICY_FILE")
                .env_remove("RSI_JUDGE_PUBLIC_KEY")
                .current_dir(&t.root)
                .arg(sub)
                .arg(&t.candidate)
                .args(args)
                .output()
                .unwrap()
        };
        let out = run(&["--judge-policy-file".as_ref(), bad.as_os_str()]);
        assert_refused(&out, "policy");
        let out = run(&[
            "--judge-policy-file".as_ref(),
            good.as_os_str(),
            "--judge-public-key".as_ref(),
            "zz-not-a-key".as_ref(),
        ]);
        assert_refused(&out, "judge public key");
        let out = Command::new(bin())
            .env("RSI_JUDGE_POLICY_FILE", &bad)
            .current_dir(&t.root)
            .arg(sub)
            .arg(&t.candidate)
            .output()
            .unwrap();
        assert_refused(&out, "policy");
    }
}
