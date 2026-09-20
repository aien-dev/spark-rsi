use p256::ecdsa::{SigningKey, VerifyingKey};
use spark_rsi::evaluator::layers::{
    CorrectnessLayer, LongitudinalReplayLayer, PerformanceLayer, ResourceEfficiencyLayer,
    SecurityLayer, StyleLayer,
};
use spark_rsi::evaluator::ObjectiveEvaluator;
use spark_rsi::isolation::{ArtifactManifest, BuildJail, GpuEvaluationJail, RootOfTrust};
use std::fs;

#[test]
fn test_adversarial_holdout_secrecy_enforced() {
    let tmp = tempfile::tempdir().unwrap();
    let art = tmp.path().join("artifacts");
    fs::create_dir_all(&art).unwrap();

    let jail = GpuEvaluationJail::new("spark-rsi-eval@sha256:123456", &art);
    let args = jail.build_docker_args(&["./bench_workload"]);

    // Candidate container arguments must NEVER mount holdout paths
    for arg in &args {
        assert!(
            !arg.contains("holdout"),
            "CRITICAL SECURITY VIOLATION: Candidate jail exposed holdouts: {}",
            arg
        );
    }
}

#[test]
fn test_adversarial_network_isolation_enforced() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let out = tmp.path().join("out");
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&out).unwrap();

    let build_jail = BuildJail::new("builder-image", &src, &out);
    let build_args = build_jail.build_docker_args(&["cargo", "build"]);
    assert!(build_args.contains(&"--network".to_string()));
    assert!(build_args.contains(&"none".to_string()));

    let gpu_jail = GpuEvaluationJail::new("eval-image", &out);
    let gpu_args = gpu_jail.build_docker_args(&["./bench"]);
    assert!(gpu_args.contains(&"--network".to_string()));
    assert!(gpu_args.contains(&"none".to_string()));

    // Verify SecurityLayer catches network primitives
    let files = vec!["src/observe.rs".to_string()];
    let rogue_diff = "+ let stream = std::net::TcpStream::connect(\"198.51.100.1:443\");";
    let eval = SecurityLayer::evaluate_candidate(&files, rogue_diff, 0);

    assert!(!eval.passed);
    assert!(!eval.network_isolation_compliant);
    assert!(eval
        .violations
        .iter()
        .any(|v| v.contains("Unauthorized network primitive")));
}

#[test]
fn test_adversarial_root_of_trust_tampering_rejected() {
    // Attempting to modify protected files at tier 0 or tier 1 must fail
    assert!(RootOfTrust::assert_patch_permitted("Cargo.toml", 0).is_err());
    assert!(RootOfTrust::assert_patch_permitted("src/isolation/container.rs", 1).is_err());
    assert!(RootOfTrust::assert_patch_permitted("src/evaluator/mod.rs", 0).is_err());
    assert!(RootOfTrust::assert_patch_permitted(".rsi/ledger.db", 1).is_err());
    assert!(RootOfTrust::assert_patch_permitted("CONSTITUTION.md", 0).is_err());

    let files = vec!["Cargo.toml".to_string(), "src/observe.rs".to_string()];
    let diff = "+ p256 = \"0.13\"";
    let eval = SecurityLayer::evaluate_candidate(&files, diff, 0);

    assert!(!eval.passed);
    assert!(!eval.root_of_trust_compliant);
    assert!(eval
        .violations
        .iter()
        .any(|v| v.contains("protected root-of-trust file")));
}

#[test]
fn test_adversarial_manifest_rejects_unmanifested_extra_files() {
    let tmp = tempfile::tempdir().unwrap();
    let out_dir = tmp.path().join("output");
    fs::create_dir_all(&out_dir).unwrap();

    let bin_path = out_dir.join("legitimate_service");
    fs::write(&bin_path, "legitimate compiled binary payload").unwrap();

    let manifest = ArtifactManifest::generate_from_output_dir(
        "cand-sec-01",
        "builder@sha256:abc",
        "src@sha256:def",
        &out_dir,
    )
    .expect("Manifest generation failed");

    // Clean verification must pass
    assert!(manifest.verify_integrity(&out_dir).unwrap());

    // Adversarial injection of rogue unmanifested artifact
    let rogue_script = out_dir.join("exfiltrate.sh");
    fs::write(&rogue_script, "#!/bin/sh\necho compromised").unwrap();

    // Verification must detect the extra file and reject
    let is_valid = manifest.verify_integrity(&out_dir).unwrap();
    assert!(
        !is_valid,
        "ArtifactManifest failed to reject unmanifested extra file on disk"
    );
}

#[test]
fn test_adversarial_forged_receipt_signature_rejected() {
    let correctness = CorrectnessLayer::evaluate_synthetic(true, 10, 0, 2, 0, true);
    let security = SecurityLayer::evaluate_candidate(&["src/observe.rs".to_string()], "+ ok", 0);
    let style = StyleLayer::evaluate_text("Clean text without violations.");
    let perf = PerformanceLayer::evaluate_latencies(
        &(0..30).map(|i| 100.0 + i as f64 * 0.5).collect::<Vec<_>>(),
        &(0..30).map(|i| 80.0 + i as f64 * 0.4).collect::<Vec<_>>(),
        true,
        2000,
        Some(42),
    )
    .unwrap();
    let res_eff = ResourceEfficiencyLayer::evaluate(
        &spark_rsi::evaluator::metrics::RusageMetrics {
            user_time_us: 10_000,
            system_time_us: 5000,
            max_rss_kb: 50_000,
            voluntary_context_switches: 100,
            involuntary_context_switches: 20,
        },
        &spark_rsi::evaluator::metrics::RusageMetrics {
            user_time_us: 8000,
            system_time_us: 4000,
            max_rss_kb: 50_200,
            voluntary_context_switches: 80,
            involuntary_context_switches: 15,
        },
        None,
        Some(49_152),
    );
    let long_rep = LongitudinalReplayLayer::evaluate_results(
        &LongitudinalReplayLayer::builtin_regression_corpus(),
    );

    let mut receipt = ObjectiveEvaluator::evaluate_candidate(
        "cycle-sec-99",
        "cand-sec-99",
        "parent-sec-00",
        correctness,
        security,
        style,
        perf,
        res_eff,
        long_rep,
    );

    let signing_key_authorized = SigningKey::from_bytes(&[101u8; 32].into()).unwrap();
    let verifying_key_authorized = VerifyingKey::from(&signing_key_authorized);

    let signing_key_attacker = SigningKey::from_bytes(&[202u8; 32].into()).unwrap();
    let verifying_key_attacker = VerifyingKey::from(&signing_key_attacker);

    // Legitimate signature verification passes
    receipt.sign(&signing_key_authorized);
    assert!(receipt.verify_signature(&verifying_key_authorized));

    // Attack 1: Verify against attacker public key fails
    assert!(!receipt.verify_signature(&verifying_key_attacker));

    // Attack 2: Tamper with candidate ID or fields
    let mut tampered_receipt = receipt.clone();
    tampered_receipt.candidate_id = "cand-attacker-substituted".to_string();
    assert!(!tampered_receipt.verify_signature(&verifying_key_authorized));

    // Attack 3: Forged arbitrary signature string
    let mut forged_receipt = receipt.clone();
    forged_receipt.signature = Some("tpm2-p256:00112233445566778899aabbccddeeff".to_string());
    assert!(!forged_receipt.verify_signature(&verifying_key_authorized));

    // Attack 4: Attacker signs tampered receipt with attacker key, evaluated against authorized key
    let mut re_signed_receipt = receipt.clone();
    re_signed_receipt.admitted = true;
    re_signed_receipt.sign(&signing_key_attacker);
    assert!(!re_signed_receipt.verify_signature(&verifying_key_authorized));
}
