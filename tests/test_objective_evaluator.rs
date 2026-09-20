use spark_rsi::actor::{BlindJudge, HoldoutSuite};
use spark_rsi::evaluator::layers::{
    CorrectnessLayer, DefectTestResult, LongitudinalReplayLayer, PerformanceLayer,
    ResourceEfficiencyLayer, SecurityLayer, StyleLayer,
};
use spark_rsi::evaluator::metrics::{
    LatencyDistribution, LatencyTimer, ProcessMetricsSnapshot, RusageMetrics, StatmMetrics,
};
use spark_rsi::evaluator::stats::StatisticalEngine;
use spark_rsi::evaluator::{EvaluationReceipt, ObjectiveEvaluator};
use std::fs;

#[test]
fn test_rusage_and_statm_accounting() {
    let rusage = RusageMetrics::capture_self().expect("Failed to capture self rusage");
    assert!(rusage.max_rss_kb > 0);

    let statm = StatmMetrics::read_self().expect("Failed to read self statm");
    assert!(statm.resident_pages > 0);
    assert!(statm.resident_kb > 0);

    let snapshot = ProcessMetricsSnapshot::capture_current().expect("Failed to capture snapshot");
    assert!(snapshot.rusage.max_rss_kb > 0);
    assert!(snapshot.statm.is_some());
}

#[test]
fn test_latency_timer_and_distribution() {
    let timer = LatencyTimer::start();
    std::thread::sleep(std::time::Duration::from_millis(5));
    let elapsed = timer.elapsed_us();
    assert!(elapsed >= 4000.0);

    let samples: Vec<f64> = (1..=100).map(|i| (i as f64) * 10.0).collect();
    let dist = LatencyDistribution::from_samples(&samples, 100_000).expect("Failed distribution");
    assert_eq!(dist.count, 100);
    assert!((dist.p50_us - 505.0).abs() < 1e-4);
    assert!(dist.p95_us > 900.0);
    assert!(dist.p99_us > 950.0);
}

#[test]
fn test_paired_bootstrap_and_tail_non_inferiority_matrix() {
    // 30 iterations paired workload
    let mut parent = Vec::with_capacity(30);
    let mut candidate = Vec::with_capacity(30);
    for i in 0..30 {
        let base = 50.0 + (i as f64) * 1.2;
        parent.push(base);
        candidate.push(base * 0.85); // 15% improvement
    }

    let boot =
        StatisticalEngine::bootstrap_paired_comparison(&parent, &candidate, 10_000, Some(42))
            .expect("Bootstrap failed");
    assert!(boot.is_statistically_significant);
    assert!(boot.p_value < 0.01);
    assert!(boot.delta_pct < -10.0);

    // Tail percentile non-inferiority
    let tail_res = StatisticalEngine::evaluate_tail_non_inferiority(
        &parent,
        &candidate,
        95.0,
        1.0,
        10_000,
        Some(42),
    )
    .expect("Tail non-inferiority failed");
    assert!(tail_res.passes_non_inferiority);
    assert!(tail_res.ci_95_upper_pct <= 1.0);
}

#[test]
fn test_fishers_exact_contingency_matrix() {
    // Known 2x2 contingency table
    let res =
        StatisticalEngine::fishers_exact_test(2, 18, 15, 5).expect("Fisher exact test failed");
    assert!(res.p_value_two_sided < 0.01);
    assert!(res.is_significant);
    assert!(res.candidate_rate > res.parent_rate);
}

#[test]
fn test_six_layer_evaluator_end_to_end() {
    let correctness = CorrectnessLayer::evaluate_synthetic(true, 50, 0, 12, 0, true);
    assert!(correctness.passed);

    let security = SecurityLayer::evaluate_candidate(
        &["src/observe.rs".to_string()],
        "+ let cache_size = 1024;",
        0,
    );
    assert!(security.passed);

    let style = StyleLayer::evaluate_text(
        "Direct systems programming in Rust and Mojo. Zero unslop violations.",
    );
    assert!(style.passed);

    let parent_lat: Vec<f64> = (0..30).map(|i| 100.0 + (i as f64) * 0.5).collect();
    let cand_lat: Vec<f64> = (0..30).map(|i| 82.0 + (i as f64) * 0.4).collect();
    let performance =
        PerformanceLayer::evaluate_latencies(&parent_lat, &cand_lat, true, 5000, Some(42))
            .expect("Performance eval failed");
    assert!(performance.passed);

    let p_ru = RusageMetrics {
        user_time_us: 5000,
        system_time_us: 2000,
        max_rss_kb: 40_000,
        voluntary_context_switches: 50,
        involuntary_context_switches: 10,
    };
    let c_ru = RusageMetrics {
        user_time_us: 4200,
        system_time_us: 1800,
        max_rss_kb: 40_300, // 0.75% growth
        voluntary_context_switches: 45,
        involuntary_context_switches: 8,
    };
    let resource_eff = ResourceEfficiencyLayer::evaluate(&p_ru, &c_ru, None, Some(49_152));
    assert!(resource_eff.passed);

    let longitudinal = LongitudinalReplayLayer::evaluate_results(&[
        DefectTestResult {
            defect_id: "ROT-01".to_string(),
            title: "Root of trust".to_string(),
            passed: true,
            details: None,
        },
        DefectTestResult {
            defect_id: "SEC-01".to_string(),
            title: "Zero secrets".to_string(),
            passed: true,
            details: None,
        },
    ]);
    assert!(longitudinal.passed);

    let receipt = ObjectiveEvaluator::evaluate_candidate(
        "cycle-integration-01",
        "cand-integration-01",
        "parent-integration-00",
        correctness,
        security,
        style,
        performance,
        resource_eff,
        longitudinal,
    );

    assert!(receipt.admitted);
    assert!(receipt.passed_all_hard_invariants);
    assert!(receipt.passed_statistical_gates);
    assert!(receipt.verify_digest());
    assert_eq!(receipt.layer_results.len(), 6);
}

#[test]
fn test_blind_judge_receipt_roundtrip_and_persistence() {
    let tmp = tempfile::tempdir().unwrap();
    let holdouts = tmp.path().join("holdouts");
    let outputs = tmp.path().join("eval_outputs");
    let candidate = tmp.path().join("cand");
    fs::create_dir_all(&candidate).unwrap();
    let parent = tmp.path().join("parent");
    fs::create_dir_all(&parent).unwrap();

    let exe = spark_rsi::actor::judge::find_executable(std::path::Path::new("."))
        .expect("spark-rsi executable must exist");
    fs::copy(&exe, candidate.join("spark-rsi")).unwrap();
    fs::copy(&exe, parent.join("spark-rsi")).unwrap();

    let suites = HoldoutSuite::builtin_suites();
    for suite in suites {
        suite.save_to_dir(&holdouts).unwrap();
    }

    let signing_key = p256::ecdsa::SigningKey::from_bytes(&[88u8; 32].into()).unwrap();
    let verifying_key = p256::ecdsa::VerifyingKey::from(&signing_key);
    let judge = BlindJudge::new(holdouts, outputs.clone())
        .with_signing_key(signing_key)
        .with_non_inferiority_margin(1000.0);
    let receipt = judge
        .evaluate_cycle(
            "cycle-persisted-99",
            "cand-99",
            "parent-98",
            &candidate,
            &parent,
        )
        .expect("BlindJudge failed");

    assert!(receipt.admitted);
    assert!(receipt.verify_digest());
    assert!(receipt.signature.is_some());
    assert!(receipt.verify_signature(&verifying_key));

    let target_file = outputs.join("cycle-persisted-99.json");
    assert!(target_file.exists());

    let loaded = EvaluationReceipt::load_from_file(&target_file).expect("Failed to load receipt");
    assert_eq!(loaded.cycle_id, "cycle-persisted-99");
    assert!(loaded.verify_digest());
    assert_eq!(loaded.layer_results.len(), 6);
}
