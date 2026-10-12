//! M1 Measurement acceptance: stage samples from completed prior cycles drive the ranking.

use spark_rsi::explain::{evidence_graph, MetricsOrigin, RsiCycleEvidence};
use spark_rsi::graph::{Measurement, RankingBasis};
use spark_rsi::measure::profile::{normalize_remote, ExecutionConfig, ExecutionProfile};
use spark_rsi::measure::select::try_measure;
use spark_rsi::measure::{
    build_capability_graph, check_claim, measure_stages, median, p95_if_sufficient,
    percentile_nearest_rank, CycleSampleRecord, MeasureContext, SampleLog, Stage, StageClock,
    StageMeasurement, StageOutcome, StageSample, SCHEMA_VERSION,
};
use spark_rsi::models::{ProposalKind, RsiConfig};
use spark_rsi::propose::hypothesis::HypothesisContract;
use std::collections::BTreeMap;
use std::time::Duration;

fn profile(config: &RsiConfig) -> ExecutionProfile {
    ExecutionProfile {
        model: config.max_model.clone(),
        execution_config: ExecutionConfig::from_config(config),
        cpu_count: Some(20),
        memory_total_kib: Some(128 * 1024 * 1024),
        gpu: "NVIDIA GB10".to_string(),
    }
}

fn ctx(config: &RsiConfig) -> MeasureContext {
    MeasureContext::from_parts(
        "remote:example.org/repo",
        profile(config),
        Some("abc".into()),
    )
}

fn record(ctx: &MeasureContext, id: &str, durations: [u64; 6]) -> CycleSampleRecord {
    CycleSampleRecord {
        schema_version: SCHEMA_VERSION,
        cycle_id: id.to_string(),
        workload_key: ctx.workload_key.clone(),
        execution_profile_fingerprint: ctx.fingerprint.clone(),
        execution_profile: ctx.profile.clone(),
        stages: Stage::ALL
            .iter()
            .zip(durations)
            .map(|(stage, d)| StageSample {
                stage: *stage,
                duration_us: d,
                outcome: StageOutcome::Ok,
                canary_protocol_version: None,
            })
            .collect(),
        source_commit: Some("abc".into()),
        recorded_at: "2026-10-12T00:00:00Z".to_string(),
    }
}

fn history(ctx: &MeasureContext, durations: [u64; 6], n: usize) -> Vec<CycleSampleRecord> {
    (0..n)
        .map(|i| record(ctx, &format!("cycle-{i}"), durations))
        .collect()
}

fn rank_ids(measurements: &BTreeMap<Stage, StageMeasurement>) -> Vec<String> {
    build_capability_graph(measurements)
        .unwrap()
        .rank_bottlenecks()
        .into_iter()
        .map(|r| r.node_id)
        .collect()
}

#[test]
fn different_valid_sample_sets_change_the_ranking_deterministically() {
    let config = RsiConfig::default();
    let c = ctx(&config);
    let slow_build = history(&c, [10, 20, 90_000, 30, 10, 10], 5);
    let slow_propose = history(&c, [10, 90_000, 20, 30, 10, 10], 5);
    let a = try_measure(&slow_build, "now", &c, 3, 20, 20).unwrap();
    let b = try_measure(&slow_propose, "now", &c, 3, 20, 20).unwrap();
    let order_a = rank_ids(&a);
    let order_b = rank_ids(&b);
    assert_ne!(order_a, order_b);
    for _ in 0..25 {
        assert_eq!(rank_ids(&a), order_a);
        assert_eq!(rank_ids(&b), order_b);
    }
    let graph = build_capability_graph(&a).unwrap();
    let top = graph.top_bottleneck().unwrap();
    assert_eq!(top.node_id, "BuildJail");
    assert_eq!(top.ranking_basis, RankingBasis::Measured);
    assert_eq!(top.latency_median_us, Some(90_000.0));
}

#[test]
fn removing_samples_gives_cold_start_structural_ranking_never_old_constants() {
    let config = RsiConfig::default();
    let c = ctx(&config);
    let measured = try_measure(
        &history(&c, [90_000, 20, 10, 30, 10, 10], 5),
        "now",
        &c,
        3,
        20,
        20,
    )
    .unwrap();
    let cold = measure_stages(Ok(Vec::new()), "now", &c, &config);
    let graph = build_capability_graph(&cold).unwrap();
    let ranks = graph.rank_bottlenecks();
    assert_eq!(ranks.len(), 6);
    for r in &ranks {
        assert_eq!(r.measurement, Measurement::Unavailable);
        assert_eq!(r.ranking_basis, RankingBasis::Structural);
        assert_eq!(r.latency_median_us, None);
        assert_eq!(r.error_rate_measured, None);
        assert!(r
            .unavailable_reason
            .as_deref()
            .unwrap()
            .contains("fewer than 3 compatible completed samples in the last 20 cycles"));
        // Score is centrality alone, so none of the old constants can have fed it.
        assert_eq!(r.bottleneck_score, r.centrality);
    }
    assert_ne!(rank_ids(&measured), rank_ids(&cold));
    // Ties break by stage id ascending (byte order).
    let tied: Vec<_> = ranks
        .windows(2)
        .filter(|w| (w[0].bottleneck_score - w[1].bottleneck_score).abs() < 1e-9)
        .collect();
    for w in tied {
        assert!(w[0].node_id < w[1].node_id);
    }
}

#[test]
fn one_unavailable_stage_forces_structural_ranking_for_all() {
    let config = RsiConfig::default();
    let c = ctx(&config);
    let mut recs = history(&c, [10, 20, 90_000, 30, 10, 10], 5);
    for r in &mut recs {
        r.stages.retain(|s| s.stage != Stage::SupervisorCanary);
    }
    let m = try_measure(&recs, "now", &c, 3, 20, 20).unwrap();
    let ranks = build_capability_graph(&m).unwrap().rank_bottlenecks();
    assert!(ranks
        .iter()
        .all(|r| r.ranking_basis == RankingBasis::Structural));
    let canary = ranks
        .iter()
        .find(|r| r.node_id == "SupervisorCanary")
        .unwrap();
    assert_eq!(canary.measurement, Measurement::Unavailable);
    let build = ranks.iter().find(|r| r.node_id == "BuildJail").unwrap();
    assert_eq!(build.measurement, Measurement::Measured);
}

#[test]
fn explanation_distinguishes_measured_from_unavailable_for_every_stage() {
    let config = RsiConfig::default();
    let c = ctx(&config);
    let mut recs = history(&c, [10, 20, 90_000, 30, 10, 10], 5);
    for r in &mut recs {
        r.stages.retain(|s| s.stage != Stage::CortexCommit);
    }
    let m = try_measure(&recs, "now", &c, 3, 20, 20).unwrap();
    let graph = build_capability_graph(&m).unwrap();
    let ranks = graph.rank_bottlenecks();
    let doc = evidence_graph(&RsiCycleEvidence {
        cycle_id: "now",
        graph: Some(&graph),
        metrics_origin: MetricsOrigin::Measured,
        bottlenecks: &ranks,
        hypothesis: None,
        diagnostic: None,
        receipt: None,
        ratification: None,
    });
    let caps: Vec<_> = doc
        .nodes
        .iter()
        .filter(|n| n.id.starts_with("rsi:capability:"))
        .collect();
    assert_eq!(caps.len(), 6);
    for n in caps {
        let measured = n.measurements.iter().any(|x| x.name == "latency_median_us");
        let marked = n
            .missing
            .iter()
            .any(|x| x.expected.contains("measured median latency"));
        assert_ne!(measured, marked, "{} must be exactly one of the two", n.id);
        if n.id.ends_with("CortexCommit") {
            assert!(marked);
            assert!(n.missing[0]
                .reason
                .contains("fewer than 3 compatible completed samples"));
            assert_eq!(n.status, 0);
        } else {
            assert!(measured);
            assert_eq!(n.status, 1);
            // 5 samples: p95 is unavailable and says why.
            assert!(n.missing.iter().any(|x| x.expected.contains("p95")));
        }
    }
    let analysis = doc
        .nodes
        .iter()
        .find(|n| n.id == "rsi:bottleneck:now")
        .unwrap();
    assert!(analysis
        .missing
        .iter()
        .any(|x| x.expected.contains("latency and error terms")));
}

#[test]
fn cold_start_hypothesis_claims_nothing_and_measured_one_uses_the_median() {
    let config = RsiConfig::default();
    let c = ctx(&config);
    let cold = measure_stages(Ok(Vec::new()), "now", &c, &config);
    let top = build_capability_graph(&cold)
        .unwrap()
        .top_bottleneck()
        .unwrap();
    let h = HypothesisContract::from_bottleneck("h1", "now", &top, 5.0);
    assert!(h.is_exploratory());
    assert_eq!(h.latency_claim(), None);
    assert_eq!(h.target_metric, "structural_ranking");
    assert!(h.validate().is_ok());

    let m = try_measure(
        &history(&c, [10, 20, 90_000, 30, 10, 10], 5),
        "now",
        &c,
        3,
        20,
        20,
    )
    .unwrap();
    let top = build_capability_graph(&m)
        .unwrap()
        .top_bottleneck()
        .unwrap();
    let h = HypothesisContract::from_bottleneck("h2", "now", &top, 5.0);
    assert!(!h.is_exploratory());
    assert_eq!(h.latency_claim(), Some((90_000.0, 5.0)));
    assert_eq!(h.baseline_value, 90_000.0);
    assert!(h.validate().is_ok());
}

#[test]
fn optimization_and_latency_policy_candidates_need_a_measured_diagnosis() {
    assert!(check_claim(&ProposalKind::Optimization, false, false).is_err());
    assert!(check_claim(&ProposalKind::Optimization, false, true).is_ok());
    for kind in [
        ProposalKind::Refactor,
        ProposalKind::Documentation,
        ProposalKind::UnslopSanitization,
        ProposalKind::InvariantFix,
        ProposalKind::MetaEngineImprovement,
    ] {
        assert!(check_claim(&kind, false, false).is_ok());
        let refused = check_claim(&kind, true, false).unwrap_err();
        assert!(refused.contains("require_latency_improvement"));
        assert!(check_claim(&kind, true, true).is_ok());
    }
    let why = check_claim(&ProposalKind::Optimization, false, false).unwrap_err();
    assert!(why.contains("unavailable diagnosis"));
}

#[test]
fn percentile_matches_pinned_golden_values() {
    let one_to_twenty: Vec<f64> = (1..=20).map(f64::from).collect();
    let one_to_hundred: Vec<f64> = (1..=100).map(f64::from).collect();
    assert_eq!(percentile_nearest_rank(&one_to_twenty, 95.0).unwrap(), 19.0);
    assert_eq!(percentile_nearest_rank(&one_to_twenty, 50.0).unwrap(), 10.0);
    assert_eq!(
        percentile_nearest_rank(&one_to_twenty, 100.0).unwrap(),
        20.0
    );
    assert_eq!(percentile_nearest_rank(&one_to_twenty, 0.0).unwrap(), 1.0);
    assert_eq!(
        percentile_nearest_rank(&one_to_hundred, 95.0).unwrap(),
        95.0
    );
    assert_eq!(
        percentile_nearest_rank(&one_to_hundred, 99.0).unwrap(),
        99.0
    );
    assert_eq!(percentile_nearest_rank(&[7.0], 95.0).unwrap(), 7.0);
    assert_eq!(
        percentile_nearest_rank(&[30.0, 10.0, 20.0], 50.0).unwrap(),
        20.0
    );
    // Even count: the lower of the two middle values.
    assert_eq!(median(&[40.0, 10.0, 30.0, 20.0]).unwrap(), 20.0);
    assert_eq!(
        percentile_nearest_rank(&[10.0, 20.0, 30.0, 40.0, 50.0], 95.0).unwrap(),
        50.0
    );
}

#[test]
fn p95_is_unavailable_below_twenty_samples() {
    let nineteen: Vec<f64> = (1..=19).map(f64::from).collect();
    let twenty: Vec<f64> = (1..=20).map(f64::from).collect();
    assert_eq!(p95_if_sufficient(&nineteen, 20).unwrap(), None);
    assert_eq!(p95_if_sufficient(&twenty, 20).unwrap(), Some(19.0));
}

#[test]
fn non_finite_and_negative_measurements_are_rejected_not_clamped() {
    assert!(median(&[1.0, f64::NAN]).is_err());
    assert!(median(&[1.0, f64::INFINITY]).is_err());
    assert!(median(&[1.0, -2.0]).is_err());
    assert!(median(&[]).is_err());
    assert!(percentile_nearest_rank(&[1.0], 101.0).is_err());
    assert!(p95_if_sufficient(&[f64::NEG_INFINITY], 1).is_err());
}

#[test]
fn partial_cycles_are_stored_separately_and_never_ranked() {
    let tmp = tempfile::tempdir().unwrap();
    let config = RsiConfig::default();
    let c = ctx(&config);
    let log = SampleLog::new(tmp.path());
    for r in history(&c, [10, 20, 30, 40, 50, 60], 2) {
        log.append_complete(&r).unwrap();
    }
    // A failed cycle with huge durations goes to the partial log only.
    log.append_partial(&record(&c, "cycle-failed", [9_999_999; 6]))
        .unwrap();
    assert_eq!(log.read_complete().unwrap().len(), 2);
    assert_eq!(log.read_partial().unwrap().len(), 1);
    assert!(log.complete_path().ends_with("measure/stage-samples.jsonl"));
    assert!(log.partial_path().ends_with("measure/partial-cycles.jsonl"));

    log.append_complete(&record(&c, "cycle-2", [10, 20, 30, 40, 50, 60]))
        .unwrap();
    let m = measure_stages(log.read_complete(), "now", &c, &config);
    match &m[&Stage::Observe] {
        StageMeasurement::Measured {
            latency_median_us,
            sample_count,
            ..
        } => {
            assert_eq!(*latency_median_us, 10.0);
            assert_eq!(*sample_count, 3);
        }
        other => panic!("expected measured, got {other:?}"),
    }
}

#[test]
fn different_fingerprint_workload_key_or_current_cycle_are_excluded() {
    let config = RsiConfig::default();
    let c = ctx(&config);
    let mut recs = history(&c, [10, 20, 30, 40, 50, 60], 2);

    let mut other_gpu = profile(&config);
    other_gpu.gpu = "none".to_string();
    let other_hw = MeasureContext::from_parts("remote:example.org/repo", other_gpu, None);
    assert_eq!(
        other_hw.workload_key, c.workload_key,
        "hardware is not in the key"
    );
    assert_ne!(other_hw.fingerprint, c.fingerprint);
    recs.push(record(&other_hw, "cycle-other-hw", [1; 6]));

    let other_repo = MeasureContext::from_parts("remote:example.org/other", profile(&config), None);
    assert_ne!(other_repo.workload_key, c.workload_key);
    recs.push(record(&other_repo, "cycle-other-repo", [1; 6]));

    recs.push(record(&c, "now", [1; 6]));

    // Only two compatible prior samples remain, below the minimum of three.
    let m = try_measure(&recs, "now", &c, 3, 20, 20).unwrap();
    for s in Stage::ALL {
        assert!(matches!(
            &m[&s],
            StageMeasurement::Unavailable {
                sample_count: 2,
                ..
            }
        ));
    }
    // With a minimum of two the median comes only from the two compatible prior cycles.
    let m = try_measure(&recs, "now", &c, 2, 20, 20).unwrap();
    assert!(matches!(
        &m[&Stage::Observe],
        StageMeasurement::Measured { latency_median_us, sample_count: 2, .. } if *latency_median_us == 10.0
    ));
}

#[test]
fn window_keeps_only_the_most_recent_compatible_cycles() {
    let config = RsiConfig::default();
    let c = ctx(&config);
    let mut recs = history(&c, [1_000, 1, 1, 1, 1, 1], 4);
    recs.extend((0..3).map(|i| record(&c, &format!("recent-{i}"), [5, 1, 1, 1, 1, 1])));
    let m = try_measure(&recs, "now", &c, 3, 3, 20).unwrap();
    assert!(matches!(
        &m[&Stage::Observe],
        StageMeasurement::Measured { latency_median_us, sample_count: 3, .. } if *latency_median_us == 5.0
    ));
}

#[test]
fn error_rate_counts_failed_outcomes_only() {
    let config = RsiConfig::default();
    let c = ctx(&config);
    let mut recs = history(&c, [10, 20, 30, 40, 50, 60], 4);
    recs[0].stages[2].outcome = StageOutcome::Failed;
    recs[1].stages[2].outcome = StageOutcome::Refused;
    let m = try_measure(&recs, "now", &c, 3, 20, 20).unwrap();
    assert!(matches!(
        &m[&Stage::BuildJail],
        StageMeasurement::Measured { error_rate, .. } if *error_rate == 0.25
    ));
}

#[test]
fn log_is_strict_but_skips_a_torn_trailing_line_and_drops_it_on_append() {
    let tmp = tempfile::tempdir().unwrap();
    let config = RsiConfig::default();
    let c = ctx(&config);
    let log = SampleLog::new(tmp.path());
    log.append_complete(&record(&c, "cycle-a", [1; 6])).unwrap();

    let path = log.complete_path();
    let mut torn = std::fs::read(&path).unwrap();
    torn.extend_from_slice(b"{\"schema_version\":1,\"cycle_id\":\"cycle-b\",\"wor");
    std::fs::write(&path, &torn).unwrap();
    assert_eq!(
        log.read_complete().unwrap().len(),
        1,
        "torn tail is skipped"
    );

    log.append_complete(&record(&c, "cycle-c", [2; 6])).unwrap();
    let ids: Vec<_> = log
        .read_complete()
        .unwrap()
        .into_iter()
        .map(|r| r.cycle_id)
        .collect();
    assert_eq!(ids, ["cycle-a", "cycle-c"]);

    // A terminated line that does not parse is corruption, not a torn write.
    let mut bad = std::fs::read(&path).unwrap();
    bad.extend_from_slice(b"not json\n");
    std::fs::write(&path, &bad).unwrap();
    assert!(log.read_complete().is_err());
    let m = measure_stages(log.read_complete(), "now", &c, &config);
    assert!(m.values().all(|v| matches!(
        v,
        StageMeasurement::Unavailable { reason, .. } if reason.contains("rejected")
    )));

    // Unknown fields and other schema versions are refused too.
    let mut v2 = record(&c, "cycle-v2", [1; 6]);
    v2.schema_version = 2;
    assert!(log.append_complete(&v2).is_err());
    std::fs::write(&path, b"{\"schema_version\":1,\"extra\":true}\n").unwrap();
    assert!(log.read_complete().is_err());
}

#[test]
fn workload_key_and_fingerprint_follow_the_documented_fields() {
    let base = RsiConfig::default();
    let c = ctx(&base);

    // Evaluation policy is not an execution mode.
    let mut policy = base.clone();
    policy.require_latency_improvement = true;
    policy.non_inferiority_margin = Some(42.0);
    policy.measure_min_samples = 9;
    let p = ctx(&policy);
    assert_eq!(p.workload_key, c.workload_key);
    assert_eq!(p.fingerprint, c.fingerprint);

    // Model and execution configuration change both.
    let mut model = base.clone();
    model.max_model = "another-model".into();
    assert_ne!(ctx(&model).workload_key, c.workload_key);
    assert_ne!(ctx(&model).fingerprint, c.fingerprint);
    let mut exec = base.clone();
    exec.canary_target = 77;
    assert_ne!(ctx(&exec).workload_key, c.workload_key);

    // The target commit is provenance only.
    let moved = MeasureContext::from_parts(
        "remote:example.org/repo",
        profile(&base),
        Some("def".into()),
    );
    assert_eq!(moved.workload_key, c.workload_key);
    assert_eq!(moved.fingerprint, c.fingerprint);

    // Machine facts change the fingerprint only.
    let mut small = profile(&base);
    small.cpu_count = Some(4);
    let s = MeasureContext::from_parts("remote:example.org/repo", small, None);
    assert_eq!(s.workload_key, c.workload_key);
    assert_ne!(s.fingerprint, c.fingerprint);
}

#[test]
fn remote_urls_are_normalized_without_credentials() {
    assert_eq!(
        normalize_remote("https://user:token@github.com/aien-dev/spark-rsi.git/"),
        "https://github.com/aien-dev/spark-rsi"
    );
    assert_eq!(
        normalize_remote("git@github.com:aien-dev/spark-rsi.git"),
        "git@github.com:aien-dev/spark-rsi"
    );
}

#[test]
fn canary_protocol_version_is_recorded_on_canary_samples_only() {
    let mut clock = StageClock::new();
    clock.record(Stage::Observe, Duration::from_micros(5), StageOutcome::Ok);
    clock.record(Stage::BuildJail, Duration::from_micros(7), StageOutcome::Ok);
    clock.record(
        Stage::BuildJail,
        Duration::from_micros(3),
        StageOutcome::Failed,
    );
    clock.record(
        Stage::SupervisorCanary,
        Duration::from_micros(9),
        StageOutcome::Refused,
    );
    let samples = clock.samples();
    assert_eq!(samples.len(), 3);
    let build = samples
        .iter()
        .find(|s| s.stage == Stage::BuildJail)
        .unwrap();
    assert_eq!(
        (build.duration_us, build.outcome),
        (10, StageOutcome::Failed)
    );
    for s in &samples {
        assert_eq!(
            s.canary_protocol_version.is_some(),
            s.stage == Stage::SupervisorCanary
        );
    }
    assert_eq!(
        samples.last().unwrap().canary_protocol_version,
        Some(spark_rsi::canary::CANARY_PROTOCOL_VERSION)
    );
}

#[tokio::test]
async fn a_completed_cycle_appends_one_record_to_the_sample_log() {
    let tmp = tempfile::tempdir().unwrap();
    let rsi_root = tmp.path().join(".rsi");
    std::fs::create_dir_all(&rsi_root).unwrap();
    spark_rsi::ledger::ImprovementLedger::open(&rsi_root).unwrap();
    let holdouts = rsi_root.join("holdouts");
    std::fs::create_dir_all(&holdouts).unwrap();
    for s in spark_rsi::actor::judge::HoldoutSuite::builtin_suites() {
        s.save_to_dir(&holdouts).unwrap();
    }
    let key = p256::ecdsa::SigningKey::from_bytes(&[88u8; 32].into()).unwrap();
    let config = RsiConfig {
        target_repo: ".".to_string(),
        sandbox_root: tmp.path().join("sandbox").display().to_string(),
        rsi_root: rsi_root.display().to_string(),
        holdouts_dir: Some(holdouts.display().to_string()),
        signing_key_hex: Some(hex::encode(key.to_bytes())),
        max_url: "http://127.0.0.1:9999/v1".to_string(),
        non_inferiority_margin: Some(150.0),
        ..Default::default()
    };
    let result = spark_rsi::daemon::RsiEngine::run_cycle(&config)
        .await
        .unwrap();
    let log = SampleLog::new(&rsi_root);
    let records = log.read_complete().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].cycle_id, result.cycle_id);
    assert!(records[0].stages.iter().any(|s| s.stage == Stage::Observe));
    assert!(records[0].stages.iter().any(|s| s.stage == Stage::Propose));
    assert!(log.read_partial().unwrap().is_empty());
}
