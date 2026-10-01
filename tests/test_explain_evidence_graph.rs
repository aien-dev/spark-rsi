//! RSI -> explanation evidence graph (contract aien.explain.evidence-graph v1).
//!
//! Builds one RSI cycle from the real types (capability graph, bottleneck ranking,
//! hypothesis contract built the way the daemon builds it, diagnostic context,
//! evaluation receipt, ratification record) and checks the emitted document. The
//! golden file tests/fixtures/rsi_kv_cycle.evidence.json is shared byte for byte with
//! aien-dev/aienos crates/aienos-explain, which builds and renders the explanation.
//! Regenerate with EXPLAIN_BLESS=1 and copy it to aienos.

use sha2::{Digest, Sha256};
use spark_rsi::evaluator::{EvaluationMetricsSummary, EvaluationReceipt, LayerResult};
use spark_rsi::explain::{
    conclusion_id, evidence_graph, hypothesis_derived_from, EvidenceGraphDoc, MetricsOrigin,
    RsiCycleEvidence, FORMAT, KIND_HYPOTHESIS, REL_REFERENCES, STATUS_HYPOTHESIS,
    STATUS_UNCLASSIFIED, STATUS_VERIFIED_FACT, VERSION,
};
use spark_rsi::graph::{CapabilityGraph, CapabilityNode};
use spark_rsi::models::RatificationRecord;
use spark_rsi::propose::diagnose::{DefectCategory, DiagnosticContext};
use spark_rsi::propose::hypothesis::HypothesisContract;

const CYCLE: &str = "cycle-kv-0001";
const FIXTURE: &str = "tests/fixtures/rsi_kv_cycle.evidence.json";
/// sha256 of the fixture; the aienos side asserts the same value.
const FIXTURE_SHA256: &str = "0c04376ca36d95d677942d7e97c0a3eef3728ef72dc3cdf070494174e6a6cc31";

fn kv_graph() -> CapabilityGraph {
    let mut g = CapabilityGraph::new();
    g.add_node(
        CapabilityNode::new("req_gateway", "Request Gateway", "network")
            .with_resource_metrics(120.0, 1024, 0.0),
    );
    g.add_node(
        CapabilityNode::new("scheduler", "Batch Scheduler", "scheduling")
            .with_resource_metrics(340.0, 2048, 0.0),
    );
    g.add_node(
        CapabilityNode::new("kv_allocator", "Unified LPDDR5x KV Allocator", "memory")
            .with_resource_metrics(4200.0, 32768, 0.08),
    );
    g.add_node(
        CapabilityNode::new("mojo_kernel", "Mojo Blackwell GEMM Kernel", "compute")
            .with_resource_metrics(1800.0, 16384, 0.01),
    );
    g.add_node(
        CapabilityNode::new("sampler", "Greedy Token Sampler", "inference")
            .with_resource_metrics(150.0, 1024, 0.0),
    );
    g.add_edge("req_gateway", "scheduler", 100.0, 1.0);
    g.add_edge("scheduler", "kv_allocator", 500.0, 1.0);
    g.add_edge("kv_allocator", "mojo_kernel", 1200.0, 1.0);
    g.add_edge("mojo_kernel", "sampler", 200.0, 1.0);
    g
}

/// Same construction as RsiEngine::run_cycle in src/daemon.rs (step 5).
fn daemon_style_hypothesis(b: &spark_rsi::graph::BottleneckRank) -> HypothesisContract {
    HypothesisContract::new(
        "hypo-kv-0001",
        CYCLE,
        &format!(
            "System throughput limited by bottleneck node '{}' (centrality={:.4})",
            b.node_name, b.centrality
        ),
        &format!(
            "High latency on '{}': {}",
            b.node_name, b.causal_explanation
        ),
        "latency_us",
        b.latency_p95_us,
        15.0,
    )
    .with_protected_metric("correctness", 0.0)
    .with_falsification_test("assert!(receipt.passed_all_hard_invariants)")
}

fn receipt() -> EvaluationReceipt {
    let layers = vec![
        LayerResult {
            layer_name: "Correctness".into(),
            is_hard_invariant: true,
            passed: true,
            score: 1.0,
            summary: "all holdouts pass".into(),
            violations: vec![],
        },
        LayerResult {
            layer_name: "Performance".into(),
            is_hard_invariant: false,
            passed: true,
            score: 0.82,
            summary: "p95 improved".into(),
            violations: vec![],
        },
    ];
    let digest = EvaluationReceipt::compute_digest(CYCLE, "cand-kv-0001", "parent", true, &layers);
    EvaluationReceipt {
        cycle_id: CYCLE.into(),
        candidate_id: "cand-kv-0001".into(),
        parent_id: "parent".into(),
        evaluated_at: "2026-10-01T00:00:00Z".into(),
        evaluator_version: "test".into(),
        passed_all_hard_invariants: true,
        passed_statistical_gates: true,
        admitted: true,
        layer_results: layers,
        metrics_summary: Some(EvaluationMetricsSummary {
            latency_delta_pct: -17.5,
            p_value: 0.004,
            p95_ci_upper_degradation_pct: -9.0,
            p99_ci_upper_degradation_pct: -4.0,
            rss_growth_pct: 0.5,
            candidate_resident_mb: 512,
        }),
        receipt_digest: digest,
        signature: None,
    }
}

fn ratification() -> RatificationRecord {
    RatificationRecord {
        proposal_id: "cand-kv-0001".into(),
        commit_hash: None,
        author: "test".into(),
        cortex_receipt_id: None,
        cortex_recorded: false,
        timestamp: "2026-10-01T00:00:01Z".into(),
        status: "Ratified".into(),
        message: "test record".into(),
    }
}

fn kv_cycle_doc() -> EvidenceGraphDoc {
    let g = kv_graph();
    let ranks = g.rank_bottlenecks();
    let h = daemon_style_hypothesis(&ranks[0]);
    let diag = DiagnosticContext::from_violations(
        CYCLE,
        "src/kv_allocator.rs",
        "SOURCE TEXT MUST NOT APPEAR IN EVIDENCE",
        DefectCategory::PerformanceRegression,
        vec![format!("Bottleneck identified at {}", ranks[0].node_name)],
        vec!["LESSON TEXT MUST NOT APPEAR IN EVIDENCE".into()],
    )
    .with_hypothesis(h.clone());
    let r = receipt();
    let rat = ratification();
    evidence_graph(&RsiCycleEvidence {
        cycle_id: CYCLE,
        graph: Some(&g),
        metrics_origin: MetricsOrigin::Declared,
        bottlenecks: &ranks,
        hypothesis: Some(&h),
        diagnostic: Some(&diag),
        receipt: Some(&r),
        ratification: Some(&rat),
    })
}

fn find<'a>(d: &'a EvidenceGraphDoc, id: &str) -> &'a spark_rsi::explain::NodeDoc {
    d.nodes
        .iter()
        .find(|n| n.id == id)
        .unwrap_or_else(|| panic!("node {id}"))
}

#[test]
fn rsi_cycle_emits_contract_v1_with_explicit_links_only() {
    let d = kv_cycle_doc();
    assert_eq!(d.format, FORMAT);
    assert_eq!(d.version, VERSION);

    // Observed: five capability nodes, declared (not measured) metrics.
    let caps: Vec<_> = d
        .nodes
        .iter()
        .filter(|n| n.id.starts_with("rsi:capability:"))
        .collect();
    assert_eq!(caps.len(), 5);
    assert!(caps.iter().all(|n| n.status == STATUS_UNCLASSIFIED));
    assert!(caps
        .iter()
        .all(|n| n.notes.iter().any(|t| t.contains("not measured"))));

    // System analysis rests on the metrics; alternatives are AlternativeTo, not support.
    let a = find(&d, &format!("rsi:bottleneck:{CYCLE}"));
    assert_eq!(a.parents.len(), 5);
    assert!(a.statement.contains("Unified LPDDR5x KV Allocator"));
    let alts: Vec<_> = d
        .nodes
        .iter()
        .filter(|n| n.id.starts_with("rsi:alternative:"))
        .collect();
    assert_eq!(alts.len(), 3);
    assert!(alts
        .iter()
        .all(|n| n.parents.len() == 1 && n.parents[0].relation == 5));

    // Hypothesis keeps its status and declared confidence, and links to the analysis.
    let h = find(&d, "rsi:hypothesis:hypo-kv-0001");
    assert_eq!(h.kind, KIND_HYPOTHESIS);
    assert_eq!(h.status, STATUS_HYPOTHESIS);
    assert_eq!(h.confidence_permille, Some(850));
    assert!(h
        .confidence_basis
        .as_deref()
        .unwrap()
        .contains("not measured"));
    // Matched by text and baseline only: a weak "references" link plus a declared gap.
    assert_eq!(h.parents.len(), 1);
    assert_eq!(h.parents[0].relation, REL_REFERENCES);
    assert_eq!(h.missing.len(), 1);
    assert!(h.missing[0].reason.contains("linked only because"));

    // Receipt digest verifies -> VerifiedFact; no fabricated Evaluates edge anywhere.
    let r = find(&d, &format!("rsi:receipt:{CYCLE}:cand-kv-0001"));
    assert_eq!(r.status, STATUS_VERIFIED_FACT);
    assert!(r.source.digest.is_some());
    assert!(!r.statement.contains("hard invariants"));
    // Fields outside the receipt digest are reported, not verified.
    let s = find(&d, &format!("rsi:receipt:{CYCLE}:cand-kv-0001:summary"));
    assert_eq!(s.status, STATUS_UNCLASSIFIED);
    assert!(s.statement.contains("hard invariants passed=true"));
    assert!(s
        .notes
        .iter()
        .any(|t| t.contains("not covered by the receipt digest")));
    assert!(d
        .nodes
        .iter()
        .all(|n| n.parents.iter().all(|e| e.relation != 2)));

    // The candidate-to-hypothesis gap is declared, not bridged.
    let c = find(&d, &conclusion_id(CYCLE));
    assert!(c
        .missing
        .iter()
        .any(|m| m.expected.contains("linking candidate cand-kv-0001")));
    assert!(c.notes.iter().any(|t| t.contains("does not authorize")));

    // Source code and outside free-text lessons never enter the evidence.
    let json = String::from_utf8(d.to_json()).unwrap();
    assert!(!json.contains("SOURCE TEXT MUST NOT APPEAR"));
    assert!(!json.contains("LESSON TEXT MUST NOT APPEAR"));
}

#[test]
fn hypothesis_not_from_bottleneck_is_declared_missing() {
    let g = kv_graph();
    let ranks = g.rank_bottlenecks();
    let unrelated = HypothesisContract::new(
        "hypo-other",
        CYCLE,
        "Problem elsewhere",
        "Some other cause",
        "p95",
        1.0,
        5.0,
    );
    assert!(!hypothesis_derived_from(&unrelated, &ranks[0]));
    let d = evidence_graph(&RsiCycleEvidence {
        cycle_id: CYCLE,
        graph: Some(&g),
        metrics_origin: MetricsOrigin::Measured,
        bottlenecks: &ranks,
        hypothesis: Some(&unrelated),
        diagnostic: None,
        receipt: None,
        ratification: None,
    });
    let h = find(&d, "rsi:hypothesis:hypo-other");
    assert!(h.parents.is_empty());
    assert_eq!(h.missing.len(), 1);
    let c = find(&d, &conclusion_id(CYCLE));
    assert!(c
        .missing
        .iter()
        .any(|m| m.expected.contains("evaluation receipt")));
    // Measured metrics are observations.
    assert!(d
        .nodes
        .iter()
        .filter(|n| n.id.starts_with("rsi:capability:"))
        .all(|n| n.status == 1));
}

#[test]
fn tampered_receipt_is_not_a_verified_fact() {
    let g = kv_graph();
    let ranks = g.rank_bottlenecks();
    let mut r = receipt();
    r.admitted = false; // digest no longer matches
    let d = evidence_graph(&RsiCycleEvidence {
        cycle_id: CYCLE,
        graph: Some(&g),
        metrics_origin: MetricsOrigin::Declared,
        bottlenecks: &ranks,
        hypothesis: None,
        diagnostic: None,
        receipt: Some(&r),
        ratification: None,
    });
    let n = find(&d, &format!("rsi:receipt:{CYCLE}:cand-kv-0001"));
    assert_eq!(n.status, STATUS_UNCLASSIFIED);
    assert!(n.notes.iter().any(|t| t.contains("does not match")));
}

#[test]
fn rsi_evidence_graph_is_deterministic_and_matches_shared_fixture() {
    let a = kv_cycle_doc().to_json_pretty();
    let b = kv_cycle_doc().to_json_pretty();
    assert_eq!(a, b, "same artifacts must give the same document");
    let bytes = format!("{a}\n");
    if std::env::var("EXPLAIN_BLESS").as_deref() == Ok("1") {
        std::fs::write(FIXTURE, &bytes).unwrap();
    }
    let on_disk = std::fs::read_to_string(FIXTURE).expect("fixture present");
    assert_eq!(
        on_disk, bytes,
        "fixture drifted; rerun with EXPLAIN_BLESS=1 and copy to aienos"
    );
    let digest = hex::encode(Sha256::digest(on_disk.as_bytes()));
    assert_eq!(digest, FIXTURE_SHA256, "update the pin here and in aienos");
}

#[test]
fn artifacts_from_another_cycle_are_not_attached() {
    let g = kv_graph();
    let ranks = g.rank_bottlenecks();
    let mut r = receipt();
    r.cycle_id = "cycle-other".into();
    r.receipt_digest = EvaluationReceipt::compute_digest(
        &r.cycle_id,
        &r.candidate_id,
        &r.parent_id,
        r.admitted,
        &r.layer_results,
    );
    let h = daemon_style_hypothesis(&ranks[0]);
    let d = evidence_graph(&RsiCycleEvidence {
        cycle_id: CYCLE,
        graph: Some(&g),
        metrics_origin: MetricsOrigin::Declared,
        bottlenecks: &ranks,
        hypothesis: Some(&h),
        diagnostic: None,
        receipt: Some(&r),
        ratification: None,
    });
    assert!(d.nodes.iter().all(|n| !n.id.starts_with("rsi:receipt:")));
    let c = find(&d, &conclusion_id(CYCLE));
    assert!(c
        .missing
        .iter()
        .any(|m| m.reason.contains("belongs to cycle cycle-other")));
}
