use spark_rsi::graph::{CapabilityGraph, CapabilityNode};
use spark_rsi::propose::hypothesis::HypothesisContract;
use spark_rsi::propose::diagnose::{DefectCategory, DiagnosticContext};
use spark_rsi::propose::max_client::MaxClient;
use spark_rsi::propose::ProposalGenerator;

#[test]
fn test_capability_graph_topology_and_bottleneck_detection() {
    let mut graph = CapabilityGraph::new();

    // Model DGX Spark GB10 inference pipeline
    graph.add_node(CapabilityNode::new("req_gateway", "Request Gateway", "network").with_telemetry(120.0, 1024, 0.0));
    graph.add_node(CapabilityNode::new("scheduler", "Batch Scheduler", "scheduling").with_telemetry(340.0, 2048, 0.0));
    graph.add_node(CapabilityNode::new("kv_allocator", "Unified LPDDR5x KV Allocator", "memory").with_telemetry(4200.0, 32768, 0.08));
    graph.add_node(CapabilityNode::new("mojo_kernel", "Mojo Blackwell GEMM Kernel", "compute").with_telemetry(1800.0, 16384, 0.01));
    graph.add_node(CapabilityNode::new("sampler", "Greedy Token Sampler", "inference").with_telemetry(150.0, 1024, 0.0));

    // Define dataflow dependencies
    graph.add_edge("req_gateway", "scheduler", 100.0, 1.0);
    graph.add_edge("scheduler", "kv_allocator", 500.0, 1.0);
    graph.add_edge("kv_allocator", "mojo_kernel", 1200.0, 1.0);
    graph.add_edge("mojo_kernel", "sampler", 200.0, 1.0);

    let centrality = graph.calculate_betweenness_centrality();
    assert!(centrality.contains_key("kv_allocator"));

    let ranks = graph.rank_bottlenecks();
    assert_eq!(ranks.len(), 5);

    // KV Allocator has highest latency (4200us) and error rate (8%), plus high centrality
    let top = graph.top_bottleneck().expect("Graph must have a top bottleneck");
    assert_eq!(top.node_id, "kv_allocator");
    assert_eq!(top.subsystem, "memory");
    assert!(top.bottleneck_score > ranks[1].bottleneck_score);

    let dot = graph.to_dot();
    assert!(dot.contains("Unified LPDDR5x KV Allocator"));
    assert!(dot.contains("req_gateway\" -> \"scheduler"));
}

#[test]
fn test_hypothesis_contract_validation_and_falsification() {
    let contract = HypothesisContract::new(
        "hypo-kv-01",
        "cycle-102",
        "p95 latency exceeded budget due to paging locks in KV cache",
        "Suboptimal bucket lock granularity in PageTableAllocator::allocate",
        "p95_latency",
        4200.0,
        25.0,
    )
    .with_falsification_test("assert_eq!(lock_contention_events(), 0, \"Locks must not contend under load\")")
    .with_protected_metric("p99_latency", 1.0)
    .with_protected_metric("max_rss_kb", 2.0);

    assert!(contract.validate().is_ok());

    let directive = contract.format_prompt_directive();
    assert!(directive.contains("FALSIFIABLE HYPOTHESIS CONTRACT"));
    assert!(directive.contains("PageTableAllocator::allocate"));
    assert!(directive.contains("Target Metric: p95_latency"));
    assert!(directive.contains("assert_eq!(lock_contention_events(), 0"));
    assert!(directive.contains("p99_latency <= +1.0%"));
}

#[test]
fn test_hypothesis_contract_invalid_deltas_rejected() {
    let zero_delta = HypothesisContract::new(
        "hypo-zero",
        "cycle-01",
        "Problem",
        "Cause",
        "p95",
        100.0,
        0.0,
    );
    assert!(zero_delta.validate().is_err(), "Zero predicted delta must be rejected");

    let empty_target = HypothesisContract::new(
        "hypo-empty-target",
        "cycle-01",
        "Problem",
        "Cause",
        "",
        100.0,
        10.0,
    );
    assert!(empty_target.validate().is_err(), "Empty target metric must be rejected");
}

#[tokio::test]
async fn test_diagnosis_prompt_includes_hypothesis_directive() {
    let contract = HypothesisContract::new(
        "hypo-mem-02",
        "cycle-105",
        "Memory allocation exceeded 48GB threshold",
        "Leaked intermediate tensor slots in graph execution",
        "max_rss_kb",
        49152.0,
        15.0,
    )
    .with_falsification_test("assert!(peak_rss_mb() <= 40960)");

    let diag = DiagnosticContext::from_violations(
        "cycle-105",
        "src/runtime/allocator.rs",
        "pub fn alloc_slot() -> usize { 0 }",
        DefectCategory::ResourceViolation,
        vec!["Host watchdog detected memory violation > 48 GB".to_string()],
        vec!["Ensure buffers are reused in memory pool".to_string()],
    )
    .with_hypothesis(contract);

    let (sys, user) = diag.build_prompts();
    assert!(sys.contains("CRITICAL INVARIANTS"));
    assert!(user.contains("FALSIFIABLE HYPOTHESIS CONTRACT (ID: hypo-mem-02)"));
    assert!(user.contains("Leaked intermediate tensor slots in graph execution"));
    assert!(user.contains("assert!(peak_rss_mb() <= 40960)"));
}

#[tokio::test]
async fn test_live_max_generates_patch_satisfying_hypothesis() {
    let max = MaxClient::new("http://127.0.0.1:18006/v1", "atlas-lightning-omni");
    if !max.is_available().await {
        eprintln!("Skipping live MAX hypothesis test: endpoint not reachable");
        return;
    }

    let contract = HypothesisContract::new(
        "hypo-live-01",
        "cycle-live-hypo",
        "Integer overflow during buffer capacity calculation",
        "Unchecked multiplication in compute_buffer_size",
        "correctness",
        0.0,
        100.0,
    )
    .with_falsification_test("assert_eq!(compute_buffer_size(usize::MAX, 2), None)");

    let diag = DiagnosticContext::from_violations(
        "cycle-live-hypo",
        "src/buffer.rs",
        "pub fn compute_buffer_size(count: usize, item_size: usize) -> Option<usize> {\n    Some(count * item_size)\n}",
        DefectCategory::HoldoutFailure,
        vec!["Overflow panic on large inputs".to_string()],
        vec!["Use checked_mul for safe capacity arithmetic".to_string()],
    )
    .with_hypothesis(contract);

    let proposal = ProposalGenerator::propose_from_diagnosis(&max, &diag)
        .await
        .expect("MAX should successfully generate patch satisfying hypothesis");

    assert_eq!(proposal.target_file, "src/buffer.rs");
    assert!(
        proposal.proposed_patch.contains("checked_mul"),
        "Generated patch should use checked_mul as instructed by hypothesis, got:\n{}",
        proposal.proposed_patch
    );
    assert!(!proposal.proposed_patch.contains('\u{2014}'));
}
