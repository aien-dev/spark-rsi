use spark_rsi::evaluator::layers::LayerResult;
use spark_rsi::evaluator::EvaluationReceipt;
use spark_rsi::models::ProposalKind;
use spark_rsi::propose::cortex::CortexExperienceClient;
use spark_rsi::propose::diagnose::{DefectCategory, DiagnosticContext};
use spark_rsi::propose::max_client::{ChatMessage, MaxClient};
use spark_rsi::propose::ProposalGenerator;

#[tokio::test]
async fn test_max_client_availability_and_completion() {
    let client = MaxClient::new("http://127.0.0.1:18006/v1", "atlas-lightning-omni");
    let is_avail = client.is_available().await;
    if !is_avail { eprintln!("Skipping live MAX availability test: service not reachable on port 18006"); return; }

    let messages = vec![
        ChatMessage {
            role: "system".to_string(),
            content: "You are a code synthesis test engine. Respond with: PONG".to_string(),
        },
        ChatMessage {
            role: "user".to_string(),
            content: "ping".to_string(),
        },
    ];

    let resp = client.complete(&messages, 256, 0.0).await.expect("MAX completion failed");
    assert!(resp.contains("PONG"), "Expected PONG in completion, got: {}", resp);
}

#[test]
fn test_code_block_extraction() {
    let raw = "Here is the repaired file:\n```rust\npub fn fixed_logic() -> bool {\n    true\n}\n```\nAll done.";
    let extracted = ProposalGenerator::extract_code_block(raw);
    assert_eq!(extracted, "pub fn fixed_logic() -> bool {\n    true\n}");

    let plain = "pub fn simple() -> bool { false }";
    assert_eq!(ProposalGenerator::extract_code_block(plain), plain);
}

#[test]
fn test_diagnostic_context_from_failing_receipt() {
    let receipt = EvaluationReceipt {
        cycle_id: "cycle-test-diag".to_string(),
        candidate_id: "cand-test-diag".to_string(),
        parent_id: "parent-test".to_string(),
        evaluated_at: chrono::Utc::now().to_rfc3339(),
        evaluator_version: "0.1.0".to_string(),
        passed_all_hard_invariants: false,
        passed_statistical_gates: false,
        admitted: false,
        layer_results: vec![
            LayerResult {
                layer_name: "Correctness".to_string(),
                is_hard_invariant: true,
                passed: false,
                score: 0.0,
                summary: "Compilation failed".to_string(),
                violations: vec!["E0308: mismatched types".to_string()],
            },
            LayerResult {
                layer_name: "Style".to_string(),
                is_hard_invariant: true,
                passed: false,
                score: 0.0,
                summary: "Style violation".to_string(),
                violations: vec!["Em dash detected at line 14".to_string()],
            },
        ],
        metrics_summary: None,
        receipt_digest: "abcd1234".to_string(),
        signature: None,
    };

    let target_file = "src/example.rs";
    let content = "pub fn example() {}";
    let lessons = vec!["Avoid em dashes in comments".to_string()];

    let diag = DiagnosticContext::from_receipt(
        "cycle-test-diag",
        &receipt,
        target_file,
        content,
        lessons,
    );

    assert_eq!(diag.target_file, "src/example.rs");
    assert_eq!(diag.primary_defect, DefectCategory::StyleViolation);
    assert_eq!(diag.violations.len(), 2);
    assert_eq!(diag.past_lessons.len(), 1);

    let (sys, user) = diag.build_prompts();
    assert!(sys.contains("CRITICAL INVARIANTS"));
    assert!(sys.contains("Anti-Slop"));
    assert!(user.contains("TARGET FILE: src/example.rs"));
    assert!(user.contains("E0308: mismatched types"));
    assert!(user.contains("Em dash detected at line 14"));
    assert!(user.contains("Avoid em dashes in comments"));
}

#[tokio::test]
async fn test_cortex_experience_client_query() {
    let cortex = CortexExperienceClient::new("http://127.0.0.1:18080");
    let lessons = cortex.recall_lessons("spark-rsi", 3).await;
    for l in &lessons {
        assert!(!l.is_empty());
    }
}

#[tokio::test]
async fn test_propose_from_diagnosis_live_max() {
    let max = MaxClient::new("http://127.0.0.1:18006/v1", "atlas-lightning-omni");
    if !max.is_available().await {
        eprintln!("Skipping live MAX test: service not running");
        return;
    }

    let diag = DiagnosticContext::from_violations(
        "cycle-diag-live",
        "src/calc.rs",
        "pub fn add(a: i32, b: i32) -> i32 {\n    a - b\n}",
        DefectCategory::HoldoutFailure,
        vec!["Holdout 'ADD-001' failed: expected 5, got -1".to_string()],
        vec!["Verify operator signs in arithmetic functions".to_string()],
    );

    let proposal = ProposalGenerator::propose_from_diagnosis(&max, &diag)
        .await
        .expect("Failed to generate proposal from diagnosis");

    assert_eq!(proposal.target_file, "src/calc.rs");
    assert_eq!(proposal.kind, ProposalKind::InvariantFix);
    assert!(!proposal.proposed_patch.is_empty());
    // Ensure no forbidden unicode dashes
    assert!(!proposal.proposed_patch.contains('\u{2014}'));
    assert!(!proposal.proposed_patch.contains('\u{2013}'));
}
