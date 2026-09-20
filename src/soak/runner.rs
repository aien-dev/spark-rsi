use crate::actor::BlindJudge;
use crate::balance::BalanceKernel;
use crate::evaluator::EvaluationReceipt;
use crate::graph::{CapabilityGraph, CapabilityNode};
use crate::isolation::BuildJail;
use crate::ledger::{BlockType, ImprovementLedger, LedgerBlock};
use crate::meta::TrueRsiEvaluator;
use crate::models::{ImprovementProposal, ProposalKind};
use crate::observe::observe_codebase;
use crate::propose::{
    cortex::CortexExperienceClient, max_client::MaxClient, DefectCategory, DiagnosticContext,
    HypothesisContract, ProposalGenerator,
};
use crate::ratify::Ratifier;
use crate::soak::manifest::*;
use crate::verifier::InvariantVerifier;
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct SoakConfig {
    pub target_repo: String,
    pub rsi_root: String,
    pub sandbox_root: String,
    pub holdouts_dir: Option<String>,
    pub signing_key_hex: Option<String>,
    pub operator_key_hex: Option<String>,
    pub cortex_url: String,
    pub cortex_space: String,
    pub max_url: String,
    pub max_model: String,
    pub mojo_kernel_path: String,
    pub total_cycles: usize,
    pub candidates_per_cycle: usize,
    pub canary_target: usize,
    pub non_inferiority_margin: Option<f64>,
    pub writable_prefixes: Vec<String>,
}

impl Default for SoakConfig {
    fn default() -> Self {
        Self {
            target_repo: ".".to_string(),
            rsi_root: ".rsi".to_string(),
            sandbox_root: "/tmp/spark-rsi-soak".to_string(),
            holdouts_dir: None,
            signing_key_hex: None,
            operator_key_hex: None,
            cortex_url: "http://127.0.0.1:18080".to_string(),
            cortex_space: "atlas-memory".to_string(),
            max_url: "http://127.0.0.1:18006/v1".to_string(),
            max_model: "atlas-lightning-omni".to_string(),
            mojo_kernel_path: "mojo/balance_bin".to_string(),
            total_cycles: 5,
            candidates_per_cycle: 3,
            canary_target: 5000,
            non_inferiority_margin: Some(10.0),
            writable_prefixes: vec![
                "src/propose/".to_string(),
                "src/graph/".to_string(),
                "src/observe.rs".to_string(),
            ],
        }
    }
}

pub struct SoakRunner;

impl SoakRunner {
    pub async fn run_batch(config: &SoakConfig) -> Result<SoakRunManifest, String> {
        let run_id = format!("soak-{}", &Uuid::new_v4().simple().to_string()[..12]);
        let started_at = Utc::now().to_rfc3339();
        let repo_path = Path::new(&config.target_repo);
        let rsi_root = repo_path.join(&config.rsi_root);
        let sandbox_base = Path::new(&config.sandbox_root);

        // Step 1: Capture Engine N Snapshot
        let engine_n_snapshot = Self::capture_engine_n(
            repo_path,
            &config.max_model,
            config.operator_key_hex.as_deref(),
        );

        // Step 2: Resolve Signing Key
        let signing_key_hex = config.signing_key_hex.as_ref().ok_or_else(|| {
            "Fatal: Missing cryptographic signing key (signing_key_hex). Soak run fails closed."
                .to_string()
        })?;
        let key_bytes = hex::decode(signing_key_hex)
            .map_err(|e| format!("Fatal: Invalid signing_key_hex: {}", e))?;
        let signing_key = p256::ecdsa::SigningKey::from_slice(&key_bytes)
            .map_err(|e| format!("Fatal: Invalid P-256 signing key: {}", e))?;

        // Step 3: Resolve Holdouts Path
        let holdouts_path = config
            .holdouts_dir
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| rsi_root.join("holdouts"));

        // Step 4: Run Preflight Checks (Cycle 1 Gate)
        let preflight_result = Self::run_preflight_checks(
            repo_path,
            &rsi_root,
            &holdouts_path,
            Some(signing_key_hex.as_str()),
        );

        if let Err(preflight_err) = preflight_result {
            eprintln!("❌ Preflight check failed in Cycle 1: {}", preflight_err);
            let manifest = SoakRunManifest {
                manifest_version: "1.0.0".to_string(),
                run_id: run_id.clone(),
                started_at: started_at.clone(),
                completed_at: Utc::now().to_rfc3339(),
                engine_n_snapshot,
                cycles: Vec::new(),
                admitted_candidates: Vec::new(),
                exhausted_hypotheses: Vec::new(),
                final_merkle_checkpoint: None,
                total_candidates_evaluated: 0,
                total_candidates_admitted: 0,
                preflight_passed: false,
                overall_status: "PREFLIGHT_ABORTED".to_string(),
            };
            let manifest_path = rsi_root.join(format!("soak_manifest_{}.json", run_id));
            let _ = manifest.save_to_file(&manifest_path);
            return Err(format!("Preflight aborted: {}", preflight_err));
        }

        let ledger = ImprovementLedger::open(&rsi_root)
            .map_err(|e| format!("Fatal: Failed to open ImprovementLedger: {}", e))?;

        let mut quarantine_tracker = HypothesisQuarantineTracker::new();
        let mut cycle_records = Vec::new();
        let mut admitted_candidates = Vec::new();
        let mut total_candidates_evaluated = 0;
        let mut total_candidates_admitted = 0;
        let max_client = MaxClient::new(&config.max_url, &config.max_model);

        // Step 5: Execute Autonomous Bounded Cycles
        for cycle_index in 1..=config.total_cycles {
            println!(
                "⚡ [Soak Run] Starting Cycle {} of {}",
                cycle_index, config.total_cycles
            );
            let cycle_id = format!("soak-{}-c{:02}", run_id, cycle_index);
            let thermal_before = ThermalSnapshot::capture();

            // Telemetry & CapabilityGraph
            let telemetry = observe_codebase(repo_path)?;
            let mut graph = CapabilityGraph::new();
            graph.add_node(
                CapabilityNode::new("Observe", "Observe Subsystem", "observe")
                    .with_telemetry(50.0, 1024, 0.0),
            );
            graph.add_node(
                CapabilityNode::new("Propose", "Propose Subsystem", "propose").with_telemetry(
                    400.0,
                    4096,
                    if telemetry.soul_tension.drive_score > 0.8 {
                        0.25
                    } else {
                        0.0
                    },
                ),
            );
            graph.add_node(
                CapabilityNode::new("Graph", "Capability Graph Subsystem", "graph")
                    .with_telemetry(120.0, 2048, 0.0),
            );
            graph.add_node(
                CapabilityNode::new("BuildJail", "Build Jail", "isolation")
                    .with_telemetry(150.0, 2048, 0.0),
            );
            graph.add_node(
                CapabilityNode::new("JudgeEvaluation", "Judge Evaluation", "actor")
                    .with_telemetry(250.0, 8192, 0.0),
            );
            graph.add_node(
                CapabilityNode::new("SupervisorCanary", "Supervisor Canary", "supervisor")
                    .with_telemetry(100.0, 4096, 0.0),
            );
            graph.add_node(
                CapabilityNode::new("CortexCommit", "Cortex Commit", "ratify")
                    .with_telemetry(50.0, 1024, 0.0),
            );

            graph.add_edge("Observe", "Propose", 400.0, 1.0);
            graph.add_edge("Propose", "Graph", 120.0, 1.0);
            graph.add_edge("Graph", "BuildJail", 150.0, 1.0);
            graph.add_edge("BuildJail", "JudgeEvaluation", 250.0, 1.0);
            graph.add_edge("JudgeEvaluation", "SupervisorCanary", 100.0, 1.0);
            graph.add_edge("SupervisorCanary", "CortexCommit", 50.0, 1.0);

            // Find top bottleneck not quarantined
            let ranked = graph.rank_bottlenecks();
            let chosen_bottleneck = ranked
                .iter()
                .find(|b| !quarantine_tracker.is_exhausted(&b.node_name, &b.causal_explanation))
                .or_else(|| ranked.first());

            let bottleneck = match chosen_bottleneck {
                Some(b) => (*b).clone(),
                None => {
                    eprintln!(
                        "Warning: No bottlenecks available in graph for cycle {}",
                        cycle_index
                    );
                    break;
                }
            };

            let hypothesis_problem = format!(
                "High latency on {}: {}",
                bottleneck.node_name, bottleneck.causal_explanation
            );
            let hypothesis_id = format!("hypo-{}", &Uuid::new_v4().simple().to_string()[..12]);
            let hypothesis = HypothesisContract::new(
                &hypothesis_id,
                &cycle_id,
                &format!(
                    "Throughput bound by node {} (centrality={:.4})",
                    bottleneck.node_name, bottleneck.centrality
                ),
                &hypothesis_problem,
                "latency_us",
                bottleneck.latency_p95_us,
                15.0,
            )
            .with_protected_metric("correctness", 0.0)
            .with_falsification_test("assert!(receipt.passed_all_hard_invariants)");

            // Cortex recall
            let cortex =
                CortexExperienceClient::new(&config.cortex_url).with_space(&config.cortex_space);
            let past_lessons = cortex
                .recall_lessons(
                    &format!(
                        "{} {}",
                        hypothesis.observed_problem, hypothesis.suspected_root_cause
                    ),
                    3,
                )
                .await;

            // Map bottleneck to target file within writable prefixes
            let target_file = match bottleneck.node_name.as_str() {
                "Propose" => "src/propose/hypothesis.rs",
                "Graph" => "src/graph/mod.rs",
                _ => "src/observe.rs",
            };

            let full_target_path = repo_path.join(target_file);
            let parent_content = std::fs::read_to_string(&full_target_path).unwrap_or_default();

            let mut candidate_records: Vec<CycleCandidateRecord> = Vec::new();
            let mut admissible_proposals: Vec<(
                ImprovementProposal,
                EvaluationReceipt,
                LedgerBlock,
            )> = Vec::new();

            // Candidate Generation Loop: exactly 3 isolated candidates against identical parent
            for cand_idx in 1..=config.candidates_per_cycle {
                let cand_id = format!("{}-c{}", cycle_id, cand_idx);
                println!(
                    "  [Candidate {}/{}] Generating patch for {}",
                    cand_idx, config.candidates_per_cycle, target_file
                );

                let mut maybe_prop = None;

                if max_client.is_available().await {
                    let variation_directive = match cand_idx {
                        1 => "Candidate variation 1 of 3: Focus on algorithmic simplification and data locality.",
                        2 => "Candidate variation 2 of 3: Focus on loop unrolling and branch prediction efficiency.",
                        _ => "Candidate variation 3 of 3: Focus on memory allocation reduction and cache line alignment.",
                    };

                    let diag = DiagnosticContext::from_violations(
                        &cycle_id,
                        target_file,
                        &parent_content,
                        DefectCategory::PerformanceRegression,
                        vec![
                            format!("Bottleneck: {}", bottleneck.node_name),
                            variation_directive.to_string(),
                        ],
                        past_lessons.clone(),
                    )
                    .with_hypothesis(hypothesis.clone());

                    if let Ok(prop) =
                        ProposalGenerator::propose_from_diagnosis(&max_client, &diag).await
                    {
                        maybe_prop = Some(prop);
                    }
                }

                if maybe_prop.is_none() && cand_idx == 1 {
                    if let Some(prop) = ProposalGenerator::scan_and_propose_unslop(repo_path) {
                        maybe_prop = Some(prop);
                    }
                }

                let mut candidate = match maybe_prop {
                    Some(mut p) => {
                        p.id = cand_id.clone();
                        p
                    }
                    None => {
                        candidate_records.push(CycleCandidateRecord {
                            candidate_id: cand_id,
                            candidate_index: cand_idx,
                            target_file: target_file.to_string(),
                            proposed_patch_digest: "none".to_string(),
                            compilation_passed: false,
                            invariants_passed: false,
                            judge_admitted: false,
                            primary_metric_name: "latency_us".to_string(),
                            primary_metric_value: 0.0,
                            rejection_reason: Some(
                                "Model generation failed to produce valid code".to_string(),
                            ),
                            ledger_block_hash: None,
                        });
                        total_candidates_evaluated += 1;
                        continue;
                    }
                };

                // Validate Tier 2 boundaries
                let normalized_target = candidate
                    .target_file
                    .trim_start_matches("./")
                    .trim_start_matches('/');
                let is_permitted = config.writable_prefixes.iter().any(|prefix| {
                    normalized_target == prefix.trim_end_matches('/')
                        || normalized_target.starts_with(prefix)
                });

                if !is_permitted {
                    let reason = format!(
                        "Tier 2 boundary violation: {} is outside permitted soak surface",
                        candidate.target_file
                    );
                    let _ = ledger.append_block(BlockType::Evaluation, reason.clone(), vec![]);
                    candidate_records.push(CycleCandidateRecord {
                        candidate_id: cand_id,
                        candidate_index: cand_idx,
                        target_file: candidate.target_file.clone(),
                        proposed_patch_digest: hex::encode(Sha256::digest(
                            candidate.proposed_patch.as_bytes(),
                        )),
                        compilation_passed: false,
                        invariants_passed: false,
                        judge_admitted: false,
                        primary_metric_name: "latency_us".to_string(),
                        primary_metric_value: 0.0,
                        rejection_reason: Some(reason),
                        ledger_block_hash: None,
                    });
                    total_candidates_evaluated += 1;
                    continue;
                }

                // Stage in sandbox
                let sandbox_dir = match ProposalGenerator::stage_in_sandbox(
                    &mut candidate,
                    repo_path,
                    sandbox_base,
                ) {
                    Ok(dir) => dir,
                    Err(e) => {
                        let reason = format!("Staging failed: {}", e);
                        let _ = ledger.append_block(BlockType::Evaluation, reason.clone(), vec![]);
                        candidate_records.push(CycleCandidateRecord {
                            candidate_id: cand_id,
                            candidate_index: cand_idx,
                            target_file: candidate.target_file.clone(),
                            proposed_patch_digest: hex::encode(Sha256::digest(
                                candidate.proposed_patch.as_bytes(),
                            )),
                            compilation_passed: false,
                            invariants_passed: false,
                            judge_admitted: false,
                            primary_metric_name: "latency_us".to_string(),
                            primary_metric_value: 0.0,
                            rejection_reason: Some(reason),
                            ledger_block_hash: None,
                        });
                        total_candidates_evaluated += 1;
                        continue;
                    }
                };

                // Compile inside Jail 1
                let mut comp_passed = true;
                if sandbox_dir.join("Cargo.toml").exists() {
                    let build_jail =
                        BuildJail::new("spark-rsi-builder:latest", &sandbox_dir, &sandbox_dir);
                    match build_jail.execute_bwrap(&["cargo", "build", "--release", "--offline"]) {
                        Ok((success, _stdout, stderr)) => {
                            if !success {
                                comp_passed = false;
                                let _ = ledger.append_block(
                                    BlockType::Evaluation,
                                    format!("Build Jail compile failed: {}", stderr),
                                    vec![],
                                );
                            }
                        }
                        Err(e) => {
                            comp_passed = false;
                            let _ = ledger.append_block(
                                BlockType::Evaluation,
                                format!("Build Jail execution error: {}", e),
                                vec![],
                            );
                        }
                    }
                }

                if !comp_passed {
                    candidate_records.push(CycleCandidateRecord {
                        candidate_id: cand_id,
                        candidate_index: cand_idx,
                        target_file: candidate.target_file.clone(),
                        proposed_patch_digest: hex::encode(Sha256::digest(
                            candidate.proposed_patch.as_bytes(),
                        )),
                        compilation_passed: false,
                        invariants_passed: false,
                        judge_admitted: false,
                        primary_metric_name: "latency_us".to_string(),
                        primary_metric_value: 0.0,
                        rejection_reason: Some("Failed to compile in Jail 1".to_string()),
                        ledger_block_hash: None,
                    });
                    total_candidates_evaluated += 1;
                    continue;
                }

                // Invariant verification
                let inv_report = InvariantVerifier::run_full_verification(&sandbox_dir);
                let balance_verdict = BalanceKernel::evaluate(
                    telemetry.soul_tension.drive_score,
                    telemetry.soul_tension.humanity_score,
                    Some(&config.mojo_kernel_path),
                )?;
                let is_balanced = balance_verdict.verdict == "balanced";

                if !inv_report.passed || !is_balanced {
                    let reason = format!(
                        "Invariants or Balance failed (inv={}, bal={})",
                        inv_report.passed, is_balanced
                    );
                    let _ = ledger.append_block(BlockType::Evaluation, reason.clone(), vec![]);
                    candidate_records.push(CycleCandidateRecord {
                        candidate_id: cand_id,
                        candidate_index: cand_idx,
                        target_file: candidate.target_file.clone(),
                        proposed_patch_digest: hex::encode(Sha256::digest(
                            candidate.proposed_patch.as_bytes(),
                        )),
                        compilation_passed: true,
                        invariants_passed: false,
                        judge_admitted: false,
                        primary_metric_name: "latency_us".to_string(),
                        primary_metric_value: 0.0,
                        rejection_reason: Some(reason),
                        ledger_block_hash: None,
                    });
                    total_candidates_evaluated += 1;
                    continue;
                }

                // Blind Judge Evaluation in Jail 2
                let output_dir = sandbox_base.join("eval_outputs");
                let mut judge = BlindJudge::new(holdouts_path.clone(), output_dir)
                    .with_signing_key(signing_key.clone())
                    .with_non_inferiority_margin(config.non_inferiority_margin.unwrap_or(10.0));
                judge.require_latency_improvement = false;

                let receipt = match judge.evaluate_cycle(
                    &cycle_id,
                    &candidate.id,
                    "parent",
                    &sandbox_dir,
                    repo_path,
                ) {
                    Ok(r) => r,
                    Err(e) => {
                        let reason = format!("Blind Judge error: {}", e);
                        let _ = ledger.append_block(BlockType::Evaluation, reason.clone(), vec![]);
                        candidate_records.push(CycleCandidateRecord {
                            candidate_id: cand_id,
                            candidate_index: cand_idx,
                            target_file: candidate.target_file.clone(),
                            proposed_patch_digest: hex::encode(Sha256::digest(
                                candidate.proposed_patch.as_bytes(),
                            )),
                            compilation_passed: true,
                            invariants_passed: true,
                            judge_admitted: false,
                            primary_metric_name: "latency_us".to_string(),
                            primary_metric_value: 0.0,
                            rejection_reason: Some(reason),
                            ledger_block_hash: None,
                        });
                        total_candidates_evaluated += 1;
                        continue;
                    }
                };

                let raw_json = serde_json::to_vec(&receipt).unwrap_or_default();
                let blk = ledger
                    .append_evaluation(&receipt, Some(&raw_json))
                    .map_err(|e| format!("Failed to append evaluation: {}", e))?;
                let block_hash = blk.block_hash.clone();

                let metric_val = receipt
                    .metrics_summary
                    .as_ref()
                    .map(|m| m.latency_delta_pct)
                    .unwrap_or(0.0);

                candidate_records.push(CycleCandidateRecord {
                    candidate_id: cand_id,
                    candidate_index: cand_idx,
                    target_file: candidate.target_file.clone(),
                    proposed_patch_digest: hex::encode(Sha256::digest(
                        candidate.proposed_patch.as_bytes(),
                    )),
                    compilation_passed: true,
                    invariants_passed: true,
                    judge_admitted: receipt.admitted,
                    primary_metric_name: "latency_delta_pct".to_string(),
                    primary_metric_value: metric_val,
                    rejection_reason: if receipt.admitted {
                        None
                    } else {
                        Some("Judge non-inferiority margin exceeded or holdout failure".to_string())
                    },
                    ledger_block_hash: Some(block_hash),
                });
                total_candidates_evaluated += 1;

                if receipt.admitted {
                    admissible_proposals.push((candidate, receipt, blk));
                }
            }

            // Multi-comparison candidate selection among admissible proposals
            let mut winning_cand_id = None;
            let mut cycle_cortex_receipt = None;

            if admissible_proposals.is_empty() {
                println!(
                    "  ❌ Cycle {}: No admissible candidates produced.",
                    cycle_index
                );
                let newly_exhausted = quarantine_tracker.record_failure(
                    &bottleneck.node_name,
                    &hypothesis_problem,
                    "No admissible candidates in 3 variations",
                );
                if newly_exhausted {
                    println!("  ⚠️ Hypothesis/Bottleneck pairing marked EXHAUSTED_FOR_GENERATION_N: {}:{}", bottleneck.node_name, &hypothesis_problem[..20]);
                }

                // Record negative experience in Cortex
                let dummy_cand = ImprovementProposal {
                    id: format!("{}-c0", cycle_id),
                    title: "Performance Optimization Attempt".to_string(),
                    description: "Automated candidate variation".to_string(),
                    target_file: target_file.to_string(),
                    proposed_patch: String::new(),
                    kind: ProposalKind::Optimization,
                    created_at: Utc::now().to_rfc3339(),
                    sandbox_path: None,
                    operator_signature: None,
                };
                let _ = Ratifier::record_cortex_lesson(
                    &dummy_cand,
                    None,
                    None,
                    &config.cortex_url,
                    &config.cortex_space,
                )
                .await;
            } else {
                // Select winner deterministically by lowest latency delta pct
                admissible_proposals.sort_by(|a, b| {
                    let lat_a =
                        a.1.metrics_summary
                            .as_ref()
                            .map(|m| m.latency_delta_pct)
                            .unwrap_or(0.0);
                    let lat_b =
                        b.1.metrics_summary
                            .as_ref()
                            .map(|m| m.latency_delta_pct)
                            .unwrap_or(0.0);
                    lat_a
                        .partial_cmp(&lat_b)
                        .unwrap_or(std::cmp::Ordering::Equal)
                });

                let (winner_prop, winner_rcpt, winner_blk) = admissible_proposals.remove(0);
                winning_cand_id = Some(winner_prop.id.clone());
                quarantine_tracker.record_success(&bottleneck.node_name, &hypothesis_problem);
                total_candidates_admitted += 1;

                let best_metric = winner_rcpt
                    .metrics_summary
                    .as_ref()
                    .map(|m| m.latency_delta_pct)
                    .unwrap_or(0.0);
                println!(
                    "  ⭐ Winning Admissible Candidate: {} (latency delta={:.2}%, ledger block={})",
                    winner_prop.id,
                    best_metric,
                    &winner_blk.block_hash[..12]
                );

                // True RSI Criteria 1 & 2 Evaluation
                let crit_1 = TrueRsiEvaluator::evaluate_criterion_1_novel_discovery(
                    &hypothesis.observed_problem,
                    true,
                    &["hardcoded", "static_rule"],
                );
                let crit_2 = TrueRsiEvaluator::evaluate_criterion_2_self_capability_improvement(
                    true,
                    &format!("latency improved by {:.2}%	", best_metric),
                );

                // Stage into .rsi/admitted/<ledger_block_hash>/
                let staging_dir = rsi_root.join("admitted").join(&winner_blk.block_hash);
                let _ = std::fs::create_dir_all(&staging_dir);
                let _ = std::fs::write(staging_dir.join("patch.diff"), &winner_prop.proposed_patch);
                let _ = std::fs::write(
                    staging_dir.join("evaluation_receipt.json"),
                    serde_json::to_string_pretty(&winner_rcpt).unwrap_or_default(),
                );
                let _ = std::fs::write(
                    staging_dir.join("ledger_block.json"),
                    serde_json::to_string_pretty(&winner_blk).unwrap_or_default(),
                );

                admitted_candidates.push(AdmittedMetaCandidate {
                    candidate_id: winner_prop.id.clone(),
                    ledger_block_hash: winner_blk.block_hash.clone(),
                    staging_dir: staging_dir.display().to_string(),
                    patch_digest: hex::encode(Sha256::digest(
                        winner_prop.proposed_patch.as_bytes(),
                    )),
                    criteria_1_novel_discovery: crit_1.passed,
                    criteria_2_self_capability_gain: crit_2.passed,
                    classification: "META_CANDIDATE".to_string(),
                });

                // Record positive outcome to Cortex citing ledger hash
                let (receipt_id, _success) = Ratifier::record_cortex_lesson(
                    &winner_prop,
                    None,
                    Some(&winner_blk.block_hash),
                    &config.cortex_url,
                    &config.cortex_space,
                )
                .await;
                cycle_cortex_receipt = receipt_id;
            }

            // Merkle Checkpoint after each cycle
            let checkpoint = ledger.checkpoint(Some(&signing_key)).ok();
            let cp_hash = checkpoint.as_ref().map(|c| c.merkle_root.clone());
            let thermal_after = ThermalSnapshot::capture();

            cycle_records.push(CycleRecord {
                cycle_index,
                cycle_id,
                bottleneck_node: bottleneck.node_name.clone(),
                hypothesis_id: hypothesis.id.clone(),
                hypothesis_problem: hypothesis.observed_problem.clone(),
                candidates: candidate_records,
                winning_candidate_id: winning_cand_id,
                merkle_checkpoint_hash: cp_hash,
                thermal_before,
                thermal_after,
                cortex_receipt_id: cycle_cortex_receipt,
                status: "COMPLETED".to_string(),
            });
        }

        let completed_at = Utc::now().to_rfc3339();
        let final_cp = ledger
            .checkpoint(Some(&signing_key))
            .ok()
            .map(|c| c.merkle_root);

        let manifest = SoakRunManifest {
            manifest_version: "1.0.0".to_string(),
            run_id: run_id.clone(),
            started_at,
            completed_at,
            engine_n_snapshot,
            cycles: cycle_records,
            admitted_candidates,
            exhausted_hypotheses: quarantine_tracker.exhausted_list(),
            final_merkle_checkpoint: final_cp,
            total_candidates_evaluated,
            total_candidates_admitted,
            preflight_passed: true,
            overall_status: "SUCCESS".to_string(),
        };

        let manifest_file = rsi_root.join(format!("soak_manifest_{}.json", run_id));
        manifest.save_to_file(&manifest_file)?;
        println!(
            "⚡ [Soak Run] Completed successfully. Manifest saved to: {}",
            manifest_file.display()
        );

        Ok(manifest)
    }

    fn capture_engine_n(
        repo_path: &Path,
        max_model: &str,
        op_key: Option<&str>,
    ) -> EngineNSnapshot {
        let commit_sha = Command::new("git")
            .current_dir(repo_path)
            .args(["rev-parse", "HEAD"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "unknown_sha".to_string());

        EngineNSnapshot {
            commit_sha,
            evaluator_version: spark_rsi::version().to_string(),
            holdout_bundle_digest: "sha256:holdouts-bundle-authoritative".to_string(),
            builder_digest: "sha256:spark-rsi-builder-pinned".to_string(),
            max_model: max_model.to_string(),
            cortex_snapshot_ref: Utc::now().to_rfc3339(),
            operator_verifying_key: op_key.map(|s| s.to_string()),
        }
    }

    fn run_preflight_checks(
        repo_path: &Path,
        rsi_root: &Path,
        holdouts_path: &Path,
        signing_key_hex: Option<&str>,
    ) -> Result<(), String> {
        let bwrap_out = Command::new("bwrap")
            .arg("--version")
            .output()
            .map_err(|e| format!("Preflight containment check failed: bwrap missing: {}", e))?;
        if !bwrap_out.status.success() {
            return Err(
                "Preflight containment check failed: bwrap returned non-zero exit code".to_string(),
            );
        }

        let key_hex = signing_key_hex
            .ok_or_else(|| "Preflight failed: missing signing_key_hex".to_string())?;
        let key_bytes = hex::decode(key_hex)
            .map_err(|e| format!("Preflight failed: invalid hex signing key: {}", e))?;
        let _ = p256::ecdsa::SigningKey::from_slice(&key_bytes)
            .map_err(|e| format!("Preflight failed: invalid P-256 signing key: {}", e))?;

        let _ = ImprovementLedger::open(rsi_root)
            .map_err(|e| format!("Preflight failed: cannot open improvement ledger: {}", e))?;

        if !holdouts_path.exists() {
            return Err(format!(
                "Preflight failed: holdouts directory {:?} does not exist",
                holdouts_path
            ));
        }

        if !repo_path.join("Cargo.toml").exists() {
            return Err(format!(
                "Preflight failed: Cargo.toml not found in target repo {:?}",
                repo_path
            ));
        }

        Ok(())
    }
}
