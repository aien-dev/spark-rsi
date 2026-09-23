use crate::actor::judge::BlindJudge;
use crate::balance::BalanceKernel;
use crate::evaluator::EvaluationReceipt;
use crate::graph::{CapabilityGraph, CapabilityNode};
use crate::isolation::BuildJail;
use crate::ledger::{BlockType, ImprovementLedger, LedgerBlock};
use crate::models::{RsiConfig, RsiCycleResult};
use crate::observe::observe_codebase;
use crate::propose::{
    CortexExperienceClient, DefectCategory, DiagnosticContext, HypothesisContract, MaxClient,
    ProposalGenerator,
};
use crate::ratify::Ratifier;
use crate::supervisor::daemon::{resolve_supervisor_secret, SupervisorConfig, SupervisorDaemon};
use crate::supervisor::{GenerationInfo, GenerationState};
use crate::verifier::InvariantVerifier;
use sha2::Digest;
use std::path::{Path, PathBuf};
use std::time::Instant;
use uuid::Uuid;

pub struct RsiEngine;

impl RsiEngine {
    pub async fn run_cycle(config: &RsiConfig) -> Result<RsiCycleResult, String> {
        let start = Instant::now();
        let cycle_id = format!("cycle-{}", Uuid::new_v4().simple());
        let repo_path = Path::new(&config.target_repo);
        let rsi_root = repo_path.join(&config.rsi_root);

        // 1. Immutable Provenance: Fail closed if ledger cannot be opened
        let ledger = ImprovementLedger::open(&rsi_root).map_err(|e| {
            format!(
                "Fatal: Improvement Ledger must be active and accessible at {:?}: {}",
                rsi_root, e
            )
        })?;

        // 2. Strict Holdouts: Fail closed if holdout test suite is missing
        let holdouts_path = config
            .holdouts_dir
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| rsi_root.join("holdouts"));

        if !holdouts_path.exists() {
            return Err(format!(
                "Fatal: Missing holdouts directory at {:?}. Production evaluation fails closed.",
                holdouts_path
            ));
        }

        // 3. Cryptographic Signer: Fail closed if signing key is missing or invalid
        let signing_key_hex = config.signing_key_hex.as_ref().ok_or_else(|| {
            "Fatal: Missing cryptographic signing key (signing_key_hex). Production evaluation fails closed.".to_string()
        })?;
        let key_bytes = hex::decode(signing_key_hex)
            .map_err(|e| format!("Fatal: Invalid signing_key_hex: {}", e))?;
        let signing_key = p256::ecdsa::SigningKey::from_slice(&key_bytes)
            .map_err(|e| format!("Fatal: Invalid P-256 signing key: {}", e))?;

        // 4. Telemetry Ingestion & CapabilityGraph Population
        let telemetry = observe_codebase(repo_path)?;
        let mut graph = CapabilityGraph::new();
        graph.add_node(
            CapabilityNode::new("Observe", "Observe Subsystem", "observe")
                .with_resource_metrics(50.0, 1024, 0.0),
        );
        let is_high_drive = telemetry.soul_tension.drive_score > 0.8; // zero telemetry
        graph.add_node(
            CapabilityNode::new("Propose", "Propose Subsystem", "propose").with_resource_metrics(
                400.0,
                4096,
                if is_high_drive { 0.25 } else { 0.0 },
            ),
        );
        graph.add_node(
            CapabilityNode::new("BuildJail", "Build Jail", "isolation")
                .with_resource_metrics(150.0, 2048, 0.0),
        );
        graph.add_node(
            CapabilityNode::new("JudgeEvaluation", "Judge Evaluation", "actor")
                .with_resource_metrics(250.0, 8192, 0.0),
        );
        graph.add_node(
            CapabilityNode::new("SupervisorCanary", "Supervisor Canary", "supervisor")
                .with_resource_metrics(100.0, 4096, 0.0),
        );
        graph.add_node(
            CapabilityNode::new("CortexCommit", "Cortex Commit", "ratify")
                .with_resource_metrics(50.0, 1024, 0.0),
        );

        graph.add_edge("Observe", "Propose", 400.0, 1.0);
        graph.add_edge("Propose", "BuildJail", 150.0, 1.0);
        graph.add_edge("BuildJail", "JudgeEvaluation", 250.0, 1.0);
        graph.add_edge("JudgeEvaluation", "SupervisorCanary", 100.0, 1.0);
        graph.add_edge("SupervisorCanary", "CortexCommit", 50.0, 1.0);

        let top_bottleneck = graph.top_bottleneck();

        // 5. Bottleneck Hypothesis Contract & Cortex Recall
        let hypothesis = top_bottleneck.as_ref().map(|b| {
            HypothesisContract::new(
                &format!("hypo-{}", Uuid::new_v4().simple()),
                &cycle_id,
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
        });

        let cortex =
            CortexExperienceClient::new(&config.cortex_url).with_space(&config.cortex_space);
        let cortex_query = if let Some(ref h) = hypothesis {
            format!("{} {}", h.observed_problem, h.suspected_root_cause)
        } else {
            "performance bottleneck repair".to_string()
        };
        let past_lessons = cortex.recall_lessons(&cortex_query, 3).await;

        // 6. Proposer: Modular MAX Proposer & Constrained Candidates
        let mut candidates = Vec::new();
        let max_client = MaxClient::new(&config.max_url, &config.max_model);

        if max_client.is_available().await {
            let target_file = "src/lib.rs";
            let full_path = repo_path.join(target_file);
            let content = std::fs::read_to_string(&full_path).unwrap_or_default();

            let mut diag = DiagnosticContext::from_violations(
                &cycle_id,
                target_file,
                &content,
                DefectCategory::PerformanceRegression,
                vec![format!(
                    "Bottleneck identified at {:?}",
                    top_bottleneck.as_ref().map(|b| &b.node_name)
                )],
                past_lessons.clone(),
            );
            if let Some(h) = hypothesis.clone() {
                diag = diag.with_hypothesis(h);
            }

            if let Ok(prop) = ProposalGenerator::propose_from_diagnosis(&max_client, &diag).await {
                candidates.push(prop);
            }
        }

        if let Some(prop) = ProposalGenerator::scan_and_propose_unslop(repo_path) {
            candidates.push(prop);
        }

        let mut maybe_invariants = None;
        let mut maybe_balance = None;
        let mut maybe_receipt: Option<EvaluationReceipt> = None;
        let mut maybe_generation: Option<GenerationInfo> = None;
        let mut maybe_ledger_block: Option<LedgerBlock> = None;
        let mut maybe_ratification = None;
        let mut winning_proposal: Option<crate::models::ImprovementProposal> = None;
        let mut success = true;

        let sandbox_base = Path::new(&config.sandbox_root);

        for mut candidate in candidates {
            // Tier Governance: Check candidate tier and boundaries
            let tier = crate::meta::TierGovernance::classify_proposal(&candidate);
            if tier == crate::meta::CandidateTier::Tier2Engine {
                if let Err(e) = crate::meta::TierGovernance::validate_tier2_candidate_boundaries(
                    &candidate.target_file,
                ) {
                    let _ = ledger.append_block(
                        BlockType::Evaluation,
                        format!("Tier 2 Invariant Rejected: {}", e),
                        vec![],
                    );
                    continue;
                }
                if let Some(ref op_key_hex) = config.operator_key_hex {
                    let key_bytes = match hex::decode(op_key_hex) {
                        Ok(b) => b,
                        Err(_) => {
                            let _ = ledger.append_block(
                                BlockType::Evaluation,
                                "Invalid operator_key_hex".to_string(),
                                vec![],
                            );
                            continue;
                        }
                    };
                    let op_key = match p256::ecdsa::VerifyingKey::from_sec1_bytes(&key_bytes) {
                        Ok(k) => k,
                        Err(_) => {
                            let _ = ledger.append_block(
                                BlockType::Evaluation,
                                "Invalid operator verifying key".to_string(),
                                vec![],
                            );
                            continue;
                        }
                    };
                    let digest = sha2::Sha256::digest(candidate.proposed_patch.as_bytes());
                    let sig = candidate.operator_signature.as_deref().unwrap_or_default();
                    if crate::meta::TierGovernance::verify_operator_authorization(
                        &digest, sig, &op_key,
                    )
                    .is_err()
                    {
                        let _ = ledger.append_block(
                            BlockType::Evaluation,
                            "Operator signature unauthorized".to_string(),
                            vec![],
                        );
                        continue;
                    }
                }
            }

            let sandbox_dir = match ProposalGenerator::stage_in_sandbox(
                &mut candidate,
                repo_path,
                sandbox_base,
            ) {
                Ok(dir) => dir,
                Err(e) => {
                    let _ = ledger.append_block(
                        BlockType::Evaluation,
                        format!("Stage failed: {}", e),
                        vec![],
                    );
                    continue;
                }
            };

            // 7. Jail 1 Build: Compile candidate artifact strictly in isolated Build Jail if Cargo.toml is present
            // and no pre-existing candidate binary is available or Rust source was modified
            let needs_build = sandbox_dir.join("Cargo.toml").exists()
                && (!sandbox_dir.join("spark-rsi").exists()
                    || candidate.target_file.ends_with(".rs"));
            if needs_build {
                let build_jail =
                    BuildJail::new("spark-rsi-builder:latest", &sandbox_dir, &sandbox_dir);
                let (build_success, build_stdout, build_stderr) =
                    match build_jail.execute_bwrap(&["cargo", "build", "--release", "--offline"]) {
                        Ok(res) => res,
                        Err(e) => {
                            let _ = ledger.append_block(
                                BlockType::Evaluation,
                                format!("Build Jail exec error: {}", e),
                                vec![],
                            );
                            continue;
                        }
                    };

                if !build_success {
                    let err_msg = format!(
                        "Candidate failed to compile in Build Jail:
{}",
                        build_stderr
                    );
                    let raw_err = serde_json::to_string(&serde_json::json!({
                        "proposal_id": candidate.id,
                        "stage": "build_jail",
                        "error": err_msg,
                        "stdout": build_stdout,
                    }))
                    .unwrap_or_default();
                    let _ = ledger.append_block(BlockType::Evaluation, raw_err, vec![]);
                    continue;
                }
            }

            // 8. Invariant Verification in isolated sandbox
            // Non-code proposals skip compile and test gates: the sandbox cannot
            // resolve sibling path dependencies and markdown carries no build risk.
            let is_code_change = candidate.target_file.ends_with(".rs")
                || candidate.target_file.ends_with(".toml")
                || candidate.target_file.ends_with("Cargo.lock");
            let inv_report =
                InvariantVerifier::run_full_verification_scoped(&sandbox_dir, is_code_change);
            let passed = inv_report.passed;

            // 9. Balance: evaluate soul tension via Mojo kernel
            let balance_verdict = BalanceKernel::evaluate(
                telemetry.soul_tension.drive_score,
                telemetry.soul_tension.humanity_score,
                Some(&config.mojo_kernel_path),
            )?;
            let is_balanced = balance_verdict.verdict == "balanced";

            if !passed || !is_balanced {
                let raw_fail = serde_json::to_string(&serde_json::json!({
                    "proposal_id": candidate.id,
                    "invariants_passed": passed,
                    "is_balanced": is_balanced,
                    "notes": inv_report.notes,
                    "compile_error": inv_report.compilation_error,
                    "test_summary": inv_report.test_output_summary,
                }))
                .unwrap_or_default();
                let _ = ledger.append_block(BlockType::Evaluation, raw_fail, vec![]);
                continue;
            }

            // 10. Objective Evaluation via BlindJudge with holdouts and cryptographic signing key
            let output_dir = Path::new(&config.sandbox_root).join("eval_outputs");
            let mut judge = BlindJudge::new(holdouts_path.clone(), output_dir)
                .with_signing_key(signing_key.clone())
                .with_non_inferiority_margin(config.non_inferiority_margin.unwrap_or(5.0));
            judge.require_latency_improvement = config.require_latency_improvement;
            judge.require_build_verification = is_code_change;

            let receipt = match judge.evaluate_cycle(
                &cycle_id,
                &candidate.id,
                "parent",
                &sandbox_dir,
                repo_path,
            ) {
                Ok(rcpt) => rcpt,
                Err(e) => {
                    let _ = ledger.append_block(
                        BlockType::Evaluation,
                        format!("Judge evaluation error: {}", e),
                        vec![],
                    );
                    continue;
                }
            };

            let raw_json = serde_json::to_vec(&receipt).unwrap_or_default();
            let blk = ledger
                .append_evaluation(&receipt, Some(&raw_json))
                .map_err(|e| format!("Fatal: Failed to append evaluation to ledger: {}", e))?;
            let ledger_hash = blk.block_hash.clone();
            let judge_admitted = receipt.admitted;

            if !judge_admitted {
                let _ = Ratifier::record_cortex_lesson(
                    &candidate,
                    None,
                    Some(&ledger_hash),
                    &config.cortex_url,
                    &config.cortex_space,
                )
                .await;
                continue;
            }

            maybe_invariants = Some(inv_report);
            maybe_balance = Some(balance_verdict);
            maybe_receipt = Some(receipt);
            maybe_ledger_block = Some(blk);
            winning_proposal = Some(candidate);
            break;
        }

        if let Some(ref proposal) = winning_proposal {
            let sandbox_dir = sandbox_base.join(&proposal.id);
            // 11. Async Supervisor Daemon Probation & Canary Quota
            let supervisor_sock = rsi_root.join("supervisor.sock");
            let active_link = rsi_root.join("active.sock");
            let supervisor_config = SupervisorConfig {
                rsi_root: rsi_root.clone(),
                socket_path: supervisor_sock.clone(),
                memory_limit_mb: 49152,
                canary_target: config.canary_target,
                max_latency_us: 1_000_000,
                max_error_rate: 0.0,
                shared_secret: resolve_supervisor_secret(),
            };
            let supervisor_daemon = SupervisorDaemon::new(supervisor_config);

            // Stage canary generation
            let mut gen_info = supervisor_daemon
                .stage_canary(
                    &proposal.id,
                    &sandbox_dir,
                    &maybe_receipt.as_ref().unwrap().receipt_digest,
                )
                .await?;

            // Production promotion counts measured observations only.
            // This cycle has no execution feed, so the quota fails closed.
            // A caller-supplied success and a fixed latency are not observations.
            let patch_bytes = proposal.proposed_patch.as_bytes();
            let mut patch_hasher = sha2::Sha256::new();
            patch_hasher.update(patch_bytes);
            let patch_digest: [u8; 32] = patch_hasher.finalize().into();
            let candidate_digest = hex::encode(patch_digest);
            let quota = crate::canary_observation::admit_production_quota(
                &[],
                &candidate_digest,
                config.canary_target,
            );

            if let Err(reason) = quota {
                success = false;
                supervisor_daemon
                    .trigger_instant_rollback(&active_link)
                    .await?;
                let _ = ledger.append_rollback(&proposal.id, &reason);
                let ledger_hash = maybe_ledger_block.as_ref().map(|b| b.block_hash.as_str());
                let _ = Ratifier::record_cortex_lesson(
                    proposal,
                    None,
                    ledger_hash,
                    &config.cortex_url,
                    &config.cortex_space,
                )
                .await;
            } else {
                // Safety envelope gate: no promotion without a signed canary
                // evaluation receipt from the production signer. Fails closed.
                let envelope_signer = std::sync::Arc::new(
                    aien_evaluation_protocol::SoftwareP256Signer::new(signing_key.clone()),
                );
                use aien_evaluation_protocol::VerifierSigner as _RsiEnvelopeSignerExt;
                let envelope_verifier = aien_evaluation_protocol::VerifierIdentity {
                    principal_id: "rsi-production-daemon".to_string(),
                    key_id: envelope_signer.key_fingerprint(),
                    trust_epoch: 1,
                    trusted_build_digest: aien_protocol_types::Digest32(patch_digest),
                    policy_bundle_digest: aien_protocol_types::Digest32({
                        let mut h = sha2::Sha256::new();
                        h.update(
                            format!("rsi-production-policy:{}", config.canary_target).as_bytes(),
                        );
                        h.finalize().into()
                    }),
                };
                let envelope = crate::safety_envelope::CanarySafetyEnvelope::new(
                    envelope_verifier,
                    envelope_signer,
                );
                let subject = aien_protocol_types::ArtifactRef {
                    artifact_id: Uuid::new_v4(),
                    digest: aien_protocol_types::Digest32(patch_digest),
                    media_type: "application/rust-patch".to_string(),
                    byte_size: patch_bytes.len() as u64,
                };
                let started_at = aien_protocol_types::Timestamp(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64,
                );
                if let Err(e) = envelope
                    .evaluate_and_enforce(&subject, "rsi-production", started_at, || async {
                        Ok(())
                    })
                    .await
                {
                    success = false;
                    supervisor_daemon
                        .trigger_instant_rollback(&active_link)
                        .await?;
                    let _ = ledger.append_rollback(
                        &proposal.id,
                        &format!("Safety envelope rejected promotion: {}", e),
                    );
                    let ledger_hash = maybe_ledger_block.as_ref().map(|b| b.block_hash.as_str());
                    let _ = Ratifier::record_cortex_lesson(
                        proposal,
                        None,
                        ledger_hash,
                        &config.cortex_url,
                        &config.cortex_space,
                    )
                    .await;
                } else {
                    // Canary probation passed and envelope admitted. Promote to Durable and record in ledger
                    supervisor_daemon
                        .supervisor
                        .atomic_symlink_swap(&proposal.id)?;
                    gen_info.state = GenerationState::Durable;

                    let prom_blk = ledger
                        .append_promotion(
                            &gen_info,
                            &maybe_receipt.as_ref().unwrap().receipt_digest,
                        )
                        .map_err(|e| {
                            format!("Fatal: Failed to append promotion to ledger: {}", e)
                        })?;
                    let prom_hash = prom_blk.block_hash.clone();
                    maybe_ledger_block = Some(prom_blk);
                    maybe_generation = Some(gen_info);

                    // 12. Ratify proposal, commit to git, and record in Cortex memory tied to ledger hash
                    let rat = Ratifier::ratify_proposal(
                        proposal,
                        maybe_invariants.as_ref().unwrap(),
                        repo_path,
                        Some(&prom_hash),
                        &config.cortex_url,
                        &config.cortex_space,
                    )
                    .await?;
                    maybe_ratification = Some(rat);
                }
            }
        } else {
            let balance_verdict = BalanceKernel::evaluate(
                telemetry.soul_tension.drive_score,
                telemetry.soul_tension.humanity_score,
                Some(&config.mojo_kernel_path),
            )?;
            maybe_balance = Some(balance_verdict);
        }
        // Checkpoint ledger Merkle root with TPM signer
        let _ = ledger.checkpoint(Some(&signing_key));

        let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;

        Ok(RsiCycleResult {
            cycle_id,
            telemetry,
            proposal: winning_proposal,
            invariants: maybe_invariants,
            balance: maybe_balance,
            receipt: maybe_receipt,
            generation: maybe_generation,
            ledger_block: maybe_ledger_block,
            ratification: maybe_ratification,
            success,
            elapsed_ms,
        })
    }

    pub async fn run_daemon(config: RsiConfig) -> Result<(), String> {
        tracing::info!(
            "Starting continuous RSI daemon for repository {:?} with interval {}s",
            config.target_repo,
            config.loop_interval_secs
        );

        loop {
            match Self::run_cycle(&config).await {
                Ok(res) => {
                    tracing::info!(
                        "RSI cycle {} completed in {:.2}ms (success: {}, proposed: {}, admitted: {})",
                        res.cycle_id,
                        res.elapsed_ms,
                        res.success,
                        res.proposal.is_some(),
                        res.receipt.as_ref().map(|r| r.admitted).unwrap_or(true)
                    );
                }
                Err(e) => {
                    tracing::error!("RSI cycle failed with error: {}", e);
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(config.loop_interval_secs)).await;
        }
    }
}
