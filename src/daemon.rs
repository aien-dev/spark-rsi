use crate::actor::judge::BlindJudge;
use crate::balance::BalanceKernel;
use crate::evaluator::EvaluationReceipt;
use crate::models::{RsiConfig, RsiCycleResult};
use crate::observe::observe_codebase;
use crate::propose::ProposalGenerator;
use crate::ratify::Ratifier;
use crate::supervisor::{GenerationInfo, HostSupervisor};
use crate::verifier::InvariantVerifier;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;
use uuid::Uuid;

pub struct RsiEngine;

impl RsiEngine {
    pub async fn run_cycle(config: &RsiConfig) -> Result<RsiCycleResult, String> {
        let start = Instant::now();
        let cycle_id = format!("cycle-{}", Uuid::new_v4().simple());
        let repo_path = Path::new(&config.target_repo);

        // 1. Observe codebase telemetry
        let telemetry = observe_codebase(repo_path)?;

        // 2. Propose improvement
        let mut maybe_proposal = ProposalGenerator::scan_and_propose_unslop(repo_path);

        let mut maybe_invariants = None;
        let maybe_balance;
        let mut maybe_receipt: Option<EvaluationReceipt> = None;
        let mut maybe_generation: Option<GenerationInfo> = None;
        let mut maybe_ratification = None;
        let mut success = true;

        if let Some(ref mut proposal) = maybe_proposal {
            let sandbox_base = Path::new(&config.sandbox_root);
            let sandbox_dir = ProposalGenerator::stage_in_sandbox(proposal, repo_path, sandbox_base)?;

            // 3. Verify Invariants in isolated sandbox
            let inv_report = InvariantVerifier::run_full_verification(&sandbox_dir);
            let passed = inv_report.passed;
            maybe_invariants = Some(inv_report.clone());

            // 4. Balance: evaluate soul tension via Mojo kernel
            let balance_verdict = BalanceKernel::evaluate(
                telemetry.soul_tension.drive_score,
                telemetry.soul_tension.humanity_score,
                Some(&config.mojo_kernel_path),
            )?;
            let is_balanced = balance_verdict.verdict == "balanced";
            maybe_balance = Some(balance_verdict);

            if !passed || !is_balanced {
                success = false;
            } else {
                // 5. Objective Evaluation via BlindJudge if holdouts exist or are configured
                let holdouts_path = config
                    .holdouts_dir
                    .as_ref()
                    .map(PathBuf::from)
                    .unwrap_or_else(|| repo_path.join(".rsi").join("holdouts"));

                let mut judge_admitted = true;
                if holdouts_path.exists() {
                    // Ensure candidate executable exists in sandbox
                    if crate::actor::judge::find_executable(&sandbox_dir).is_none() {
                        let _ = Command::new("cargo")
                            .arg("build")
                            .current_dir(&sandbox_dir)
                            .output();
                    }

                    let output_dir = Path::new(&config.sandbox_root).join("eval_outputs");
                    let mut judge = BlindJudge::new(holdouts_path, output_dir);
                    judge.require_latency_improvement = config.require_latency_improvement;

                    if let Some(ref key_hex) = config.signing_key_hex {
                        let key_bytes = hex::decode(key_hex)
                            .map_err(|e| format!("Invalid signing_key_hex: {}", e))?;
                        let signing_key = p256::ecdsa::SigningKey::from_slice(&key_bytes)
                            .map_err(|e| format!("Invalid P-256 signing key: {}", e))?;
                        judge = judge.with_signing_key(signing_key);
                    }

                    match judge.evaluate_cycle(&cycle_id, &proposal.id, "parent", &sandbox_dir, repo_path) {
                        Ok(receipt) => {
                            judge_admitted = receipt.admitted;
                            maybe_receipt = Some(receipt);
                        }
                        Err(e) => {
                            tracing::warn!("BlindJudge evaluation failed closed: {}", e);
                            judge_admitted = false;
                        }
                    }
                }

                if !judge_admitted {
                    success = false;
                } else {
                    // 6. Candidate Promotion via HostSupervisor rather than in-place mutation
                    let rsi_root = repo_path.join(&config.rsi_root);
                    let supervisor = HostSupervisor::new(&rsi_root, 49_152);
                    let manifest_digest = maybe_receipt
                        .as_ref()
                        .map(|r| r.receipt_digest.clone())
                        .unwrap_or_else(|| {
                            let mut hasher = Sha256::new();
                            hasher.update(proposal.proposed_patch.as_bytes());
                            format!("{:x}", hasher.finalize())
                        });

                    // Stage generation directory under supervisor
                    let mut gen_info = supervisor.stage_generation(
                        &proposal.id,
                        &sandbox_dir,
                        &manifest_digest,
                    )?;

                    // Atomic symlink swap: switches active generation
                    supervisor.atomic_symlink_swap(&proposal.id)?;

                    // Record canary transaction
                    supervisor.record_canary_transaction(&mut gen_info, true, 1)?;
                    maybe_generation = Some(gen_info);

                    // 7. Ratify proposal and record to git & Cortex memory
                    let rat = Ratifier::ratify_proposal(
                        proposal,
                        &inv_report,
                        repo_path,
                        &config.cortex_url,
                        &config.cortex_space,
                    )
                    .await?;
                    maybe_ratification = Some(rat);
                }
            }
        } else {
            // Still run balance check on current state
            let balance_verdict = BalanceKernel::evaluate(
                telemetry.soul_tension.drive_score,
                telemetry.soul_tension.humanity_score,
                Some(&config.mojo_kernel_path),
            )?;
            maybe_balance = Some(balance_verdict);
        }

        let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;

        Ok(RsiCycleResult {
            cycle_id,
            telemetry,
            proposal: maybe_proposal,
            invariants: maybe_invariants,
            balance: maybe_balance,
            receipt: maybe_receipt,
            generation: maybe_generation,
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
