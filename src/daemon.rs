use crate::balance::BalanceKernel;
use crate::models::{RsiConfig, RsiCycleResult};
use crate::observe::observe_codebase;
use crate::propose::ProposalGenerator;
use crate::ratify::Ratifier;
use crate::verifier::InvariantVerifier;
use std::path::Path;
use std::time::Instant;
use uuid::Uuid;

pub struct RsiEngine;

impl RsiEngine {
    pub async fn run_cycle(config: &RsiConfig) -> Result<RsiCycleResult, String> {
        let start = Instant::now();
        let cycle_id = format!("cycle-{}", Uuid::new_v4().simple());
        let repo_path = Path::new(&config.target_repo);

        // 1. Observe
        let telemetry = observe_codebase(repo_path)?;

        // 2. Propose (check if an unslop sanitization or optimization proposal is needed)
        let mut maybe_proposal = ProposalGenerator::scan_and_propose_unslop(repo_path);

        let mut maybe_invariants = None;
        let maybe_balance;
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

            // 5. Ratify: if invariants passed and balance is maintained
            if passed && is_balanced {
                let rat = Ratifier::ratify_proposal(
                    proposal,
                    &inv_report,
                    repo_path,
                    &config.cortex_url,
                    &config.cortex_space,
                )
                .await?;
                maybe_ratification = Some(rat);
            } else {
                success = false;
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
                        "RSI cycle {} completed in {:.2}ms (success: {}, proposed: {})",
                        res.cycle_id,
                        res.elapsed_ms,
                        res.success,
                        res.proposal.is_some()
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
