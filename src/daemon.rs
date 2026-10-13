use crate::actor::judge::BlindJudge;
use crate::balance::BalanceKernel;
use crate::canary::identity::{digest_file, tree_digest};
use crate::canary::{
    admit_sealed_quota, CanaryAdapterManifest, CanaryWorkloadManifest, CandidateIdentity,
    LoadedAdapterManifest, PinnedWorkload,
};
use crate::dual::ScarcityDiagnostic;
use crate::evaluator::EvaluationReceipt;
use crate::isolation::BuildJail;
use crate::ledger::{BlockType, ImprovementLedger, LedgerBlock};
use crate::measure::{
    build_capability_graph, check_claim, measure_stages, CycleSampleRecord, MeasureContext,
    SampleLog, Stage, StageClock, StageMeasurement, StageOutcome, SCHEMA_VERSION,
};
use crate::models::{
    CanaryExecutionRecord, CanarySummary, GateDecisionRecord, QuotaDecisionRecord, RsiConfig,
    RsiCycleResult, ENVELOPE_REFERENCE_NOTE,
};
use crate::observe::observe_codebase;
use crate::propose::{
    CortexExperienceClient, DefectCategory, DiagnosticContext, HypothesisContract, MaxClient,
    ProposalGenerator,
};
use crate::ratify::Ratifier;
use crate::supervisor::canary_exec::{CanaryExecutor, ExecutionOutcome, ExecutorConfig};
use crate::supervisor::daemon::{resolve_supervisor_secret, SupervisorConfig, SupervisorDaemon};
use crate::supervisor::{GenerationInfo, GenerationState};
use crate::verifier::InvariantVerifier;
use sha2::Digest;
use std::path::{Path, PathBuf};
use std::time::Instant;
use uuid::Uuid;

pub struct RsiEngine;

impl RsiEngine {
    /// Runs one cycle and records its stage samples. A cycle that returns an error is a partial
    /// cycle: its samples go to the partial-cycle log and are never ranked. A cycle that ends
    /// early for a normal reason (no candidate, judge refused, canary quota refused) is complete
    /// for the stages it ran.
    pub async fn run_cycle(config: &RsiConfig) -> Result<RsiCycleResult, String> {
        let cycle_id = format!("cycle-{}", Uuid::new_v4().simple());
        let repo_path = Path::new(&config.target_repo);
        let rsi_root = repo_path.join(&config.rsi_root);
        let ctx = MeasureContext::for_config(config, repo_path);
        let mut clock = StageClock::new();
        let result = Self::run_cycle_inner(config, &cycle_id, &ctx, &mut clock).await;
        Self::record_stage_samples(&rsi_root, &cycle_id, &ctx, &clock, result.is_ok());
        result
    }

    fn record_stage_samples(
        rsi_root: &Path,
        cycle_id: &str,
        ctx: &MeasureContext,
        clock: &StageClock,
        completed: bool,
    ) {
        if clock.is_empty() {
            return;
        }
        let record = CycleSampleRecord {
            schema_version: SCHEMA_VERSION,
            cycle_id: cycle_id.to_string(),
            workload_key: ctx.workload_key.clone(),
            execution_profile_fingerprint: ctx.fingerprint.clone(),
            execution_profile: ctx.profile.clone(),
            stages: clock.samples(),
            source_commit: ctx.source_commit.clone(),
            recorded_at: chrono::Utc::now().to_rfc3339(),
        };
        let log = SampleLog::new(rsi_root);
        let written = if completed {
            log.append_complete(&record)
        } else {
            log.append_partial(&record)
        };
        if let Err(e) = written {
            tracing::warn!("stage samples for {} were not recorded: {}", cycle_id, e);
        }
    }

    async fn run_cycle_inner(
        config: &RsiConfig,
        cycle_id: &str,
        ctx: &MeasureContext,
        clock: &mut StageClock,
    ) -> Result<RsiCycleResult, String> {
        let start = Instant::now();
        let cycle_id = cycle_id.to_string();
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
        let observe_guard = clock.guard(Stage::Observe);
        let telemetry = observe_codebase(repo_path)?;
        observe_guard.complete(StageOutcome::Ok);

        // Ranking reads measurements from completed prior cycles only. This cycle's own samples
        // are appended after it ends, and its id is excluded as well.
        let measurements = measure_stages(
            SampleLog::new(&rsi_root).read_complete(),
            &cycle_id,
            ctx,
            config,
        );
        let graph = build_capability_graph(&measurements)?;
        let top_bottleneck = graph.top_bottleneck();
        let diagnosis_measured = top_bottleneck.as_ref().is_some_and(|b| {
            Stage::ALL.iter().any(|s| {
                s.id() == b.node_id
                    && matches!(measurements.get(s), Some(StageMeasurement::Measured { .. }))
            })
        });

        // 4b. DUAL scarcity reading (ADR 0031 section 7.5). Diagnostic only: read
        // after ranking, never fed into rank_bottlenecks, hard invariants,
        // admission, ratification or promotion. Unconfigured = Unavailable(Missing).
        let scarcity = match config.dual_price_vector_dir.as_deref() {
            Some(dir) => ScarcityDiagnostic::load_from_dir(Path::new(dir)),
            None => ScarcityDiagnostic::default(),
        };

        // 5. Bottleneck Hypothesis Contract & Cortex Recall
        let hypothesis = top_bottleneck.as_ref().map(|b| {
            HypothesisContract::from_bottleneck(
                &format!("hypo-{}", Uuid::new_v4().simple()),
                &cycle_id,
                b,
                config.measure_target_improvement_pct,
            )
            .with_protected_metric("correctness", 0.0)
            .with_falsification_test("assert!(receipt.passed_all_hard_invariants)")
        });

        let propose_started = Instant::now();
        let mut propose_outcome = StageOutcome::Ok;

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
                {
                    let mut violations = vec![format!(
                        "Bottleneck identified at {:?}",
                        top_bottleneck.as_ref().map(|b| &b.node_name)
                    )];
                    // Rationale text only, and only when a price vector is configured.
                    if config.dual_price_vector_dir.is_some() {
                        violations.push(format!(
                            "DUAL scarcity reading (diagnostic only, no authority): {}",
                            scarcity.summary()
                        ));
                    }
                    violations
                },
                past_lessons.clone(),
            );
            if let Some(h) = hypothesis.clone() {
                diag = diag.with_hypothesis(h);
            }

            match ProposalGenerator::propose_from_diagnosis(&max_client, &diag).await {
                Ok(prop) => candidates.push(prop),
                Err(_) => propose_outcome = StageOutcome::Failed,
            }
        }

        if let Some(prop) = ProposalGenerator::scan_and_propose_unslop(repo_path) {
            candidates.push(prop);
        }
        clock.record(Stage::Propose, propose_started.elapsed(), propose_outcome);

        let mut maybe_invariants = None;
        let mut maybe_balance = None;
        let mut maybe_receipt: Option<EvaluationReceipt> = None;
        let mut maybe_generation: Option<GenerationInfo> = None;
        let mut maybe_ledger_block: Option<LedgerBlock> = None;
        let mut maybe_ratification = None;
        let mut winning_proposal: Option<crate::models::ImprovementProposal> = None;
        let mut success = true;
        let mut canary_summary: Option<CanarySummary> = None;
        let mut canary_build: Option<(LoadedAdapterManifest, PathBuf)> = None;
        let mut pinned_workload: Option<PinnedWorkload> = None;

        let sandbox_base = Path::new(&config.sandbox_root);

        for mut candidate in candidates {
            // Claim policy: a performance claim needs a measured diagnosis. Refused before
            // anything is staged.
            if let Err(e) = check_claim(
                &candidate.kind,
                config.require_latency_improvement,
                diagnosis_measured,
            ) {
                let _ = ledger.append_block(BlockType::Evaluation, e, vec![]);
                continue;
            }

            // Declared-target gate before anything is staged: normalized path,
            // no `..`, inside the declared roots, not a root-of-trust file.
            if let Err(e) = crate::diff_gate::check_declared_target(
                &candidate.target_file,
                &config.ratify_roots,
            ) {
                let _ = ledger.append_block(
                    BlockType::Evaluation,
                    format!("Declared target refused: {}", e),
                    vec![],
                );
                continue;
            }

            // Tier Governance: Check candidate tier and boundaries
            let tier = crate::meta::TierGovernance::classify_proposal(&candidate);
            if tier == crate::meta::CandidateTier::Tier2Engine {
                if config.operator_key_hex.is_none() {
                    // Engine changes need operator authorization; no key means no authorization.
                    let _ = ledger.append_block(
                        BlockType::Evaluation,
                        "Tier 2 candidate refused: no operator key configured".to_string(),
                        vec![],
                    );
                    continue;
                }
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

            // Canary applicability. An executable change always goes through canary admission;
            // only a kind the operator listed in `canary_exempt_kinds` can skip it, and only
            // when nothing executable is involved.
            let is_code_change = candidate.target_file.ends_with(".rs")
                || candidate.target_file.ends_with(".toml")
                || candidate.target_file.ends_with("Cargo.lock");
            let adapter_declared = CanaryAdapterManifest::is_declared(&sandbox_dir);
            let heuristic_build = sandbox_dir.join("Cargo.toml").exists()
                && (!sandbox_dir.join("spark-rsi").exists()
                    || candidate.target_file.ends_with(".rs"));
            let executable_change = is_code_change || heuristic_build || adapter_declared;
            let exempt = !executable_change && config.canary_exempt_kinds.contains(&candidate.kind);
            let mut cand_summary = CanarySummary {
                applicable: !exempt,
                exemption: exempt.then(|| {
                    format!(
                        "kind {:?} is exempt by configuration and the change is not executable",
                        candidate.kind
                    )
                }),
                ..Default::default()
            };
            // 6b. Eligibility, fail closed before any worker starts: the evaluated tree must
            // ship a valid adapter manifest, the operator's workload must be pinned and match,
            // and the adapter must name that workload. An ineligible candidate still runs the
            // judge so its evaluation is on record, then is refused at the canary stage.
            let mut canary_target_build: Option<(LoadedAdapterManifest, PathBuf)> = None;
            if !exempt {
                'eligibility: {
                    let adapter = match CanaryAdapterManifest::load_from_tree(&sandbox_dir) {
                        Ok(a) => a,
                        Err(e) => {
                            let _ = ledger.append_block(
                                BlockType::Evaluation,
                                format!("Canary refused, candidate not eligible: {}", e),
                                vec![],
                            );
                            cand_summary.refusal = Some(e);
                            break 'eligibility;
                        }
                    };
                    if pinned_workload.is_none() {
                        match load_pinned_workload(config, &rsi_root) {
                            Ok(w) => pinned_workload = Some(w),
                            Err(e) => {
                                let _ = ledger.append_block(
                                    BlockType::Evaluation,
                                    format!("Canary workload refused: {}", e),
                                    vec![],
                                );
                                return Err(format!("Fatal: canary workload refused: {}", e));
                            }
                        }
                    }
                    let workload = pinned_workload.as_ref().expect("loaded above");
                    cand_summary.workload_digest = Some(workload.digest.clone());
                    if adapter.manifest.workload_id != workload.manifest.workload_id {
                        let e = format!(
                            "adapter names workload {:?}, the pinned workload is {:?}",
                            adapter.manifest.workload_id, workload.manifest.workload_id
                        );
                        let _ = ledger.append_block(
                            BlockType::Evaluation,
                            format!("Canary refused, candidate not eligible: {}", e),
                            vec![],
                        );
                        cand_summary.refusal = Some(e);
                        break 'eligibility;
                    }
                    let built = adapter
                        .manifest
                        .executable_path(Path::new(BUILD_OUTPUT_ROOT));
                    // A file left by an earlier build is never the executable under evaluation.
                    if built.symlink_metadata().is_ok() {
                        if let Err(e) = std::fs::remove_file(&built) {
                            let e = format!("cannot clear stale executable {:?}: {}", built, e);
                            let _ = ledger.append_block(BlockType::Evaluation, e.clone(), vec![]);
                            cand_summary.refusal = Some(e);
                            break 'eligibility;
                        }
                    }
                    cand_summary.eligible = true;
                    canary_target_build = Some((adapter, built));
                }
            }

            // 7. Jail 1 Build: Compile candidate artifact strictly in isolated Build Jail. The
            // `spark-rsi` heuristic never decides this for a canary-eligible tree: it is always
            // built, so the adapter executable exists fresh from this exact tree.
            let needs_build = heuristic_build || canary_target_build.is_some();
            if needs_build {
                let build_started = Instant::now();
                let build_jail =
                    BuildJail::new("spark-rsi-builder:latest", &sandbox_dir, &sandbox_dir);
                let (build_success, build_stdout, build_stderr) =
                    match build_jail.execute_bwrap(&["cargo", "build", "--release", "--offline"]) {
                        Ok(res) => res,
                        Err(e) => {
                            clock.record(
                                Stage::BuildJail,
                                build_started.elapsed(),
                                StageOutcome::Failed,
                            );
                            let _ = ledger.append_block(
                                BlockType::Evaluation,
                                format!("Build Jail exec error: {}", e),
                                vec![],
                            );
                            continue;
                        }
                    };

                clock.record(
                    Stage::BuildJail,
                    build_started.elapsed(),
                    if build_success {
                        StageOutcome::Ok
                    } else {
                        StageOutcome::Failed
                    },
                );
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
            let built_missing = canary_target_build.as_ref().and_then(|(_, built)| {
                let is_file = built
                    .symlink_metadata()
                    .map(|m| m.file_type().is_file())
                    .unwrap_or(false);
                (!is_file).then(|| {
                    format!(
                        "the build did not produce the adapter executable {:?}; not eligible for canary",
                        built
                    )
                })
            });
            if let Some(e) = built_missing {
                let _ = ledger.append_block(BlockType::Evaluation, e.clone(), vec![]);
                cand_summary.eligible = false;
                cand_summary.refusal = Some(e);
                canary_target_build = None;
            }

            // The JudgeEvaluation stage covers invariant verification, the balance reading and the
            // judge's evaluation of this candidate.
            let eval_started = Instant::now();
            // 8. Invariant Verification in isolated sandbox
            // Non-code proposals skip compile and test gates: the sandbox cannot
            // resolve sibling path dependencies and markdown carries no build risk.
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
                clock.record(
                    Stage::JudgeEvaluation,
                    eval_started.elapsed(),
                    StageOutcome::Refused,
                );
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
                    clock.record(
                        Stage::JudgeEvaluation,
                        eval_started.elapsed(),
                        StageOutcome::Failed,
                    );
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
            clock.record(
                Stage::JudgeEvaluation,
                eval_started.elapsed(),
                if judge_admitted {
                    StageOutcome::Ok
                } else {
                    StageOutcome::Refused
                },
            );

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
            canary_summary = Some(cand_summary);
            canary_build = canary_target_build;
            winning_proposal = Some(candidate);
            break;
        }

        let canary_started = Instant::now();
        if let Some(ref proposal) = winning_proposal {
            let sandbox_dir = sandbox_base.join(&proposal.id);
            // 11. Supervisor-driven canary and admission. Sequence: Collect -> Seal -> Verify ->
            // Quota admission -> Safety envelope -> Judge / promotion gate -> Durable.
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
            let supervisor_daemon = SupervisorDaemon::new(supervisor_config.clone());
            let mut summary = canary_summary.take().unwrap_or_default();
            let receipt_digest = maybe_receipt.as_ref().unwrap().receipt_digest.clone();
            let judge_ledger_hash = maybe_ledger_block.as_ref().map(|b| b.block_hash.clone());

            // Stage canary generation
            let mut gen_info = supervisor_daemon
                .stage_canary(&proposal.id, &sandbox_dir, &receipt_digest)
                .await?;

            let patch_bytes = proposal.proposed_patch.as_bytes();
            let patch_digest: [u8; 32] = sha2::Sha256::digest(patch_bytes).into();
            let candidate_digest = hex::encode(patch_digest);

            let admitted = Self::admit_canary(
                config,
                &ledger,
                proposal,
                &sandbox_dir,
                &patch_digest,
                canary_build.as_ref(),
                pinned_workload.as_ref(),
                &supervisor_daemon,
                &supervisor_config,
                &mut gen_info,
                &mut summary,
            )
            .await;

            // The subject of the envelope is the candidate identity binding (or, for a
            // configured exemption, the patch digest). Quota refusal rolls back here.
            let subject_digest = match admitted {
                Ok(digest) => Some(digest),
                Err(reason) => {
                    success = false;
                    Self::roll_back(&supervisor_daemon, &active_link, &ledger, proposal, &reason)
                        .await?;
                    Self::record_decision(&ledger, &proposal.id, &summary);
                    let _ = Ratifier::record_cortex_lesson(
                        proposal,
                        None,
                        judge_ledger_hash.as_deref(),
                        &config.cortex_url,
                        &config.cortex_space,
                    )
                    .await;
                    None
                }
            };

            if let Some(subject_digest) = subject_digest {
                // Safety envelope gate: no promotion without a signed canary
                // evaluation receipt from the production signer. Fails closed. It evaluates
                // through the deterministic reference backend, which is recorded as such.
                let envelope_signer = std::sync::Arc::new(
                    aien_evaluation_protocol::SoftwareP256Signer::new(signing_key.clone()),
                );
                use aien_evaluation_protocol::VerifierSigner as _RsiEnvelopeSignerExt;
                let envelope_verifier = aien_evaluation_protocol::VerifierIdentity {
                    principal_id: "rsi-production-daemon".to_string(),
                    key_id: envelope_signer.key_fingerprint(),
                    trust_epoch: 1,
                    trusted_build_digest: aien_protocol_types::Digest32(subject_digest),
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
                    digest: aien_protocol_types::Digest32(subject_digest),
                    media_type: "application/rust-patch".to_string(),
                    byte_size: patch_bytes.len() as u64,
                };
                let started_at = aien_protocol_types::Timestamp(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64,
                );
                summary.envelope_note = Some(ENVELOPE_REFERENCE_NOTE.to_string());
                if let Err(e) = envelope
                    .evaluate_and_enforce(&subject, "rsi-production", started_at, || async {
                        Ok(())
                    })
                    .await
                {
                    success = false;
                    summary.envelope = Some(GateDecisionRecord {
                        passed: false,
                        detail: e.to_string(),
                    });
                    let reason = format!("Safety envelope rejected promotion: {}", e);
                    Self::roll_back(&supervisor_daemon, &active_link, &ledger, proposal, &reason)
                        .await?;
                    Self::record_decision(&ledger, &proposal.id, &summary);
                    let _ = Ratifier::record_cortex_lesson(
                        proposal,
                        None,
                        judge_ledger_hash.as_deref(),
                        &config.cortex_url,
                        &config.cortex_space,
                    )
                    .await;
                } else {
                    summary.envelope = Some(GateDecisionRecord {
                        passed: true,
                        detail: "signed canary evaluation receipt issued".to_string(),
                    });
                    let gate = crate::promotion_gate::check_v2_promotion(
                        maybe_receipt.as_ref().unwrap(),
                        config.judge_public_key_hex.as_deref(),
                        signing_key.verifying_key(),
                        config.judge_policy_file.as_deref(),
                        &crate::promotion_gate::PromotionSubject {
                            // The parent this daemon handed its judge (a label, not a commit), so
                            // only a receipt for this cycle's own tree can match.
                            parent_id: "parent",
                            path: &proposal.target_file,
                            content_sha256: &candidate_digest,
                            // Re-read the generation the swap promotes, right before the swap;
                            // unreadable never matches.
                            disk_sha256: &crate::actor::judge::sha256_file(
                                &supervisor_daemon
                                    .supervisor
                                    .generations_root
                                    .join(&proposal.id)
                                    .join(&proposal.target_file),
                            )
                            .unwrap_or_else(|e| format!("unreadable: {}", e)),
                        },
                    );
                    if let Err(e) = gate {
                        // No promotion without a version 2 receipt from the separate judge that
                        // binds this exact change. Version 1 receipts are history, never authority.
                        success = false;
                        summary.promotion_gate = Some(GateDecisionRecord {
                            passed: false,
                            detail: e.to_string(),
                        });
                        let reason = format!("Promotion gate refused: {}", e);
                        Self::roll_back(
                            &supervisor_daemon,
                            &active_link,
                            &ledger,
                            proposal,
                            &reason,
                        )
                        .await?;
                        Self::record_decision(&ledger, &proposal.id, &summary);
                    } else {
                        summary.promotion_gate = Some(GateDecisionRecord {
                            passed: true,
                            detail: "version 2 judge receipt accepted".to_string(),
                        });
                        Self::record_decision(&ledger, &proposal.id, &summary);
                        // Quota, envelope and promotion gate all passed. Only now is the
                        // generation Durable.
                        supervisor_daemon
                            .supervisor
                            .atomic_symlink_swap(&proposal.id)?;
                        gen_info.state = GenerationState::Durable;

                        let prom_blk = ledger
                            .append_promotion(&gen_info, &receipt_digest)
                            .map_err(|e| {
                                format!("Fatal: Failed to append promotion to ledger: {}", e)
                            })?;
                        let prom_hash = prom_blk.block_hash.clone();
                        maybe_ledger_block = Some(prom_blk);
                        maybe_generation = Some(gen_info);

                        // 12. Ratify proposal onto a review branch + patch (never the default branch), and record in Cortex memory tied to ledger hash
                        let commit_started = Instant::now();
                        let rat = Ratifier::ratify_proposal(
                            proposal,
                            maybe_invariants.as_ref().unwrap(),
                            repo_path,
                            &config.ratify_roots,
                            &Path::new(&config.rsi_root).join("patches"),
                            Some(&prom_hash),
                            &config.cortex_url,
                            &config.cortex_space,
                        )
                        .await?;
                        clock.record(
                            Stage::CortexCommit,
                            commit_started.elapsed(),
                            if rat.cortex_recorded {
                                StageOutcome::Ok
                            } else {
                                StageOutcome::Failed
                            },
                        );
                        maybe_ratification = Some(rat);
                    }
                }
            }
            canary_summary = Some(summary);
        } else {
            let balance_verdict = BalanceKernel::evaluate(
                telemetry.soul_tension.drive_score,
                telemetry.soul_tension.humanity_score,
                Some(&config.mojo_kernel_path),
            )?;
            maybe_balance = Some(balance_verdict);
        }
        if winning_proposal.is_some() {
            // The canary stage is the supervised block minus the CortexCommit time inside it.
            let canary_time = canary_started
                .elapsed()
                .saturating_sub(clock.duration(Stage::CortexCommit));
            clock.record(
                Stage::SupervisorCanary,
                canary_time,
                if success {
                    StageOutcome::Ok
                } else {
                    StageOutcome::Refused
                },
            );
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
            scarcity,
            canary: canary_summary,
        })
    }

    /// Rolls the staged generation back through the supervisor and records the reason.
    async fn roll_back(
        supervisor_daemon: &SupervisorDaemon,
        active_link: &Path,
        ledger: &ImprovementLedger,
        proposal: &crate::models::ImprovementProposal,
        reason: &str,
    ) -> Result<(), String> {
        supervisor_daemon
            .trigger_instant_rollback(active_link)
            .await?;
        let _ = ledger.append_rollback(&proposal.id, reason);
        Ok(())
    }

    /// Records the quota, envelope and promotion gate decisions for the generation. The
    /// envelope entry carries the reference-backend note.
    fn record_decision(ledger: &ImprovementLedger, generation_id: &str, summary: &CanarySummary) {
        let payload = serde_json::json!({
            "canary_decision": {
                "generation_id": generation_id,
                "identity_binding_digest": summary.identity_binding_digest,
                "log_digest": summary.log_digest,
                "commitment_block_hash": summary.commitment_block_hash,
                "quota": summary.quota,
                "envelope": summary.envelope,
                "envelope_note": summary.envelope_note,
                "promotion_gate": summary.promotion_gate,
            }
        });
        let _ = ledger.append_block(BlockType::Evaluation, payload.to_string(), vec![]);
    }

    /// Runs the supervisor-driven canary for the staged generation and the quota decision.
    /// Returns the digest the safety envelope takes as its subject, or the refusal reason; the
    /// caller rolls back on `Err`. A configured exemption skips the canary and returns the
    /// patch digest.
    #[allow(clippy::too_many_arguments)]
    async fn admit_canary(
        config: &RsiConfig,
        ledger: &ImprovementLedger,
        proposal: &crate::models::ImprovementProposal,
        sandbox_dir: &Path,
        patch_digest: &[u8; 32],
        build: Option<&(LoadedAdapterManifest, PathBuf)>,
        workload: Option<&PinnedWorkload>,
        supervisor_daemon: &SupervisorDaemon,
        supervisor_config: &SupervisorConfig,
        gen_info: &mut GenerationInfo,
        summary: &mut CanarySummary,
    ) -> Result<[u8; 32], String> {
        if let Some(refusal) = summary.refusal.as_ref().filter(|_| summary.applicable) {
            return Err(format!(
                "canary refused, candidate not eligible: {}",
                refusal
            ));
        }
        if !summary.applicable {
            return Ok(*patch_digest);
        }
        let (Some((adapter, built)), Some(workload)) = (build, workload) else {
            return Err(
                "canary applies but no adapter or pinned workload was resolved".to_string(),
            );
        };

        // Identity chain: patch, evaluated tree, built executable, generation.
        let evaluated_tree = tree_digest(sandbox_dir)?;
        let staged_tree = tree_digest(&gen_info.installed_path)?;
        if staged_tree != evaluated_tree {
            return Err(format!(
                "staged tree digest {} differs from the evaluated tree digest {}",
                staged_tree, evaluated_tree
            ));
        }
        let exe_name = built
            .file_name()
            .ok_or_else(|| format!("adapter executable path {:?} has no file name", built))?;
        let exe_dir = gen_info.installed_path.join(".rsi-canary");
        std::fs::create_dir_all(&exe_dir)
            .map_err(|e| format!("cannot create {:?}: {}", exe_dir, e))?;
        let staged_exe = exe_dir.join(exe_name);
        std::fs::copy(built, &staged_exe)
            .map_err(|e| format!("cannot stage executable {:?}: {}", built, e))?;
        let identity = CandidateIdentity::new(
            &hex::encode(patch_digest),
            &evaluated_tree,
            &digest_file(&staged_exe)?,
            &proposal.id,
        );
        identity.validate()?;
        let binding = identity.binding_digest();
        summary.identity_binding_digest = Some(binding.clone());
        summary.executable_digest = Some(identity.executable_digest.clone());

        // Collect and seal: the supervisor issues every request and measures every answer.
        let executor = CanaryExecutor::new(
            &supervisor_daemon.supervisor,
            supervisor_config.clone(),
            workload.clone(),
            identity.clone(),
            staged_exe,
            adapter.manifest.args.clone(),
            ExecutorConfig::default(),
        );
        let (sealed, exec_summary) = match executor.run(gen_info).await? {
            ExecutionOutcome::Sealed { sealed, summary } => (sealed, summary),
            ExecutionOutcome::Halted { .. } => {
                return Err("canary run halted without sealing; refusing".to_string())
            }
        };
        summary.execution = Some(CanaryExecutionRecord {
            requests_planned: exec_summary.requests_planned,
            issued: exec_summary.issued,
            verified_success: exec_summary.verified_success,
            wrong_result: exec_summary.wrong_result,
            timeout: exec_summary.timeout,
            invalid_response: exec_summary.invalid_response,
            connection_closed: exec_summary.connection_closed,
            rejections: exec_summary.rejections,
            ready: exec_summary.ready,
            reverted: exec_summary.reverted,
            first_failure: exec_summary.first_failure.clone(),
        });
        summary.log_digest = Some(sealed.seal.log_digest.clone());

        // The ledger holds the commitment before quota admission runs.
        let commitment = serde_json::json!({
            "canary_commitment": {
                "generation_id": identity.generation_id,
                "patch_digest": identity.patch_digest,
                "tree_digest": identity.tree_digest,
                "executable_digest": identity.executable_digest,
                "identity_binding_digest": binding,
                "workload_id": workload.manifest.workload_id,
                "workload_digest": workload.digest,
                "adapter_manifest_digest": adapter.digest,
                "sealed_log_path": sealed.path.as_ref().map(|p| p.display().to_string()),
                "log_digest": sealed.seal.log_digest,
                "observation_count": sealed.seal.observation_count,
                "qualifying_count": sealed.seal.qualifying_count,
                "rejection_count": sealed.rejections.len(),
            }
        });
        let block = ledger
            .append_block(BlockType::Evaluation, commitment.to_string(), vec![])
            .map_err(|e| format!("cannot commit the sealed log to the ledger: {}", e))?;
        summary.commitment_block_hash = Some(block.block_hash);

        // Quota admission: the one authority on evidence sufficiency.
        match admit_sealed_quota(&sealed, &identity, &workload.manifest, config.canary_target) {
            Ok(decision) => {
                summary.quota = Some(QuotaDecisionRecord {
                    admitted: true,
                    counted: Some(decision.counted),
                    target: decision.target,
                    refusal: None,
                });
            }
            Err(reason) => {
                let reason = match exec_summary.first_failure {
                    Some(f) => format!("{} (first failure: {})", reason, f),
                    None => reason,
                };
                summary.quota = Some(QuotaDecisionRecord {
                    admitted: false,
                    counted: None,
                    target: config.canary_target,
                    refusal: Some(reason.clone()),
                });
                return Err(reason);
            }
        }

        let mut subject = [0u8; 32];
        hex::decode_to_slice(&binding, &mut subject)
            .map_err(|e| format!("identity binding digest is not 32 bytes of hex: {}", e))?;
        Ok(subject)
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
                    if config.dual_price_vector_dir.is_some() {
                        tracing::info!(
                            "DUAL scarcity reading (diagnostic only): {}",
                            res.scarcity.summary()
                        );
                    }
                }
                Err(e) => {
                    tracing::error!("RSI cycle failed with error: {}", e);
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(config.loop_interval_secs)).await;
        }
    }
}

/// The root the build jail passes to cargo as CARGO_TARGET_DIR. The adapter's executable path
/// is relative to it.
const BUILD_OUTPUT_ROOT: &str = "/tmp/spark-rsi-target";

/// Loads the operator's canary workload. The digest pin is mandatory: an unpinned workload fails
/// closed, and a workload that does not hash to the pin is refused.
fn load_pinned_workload(config: &RsiConfig, rsi_root: &Path) -> Result<PinnedWorkload, String> {
    let pin = config.canary_workload_sha256.as_deref().ok_or_else(|| {
        "canary_workload_sha256 is not set: the operator must pin the canary workload".to_string()
    })?;
    let path = config
        .canary_workload_path
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| rsi_root.join("canary").join("workload.json"));
    CanaryWorkloadManifest::load_pinned(&path, pin)
}
