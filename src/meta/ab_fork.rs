use crate::meta::benchmark_suite::{MetaBenchmarkMetrics, MetaBenchmarkSuite};
use crate::meta::three_criteria::{TrueRsiEvaluator, TrueRsiVerdict};
use crate::meta::tier::TierGovernance;
use crate::models::ImprovementProposal;
use p256::ecdsa::VerifyingKey;
use sha2::{Digest, Sha256};
use std::path::Path;

pub struct AbForkEvaluator;

impl AbForkEvaluator {
    /// Engine N judges candidate Engine N+1 on an isolated A/B fork
    pub fn evaluate_tier2_candidate(
        _parent_repo: &Path,
        _candidate_repo: &Path,
        proposal: &ImprovementProposal,
        parent_metrics: &MetaBenchmarkMetrics,
        candidate_metrics: &MetaBenchmarkMetrics,
        operator_verifying_key: Option<&VerifyingKey>,
        non_inferiority_margin_pct: f64,
        downstream_evidence: Option<(&str, &str, &str, &str)>, // (meta_hash, down_cycle, down_hash, proof)
    ) -> Result<TrueRsiVerdict, String> {
        // 1. Validate containment boundaries: Engine N+1 cannot modify immutable boundaries
        TierGovernance::validate_tier2_candidate_boundaries(&proposal.target_file)?;

        // 2. Validate Operator Cryptographic Signature for Tier 2
        let op_key = operator_verifying_key.ok_or_else(|| {
            "Tier 2 Meta-Improvement Fails Closed: Operator cryptographic verifying key required for Engine self-modification.".to_string()
        })?;

        let sig_hex = proposal.operator_signature.as_deref().ok_or_else(|| {
            "Tier 2 Meta-Improvement Fails Closed: Missing operator cryptographic signature on candidate proposal.".to_string()
        })?;

        let proposal_digest = Sha256::digest(proposal.proposed_patch.as_bytes());
        TierGovernance::verify_operator_authorization(&proposal_digest, sig_hex, op_key)?;

        // 3. A/B Benchmark Evaluation (Engine N measures Engine N+1)
        let comparison = MetaBenchmarkSuite::evaluate_candidate(
            parent_metrics,
            candidate_metrics,
            non_inferiority_margin_pct,
        );

        if !comparison.passed_non_inferiority {
            return Ok(TrueRsiVerdict {
                novel_discovery: crate::meta::three_criteria::CriterionResult {
                    criterion_name: "Criterion 1: Novel Discovery".to_string(),
                    passed: false,
                    evidence: "Candidate regressed beyond non-inferiority margins".to_string(),
                },
                self_capability_improvement: crate::meta::three_criteria::CriterionResult {
                    criterion_name: "Criterion 2: Self-Capability Improvement".to_string(),
                    passed: false,
                    evidence: "Candidate regressed on developmental latency or validity".to_string(),
                },
                recursive_persistence: crate::meta::three_criteria::CriterionResult {
                    criterion_name: "Criterion 3: Recursive Persistence & Compounding".to_string(),
                    passed: false,
                    evidence: "Evaluation aborted due to developmental regression".to_string(),
                },
                overall_classification: "REJECTED".to_string(),
                evidence_payload: None,
            });
        }

        // 4. Evaluate Three Criteria
        let c1 = TrueRsiEvaluator::evaluate_criterion_1_novel_discovery(
            &proposal.description,
            true,
            &["hardcoded_fix", "static_rule"],
        );

        let metrics_summary = format!(
            "Discovery delta: {:.2}%, Validity delta: {:.2}%, Latency delta: {:.2}%",
            comparison.discovery_rate_delta_pct,
            comparison.hypothesis_validity_delta_pct,
            comparison.latency_delta_pct
        );
        let c2 = TrueRsiEvaluator::evaluate_criterion_2_self_capability_improvement(
            comparison.passed_amplification,
            &metrics_summary,
        );

        let c3 = match downstream_evidence {
            Some((meta_hash, down_cycle, down_hash, proof)) => {
                TrueRsiEvaluator::evaluate_criterion_3_recursive_persistence(
                    Some(meta_hash),
                    Some(down_cycle),
                    Some(down_hash),
                    Some(proof),
                )
            }
            None => {
                TrueRsiEvaluator::evaluate_criterion_3_recursive_persistence(None, None, None, None)
            }
        };

        Ok(TrueRsiEvaluator::evaluate_full(c1, c2, c3))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ProposalKind;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};

    #[test]
    fn test_ab_fork_evaluation_full_lifecycle() {
        let signing_key = SigningKey::from_bytes(&[77u8; 32].into()).unwrap();
        let verifying_key = signing_key.verifying_key();

        let patch = "pub fn new_engine_feature() {}";
        let digest = Sha256::digest(patch.as_bytes());
        let sig: Signature = signing_key.sign(&digest);
        let sig_hex = hex::encode(sig.to_bytes());

        let proposal = ImprovementProposal {
            id: "meta-prop-01".to_string(),
            title: "accelerate proposal engine".to_string(),
            description: "Empirical discovery: graph centrality bottleneck in propose/mod.rs".to_string(),
            target_file: "src/propose/mod.rs".to_string(),
            proposed_patch: patch.to_string(),
            kind: ProposalKind::MetaEngineImprovement,
            created_at: "now".to_string(),
            sandbox_path: None,
            operator_signature: Some(sig_hex),
        };

        let parent_metrics = MetaBenchmarkMetrics::new(10.0, 0.85, 1.0, 400.0, 4096);
        let candidate_metrics = MetaBenchmarkMetrics::new(13.0, 0.90, 1.3, 350.0, 4096);

        let res = AbForkEvaluator::evaluate_tier2_candidate(
            Path::new("."),
            Path::new("."),
            &proposal,
            &parent_metrics,
            &candidate_metrics,
            Some(&verifying_key),
            1.0,
            Some((
                "meta-hash-01",
                "cycle-downstream-02",
                "downstream-hash-02",
                "Downstream cycle 2 improved throughput using generation 1 acceleration",
            )),
        );

        assert!(res.is_ok());
        let verdict = res.unwrap();
        assert_eq!(verdict.overall_classification, "TRUE_RSI");
        assert!(verdict.novel_discovery.passed);
        assert!(verdict.self_capability_improvement.passed);
        assert!(verdict.recursive_persistence.passed);
        assert!(verdict.evidence_payload.is_some());
    }
}
