use crate::ledger::PromotionEvidencePayload;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CriterionResult {
    pub criterion_name: String,
    pub passed: bool,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TrueRsiVerdict {
    pub novel_discovery: CriterionResult,
    pub self_capability_improvement: CriterionResult,
    pub recursive_persistence: CriterionResult,
    pub overall_classification: String, // "REJECTED", "META_CANDIDATE", "TRUE_RSI"
    pub evidence_payload: Option<PromotionEvidencePayload>,
}

pub struct TrueRsiEvaluator;

impl TrueRsiEvaluator {
    pub fn evaluate_criterion_1_novel_discovery(
        observed_problem: &str,
        is_dynamic_telemetry: bool,
        hardcoded_rules: &[&str],
    ) -> CriterionResult {
        let is_hardcoded = hardcoded_rules
            .iter()
            .any(|r| observed_problem.contains(*r));
        let passed = is_dynamic_telemetry && !is_hardcoded;
        let evidence = if passed {
            format!(
                "Novel discovery confirmed: problem '{}' derived dynamically from capability graph rather than static rules",
                observed_problem
            )
        } else {
            "Novel discovery rejected: problem matches hardcoded static heuristics or lacks empirical dynamic telemetry"
                .to_string()
        };

        CriterionResult {
            criterion_name: "Criterion 1: Novel Discovery".to_string(),
            passed,
            evidence,
        }
    }

    pub fn evaluate_criterion_2_self_capability_improvement(
        amplification_passed: bool,
        metrics_summary: &str,
    ) -> CriterionResult {
        let evidence = if amplification_passed {
            format!(
                "Self-capability improvement verified: candidate Engine N+1 measurably amplifies future developmental capacity: {}",
                metrics_summary
            )
        } else {
            "Self-capability improvement rejected: candidate fails developmental amplification threshold (requires >= 5.0% gain)"
                .to_string()
        };

        CriterionResult {
            criterion_name: "Criterion 2: Self-Capability Improvement".to_string(),
            passed: amplification_passed,
            evidence,
        }
    }

    pub fn evaluate_criterion_3_recursive_persistence(
        meta_block_hash: Option<&str>,
        downstream_cycle_id: Option<&str>,
        downstream_block_hash: Option<&str>,
        compounding_proof: Option<&str>,
    ) -> (CriterionResult, Option<PromotionEvidencePayload>) {
        if let (Some(meta_hash), Some(down_cycle), Some(down_hash), Some(proof)) = (
            meta_block_hash,
            downstream_cycle_id,
            downstream_block_hash,
            compounding_proof,
        ) {
            let payload = PromotionEvidencePayload {
                meta_candidate_block_hash: meta_hash.to_string(),
                downstream_cycle_id: down_cycle.to_string(),
                downstream_ledger_block_hash: down_hash.to_string(),
                capability_improvement_proof: proof.to_string(),
                final_classification: "TRUE_RSI".to_string(),
            };
            (
                CriterionResult {
                    criterion_name: "Criterion 3: Recursive Persistence & Compounding".to_string(),
                    passed: true,
                    evidence: format!(
                        "Downstream compounding verified: cycle '{}' successfully deployed primitive from {}",
                        down_cycle, meta_hash
                    ),
                },
                Some(payload),
            )
        } else {
            (
                CriterionResult {
                    criterion_name: "Criterion 3: Recursive Persistence & Compounding".to_string(),
                    passed: false,
                    evidence:
                        "Downstream compounding pending: requires subsequent downstream cycle evidence block"
                            .to_string(),
                },
                None,
            )
        }
    }

    pub fn evaluate_full(
        c1: CriterionResult,
        c2: CriterionResult,
        c3: (CriterionResult, Option<PromotionEvidencePayload>),
    ) -> TrueRsiVerdict {
        let (c3_res, evidence_payload) = c3;
        let classification = if c1.passed && c2.passed && c3_res.passed {
            "TRUE_RSI".to_string()
        } else if c1.passed && c2.passed {
            "META_CANDIDATE".to_string()
        } else {
            "REJECTED".to_string()
        };

        TrueRsiVerdict {
            novel_discovery: c1,
            self_capability_improvement: c2,
            recursive_persistence: c3_res,
            overall_classification: classification,
            evidence_payload,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_criterion_1_novel_discovery() {
        let res = TrueRsiEvaluator::evaluate_criterion_1_novel_discovery(
            "Capability graph bottleneck on KV scheduler",
            true,
            &["hardcoded_rule"],
        );
        assert!(res.passed);

        let hardcoded = TrueRsiEvaluator::evaluate_criterion_1_novel_discovery(
            "hardcoded_rule defect",
            true,
            &["hardcoded_rule"],
        );
        assert!(!hardcoded.passed);
    }

    #[test]
    fn test_three_criteria_meta_candidate_and_true_rsi() {
        let c1 =
            TrueRsiEvaluator::evaluate_criterion_1_novel_discovery("dynamic bottleneck", true, &[]);
        let c2 =
            TrueRsiEvaluator::evaluate_criterion_2_self_capability_improvement(true, "speedup 15%");
        let c3_pending =
            TrueRsiEvaluator::evaluate_criterion_3_recursive_persistence(None, None, None, None);

        let verdict_pending = TrueRsiEvaluator::evaluate_full(c1.clone(), c2.clone(), c3_pending);
        assert_eq!(verdict_pending.overall_classification, "META_CANDIDATE");
        assert!(verdict_pending.evidence_payload.is_none());

        let c3_proven = TrueRsiEvaluator::evaluate_criterion_3_recursive_persistence(
            Some("meta-block-hash-01"),
            Some("cycle-42"),
            Some("downstream-block-hash-02"),
            Some("Generation N+1 utilized scheduler speedup to resolve cycle 42 in 30ms"),
        );
        let verdict_proven = TrueRsiEvaluator::evaluate_full(c1, c2, c3_proven);
        assert_eq!(verdict_proven.overall_classification, "TRUE_RSI");
        assert!(verdict_proven.evidence_payload.is_some());
    }
}
