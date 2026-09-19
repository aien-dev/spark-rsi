pub mod layers;
pub mod metrics;
pub mod stats;

pub use layers::*;
pub use metrics::{
    LatencyDistribution, LatencyTimer, ProcessMetricsSnapshot, RusageMetrics, StatmMetrics,
};
pub use stats::{
    BootstrapEstimate, FastPrng, FishersExactResult, PairedSample, StatisticalEngine,
    TailNonInferiorityResult,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvaluationMetricsSummary {
    pub latency_delta_pct: f64,
    pub p_value: f64,
    pub p95_ci_upper_degradation_pct: f64,
    pub p99_ci_upper_degradation_pct: f64,
    pub rss_growth_pct: f64,
    pub candidate_resident_mb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvaluationReceipt {
    pub cycle_id: String,
    pub candidate_id: String,
    pub parent_id: String,
    pub evaluated_at: String,
    pub evaluator_version: String,
    pub passed_all_hard_invariants: bool,
    pub passed_statistical_gates: bool,
    pub admitted: bool,
    pub layer_results: Vec<LayerResult>,
    pub metrics_summary: Option<EvaluationMetricsSummary>,
    pub receipt_digest: String,
    pub signature: Option<String>,
}

impl EvaluationReceipt {
    pub fn compute_digest(
        cycle_id: &str,
        candidate_id: &str,
        parent_id: &str,
        admitted: bool,
        layers: &[LayerResult],
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(cycle_id.as_bytes());
        hasher.update(candidate_id.as_bytes());
        hasher.update(parent_id.as_bytes());
        hasher.update(if admitted { b"1" } else { b"0" });

        for lr in layers {
            hasher.update(lr.layer_name.as_bytes());
            hasher.update(if lr.passed { b"1" } else { b"0" });
            hasher.update(lr.summary.as_bytes());
        }

        hex::encode(hasher.finalize())
    }

    pub fn save_to_file(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        fs::write(path, json).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn load_from_file(path: &Path) -> Result<Self, String> {
        let content = fs::read_to_string(path).map_err(|e| e.to_string())?;
        let receipt: Self = serde_json::from_str(&content).map_err(|e| e.to_string())?;
        Ok(receipt)
    }

    pub fn verify_digest(&self) -> bool {
        let expected = Self::compute_digest(
            &self.cycle_id,
            &self.candidate_id,
            &self.parent_id,
            self.admitted,
            &self.layer_results,
        );
        self.receipt_digest == expected
    }
}

pub struct ObjectiveEvaluator;

impl ObjectiveEvaluator {
    pub fn evaluate_candidate(
        cycle_id: &str,
        candidate_id: &str,
        parent_id: &str,
        correctness: CorrectnessEvaluation,
        security: SecurityEvaluation,
        style: StyleEvaluation,
        performance: PerformanceEvaluation,
        resource_efficiency: ResourceEfficiencyEvaluation,
        longitudinal_replay: LongitudinalReplayEvaluation,
    ) -> EvaluationReceipt {
        let layer_results = vec![
            correctness.to_layer_result(),
            security.to_layer_result(),
            style.to_layer_result(),
            performance.to_layer_result(),
            resource_efficiency.to_layer_result(),
            longitudinal_replay.to_layer_result(),
        ];

        let passed_all_hard_invariants = correctness.passed
            && security.passed
            && style.passed
            && longitudinal_replay.passed;

        let passed_statistical_gates = performance.passed && resource_efficiency.passed;

        let admitted = passed_all_hard_invariants && passed_statistical_gates;

        let receipt_digest = EvaluationReceipt::compute_digest(
            cycle_id,
            candidate_id,
            parent_id,
            admitted,
            &layer_results,
        );

        let metrics_summary = Some(EvaluationMetricsSummary {
            latency_delta_pct: performance.bootstrap_estimate.delta_pct,
            p_value: performance.bootstrap_estimate.p_value,
            p95_ci_upper_degradation_pct: performance.p95_non_inferiority.ci_95_upper_pct,
            p99_ci_upper_degradation_pct: performance.p99_non_inferiority.ci_95_upper_pct,
            rss_growth_pct: resource_efficiency.rss_growth_pct,
            candidate_resident_mb: (resource_efficiency.candidate_rss_kb / 1024) as u64,
        });

        EvaluationReceipt {
            cycle_id: cycle_id.to_string(),
            candidate_id: candidate_id.to_string(),
            parent_id: parent_id.to_string(),
            evaluated_at: chrono::Utc::now().to_rfc3339(),
            evaluator_version: crate::version().to_string(),
            passed_all_hard_invariants,
            passed_statistical_gates,
            admitted,
            layer_results,
            metrics_summary,
            receipt_digest,
            signature: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_objective_evaluator_all_pass() {
        let correctness = CorrectnessLayer::evaluate_synthetic(true, 10, 0, 2, 0, true);
        let security = SecurityLayer::evaluate_candidate(&["src/observe.rs".to_string()], "+ ok", 0);
        let style = StyleLayer::evaluate_text("Clean text without violations.");
        let perf = PerformanceEvaluation {
            bootstrap_estimate: BootstrapEstimate {
                sample_size: 30,
                resamples_count: 1000,
                observed_parent_mean: 100.0,
                observed_candidate_mean: 80.0,
                observed_delta_mean: -20.0,
                delta_pct: -20.0,
                ci_99_lower: -25.0,
                ci_99_upper: -15.0,
                p_value: 0.0001,
                is_statistically_significant: true,
            },
            p95_non_inferiority: TailNonInferiorityResult {
                percentile: 95.0,
                parent_val: 110.0,
                candidate_val: 90.0,
                observed_degradation_pct: -18.18,
                ci_95_upper_pct: 0.5,
                non_inferiority_margin_pct: 1.0,
                passes_non_inferiority: true,
            },
            p99_non_inferiority: TailNonInferiorityResult {
                percentile: 99.0,
                parent_val: 120.0,
                candidate_val: 95.0,
                observed_degradation_pct: -20.83,
                ci_95_upper_pct: 0.8,
                non_inferiority_margin_pct: 1.0,
                passes_non_inferiority: true,
            },
            target_metric_improved: true,
            non_target_metrics_safe: true,
            passed: true,
            violations: vec![],
        };
        let res_eff = ResourceEfficiencyEvaluation {
            parent_rss_kb: 50_000,
            candidate_rss_kb: 50_200,
            rss_growth_pct: 0.4,
            rss_growth_within_budget: true,
            host_memory_within_budget: true,
            context_switches_delta: 0,
            passed: true,
            violations: vec![],
        };
        let long_rep = LongitudinalReplayLayer::evaluate_results(
            &LongitudinalReplayLayer::builtin_regression_corpus(),
        );

        let receipt = ObjectiveEvaluator::evaluate_candidate(
            "cycle-001",
            "cand-001",
            "parent-000",
            correctness,
            security,
            style,
            perf,
            res_eff,
            long_rep,
        );

        assert!(receipt.passed_all_hard_invariants);
        assert!(receipt.passed_statistical_gates);
        assert!(receipt.admitted);
        assert!(receipt.verify_digest());
        assert_eq!(receipt.layer_results.len(), 6);
    }

    #[test]
    fn test_objective_evaluator_hard_invariant_rejection() {
        let correctness = CorrectnessLayer::evaluate_synthetic(false, 0, 0, 0, 0, true);
        let security = SecurityLayer::evaluate_candidate(&["src/observe.rs".to_string()], "+ ok", 0);
        let style = StyleLayer::evaluate_text("Clean text.");
        let perf = PerformanceEvaluation {
            bootstrap_estimate: BootstrapEstimate {
                sample_size: 30,
                resamples_count: 1000,
                observed_parent_mean: 100.0,
                observed_candidate_mean: 80.0,
                observed_delta_mean: -20.0,
                delta_pct: -20.0,
                ci_99_lower: -25.0,
                ci_99_upper: -15.0,
                p_value: 0.0001,
                is_statistically_significant: true,
            },
            p95_non_inferiority: TailNonInferiorityResult {
                percentile: 95.0,
                parent_val: 110.0,
                candidate_val: 90.0,
                observed_degradation_pct: -18.18,
                ci_95_upper_pct: 0.5,
                non_inferiority_margin_pct: 1.0,
                passes_non_inferiority: true,
            },
            p99_non_inferiority: TailNonInferiorityResult {
                percentile: 99.0,
                parent_val: 120.0,
                candidate_val: 95.0,
                observed_degradation_pct: -20.83,
                ci_95_upper_pct: 0.8,
                non_inferiority_margin_pct: 1.0,
                passes_non_inferiority: true,
            },
            target_metric_improved: true,
            non_target_metrics_safe: true,
            passed: true,
            violations: vec![],
        };
        let res_eff = ResourceEfficiencyEvaluation {
            parent_rss_kb: 50_000,
            candidate_rss_kb: 50_200,
            rss_growth_pct: 0.4,
            rss_growth_within_budget: true,
            host_memory_within_budget: true,
            context_switches_delta: 0,
            passed: true,
            violations: vec![],
        };
        let long_rep = LongitudinalReplayLayer::evaluate_results(
            &LongitudinalReplayLayer::builtin_regression_corpus(),
        );

        let receipt = ObjectiveEvaluator::evaluate_candidate(
            "cycle-002",
            "cand-002",
            "parent-000",
            correctness,
            security,
            style,
            perf,
            res_eff,
            long_rep,
        );

        assert!(!receipt.passed_all_hard_invariants);
        assert!(!receipt.admitted);
        assert!(receipt.verify_digest());
    }
}
