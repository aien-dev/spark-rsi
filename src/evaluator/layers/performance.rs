use super::LayerResult;
use crate::evaluator::stats::{BootstrapEstimate, StatisticalEngine, TailNonInferiorityResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PerformanceEvaluation {
    pub bootstrap_estimate: BootstrapEstimate,
    pub p95_non_inferiority: TailNonInferiorityResult,
    pub p99_non_inferiority: TailNonInferiorityResult,
    pub target_metric_improved: bool,
    pub non_target_metrics_safe: bool,
    pub passed: bool,
    pub violations: Vec<String>,
}

impl PerformanceEvaluation {
    pub fn to_layer_result(&self) -> LayerResult {
        let score = if self.passed {
            1.0
        } else if self.non_target_metrics_safe {
            0.5
        } else {
            0.0
        };

        let summary = format!(
            "Performance: delta={:.2}%, p_val={:.4}, p95_ci_upper={:.2}%, p99_ci_upper={:.2}%, sig={}",
            self.bootstrap_estimate.delta_pct,
            self.bootstrap_estimate.p_value,
            self.p95_non_inferiority.ci_95_upper_pct,
            self.p99_non_inferiority.ci_95_upper_pct,
            if self.bootstrap_estimate.is_statistically_significant { "YES" } else { "NO" }
        );

        LayerResult {
            layer_name: "Performance".to_string(),
            is_hard_invariant: false,
            passed: self.passed,
            score,
            summary,
            violations: self.violations.clone(),
        }
    }
}

pub struct PerformanceLayer;

impl PerformanceLayer {
    pub fn evaluate_latencies(
        parent_latencies_us: &[f64],
        candidate_latencies_us: &[f64],
        target_is_latency_reduction: bool,
        resamples: usize,
        seed: Option<u64>,
    ) -> Result<PerformanceEvaluation, String> {
        Self::evaluate_latencies_with_policy(
            parent_latencies_us,
            candidate_latencies_us,
            target_is_latency_reduction,
            true,
            1.0,
            resamples,
            seed,
        )
    }

    pub fn evaluate_latencies_with_policy(
        parent_latencies_us: &[f64],
        candidate_latencies_us: &[f64],
        target_is_latency_reduction: bool,
        require_significant_improvement: bool,
        non_inferiority_margin_pct: f64,
        resamples: usize,
        seed: Option<u64>,
    ) -> Result<PerformanceEvaluation, String> {
        let mut violations = Vec::new();

        let boot = StatisticalEngine::bootstrap_paired_comparison(
            parent_latencies_us,
            candidate_latencies_us,
            resamples,
            seed,
        )?;

        let target_metric_improved = if target_is_latency_reduction {
            boot.is_statistically_significant && boot.observed_delta_mean < 0.0
        } else {
            boot.is_statistically_significant && boot.observed_delta_mean > 0.0
        };

        if require_significant_improvement && !target_metric_improved {
            violations.push(format!(
                "Target metric did not achieve statistical significance (p={:.4}, delta={:.2}%)",
                boot.p_value, boot.delta_pct
            ));
        }

        let p95_res = StatisticalEngine::evaluate_tail_non_inferiority(
            parent_latencies_us,
            candidate_latencies_us,
            95.0,
            non_inferiority_margin_pct,
            resamples,
            seed.map(|s| s.wrapping_add(1)),
        )?;

        if !p95_res.passes_non_inferiority {
            violations.push(format!(
                "p95 tail latency exceeded non-inferiority bound: upper_ci={:.2}% > {:.1}%",
                p95_res.ci_95_upper_pct, non_inferiority_margin_pct,
            ));
        }

        let p99_res = StatisticalEngine::evaluate_tail_non_inferiority(
            parent_latencies_us,
            candidate_latencies_us,
            99.0,
            non_inferiority_margin_pct,
            resamples,
            seed.map(|s| s.wrapping_add(2)),
        )?;

        if !p99_res.passes_non_inferiority {
            violations.push(format!(
                "p99 tail latency exceeded non-inferiority bound: upper_ci={:.2}% > {:.1}%",
                p99_res.ci_95_upper_pct, non_inferiority_margin_pct,
            ));
        }

        let non_target_metrics_safe =
            p95_res.passes_non_inferiority && p99_res.passes_non_inferiority;
        let passed = if require_significant_improvement {
            target_metric_improved && non_target_metrics_safe
        } else {
            non_target_metrics_safe
        };

        Ok(PerformanceEvaluation {
            bootstrap_estimate: boot,
            p95_non_inferiority: p95_res,
            p99_non_inferiority: p99_res,
            target_metric_improved,
            non_target_metrics_safe,
            passed,
            violations,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_performance_evaluation_improvement_passes() {
        let parent = vec![
            100.0, 101.0, 99.0, 102.0, 98.0, 100.5, 101.5, 99.5, 100.0, 101.0, 100.0, 101.0, 99.0,
            102.0, 98.0, 100.5, 101.5, 99.5, 100.0, 101.0, 100.0, 101.0, 99.0, 102.0, 98.0, 100.5,
            101.5, 99.5, 100.0, 101.0,
        ];
        let candidate = vec![
            80.0, 81.0, 79.0, 82.0, 78.0, 80.5, 81.5, 79.5, 80.0, 81.0, 80.0, 81.0, 79.0, 82.0,
            78.0, 80.5, 81.5, 79.5, 80.0, 81.0, 80.0, 81.0, 79.0, 82.0, 78.0, 80.5, 81.5, 79.5,
            80.0, 81.0,
        ];

        let eval = PerformanceLayer::evaluate_latencies(&parent, &candidate, true, 2000, Some(42))
            .unwrap();
        assert!(eval.passed);
        assert!(eval.target_metric_improved);
        assert!(eval.non_target_metrics_safe);

        let lr = eval.to_layer_result();
        assert!(lr.passed);
        assert!((lr.score - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_performance_evaluation_regression_fails() {
        let parent = vec![100.0; 30];
        let candidate = vec![110.0; 30];

        let eval = PerformanceLayer::evaluate_latencies(&parent, &candidate, true, 2000, Some(42))
            .unwrap();
        assert!(!eval.passed);
        assert!(!eval.target_metric_improved);
        assert!(!eval.non_target_metrics_safe);
    }
}
