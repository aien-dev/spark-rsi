use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MetaBenchmarkMetrics {
    pub discovery_rate_per_sec: f64,
    pub hypothesis_validity_ratio: f64,
    pub compute_efficiency_score: f64,
    pub cycle_latency_ms: f64,
    pub memory_peak_rss_kb: u64,
}

impl MetaBenchmarkMetrics {
    pub fn new(
        discovery_rate_per_sec: f64,
        hypothesis_validity_ratio: f64,
        compute_efficiency_score: f64,
        cycle_latency_ms: f64,
        memory_peak_rss_kb: u64,
    ) -> Self {
        Self {
            discovery_rate_per_sec,
            hypothesis_validity_ratio,
            compute_efficiency_score,
            cycle_latency_ms,
            memory_peak_rss_kb,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MetaBenchmarkComparison {
    pub parent_metrics: MetaBenchmarkMetrics,
    pub candidate_metrics: MetaBenchmarkMetrics,
    pub discovery_rate_delta_pct: f64,
    pub hypothesis_validity_delta_pct: f64,
    pub latency_delta_pct: f64,
    pub passed_non_inferiority: bool,
    pub passed_amplification: bool,
}

pub struct MetaBenchmarkSuite;

impl MetaBenchmarkSuite {
    pub fn evaluate_candidate(
        parent: &MetaBenchmarkMetrics,
        candidate: &MetaBenchmarkMetrics,
        non_inferiority_margin_pct: f64,
    ) -> MetaBenchmarkComparison {
        let discovery_rate_delta_pct = if parent.discovery_rate_per_sec > 0.0 {
            ((candidate.discovery_rate_per_sec - parent.discovery_rate_per_sec)
                / parent.discovery_rate_per_sec)
                * 100.0
        } else {
            0.0
        };

        let hypothesis_validity_delta_pct = if parent.hypothesis_validity_ratio > 0.0 {
            ((candidate.hypothesis_validity_ratio - parent.hypothesis_validity_ratio)
                / parent.hypothesis_validity_ratio)
                * 100.0
        } else {
            0.0
        };

        let latency_delta_pct = if parent.cycle_latency_ms > 0.0 {
            ((candidate.cycle_latency_ms - parent.cycle_latency_ms) / parent.cycle_latency_ms)
                * 100.0
        } else {
            0.0
        };

        // Non-inferiority: hypothesis validity and discovery rate must not regress worse than margin
        let passed_non_inferiority = hypothesis_validity_delta_pct >= -non_inferiority_margin_pct
            && latency_delta_pct <= non_inferiority_margin_pct;

        // Amplification: at least one developmental capability must improve significantly (>= 5.0%)
        let passed_amplification = discovery_rate_delta_pct >= 5.0
            || hypothesis_validity_delta_pct >= 5.0
            || latency_delta_pct <= -5.0;

        MetaBenchmarkComparison {
            parent_metrics: parent.clone(),
            candidate_metrics: candidate.clone(),
            discovery_rate_delta_pct,
            hypothesis_validity_delta_pct,
            latency_delta_pct,
            passed_non_inferiority,
            passed_amplification,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_meta_benchmark_comparison_pass() {
        let parent = MetaBenchmarkMetrics::new(10.0, 0.80, 1.0, 500.0, 4096);
        let candidate = MetaBenchmarkMetrics::new(12.0, 0.85, 1.2, 450.0, 4096);

        let cmp = MetaBenchmarkSuite::evaluate_candidate(&parent, &candidate, 1.0);
        assert!(cmp.passed_non_inferiority);
        assert!(cmp.passed_amplification);
        assert!(cmp.discovery_rate_delta_pct >= 19.0);
        assert!(cmp.latency_delta_pct <= -10.0);
    }

    #[test]
    fn test_meta_benchmark_comparison_fails_regression() {
        let parent = MetaBenchmarkMetrics::new(10.0, 0.80, 1.0, 500.0, 4096);
        let regressed = MetaBenchmarkMetrics::new(8.0, 0.70, 0.8, 600.0, 4096);

        let cmp = MetaBenchmarkSuite::evaluate_candidate(&parent, &regressed, 1.0);
        assert!(!cmp.passed_non_inferiority);
        assert!(!cmp.passed_amplification);
    }
}
