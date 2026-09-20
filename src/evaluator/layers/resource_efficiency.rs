use super::LayerResult;
use crate::evaluator::metrics::{RusageMetrics, StatmMetrics};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResourceEfficiencyEvaluation {
    pub parent_rss_kb: i64,
    pub candidate_rss_kb: i64,
    pub rss_growth_pct: f64,
    pub rss_growth_within_budget: bool,
    pub host_memory_within_budget: bool,
    pub context_switches_delta: i64,
    pub passed: bool,
    pub violations: Vec<String>,
}

impl ResourceEfficiencyEvaluation {
    pub fn to_layer_result(&self) -> LayerResult {
        let score = if self.passed {
            1.0
        } else if self.host_memory_within_budget {
            0.5
        } else {
            0.0
        };

        let summary = format!(
            "ResourceEfficiency: rss_growth={:.2}%, limit_mb_ok={}, ctxt_delta={}",
            self.rss_growth_pct, self.host_memory_within_budget, self.context_switches_delta
        );

        LayerResult {
            layer_name: "ResourceEfficiency".to_string(),
            is_hard_invariant: false,
            passed: self.passed,
            score,
            summary,
            violations: self.violations.clone(),
        }
    }
}

pub struct ResourceEfficiencyLayer;

impl ResourceEfficiencyLayer {
    pub const MAX_RSS_GROWTH_PCT: f64 = 2.0;
    pub const DEFAULT_UNIFIED_MEMORY_LIMIT_MB: u64 = 49_152; // 48 GB Grace Blackwell ceiling

    pub fn evaluate(
        parent_rusage: &RusageMetrics,
        candidate_rusage: &RusageMetrics,
        candidate_statm: Option<&StatmMetrics>,
        memory_limit_mb: Option<u64>,
    ) -> ResourceEfficiencyEvaluation {
        let mut violations = Vec::new();

        let parent_rss_kb = parent_rusage.max_rss_kb;
        let candidate_rss_kb = candidate_rusage.max_rss_kb;

        let rss_growth_pct = if parent_rss_kb > 0 {
            ((candidate_rss_kb - parent_rss_kb) as f64 / (parent_rss_kb as f64)) * 100.0
        } else {
            0.0
        };

        let rss_growth_within_budget = rss_growth_pct <= Self::MAX_RSS_GROWTH_PCT;
        if !rss_growth_within_budget {
            violations.push(format!(
                "Candidate peak RSS growth exceeded 2.0% threshold: {:.2}% (parent={} KB, cand={} KB)",
                rss_growth_pct, parent_rss_kb, candidate_rss_kb
            ));
        }

        let limit_mb = memory_limit_mb.unwrap_or(Self::DEFAULT_UNIFIED_MEMORY_LIMIT_MB);
        let mut host_memory_within_budget = true;

        if let Some(statm) = candidate_statm {
            let resident_mb = statm.resident_kb / 1024;
            if resident_mb > limit_mb {
                violations.push(format!(
                    "Candidate resident memory exceeded unified memory limit: {} MB > {} MB",
                    resident_mb, limit_mb
                ));
                host_memory_within_budget = false;
            }
        }

        let ctxt_parent =
            parent_rusage.voluntary_context_switches + parent_rusage.involuntary_context_switches;
        let ctxt_cand = candidate_rusage.voluntary_context_switches
            + candidate_rusage.involuntary_context_switches;
        let context_switches_delta = ctxt_cand - ctxt_parent;

        let passed = rss_growth_within_budget && host_memory_within_budget;

        ResourceEfficiencyEvaluation {
            parent_rss_kb,
            candidate_rss_kb,
            rss_growth_pct,
            rss_growth_within_budget,
            host_memory_within_budget,
            context_switches_delta,
            passed,
            violations,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_efficiency_clean() {
        let parent = RusageMetrics {
            user_time_us: 1000,
            system_time_us: 500,
            max_rss_kb: 50_000,
            voluntary_context_switches: 10,
            involuntary_context_switches: 5,
        };
        let candidate = RusageMetrics {
            user_time_us: 950,
            system_time_us: 480,
            max_rss_kb: 50_500, // 1% growth <= 2%
            voluntary_context_switches: 8,
            involuntary_context_switches: 4,
        };

        let statm = StatmMetrics {
            total_pages: 20_000,
            resident_pages: 12_500, // 50 MB
            shared_pages: 2000,
            text_pages: 500,
            data_pages: 9000,
            resident_kb: 50_000,
        };

        let eval = ResourceEfficiencyLayer::evaluate(&parent, &candidate, Some(&statm), None);
        assert!(eval.passed);
        assert!(eval.rss_growth_within_budget);
        assert!(eval.host_memory_within_budget);

        let lr = eval.to_layer_result();
        assert!(lr.passed);
        assert!((lr.score - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_resource_efficiency_rss_growth_violation() {
        let parent = RusageMetrics {
            user_time_us: 1000,
            system_time_us: 500,
            max_rss_kb: 50_000,
            voluntary_context_switches: 10,
            involuntary_context_switches: 5,
        };
        let candidate = RusageMetrics {
            user_time_us: 950,
            system_time_us: 480,
            max_rss_kb: 60_000, // 20% growth > 2%
            voluntary_context_switches: 8,
            involuntary_context_switches: 4,
        };

        let eval = ResourceEfficiencyLayer::evaluate(&parent, &candidate, None, None);
        assert!(!eval.passed);
        assert!(!eval.rss_growth_within_budget);
        assert!(eval.violations[0].contains("exceeded 2.0% threshold"));
    }

    #[test]
    fn test_resource_efficiency_host_memory_limit_exceeded() {
        let parent = RusageMetrics {
            user_time_us: 1000,
            system_time_us: 500,
            max_rss_kb: 50_000,
            voluntary_context_switches: 10,
            involuntary_context_switches: 5,
        };
        let candidate = RusageMetrics {
            user_time_us: 950,
            system_time_us: 480,
            max_rss_kb: 50_000,
            voluntary_context_switches: 8,
            involuntary_context_switches: 4,
        };

        let statm = StatmMetrics {
            total_pages: 20_000_000,
            resident_pages: 13_000_000, // 52 GB > 48 GB
            shared_pages: 2000,
            text_pages: 500,
            data_pages: 9000,
            resident_kb: 52_000_000,
        };

        let eval =
            ResourceEfficiencyLayer::evaluate(&parent, &candidate, Some(&statm), Some(49_152));
        assert!(!eval.passed);
        assert!(!eval.host_memory_within_budget);
        assert!(eval.violations[0].contains("exceeded unified memory limit"));
    }
}
