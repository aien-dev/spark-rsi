use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProtectedMetric {
    pub name: String,
    pub max_allowed_degradation_pct: f64,
}

/// Target metric of an exploratory hypothesis: it makes no performance claim, so
/// `baseline_value` and `predicted_delta_pct` carry no meaning and must be zero.
pub const EXPLORATORY_TARGET_METRIC: &str = "structural_ranking";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HypothesisContract {
    pub id: String,
    pub cycle_id: String,
    pub observed_problem: String,
    pub suspected_root_cause: String,
    pub target_metric: String,
    pub baseline_value: f64,
    pub predicted_delta_pct: f64,
    pub protected_metrics: Vec<ProtectedMetric>,
    pub falsification_test: String,
    pub confidence_score: f64,
}

impl HypothesisContract {
    pub fn new(
        id: &str,
        cycle_id: &str,
        observed_problem: &str,
        suspected_root_cause: &str,
        target_metric: &str,
        baseline_value: f64,
        predicted_delta_pct: f64,
    ) -> Self {
        Self {
            id: id.to_string(),
            cycle_id: cycle_id.to_string(),
            observed_problem: observed_problem.to_string(),
            suspected_root_cause: suspected_root_cause.to_string(),
            target_metric: target_metric.to_string(),
            baseline_value,
            predicted_delta_pct,
            protected_metrics: vec![
                ProtectedMetric {
                    name: "p95_latency".to_string(),
                    max_allowed_degradation_pct: 1.0,
                },
                ProtectedMetric {
                    name: "p99_latency".to_string(),
                    max_allowed_degradation_pct: 1.0,
                },
                ProtectedMetric {
                    name: "max_rss_kb".to_string(),
                    max_allowed_degradation_pct: 2.0,
                },
            ],
            falsification_test: String::new(),
            confidence_score: 0.85,
        }
    }

    /// A hypothesis with no performance claim: no baseline number, no predicted percentage.
    /// Used when the top-ranked stage has no measured latency (cold start).
    pub fn exploratory(
        id: &str,
        cycle_id: &str,
        observed_problem: &str,
        suspected_root_cause: &str,
    ) -> Self {
        let mut c = Self::new(
            id,
            cycle_id,
            observed_problem,
            suspected_root_cause,
            EXPLORATORY_TARGET_METRIC,
            0.0,
            0.0,
        );
        c.confidence_score = 0.0;
        c
    }

    /// Builds the hypothesis for the top-ranked stage. It carries a numeric latency target only
    /// when that stage's latency is measured; otherwise it is exploratory and claims nothing.
    pub fn from_bottleneck(
        id: &str,
        cycle_id: &str,
        b: &crate::graph::BottleneckRank,
        target_improvement_pct: f64,
    ) -> Self {
        match b.latency_median_us {
            Some(median) => Self::new(
                id,
                cycle_id,
                &format!(
                    "Stage '{}' has measured median latency {:.1} us (centrality={:.4})",
                    b.node_name, median, b.centrality
                ),
                &format!("Latency on '{}': {}", b.node_name, b.causal_explanation),
                "latency_median_us",
                median,
                target_improvement_pct,
            ),
            None => Self::exploratory(
                id,
                cycle_id,
                &format!(
                    "Stage '{}' ranks first by structural position (centrality={:.4}); no latency is measured",
                    b.node_name, b.centrality
                ),
                &format!("Structural ranking: {}", b.causal_explanation),
            ),
        }
    }

    pub fn is_exploratory(&self) -> bool {
        self.target_metric == EXPLORATORY_TARGET_METRIC
    }

    /// The numeric latency claim `(baseline_us, predicted_improvement_pct)`, or None when the
    /// hypothesis is exploratory.
    pub fn latency_claim(&self) -> Option<(f64, f64)> {
        (!self.is_exploratory()).then_some((self.baseline_value, self.predicted_delta_pct))
    }

    pub fn with_falsification_test(mut self, test_code: &str) -> Self {
        self.falsification_test = test_code.to_string();
        self
    }

    pub fn with_protected_metric(mut self, name: &str, max_degradation_pct: f64) -> Self {
        self.protected_metrics.push(ProtectedMetric {
            name: name.to_string(),
            max_allowed_degradation_pct: max_degradation_pct,
        });
        self
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.observed_problem.trim().is_empty() {
            return Err("HypothesisContract must specify a non-empty observed_problem".to_string());
        }
        if self.suspected_root_cause.trim().is_empty() {
            return Err(
                "HypothesisContract must specify a non-empty suspected_root_cause".to_string(),
            );
        }
        if self.target_metric.trim().is_empty() {
            return Err("HypothesisContract must specify a target_metric".to_string());
        }
        if self.is_exploratory() {
            if self.baseline_value != 0.0 || self.predicted_delta_pct != 0.0 {
                return Err(
                    "an exploratory HypothesisContract must carry no baseline and no predicted delta"
                        .to_string(),
                );
            }
            return Ok(());
        }
        if !self.baseline_value.is_finite() || !self.predicted_delta_pct.is_finite() {
            return Err(
                "HypothesisContract baseline and predicted delta must be finite".to_string(),
            );
        }
        if self.predicted_delta_pct.abs() < 1e-6 {
            return Err("HypothesisContract predicted_delta_pct cannot be zero".to_string());
        }
        if self.confidence_score < 0.0 || self.confidence_score > 1.0 {
            return Err("HypothesisContract confidence_score must be in [0.0, 1.0]".to_string());
        }
        Ok(())
    }

    pub fn format_prompt_directive(&self) -> String {
        let target = match self.latency_claim() {
            Some((baseline, delta)) => format!(
                "{} (Baseline: {:.2}, Expected Improvement: {:.1}%)",
                self.target_metric, baseline, delta
            ),
            None => format!(
                "{} (exploratory, no performance claim: no latency was measured)",
                self.target_metric
            ),
        };
        let mut text = format!(
            "FALSIFIABLE HYPOTHESIS CONTRACT (ID: {}):\n\
- Observed Problem: {}\n\
- Suspected Root Cause: {}\n\
- Target Metric: {}\n\
- Protected Non-Target Metrics:\n",
            self.id, self.observed_problem, self.suspected_root_cause, target
        );

        for pm in &self.protected_metrics {
            text.push_str(&format!(
                "  * {} <= +{:.1}% max degradation\n",
                pm.name, pm.max_allowed_degradation_pct
            ));
        }

        if !self.falsification_test.is_empty() {
            text.push_str(&format!(
                "- Falsification Condition: {}\n",
                self.falsification_test
            ));
        }

        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hypothesis_contract_validation_and_directive() {
        let contract = HypothesisContract::new(
            "hypo-001",
            "cycle-01",
            "Tail latency p95 spiked on holdout test case",
            "Unsynchronized lock contention in sequence allocator",
            "p95_latency",
            2450.0,
            15.0,
        )
        .with_falsification_test("assert_eq!(allocator.contention_count(), 0)");

        assert!(contract.validate().is_ok());

        let directive = contract.format_prompt_directive();
        assert!(directive.contains("FALSIFIABLE HYPOTHESIS CONTRACT"));
        assert!(directive.contains("Unsynchronized lock contention"));
        assert!(directive.contains("assert_eq!(allocator.contention_count(), 0)"));
    }

    #[test]
    fn exploratory_hypothesis_is_valid_without_a_delta_and_claims_nothing() {
        let c = HypothesisContract::exploratory("hypo-x", "cycle-01", "Stage ranks first", "Cause");
        assert!(c.is_exploratory());
        assert!(c.validate().is_ok());
        assert_eq!(c.latency_claim(), None);
        let d = c.format_prompt_directive();
        assert!(d.contains("no performance claim"));
        assert!(!d.contains("Baseline"));
        let mut forged = c.clone();
        forged.predicted_delta_pct = 15.0;
        assert!(forged.validate().is_err());
    }

    #[test]
    fn test_hypothesis_contract_rejects_empty_problem() {
        let invalid =
            HypothesisContract::new("hypo-bad", "cycle-01", "", "Cause", "p95", 100.0, 5.0);
        assert!(invalid.validate().is_err());
    }
}
