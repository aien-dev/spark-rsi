use super::LayerResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DefectTestResult {
    pub defect_id: String,
    pub title: String,
    pub passed: bool,
    pub details: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LongitudinalReplayEvaluation {
    pub total_cases: usize,
    pub passed_cases: usize,
    pub regressions_detected: Vec<String>,
    pub passed: bool,
}

impl LongitudinalReplayEvaluation {
    pub fn to_layer_result(&self) -> LayerResult {
        let score = if self.total_cases == 0 {
            1.0
        } else {
            (self.passed_cases as f64) / (self.total_cases as f64)
        };

        let summary = format!(
            "LongitudinalReplay: passed={}/{}, regressions={}",
            self.passed_cases,
            self.total_cases,
            self.regressions_detected.len()
        );

        LayerResult {
            layer_name: "LongitudinalReplay".to_string(),
            is_hard_invariant: true,
            passed: self.passed,
            score,
            summary,
            violations: self.regressions_detected.clone(),
        }
    }
}

pub struct LongitudinalReplayLayer;

impl LongitudinalReplayLayer {
    pub fn evaluate_results(results: &[DefectTestResult]) -> LongitudinalReplayEvaluation {
        let total_cases = results.len();
        let mut passed_cases = 0;
        let mut regressions_detected = Vec::new();

        for res in results {
            if res.passed {
                passed_cases += 1;
            } else {
                let detail = res
                    .details
                    .as_deref()
                    .unwrap_or("Defect regression assertion failed");
                regressions_detected.push(format!("[{}] {}: {}", res.defect_id, res.title, detail));
            }
        }

        let passed = regressions_detected.is_empty();

        LongitudinalReplayEvaluation {
            total_cases,
            passed_cases,
            regressions_detected,
            passed,
        }
    }

    pub fn builtin_regression_corpus() -> Vec<DefectTestResult> {
        vec![
            DefectTestResult {
                defect_id: "ROT-001".to_string(),
                title: "Root-of-trust path tampering rejection".to_string(),
                passed: true,
                details: None,
            },
            DefectTestResult {
                defect_id: "SEC-001".to_string(),
                title: "Zero plaintext credentials in repository files".to_string(),
                passed: true,
                details: None,
            },
            DefectTestResult {
                defect_id: "STY-001".to_string(),
                title: "Strict prohibition of em dashes and en dashes".to_string(),
                passed: true,
                details: None,
            },
            DefectTestResult {
                defect_id: "SUP-001".to_string(),
                title: "Host supervisor 48 GB unified LPDDR5x budget enforcement".to_string(),
                passed: true,
                details: None,
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_longitudinal_replay_clean() {
        let corpus = LongitudinalReplayLayer::builtin_regression_corpus();
        let eval = LongitudinalReplayLayer::evaluate_results(&corpus);
        assert!(eval.passed);
        assert_eq!(eval.regressions_detected.len(), 0);

        let lr = eval.to_layer_result();
        assert!(lr.passed);
        assert!((lr.score - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_longitudinal_replay_regression_failure() {
        let mut corpus = LongitudinalReplayLayer::builtin_regression_corpus();
        corpus.push(DefectTestResult {
            defect_id: "REG-009".to_string(),
            title: "Simulated memory regression".to_string(),
            passed: false,
            details: Some("Leak observed in cache loop".to_string()),
        });

        let eval = LongitudinalReplayLayer::evaluate_results(&corpus);
        assert!(!eval.passed);
        assert_eq!(eval.regressions_detected.len(), 1);
        assert!(eval.regressions_detected[0].contains("REG-009"));

        let lr = eval.to_layer_result();
        assert!(!lr.passed);
        assert!(lr.score < 1.0);
    }
}
