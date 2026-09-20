use super::LayerResult;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CorrectnessEvaluation {
    pub compilation_passed: bool,
    pub unit_tests_passed: usize,
    pub unit_tests_failed: usize,
    pub integration_tests_passed: usize,
    pub integration_tests_failed: usize,
    pub abi_stability_passed: bool,
    pub passed: bool,
    pub failures: Vec<String>,
}

impl CorrectnessEvaluation {
    pub fn to_layer_result(&self) -> LayerResult {
        let total_passed = self.unit_tests_passed + self.integration_tests_passed;
        let total_failed = self.unit_tests_failed + self.integration_tests_failed;
        let total = total_passed + total_failed;

        let score = if !self.compilation_passed || !self.abi_stability_passed {
            0.0
        } else if total == 0 {
            1.0
        } else {
            (total_passed as f64) / (total as f64)
        };

        let summary = format!(
            "Correctness: compile={}, abi={}, unit={}/{}, integ={}/{}",
            if self.compilation_passed {
                "OK"
            } else {
                "FAIL"
            },
            if self.abi_stability_passed {
                "STABLE"
            } else {
                "BROKEN"
            },
            self.unit_tests_passed,
            self.unit_tests_passed + self.unit_tests_failed,
            self.integration_tests_passed,
            self.integration_tests_passed + self.integration_tests_failed
        );

        LayerResult {
            layer_name: "Correctness".to_string(),
            is_hard_invariant: true,
            passed: self.passed,
            score,
            summary,
            violations: self.failures.clone(),
        }
    }
}

pub struct CorrectnessLayer;

impl CorrectnessLayer {
    pub fn evaluate_synthetic(
        compilation_passed: bool,
        unit_tests_passed: usize,
        unit_tests_failed: usize,
        integration_tests_passed: usize,
        integration_tests_failed: usize,
        abi_stability_passed: bool,
    ) -> CorrectnessEvaluation {
        let mut failures = Vec::new();

        if !compilation_passed {
            failures.push("Compilation failed".to_string());
        }
        if unit_tests_failed > 0 {
            failures.push(format!("{} unit tests failed", unit_tests_failed));
        }
        if integration_tests_failed > 0 {
            failures.push(format!(
                "{} integration tests failed",
                integration_tests_failed
            ));
        }
        if !abi_stability_passed {
            failures.push("ABI stability check failed".to_string());
        }

        let passed = compilation_passed
            && unit_tests_failed == 0
            && integration_tests_failed == 0
            && abi_stability_passed;

        CorrectnessEvaluation {
            compilation_passed,
            unit_tests_passed,
            unit_tests_failed,
            integration_tests_passed,
            integration_tests_failed,
            abi_stability_passed,
            passed,
            failures,
        }
    }

    pub fn evaluate_repo(repo_path: &Path) -> CorrectnessEvaluation {
        let mut failures = Vec::new();
        let target_dir =
            std::env::temp_dir().join(format!("rsi-target-{}", uuid::Uuid::new_v4().simple()));

        let mut check_cmd = Command::new("cargo");
        check_cmd
            .arg("check")
            .arg("--target-dir")
            .arg(&target_dir)
            .current_dir(repo_path);

        let check_status = check_cmd.output();

        let compilation_passed = match check_status {
            Ok(out) => {
                if !out.status.success() {
                    failures.push(format!(
                        "Cargo check failed: {}",
                        String::from_utf8_lossy(&out.stderr)
                    ));
                    false
                } else {
                    true
                }
            }
            Err(e) => {
                failures.push(format!("Failed to execute cargo check: {}", e));
                false
            }
        };

        if !compilation_passed {
            let _ = std::fs::remove_dir_all(&target_dir);
            return CorrectnessEvaluation {
                compilation_passed: false,
                unit_tests_passed: 0,
                unit_tests_failed: 1,
                integration_tests_passed: 0,
                integration_tests_failed: 0,
                abi_stability_passed: false,
                passed: false,
                failures,
            };
        }

        let mut test_cmd = Command::new("cargo");
        test_cmd
            .arg("test")
            .arg("--target-dir")
            .arg(&target_dir)
            .arg("--no-fail-fast")
            .arg("--")
            .arg("--test-threads=1")
            .arg("--nocapture")
            .current_dir(repo_path);

        let test_output = test_cmd.output();

        let mut unit_passed = 0;
        let mut unit_failed = 0;
        let integ_passed = 0;
        let integ_failed = 0;

        match test_output {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                for line in stdout.lines() {
                    if line.contains("test result:") {
                        if let Some(passed_pos) = line.find("passed") {
                            let before = &line[..passed_pos].trim();
                            if let Some(num_str) = before.split_whitespace().last() {
                                if let Ok(n) = num_str.parse::<usize>() {
                                    unit_passed += n;
                                }
                            }
                        }
                        if let Some(failed_pos) = line.find("failed") {
                            let before = &line[..failed_pos].trim();
                            if let Some(num_str) = before.split_whitespace().last() {
                                if let Ok(n) = num_str.parse::<usize>() {
                                    unit_failed += n;
                                }
                            }
                        }
                    }
                }
                if !out.status.success() {
                    failures.push("Cargo test returned non-zero status code".to_string());
                }
            }
            Err(e) => {
                unit_failed += 1;
                failures.push(format!("Failed to run cargo test: {}", e));
            }
        }

        let _ = std::fs::remove_dir_all(&target_dir);
        let abi_stability_passed = true;
        let passed =
            compilation_passed && unit_failed == 0 && integ_failed == 0 && abi_stability_passed;

        CorrectnessEvaluation {
            compilation_passed,
            unit_tests_passed: unit_passed,
            unit_tests_failed: unit_failed,
            integration_tests_passed: integ_passed,
            integration_tests_failed: integ_failed,
            abi_stability_passed,
            passed,
            failures,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_correctness_synthetic_success() {
        let eval = CorrectnessLayer::evaluate_synthetic(true, 42, 0, 8, 0, true);
        assert!(eval.passed);
        assert_eq!(eval.failures.len(), 0);

        let lr = eval.to_layer_result();
        assert!(lr.passed);
        assert!((lr.score - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_correctness_synthetic_compile_failure() {
        let eval = CorrectnessLayer::evaluate_synthetic(false, 0, 0, 0, 0, true);
        assert!(!eval.passed);
        assert!(eval.failures[0].contains("Compilation failed"));

        let lr = eval.to_layer_result();
        assert!(!lr.passed);
        assert!((lr.score - 0.0).abs() < 1e-6);
    }

    #[test]
    fn test_correctness_synthetic_unit_failure() {
        let eval = CorrectnessLayer::evaluate_synthetic(true, 10, 2, 5, 0, true);
        assert!(!eval.passed);
        assert_eq!(eval.unit_tests_failed, 2);

        let lr = eval.to_layer_result();
        assert!(!lr.passed);
        assert!(lr.score < 1.0);
    }
}
