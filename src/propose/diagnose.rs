use crate::evaluator::EvaluationReceipt;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DefectCategory {
    CompilationFailure,
    HoldoutFailure,
    InvariantViolation,
    PerformanceRegression,
    ResourceViolation,
    StyleViolation,
    SoulTensionDominance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticContext {
    pub cycle_id: String,
    pub target_file: String,
    pub current_content: String,
    pub primary_defect: DefectCategory,
    pub violations: Vec<String>,
    pub past_lessons: Vec<String>,
}

impl DiagnosticContext {
    pub fn from_receipt(
        cycle_id: &str,
        receipt: &EvaluationReceipt,
        target_file: &str,
        current_content: &str,
        past_lessons: Vec<String>,
    ) -> Self {
        let mut violations = Vec::new();
        let mut primary_defect = DefectCategory::HoldoutFailure;

        for layer in &receipt.layer_results {
            if !layer.passed {
                match layer.layer_name.as_str() {
                    "Correctness" => {
                        primary_defect = DefectCategory::CompilationFailure;
                    }
                    "Security" => {
                        primary_defect = DefectCategory::InvariantViolation;
                    }
                    "Style" => {
                        primary_defect = DefectCategory::StyleViolation;
                    }
                    "Performance" => {
                        primary_defect = DefectCategory::PerformanceRegression;
                    }
                    "ResourceEfficiency" => {
                        primary_defect = DefectCategory::ResourceViolation;
                    }
                    "LongitudinalReplay" => {
                        primary_defect = DefectCategory::HoldoutFailure;
                    }
                    _ => {}
                }
                for v in &layer.violations {
                    violations.push(format!("[{}] {}", layer.layer_name, v));
                }
            }
        }

        if violations.is_empty() && !receipt.admitted {
            violations.push("Evaluator rejected candidate without explicit layer violations.".to_string());
        }

        Self {
            cycle_id: cycle_id.to_string(),
            target_file: target_file.to_string(),
            current_content: current_content.to_string(),
            primary_defect,
            violations,
            past_lessons,
        }
    }

    pub fn from_violations(
        cycle_id: &str,
        target_file: &str,
        current_content: &str,
        primary_defect: DefectCategory,
        violations: Vec<String>,
        past_lessons: Vec<String>,
    ) -> Self {
        Self {
            cycle_id: cycle_id.to_string(),
            target_file: target_file.to_string(),
            current_content: current_content.to_string(),
            primary_defect,
            violations,
            past_lessons,
        }
    }

    pub fn build_prompts(&self) -> (String, String) {
        let system_prompt = "You are the autonomous recursive code synthesizer for spark-rsi on NVIDIA DGX Spark.
Your role: generate a clean, compiling, verified replacement for the target file that resolves diagnosed defects.

CRITICAL INVARIANTS:
1. Output MUST contain ONLY the complete replacement file inside a single fenced code block (e.g. ```rust ... ```).
2. Do NOT provide conversational filler, pleasantries, explanations, or text outside the code block.
3. Anti-Slop Standard: ZERO em dashes (\u{2014}), ZERO en dashes (\u{2013}), ZERO marketing adjectives or decorative adjectives.
4. Preserve existing public APIs and invariants.".to_string();

        let mut user_prompt = format!(
            "TARGET FILE: {}
PRIMARY DEFECT: {:?}

DIAGNOSTIC VIOLATIONS DETECTED BY EVALUATOR:
",
            self.target_file, self.primary_defect
        );

        if self.violations.is_empty() {
            user_prompt.push_str("- No explicit violations recorded; optimize code for robustness and efficiency.
");
        } else {
            for v in &self.violations {
                user_prompt.push_str(&format!("- {}
", v));
            }
        }

        if !self.past_lessons.is_empty() {
            user_prompt.push_str("
CANONICAL LESSONS FROM SPARK CORTEX (ATLAS-MEMORY):
");
            for lesson in &self.past_lessons {
                user_prompt.push_str(&format!("* {}
", lesson));
            }
        }

        user_prompt.push_str(&format!(
            "
CURRENT FILE CONTENT:
```
{}
```

Generate the updated file resolving the above defects:",
            self.current_content
        ));

        (system_prompt, user_prompt)
    }
}
