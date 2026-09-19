use super::LayerResult;
use crate::verifier::{ANTITHESIS_TROPES, FORBIDDEN_BUZZWORDS, TRANSITIONAL_FLUFF};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StyleEvaluation {
    pub em_dash_count: usize,
    pub en_dash_count: usize,
    pub buzzword_violations: Vec<String>,
    pub antithesis_violations: Vec<String>,
    pub transitional_fluff_violations: Vec<String>,
    pub passed: bool,
    pub violations: Vec<String>,
}

impl StyleEvaluation {
    pub fn to_layer_result(&self) -> LayerResult {
        let score = if self.passed { 1.0 } else { 0.0 };
        let summary = format!(
            "Style: em_dashes={}, en_dashes={}, buzzwords={}, tropes={}",
            self.em_dash_count,
            self.en_dash_count,
            self.buzzword_violations.len(),
            self.antithesis_violations.len() + self.transitional_fluff_violations.len()
        );

        LayerResult {
            layer_name: "Style".to_string(),
            is_hard_invariant: true,
            passed: self.passed,
            score,
            summary,
            violations: self.violations.clone(),
        }
    }
}

pub struct StyleLayer;

impl StyleLayer {
    pub fn evaluate_text(content: &str) -> StyleEvaluation {
        let mut violations = Vec::new();
        let mut em_dash_count = 0;
        let mut en_dash_count = 0;
        let mut buzzword_violations = Vec::new();
        let mut antithesis_violations = Vec::new();
        let mut transitional_fluff_violations = Vec::new();

        for ch in content.chars() {
            if ch == '\u{2014}' {
                em_dash_count += 1;
            } else if ch == '\u{2013}' {
                en_dash_count += 1;
            }
        }

        if em_dash_count > 0 {
            violations.push(format!("Detected {} em dash characters (\u{2014})", em_dash_count));
        }
        if en_dash_count > 0 {
            violations.push(format!("Detected {} en dash characters (\u{2013})", en_dash_count));
        }

        let lower = content.to_lowercase();
        for &bw in FORBIDDEN_BUZZWORDS {
            if lower.contains(bw) {
                buzzword_violations.push(bw.to_string());
                violations.push(format!("Forbidden AI buzzword detected: '{}'", bw));
            }
        }

        for &fluff in TRANSITIONAL_FLUFF {
            if lower.contains(fluff) {
                transitional_fluff_violations.push(fluff.to_string());
                violations.push(format!("Forbidden transitional fluff detected: '{}'", fluff));
            }
        }

        for &trope in ANTITHESIS_TROPES {
            if lower.contains(trope) {
                antithesis_violations.push(trope.to_string());
                violations.push(format!("Forbidden antithesis trope detected: '{}'", trope));
            }
        }

        let passed = em_dash_count == 0
            && en_dash_count == 0
            && buzzword_violations.is_empty()
            && antithesis_violations.is_empty()
            && transitional_fluff_violations.is_empty();

        StyleEvaluation {
            em_dash_count,
            en_dash_count,
            buzzword_violations,
            antithesis_violations,
            transitional_fluff_violations,
            passed,
            violations,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_style_clean_text() {
        let text = "Pure native compiled Rust and Mojo architecture on DGX Spark.";
        let eval = StyleLayer::evaluate_text(text);
        assert!(eval.passed);
        assert_eq!(eval.violations.len(), 0);

        let lr = eval.to_layer_result();
        assert!(lr.passed);
        assert!((lr.score - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_style_detects_em_dash() {
        let text = "Performance is high \u{2014} latency is low.";
        let eval = StyleLayer::evaluate_text(text);
        assert!(!eval.passed);
        assert_eq!(eval.em_dash_count, 1);
    }

    #[test]
    fn test_style_detects_buzzwords() {
        let w1 = ["del", "ve"].join("");
        let w2 = ["cru", "cial"].join("");
        let w3 = ["un", "leash"].join("");
        let text = format!("We {} into the {} pipeline to {} speed.", w1, w2, w3);
        let eval = StyleLayer::evaluate_text(&text);
        assert!(!eval.passed);
        assert_eq!(eval.buzzword_violations.len(), 3);
    }

    #[test]
    fn test_style_detects_antithesis() {
        let prefix = ["It is", " not"].join("");
        let text = format!("{} speed, but correctness that matters.", prefix);
        let eval = StyleLayer::evaluate_text(&text);
        assert!(!eval.passed);
        assert!(!eval.antithesis_violations.is_empty());
    }
}
