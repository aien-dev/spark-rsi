use super::LayerResult;
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
    const FORBIDDEN_BUZZWORDS: &'static [&'static str] = &[
        "delve",
        "tapestry",
        "beacon",
        "crucial",
        "pivotal",
        "elevate",
        "game-changer",
        "unleash",
        "harness",
        "seamlessly",
    ];

    const TRANSITIONAL_FLUFF: &'static [&'static str] = &[
        "furthermore,",
        "moreover,",
        "in conclusion,",
        "at its core,",
    ];

    const ANTITHESIS_PATTERNS: &'static [&'static str] = &[
        "not only",
        "it's not",
        "it is not",
    ];

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

        for &buzz in Self::FORBIDDEN_BUZZWORDS {
            if lower.contains(buzz) {
                let msg = format!("Forbidden AI buzzword detected: '{}'", buzz);
                buzzword_violations.push(buzz.to_string());
                violations.push(msg);
            }
        }

        for &fluff in Self::TRANSITIONAL_FLUFF {
            if lower.contains(fluff) {
                let msg = format!("Transitional fluff detected: '{}'", fluff);
                transitional_fluff_violations.push(fluff.to_string());
                violations.push(msg);
            }
        }

        for &pattern in Self::ANTITHESIS_PATTERNS {
            if lower.contains(pattern) && (lower.contains(", but") || lower.contains(" but ")) {
                let msg = format!("Antithesis formulaic trope detected containing '{}'", pattern);
                antithesis_violations.push(pattern.to_string());
                violations.push(msg);
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
        let text = "We delve into the crucial pipeline to unleash speed.";
        let eval = StyleLayer::evaluate_text(text);
        assert!(!eval.passed);
        assert_eq!(eval.buzzword_violations.len(), 3);
    }

    #[test]
    fn test_style_detects_antithesis() {
        let text = "It is not speed, but correctness that matters.";
        let eval = StyleLayer::evaluate_text(text);
        assert!(!eval.passed);
        assert!(!eval.antithesis_violations.is_empty());
    }
}
