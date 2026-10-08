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

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
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
    /// Receipt format. 1 (or absent, for records written before version 2) signs only the ids,
    /// the admitted flag and the layer results. 2 also signs `binding`. See docs/RECEIPT-V2.md.
    #[serde(default = "receipt_format_v1")]
    pub format_version: u32,
    /// Version 2 only: what exactly was evaluated, against which holdout set and policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<ReceiptBindingV2>,
}

fn receipt_format_v1() -> u32 {
    1
}

/// The identity a version 2 receipt signs, so a score cannot be paired with another change.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptBindingV2 {
    /// Path of the changed file, relative to the candidate root.
    pub subject_path: String,
    /// SHA-256 (hex) of the exact bytes of `subject_path` in the evaluated candidate.
    pub subject_sha256: String,
    /// Digest of the holdout directory (docs/RECEIPT-V2.md, "Holdout set digest").
    pub holdout_set_sha256: String,
    pub holdouts_total: u64,
    pub holdouts_passed: u64,
    /// SHA-256 (hex) of the exact policy file bytes the judge was given.
    pub policy_sha256: String,
    /// SHA-256 (hex) of the judge executable that produced the receipt.
    pub evaluator_binary_sha256: String,
}

/// Length-prefixed field encoding for the version 2 digest: u64 little-endian length, then bytes.
/// Writes one length-prefixed field (u64 little-endian length, then the bytes).
pub fn put_field(h: &mut Sha256, bytes: &[u8]) {
    h.update((bytes.len() as u64).to_le_bytes());
    h.update(bytes);
}

pub const RECEIPT_V2_DOMAIN: &str = "spark-rsi.evaluation-receipt.v2";

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
            hasher.update(lr.score.to_le_bytes());
            hasher.update(lr.summary.as_bytes());
        }

        hex::encode(hasher.finalize())
    }

    pub fn save_to_file(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let content = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        fs::write(path, content).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn load_from_file(path: &Path) -> Result<Self, String> {
        let content = fs::read_to_string(path).map_err(|e| e.to_string())?;
        serde_json::from_str(&content).map_err(|e| e.to_string())
    }

    /// Recomputes the digest for the receipt's own format. A version 1 receipt that carries a
    /// binding, a version 2 receipt without one, and unknown versions never verify.
    pub fn verify_digest(&self) -> bool {
        match (self.format_version, &self.binding) {
            (1, None) => {
                let expected = Self::compute_digest(
                    &self.cycle_id,
                    &self.candidate_id,
                    &self.parent_id,
                    self.admitted,
                    &self.layer_results,
                );
                self.receipt_digest == expected
            }
            (2, Some(_)) => self
                .compute_digest_v2()
                .is_ok_and(|d| d == self.receipt_digest),
            _ => false,
        }
    }

    /// Version 2 digest (docs/RECEIPT-V2.md): SHA-256 over length-prefixed fields in a fixed order.
    pub fn compute_digest_v2(&self) -> Result<String, String> {
        let b = self
            .binding
            .as_ref()
            .ok_or("version 2 digest needs a binding")?;
        let mut h = Sha256::new();
        put_field(&mut h, RECEIPT_V2_DOMAIN.as_bytes());
        for s in [
            &self.cycle_id,
            &self.candidate_id,
            &self.parent_id,
            &self.evaluated_at,
            &self.evaluator_version,
            &b.evaluator_binary_sha256,
            &b.subject_path,
            &b.subject_sha256,
            &b.holdout_set_sha256,
            &b.policy_sha256,
        ] {
            put_field(&mut h, s.as_bytes());
        }
        put_field(&mut h, &b.holdouts_total.to_le_bytes());
        put_field(&mut h, &b.holdouts_passed.to_le_bytes());
        for flag in [
            self.admitted,
            self.passed_all_hard_invariants,
            self.passed_statistical_gates,
        ] {
            put_field(&mut h, &[flag as u8]);
        }
        put_field(&mut h, &(self.layer_results.len() as u64).to_le_bytes());
        for lr in &self.layer_results {
            put_field(&mut h, lr.layer_name.as_bytes());
            put_field(&mut h, &[lr.is_hard_invariant as u8]);
            put_field(&mut h, &[lr.passed as u8]);
            put_field(&mut h, &lr.score.to_bits().to_le_bytes());
            put_field(&mut h, lr.summary.as_bytes());
            put_field(&mut h, &(lr.violations.len() as u64).to_le_bytes());
            for v in &lr.violations {
                put_field(&mut h, v.as_bytes());
            }
        }
        match &self.metrics_summary {
            None => put_field(&mut h, &[0u8]),
            Some(m) => {
                put_field(&mut h, &[1u8]);
                for x in [
                    m.latency_delta_pct,
                    m.p_value,
                    m.p95_ci_upper_degradation_pct,
                    m.p99_ci_upper_degradation_pct,
                    m.rss_growth_pct,
                ] {
                    put_field(&mut h, &x.to_bits().to_le_bytes());
                }
                put_field(&mut h, &m.candidate_resident_mb.to_le_bytes());
            }
        }
        Ok(hex::encode(h.finalize()))
    }

    /// Turns this receipt into version 2 with `binding`, recomputes the digest and signs it.
    pub fn bind_and_sign_v2(
        &mut self,
        binding: ReceiptBindingV2,
        signing_key: &SigningKey,
    ) -> Result<(), String> {
        self.format_version = 2;
        self.binding = Some(binding);
        self.receipt_digest = self.compute_digest_v2()?;
        self.sign(signing_key);
        Ok(())
    }

    /// The promotion check: version 2 only, valid signature under the judge's key, and the
    /// signed identity equal to what the caller is about to promote. Version 1 receipts stay
    /// verifiable with `verify_signature` for history but are never enough here.
    pub fn verify_for_promotion(
        &self,
        judge_key: &VerifyingKey,
        subject_sha256: &str,
        policy_sha256: &str,
        holdout_set_sha256: &str,
    ) -> Result<(), String> {
        if self.format_version != 2 {
            return Err(format!(
                "receipt format {} is not sufficient for promotion (version 2 required)",
                self.format_version
            ));
        }
        if !self.verify_signature(judge_key) {
            return Err("receipt signature or digest does not verify under the judge key".into());
        }
        let b = self
            .binding
            .as_ref()
            .ok_or("version 2 receipt without binding")?;
        if b.subject_sha256 != subject_sha256 {
            return Err(format!(
                "receipt subject {} is not the change being promoted ({})",
                b.subject_sha256, subject_sha256
            ));
        }
        if b.policy_sha256 != policy_sha256 {
            return Err("receipt policy digest differs from the pinned policy".into());
        }
        if b.holdout_set_sha256 != holdout_set_sha256 {
            return Err("receipt holdout set differs from the pinned holdout set".into());
        }
        if !self.admitted {
            return Err("judge did not admit the candidate".into());
        }
        Ok(())
    }

    pub fn sign(&mut self, signing_key: &SigningKey) {
        let digest_bytes = hex::decode(&self.receipt_digest)
            .unwrap_or_else(|_| self.receipt_digest.as_bytes().to_vec());
        let signature: Signature = signing_key.sign(&digest_bytes);
        self.signature = Some(format!("tpm2-p256:{}", hex::encode(signature.to_bytes())));
    }

    pub fn verify_signature(&self, verifying_key: &VerifyingKey) -> bool {
        if !self.verify_digest() {
            return false;
        }
        let Some(sig_str) = &self.signature else {
            return false;
        };
        let raw_hex = if let Some(stripped) = sig_str.strip_prefix("tpm2-p256:") {
            stripped
        } else {
            sig_str
        };
        let Ok(sig_bytes) = hex::decode(raw_hex) else {
            return false;
        };
        let Ok(signature) = Signature::from_slice(&sig_bytes) else {
            return false;
        };
        let digest_bytes = hex::decode(&self.receipt_digest)
            .unwrap_or_else(|_| self.receipt_digest.as_bytes().to_vec());
        verifying_key.verify(&digest_bytes, &signature).is_ok()
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

        let passed_all_hard_invariants =
            correctness.passed && security.passed && style.passed && longitudinal_replay.passed;

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
            format_version: 1,
            binding: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_objective_evaluator_all_pass() {
        let correctness = CorrectnessLayer::evaluate_synthetic(true, 10, 0, 2, 0, true);
        let security =
            SecurityLayer::evaluate_candidate(&["src/observe.rs".to_string()], "+ ok", 0);
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

        let mut receipt = ObjectiveEvaluator::evaluate_candidate(
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

        // Test real ECDSA P-256 signing and verification
        let signing_key = SigningKey::from_bytes(&[42u8; 32].into()).unwrap();
        let verifying_key = VerifyingKey::from(&signing_key);

        receipt.sign(&signing_key);
        assert!(receipt.signature.is_some());
        assert!(receipt.verify_signature(&verifying_key));

        // Tampered receipt fails signature verification
        let mut tampered = receipt.clone();
        tampered.candidate_id = "attacker-modified-cand".to_string();
        tampered.receipt_digest = EvaluationReceipt::compute_digest(
            &tampered.cycle_id,
            &tampered.candidate_id,
            &tampered.parent_id,
            tampered.admitted,
            &tampered.layer_results,
        );
        assert!(!tampered.verify_signature(&verifying_key));
    }

    #[test]
    fn test_objective_evaluator_hard_invariant_rejection() {
        let correctness = CorrectnessLayer::evaluate_synthetic(false, 0, 0, 0, 0, true);
        let security =
            SecurityLayer::evaluate_candidate(&["src/observe.rs".to_string()], "+ ok", 0);
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
