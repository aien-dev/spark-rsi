//! Promotion gate: no change is promoted unless its exact identity matches the identity covered
//! by a valid version 2 receipt signed by the separate judge (docs/RECEIPT-V2.md).
//!
//! Everything here fails closed. A missing judge key, a judge key equal to the proposer's own
//! key, a missing or invalid policy, a version 1 receipt, a bad signature, or any identity
//! mismatch refuses the promotion.

use crate::actor::judge::EvaluationPolicy;
use crate::evaluator::EvaluationReceipt;
use p256::ecdsa::VerifyingKey;
use std::path::Path;

/// Checks `receipt` before promoting the change whose bytes hash to `subject_sha256`.
///
/// `judge_public_key_hex` is the operator-pinned SEC1 hex key of the judge. `own_key` is the
/// promoting process's own key: a receipt the promoter could have signed itself is refused.
/// The policy file is read here, so the policy and holdout digests come from the operator's copy,
/// never from the receipt.
pub fn check_v2_promotion(
    receipt: &EvaluationReceipt,
    judge_public_key_hex: Option<&str>,
    own_key: &VerifyingKey,
    judge_policy_file: Option<&str>,
    subject_sha256: &str,
) -> Result<(), String> {
    let key_hex = judge_public_key_hex
        .ok_or("no pinned judge public key (judge_public_key_hex); promotion fails closed")?;
    let key_bytes =
        hex::decode(key_hex.trim()).map_err(|e| format!("judge public key is not hex: {}", e))?;
    let judge_key = VerifyingKey::from_sec1_bytes(&key_bytes)
        .map_err(|e| format!("judge public key is invalid: {}", e))?;
    if &judge_key == own_key {
        return Err(
            "judge public key equals the promoter's own key; the judge must be separate".into(),
        );
    }
    let policy_file = judge_policy_file
        .ok_or("no pinned evaluation policy (judge_policy_file); promotion fails closed")?;
    let (policy, policy_sha256) = EvaluationPolicy::load(Path::new(policy_file))?;
    receipt.verify_for_promotion(
        &judge_key,
        subject_sha256,
        &policy_sha256,
        &policy.holdout_set_sha256,
    )?;
    let b = receipt
        .binding
        .as_ref()
        .ok_or("version 2 receipt without binding")?;
    if !policy.allowed_targets.contains(&b.subject_path) {
        return Err(format!(
            "receipt subject {} is not an allowed target in the pinned policy",
            b.subject_path
        ));
    }
    if b.holdouts_total == 0
        || (b.holdouts_passed as f64) < policy.min_holdout_pass_ratio * (b.holdouts_total as f64)
    {
        return Err(format!(
            "holdouts passed {}/{} is below the policy threshold {}",
            b.holdouts_passed, b.holdouts_total, policy.min_holdout_pass_ratio
        ));
    }
    Ok(())
}
