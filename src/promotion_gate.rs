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

/// The change about to be promoted: the one file it replaces, the digest of the bytes the change
/// carries, and the digest of the bytes read back from the staged tree right before the swap.
pub struct PromotionSubject<'a> {
    /// The commit (or tree id) the change is applied on; the receipt must name it as its parent.
    pub parent_id: &'a str,
    pub path: &'a str,
    pub content_sha256: &'a str,
    pub disk_sha256: &'a str,
}

impl<'a> PromotionSubject<'a> {
    /// A subject whose staged bytes were confirmed equal to the change's bytes.
    pub fn same(parent_id: &'a str, path: &'a str, sha256: &'a str) -> Self {
        Self {
            parent_id,
            path,
            content_sha256: sha256,
            disk_sha256: sha256,
        }
    }
}

/// Checks `receipt` before promoting `subject`.
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
    subject: &PromotionSubject,
) -> Result<(), String> {
    if subject.content_sha256 != subject.disk_sha256 {
        return Err(format!(
            "staged {} hashes to {}, not the change's {}; refusing to promote",
            subject.path, subject.disk_sha256, subject.content_sha256
        ));
    }
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
        subject.content_sha256,
        &policy_sha256,
        &policy.holdout_set_sha256,
    )?;
    let b = receipt
        .binding
        .as_ref()
        .ok_or("version 2 receipt without binding")?;
    if receipt.parent_id != subject.parent_id {
        return Err(format!(
            "receipt judged the change against parent {}, but it applies on {}",
            receipt.parent_id, subject.parent_id
        ));
    }
    if b.subject_path != subject.path {
        return Err(format!(
            "receipt covers {}, but the change replaces {}",
            b.subject_path, subject.path
        ));
    }
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
