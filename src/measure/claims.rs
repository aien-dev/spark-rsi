//! Claim policy: which proposals need a measured diagnosis before they may be promoted.

use crate::models::ProposalKind;

/// An Optimization proposal, or any proposal while `require_latency_improvement` is on, claims a
/// performance gain and so needs a measured diagnosis. Other kinds proceed on structural ranking.
pub fn requires_measured_diagnosis(kind: &ProposalKind, require_latency_improvement: bool) -> bool {
    require_latency_improvement || *kind == ProposalKind::Optimization
}

/// `diagnosis_measured` is true only when the top-ranked stage's latency is measured.
pub fn check_claim(
    kind: &ProposalKind,
    require_latency_improvement: bool,
    diagnosis_measured: bool,
) -> Result<(), String> {
    if requires_measured_diagnosis(kind, require_latency_improvement) && !diagnosis_measured {
        let why = if require_latency_improvement {
            "require_latency_improvement is on"
        } else {
            "the proposal is an Optimization"
        };
        return Err(format!(
            "Claim refused before staging: {why}, but the top-ranked stage has no measured latency (unavailable diagnosis)"
        ));
    }
    Ok(())
}
