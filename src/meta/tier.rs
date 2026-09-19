use crate::models::{ImprovementProposal, ProposalKind};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CandidateTier {
    Tier1Target,
    Tier2Engine,
}

pub struct TierGovernance;

impl TierGovernance {
    /// Engine paths that classify a proposal as Tier 2 (Engine Code)
    pub const ENGINE_PREFIXES: &'static [&'static str] = &[
        "src/daemon.rs",
        "src/models.rs",
        "src/observe.rs",
        "src/propose",
        "src/graph",
        "src/balance",
        "src/meta",
        "src/ratify.rs",
        "src/supervisor",
        "src/actor",
        "src/evaluator",
        "src/isolation",
        "src/ledger",
        "src/verifier",
    ];

    /// Strictly forbidden paths for Tier 2: tests, scoring rules, containment boundaries, legal covenants
    pub const IMMUTABLE_ENGINE_BOUNDARIES: &'static [&'static str] = &[
        "tests",
        "src/evaluator",
        "src/isolation",
        "src/ledger",
        ".rsi/holdouts",
        "CONSTITUTION.md",
        "LICENSE",
    ];

    pub fn classify_proposal(proposal: &ImprovementProposal) -> CandidateTier {
        if proposal.kind == ProposalKind::MetaEngineImprovement {
            return CandidateTier::Tier2Engine;
        }
        let target = proposal.target_file.trim_start_matches("./").trim_start_matches('/');
        for prefix in Self::ENGINE_PREFIXES {
            if target == *prefix || target.starts_with(prefix) {
                return CandidateTier::Tier2Engine;
            }
        }
        CandidateTier::Tier1Target
    }

    pub fn validate_tier2_candidate_boundaries(target_file: &str) -> Result<(), String> {
        let normalized = target_file.trim_start_matches("./").trim_start_matches('/');
        for boundary in Self::IMMUTABLE_ENGINE_BOUNDARIES {
            if normalized == *boundary || normalized.starts_with(boundary) {
                return Err(format!(
                    "Tier 2 Engine Invariant Violation: Candidate Engine N+1 cannot modify immutable boundary '{}'. Scoring rules, containment, tests, and holdouts are strictly immutable.",
                    boundary
                ));
            }
        }
        Ok(())
    }

    pub fn verify_operator_authorization(
        proposal_digest: &[u8],
        signature_hex: &str,
        verifying_key: &VerifyingKey,
    ) -> Result<bool, String> {
        let sig_bytes = hex::decode(signature_hex)
            .map_err(|e| format!("Invalid operator signature hex: {}", e))?;
        let signature = Signature::from_slice(&sig_bytes)
            .map_err(|e| format!("Invalid P-256 operator signature format: {}", e))?;
        verifying_key
            .verify(proposal_digest, &signature)
            .map(|_| true)
            .map_err(|e| format!("Operator cryptographic signature verification failed: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;
    use sha2::{Digest, Sha256};

    #[test]
    fn test_tier_classification() {
        let p1 = ImprovementProposal {
            id: "p1".to_string(),
            title: "unslop target".to_string(),
            description: "clean".to_string(),
            target_file: "README.md".to_string(),
            proposed_patch: "clean text".to_string(),
            kind: ProposalKind::UnslopSanitization,
            created_at: "now".to_string(),
            sandbox_path: None,
            operator_signature: None,
        };
        assert_eq!(TierGovernance::classify_proposal(&p1), CandidateTier::Tier1Target);

        let p2 = ImprovementProposal {
            id: "p2".to_string(),
            title: "speedup proposal".to_string(),
            description: "optimize".to_string(),
            target_file: "src/propose/mod.rs".to_string(),
            proposed_patch: "code".to_string(),
            kind: ProposalKind::Optimization,
            created_at: "now".to_string(),
            sandbox_path: None,
            operator_signature: None,
        };
        assert_eq!(TierGovernance::classify_proposal(&p2), CandidateTier::Tier2Engine);
    }

    #[test]
    fn test_tier2_immutable_boundary_rejection() {
        assert!(TierGovernance::validate_tier2_candidate_boundaries("src/propose/mod.rs").is_ok());
        assert!(TierGovernance::validate_tier2_candidate_boundaries("src/daemon.rs").is_ok());

        assert!(TierGovernance::validate_tier2_candidate_boundaries("tests/test_foo.rs").is_err());
        assert!(TierGovernance::validate_tier2_candidate_boundaries("src/evaluator/stats.rs").is_err());
        assert!(TierGovernance::validate_tier2_candidate_boundaries("src/isolation/container.rs").is_err());
        assert!(TierGovernance::validate_tier2_candidate_boundaries("CONSTITUTION.md").is_err());
    }

    #[test]
    fn test_operator_signature_verification() {
        let signing_key = SigningKey::from_bytes(&[42u8; 32].into()).unwrap();
        let verifying_key = signing_key.verifying_key();

        let patch = "pub fn engine_accelerate() {}";
        let digest = Sha256::digest(patch.as_bytes());
        let signature: Signature = signing_key.sign(&digest);
        let sig_hex = hex::encode(signature.to_bytes());

        let res = TierGovernance::verify_operator_authorization(&digest, &sig_hex, &verifying_key);
        assert!(res.is_ok());
        assert!(res.unwrap());

        let bad_digest = Sha256::digest(b"tampered patch");
        let bad_res = TierGovernance::verify_operator_authorization(&bad_digest, &sig_hex, &verifying_key);
        assert!(bad_res.is_err());
    }
}
