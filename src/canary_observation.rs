//! Production canary evidence.
//!
//! A qualifying observation is a measured result. A synthetic rehearsal can use
//! the same shape and cannot increment the production quota. The same
//! observation id with the same canonical record is an idempotent success.
//! The same id with a different record is a conflict.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservationProvenance {
    Measured,
    Synthetic,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanaryObservation {
    pub observation_id: String,
    pub observed_at_ms: u64,
    pub candidate_digest: String,
    pub latency_us: u64,
    pub status: String,
    pub provenance: ObservationProvenance,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuotaDecision {
    pub counted: u64,
}

impl CanaryObservation {
    /// One JSON object, keys in alphabetical order, no insignificant whitespace.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let provenance = match self.provenance {
            ObservationProvenance::Measured => "measured",
            ObservationProvenance::Synthetic => "synthetic",
        };
        format!(
            "{{\"candidate_digest\":\"{}\",\"latency_us\":{},\"observation_id\":\"{}\",\"observed_at_ms\":{},\"provenance\":\"{}\",\"status\":\"{}\"}}",
            json_string(&self.candidate_digest),
            self.latency_us,
            json_string(&self.observation_id),
            self.observed_at_ms,
            provenance,
            json_string(&self.status),
        )
        .into_bytes()
    }

    pub fn digest_hex(&self) -> String {
        hex::encode(Sha256::digest(self.canonical_bytes()))
    }
}

pub fn admit_production_quota(
    observations: &[CanaryObservation],
    candidate_digest: &str,
    target: u64,
) -> Result<QuotaDecision, String> {
    if target == 0 {
        return Err("production canary quota target must be at least 1".to_string());
    }
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    let mut counted = 0u64;
    for obs in observations {
        if obs.observation_id.trim().is_empty() {
            return Err("observation id is required".to_string());
        }
        if obs.status.trim().is_empty() {
            return Err("execution status is required".to_string());
        }
        if obs.candidate_digest != candidate_digest {
            return Err("observation candidate digest does not match the candidate".to_string());
        }
        if obs.provenance != ObservationProvenance::Measured {
            return Err(
                "synthetic rehearsal cannot satisfy the production canary quota".to_string(),
            );
        }
        let digest = obs.digest_hex();
        if let Some(previous) = seen.get(&obs.observation_id) {
            if previous != &digest {
                return Err(format!(
                    "observation id {} conflicts with a different record",
                    obs.observation_id
                ));
            }
            continue;
        }
        seen.insert(obs.observation_id.clone(), digest);
        counted += 1;
    }
    if counted < target {
        return Err(format!(
            "production canary quota requires {} measured observations, received {}",
            target, counted
        ));
    }
    Ok(QuotaDecision { counted })
}

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn measured(id: &str, latency: u64, status: &str) -> CanaryObservation {
        CanaryObservation {
            observation_id: id.to_string(),
            observed_at_ms: 1_700_000_000_000,
            candidate_digest: "abc".to_string(),
            latency_us: latency,
            status: status.to_string(),
            provenance: ObservationProvenance::Measured,
        }
    }

    #[test]
    fn empty_quota_fails_closed() {
        let err = admit_production_quota(&[], "abc", 3).unwrap_err();
        assert!(err.contains("received 0"));
    }

    #[test]
    fn synthetic_rehearsal_cannot_fill_the_quota() {
        let mut obs = measured("obs-1", 1500, "ok");
        obs.provenance = ObservationProvenance::Synthetic;
        let err = admit_production_quota(&[obs], "abc", 1).unwrap_err();
        assert!(err.contains("synthetic rehearsal"));
    }

    #[test]
    fn identical_retry_counts_once_and_changed_payload_conflicts() {
        let first = measured("obs-1", 1800, "ok");
        let retry = first.clone();
        let decision = admit_production_quota(&[first.clone(), retry], "abc", 1).unwrap();
        assert_eq!(decision.counted, 1);

        let mut changed = first.clone();
        changed.latency_us = 9999;
        let err = admit_production_quota(&[first, changed], "abc", 1).unwrap_err();
        assert!(err.contains("conflicts"));
    }

    #[test]
    fn canonical_digest_covers_the_whole_record() {
        let mut other = measured("obs-1", 1800, "ok");
        other.status = "error".to_string();
        assert_ne!(
            measured("obs-1", 1800, "ok").digest_hex(),
            other.digest_hex()
        );
    }
}
