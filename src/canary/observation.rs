//! Version 2 canary observation: the supervisor's verified record of one issued request and
//! its checked outcome. Version 1 (`crate::canary_observation`) is history and stays as it is.
//!
//! Everything in the record comes from the supervisor: it issued the request, measured the
//! elapsed time on its own clock, hashed the bytes it received and compared them with the
//! pinned workload. Nothing the worker says about itself is in here.

use super::{canonical_json, domain_digest, is_hex_digest, sha256_hex, OBSERVATION_RECORD_VERSION};
use serde::{Deserialize, Serialize};

pub const OBSERVATION_DOMAIN: &str = "spark-rsi/canary-observation/v2";
pub const OBSERVATION_ID_DOMAIN: &str = "spark-rsi/canary-observation-id/v2";

/// What the supervisor established about one issued request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifiedStatus {
    /// A well-formed result for this request arrived within the deadline and its bytes equal
    /// the pinned expected output.
    VerifiedSuccess,
    /// A well-formed result arrived within the deadline but did not equal the expected output.
    WrongResult,
    /// No well-formed result arrived before the deadline.
    Timeout,
    /// A frame arrived for this request but was not a valid versioned result for this
    /// generation (wrong protocol version, wrong generation, undecodable).
    InvalidResponse,
    /// The authenticated connection closed before a result arrived.
    ConnectionClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    /// Produced by the supervisor from a request it issued over an authenticated connection.
    Measured,
    /// A rehearsal in the same shape. Never counts.
    Synthetic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryObservationV2 {
    pub record_version: u16,
    /// Domain-separated hash of (generation id, request id, request digest). Duplicates and
    /// replays collide by construction.
    pub observation_id: String,
    pub generation_id: String,
    pub request_id: String,
    pub request_digest: String,
    pub workload_digest: String,
    pub candidate_executable_digest: String,
    /// SHA-256 of the exact result bytes received, or absent when no result arrived.
    pub result_digest: Option<String>,
    /// Supervisor-measured time from sending the request to reading the complete result frame.
    pub elapsed_us: u64,
    /// Supervisor clock when the observation was recorded, milliseconds since the Unix epoch.
    pub observed_at_ms: u64,
    pub status: VerifiedStatus,
    pub provenance: Provenance,
}

/// Observation identity: domain-separated hash of the issued request's coordinates.
pub fn observation_id(generation_id: &str, request_id: &str, request_digest: &str) -> String {
    domain_digest(
        OBSERVATION_ID_DOMAIN,
        &[
            generation_id.as_bytes(),
            request_id.as_bytes(),
            request_digest.as_bytes(),
        ],
    )
}

/// SHA-256 of the exact result bytes received.
pub fn result_digest(output: &[u8]) -> String {
    sha256_hex(output)
}

/// Everything the supervisor binds into one observation, before the id is derived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationInput<'a> {
    pub generation_id: &'a str,
    pub request_id: &'a str,
    pub request_digest: &'a str,
    pub workload_digest: &'a str,
    pub candidate_executable_digest: &'a str,
    pub result_digest: Option<&'a str>,
    pub elapsed_us: u64,
    pub observed_at_ms: u64,
    pub status: VerifiedStatus,
    pub provenance: Provenance,
}

impl CanaryObservationV2 {
    /// Builds the record and derives its id.
    pub fn new(input: ObservationInput<'_>) -> Self {
        Self {
            record_version: OBSERVATION_RECORD_VERSION,
            observation_id: observation_id(
                input.generation_id,
                input.request_id,
                input.request_digest,
            ),
            generation_id: input.generation_id.to_string(),
            request_id: input.request_id.to_string(),
            request_digest: input.request_digest.to_string(),
            workload_digest: input.workload_digest.to_string(),
            candidate_executable_digest: input.candidate_executable_digest.to_string(),
            result_digest: input.result_digest.map(str::to_string),
            elapsed_us: input.elapsed_us,
            observed_at_ms: input.observed_at_ms,
            status: input.status,
            provenance: input.provenance,
        }
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        canonical_json(self)
    }

    /// Domain-separated SHA-256 of the canonical bytes. Covers every field.
    pub fn digest_hex(&self) -> String {
        domain_digest(OBSERVATION_DOMAIN, &[&self.canonical_bytes()])
    }

    /// Structural validity: version, non-empty ids, well-formed digests, id derivation, and a
    /// result digest present exactly when a result was received.
    pub fn validate(&self) -> Result<(), String> {
        if self.record_version != OBSERVATION_RECORD_VERSION {
            return Err(format!(
                "observation record version {} is not supported (expected {})",
                self.record_version, OBSERVATION_RECORD_VERSION
            ));
        }
        if self.generation_id.trim().is_empty() {
            return Err("observation generation id is required".to_string());
        }
        if self.request_id.trim().is_empty() {
            return Err("observation request id is required".to_string());
        }
        for (name, value) in [
            ("request_digest", &self.request_digest),
            ("workload_digest", &self.workload_digest),
            (
                "candidate_executable_digest",
                &self.candidate_executable_digest,
            ),
        ] {
            if !is_hex_digest(value) {
                return Err(format!("observation {} is not a hex SHA-256", name));
            }
        }
        match (&self.result_digest, self.status) {
            (Some(d), _) if !is_hex_digest(d) => {
                return Err("observation result_digest is not a hex SHA-256".to_string());
            }
            (None, VerifiedStatus::VerifiedSuccess) | (None, VerifiedStatus::WrongResult) => {
                return Err(format!(
                    "observation status {:?} requires a result digest",
                    self.status
                ));
            }
            _ => {}
        }
        let expected = observation_id(&self.generation_id, &self.request_id, &self.request_digest);
        if self.observation_id != expected {
            return Err(format!(
                "observation id {} does not derive from its generation, request and request digest",
                self.observation_id
            ));
        }
        Ok(())
    }

    /// Counts toward the quota only when measured and verified as a success. The quota
    /// validator applies the remaining checks (workload membership, expected result, identity).
    pub fn is_qualifying(&self) -> bool {
        self.provenance == Provenance::Measured
            && self.status == VerifiedStatus::VerifiedSuccess
            && self.result_digest.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn sample(status: VerifiedStatus) -> CanaryObservationV2 {
        CanaryObservationV2::new(ObservationInput {
            generation_id: "gen-0001",
            request_id: "req-001",
            request_digest: &sha256_hex(b"request"),
            workload_digest: &sha256_hex(b"workload"),
            candidate_executable_digest: &sha256_hex(b"executable"),
            result_digest: Some(&sha256_hex(b"pong")),
            elapsed_us: 1234,
            observed_at_ms: 1_700_000_000_000,
            status,
            provenance: Provenance::Measured,
        })
    }

    #[test]
    fn id_derives_from_generation_request_and_digest_only() {
        let a = sample(VerifiedStatus::VerifiedSuccess);
        let mut b = sample(VerifiedStatus::WrongResult);
        b.elapsed_us = 9;
        assert_eq!(a.observation_id, b.observation_id);
        assert_ne!(a.digest_hex(), b.digest_hex());
        let c = CanaryObservationV2::new(ObservationInput {
            request_id: "req-002",
            ..ObservationInput {
                generation_id: "gen-0001",
                request_id: "req-001",
                request_digest: &a.request_digest,
                workload_digest: &a.workload_digest,
                candidate_executable_digest: &a.candidate_executable_digest,
                result_digest: a.result_digest.as_deref(),
                elapsed_us: a.elapsed_us,
                observed_at_ms: a.observed_at_ms,
                status: a.status,
                provenance: a.provenance,
            }
        });
        assert_ne!(a.observation_id, c.observation_id);
    }

    #[test]
    fn validation_covers_version_ids_digests_and_result_presence() {
        assert!(sample(VerifiedStatus::VerifiedSuccess).validate().is_ok());

        let mut tampered_id = sample(VerifiedStatus::VerifiedSuccess);
        tampered_id.request_id = "req-999".into();
        assert!(tampered_id
            .validate()
            .unwrap_err()
            .contains("does not derive"));

        let mut bad_version = sample(VerifiedStatus::VerifiedSuccess);
        bad_version.record_version = 1;
        assert!(bad_version.validate().is_err());

        let mut no_result = sample(VerifiedStatus::VerifiedSuccess);
        no_result.result_digest = None;
        assert!(no_result
            .validate()
            .unwrap_err()
            .contains("requires a result digest"));

        let mut timeout = sample(VerifiedStatus::Timeout);
        timeout.result_digest = None;
        assert!(timeout.validate().is_ok());
        assert!(!timeout.is_qualifying());

        let mut bad_digest = sample(VerifiedStatus::VerifiedSuccess);
        bad_digest.workload_digest = "nope".into();
        assert!(bad_digest.validate().is_err());
    }

    #[test]
    fn only_measured_verified_success_qualifies() {
        assert!(sample(VerifiedStatus::VerifiedSuccess).is_qualifying());
        assert!(!sample(VerifiedStatus::WrongResult).is_qualifying());
        let mut synthetic = sample(VerifiedStatus::VerifiedSuccess);
        synthetic.provenance = Provenance::Synthetic;
        assert!(!synthetic.is_qualifying());
    }

    #[test]
    fn canonical_bytes_are_sorted_and_compact() {
        let bytes = sample(VerifiedStatus::VerifiedSuccess).canonical_bytes();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("{\"candidate_executable_digest\":\""));
        assert!(text.contains("\"status\":\"verified_success\","));
        assert!(text.ends_with(&format!(
            "\"workload_digest\":\"{}\"}}",
            sha256_hex(b"workload")
        )));
        assert!(!text.contains(' '));
    }
}
