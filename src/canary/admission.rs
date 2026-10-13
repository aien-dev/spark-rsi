//! The hand-off from a sealed observation log to the quota validator. This is the single
//! authority on evidence sufficiency for the version 2 path: the supervisor collects and
//! seals, the promotion path decides whether to promote, and only this function says whether
//! enough verified evidence exists.
//!
//! Everything fails closed. Only measured, supervisor-confirmed successes whose request is in
//! the pinned workload, whose request digest matches it, whose result digest equals the
//! workload's expected outcome, and whose elapsed time is within the request deadline count.
//! A single non-success observation in the log refuses admission: a canary with a failed or
//! slow request is not promotable. The old `CanaryReport` self-report path cannot produce a
//! version 2 observation, so it can never satisfy this validator.

use super::{
    CanaryWorkloadManifest, CandidateIdentity, Provenance, SealedObservationLog, VerifiedStatus,
};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedQuotaDecision {
    pub counted: u64,
    pub target: u64,
    pub generation_id: String,
    pub candidate_executable_digest: String,
    pub workload_digest: String,
    pub log_digest: String,
}

pub fn admit_sealed_quota(
    sealed: &SealedObservationLog,
    identity: &CandidateIdentity,
    workload: &CanaryWorkloadManifest,
    target: u64,
) -> Result<SealedQuotaDecision, String> {
    if target == 0 {
        return Err("production canary quota target must be at least 1".to_string());
    }
    identity.validate()?;
    workload.validate()?;
    let workload_digest = workload.digest();

    let header = &sealed.header;
    if header.generation_id != identity.generation_id {
        return Err(format!(
            "observation log is for generation {}, candidate is generation {}",
            header.generation_id, identity.generation_id
        ));
    }
    if header.candidate_executable_digest != identity.executable_digest {
        return Err(format!(
            "observation log executable digest {} does not match the candidate executable {}",
            header.candidate_executable_digest, identity.executable_digest
        ));
    }
    if header.workload_digest != workload_digest {
        return Err(format!(
            "observation log workload digest {} does not match the pinned workload {}",
            header.workload_digest, workload_digest
        ));
    }

    let mut counted = 0u64;
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for obs in &sealed.observations {
        obs.validate()?;
        if obs.generation_id != identity.generation_id
            || obs.candidate_executable_digest != identity.executable_digest
            || obs.workload_digest != workload_digest
        {
            return Err(format!(
                "observation {} is not bound to this generation, executable and workload",
                obs.observation_id
            ));
        }
        if obs.provenance != Provenance::Measured {
            return Err(format!(
                "observation {} is a synthetic rehearsal; it cannot satisfy the production canary quota",
                obs.observation_id
            ));
        }
        if obs.status != VerifiedStatus::VerifiedSuccess {
            return Err(format!(
                "canary observed a {:?} on request {}; the candidate is not promotable",
                obs.status, obs.request_id
            ));
        }
        let spec = workload.request(&obs.request_id).ok_or_else(|| {
            format!(
                "observation {} answers request {} which is not in the pinned workload",
                obs.observation_id, obs.request_id
            )
        })?;
        let expected_request = spec.request_digest(&workload.workload_id);
        if obs.request_digest != expected_request {
            return Err(format!(
                "observation {} carries request digest {}, workload request {} has {}",
                obs.observation_id, obs.request_digest, spec.request_id, expected_request
            ));
        }
        let expected_result = spec.expected_result_digest();
        if obs.result_digest.as_deref() != Some(expected_result.as_str()) {
            return Err(format!(
                "observation {} result digest {:?} does not equal the expected outcome of request {}",
                obs.observation_id, obs.result_digest, spec.request_id
            ));
        }
        if obs.elapsed_us > spec.deadline_ms.saturating_mul(1000) {
            return Err(format!(
                "observation {} took {} us, over the {} ms deadline of request {}",
                obs.observation_id, obs.elapsed_us, spec.deadline_ms, spec.request_id
            ));
        }
        if seen.insert(obs.observation_id.as_str()) {
            counted += 1;
        }
    }

    if counted < target {
        return Err(format!(
            "production canary quota requires {} verified observations, received {}",
            target, counted
        ));
    }
    Ok(SealedQuotaDecision {
        counted,
        target,
        generation_id: identity.generation_id.clone(),
        candidate_executable_digest: identity.executable_digest.clone(),
        workload_digest,
        log_digest: sealed.seal.log_digest.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canary::observation::ObservationInput;
    use crate::canary::{
        sha256_hex, CanaryObservationV2, CanaryRequestSpec, LogHeader, Nondeterminism,
        ObservationLogWriter,
    };

    fn workload() -> CanaryWorkloadManifest {
        CanaryWorkloadManifest {
            workload_version: 1,
            workload_id: "fixture-v1".into(),
            protocol_version: 1,
            requests: (1..=3)
                .map(|i| CanaryRequestSpec {
                    request_id: format!("req-{:03}", i),
                    input: format!("ping {}", i),
                    expected_output: format!("pong {}", i),
                    deadline_ms: 2000,
                    nondeterminism: Nondeterminism::Exact,
                })
                .collect(),
        }
    }

    fn identity() -> CandidateIdentity {
        CandidateIdentity::new(
            &sha256_hex(b"patch"),
            &sha256_hex(b"tree"),
            &sha256_hex(b"exe"),
            "gen-0001",
        )
    }

    fn observation(
        w: &CanaryWorkloadManifest,
        id: &CandidateIdentity,
        request_id: &str,
        output: &str,
        elapsed_us: u64,
        status: VerifiedStatus,
    ) -> CanaryObservationV2 {
        let spec = w.request(request_id).unwrap();
        CanaryObservationV2::new(ObservationInput {
            generation_id: &id.generation_id,
            request_id,
            request_digest: &spec.request_digest(&w.workload_id),
            workload_digest: &w.digest(),
            candidate_executable_digest: &id.executable_digest,
            result_digest: Some(&sha256_hex(output.as_bytes())),
            elapsed_us,
            observed_at_ms: 1_700_000_000_000 + elapsed_us,
            status,
            provenance: Provenance::Measured,
        })
    }

    fn sealed_with(obs: &[CanaryObservationV2]) -> SealedObservationLog {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("gen.jsonl");
        let id = identity();
        let mut w = ObservationLogWriter::create(
            &path,
            LogHeader::new(
                &id.generation_id,
                &workload().digest(),
                &id.executable_digest,
                1,
            ),
        )
        .unwrap();
        for o in obs {
            w.append_observation(o).unwrap();
        }
        w.seal(2).unwrap()
    }

    #[test]
    fn enough_genuine_observations_pass() {
        let w = workload();
        let id = identity();
        let obs: Vec<_> = (1..=3)
            .map(|i| {
                observation(
                    &w,
                    &id,
                    &format!("req-{:03}", i),
                    &format!("pong {}", i),
                    800,
                    VerifiedStatus::VerifiedSuccess,
                )
            })
            .collect();
        let sealed = sealed_with(&obs);
        let decision = admit_sealed_quota(&sealed, &id, &w, 3).unwrap();
        assert_eq!(decision.counted, 3);
        assert_eq!(decision.log_digest, sealed.seal.log_digest);
        assert!(admit_sealed_quota(&sealed, &id, &w, 4)
            .unwrap_err()
            .contains("received 3"));
    }

    #[test]
    fn zero_observations_fail_closed() {
        let sealed = sealed_with(&[]);
        let err = admit_sealed_quota(&sealed, &identity(), &workload(), 1).unwrap_err();
        assert!(err.contains("received 0"), "{}", err);
        assert!(admit_sealed_quota(&sealed, &identity(), &workload(), 0).is_err());
    }

    #[test]
    fn wrong_output_timeout_and_synthetic_cannot_qualify() {
        let w = workload();
        let id = identity();
        let good = observation(
            &w,
            &id,
            "req-001",
            "pong 1",
            800,
            VerifiedStatus::VerifiedSuccess,
        );

        let wrong = observation(
            &w,
            &id,
            "req-002",
            "pong 1",
            800,
            VerifiedStatus::WrongResult,
        );
        let err = admit_sealed_quota(&sealed_with(&[good.clone(), wrong]), &id, &w, 1).unwrap_err();
        assert!(err.contains("WrongResult"), "{}", err);

        // A success claimed with the wrong bytes is refused even if the status says success.
        let lying = observation(
            &w,
            &id,
            "req-002",
            "pong 1",
            800,
            VerifiedStatus::VerifiedSuccess,
        );
        let err = admit_sealed_quota(&sealed_with(&[lying]), &id, &w, 1).unwrap_err();
        assert!(err.contains("expected outcome"), "{}", err);

        let mut timeout = observation(&w, &id, "req-002", "", 2_000_001, VerifiedStatus::Timeout);
        timeout.result_digest = None;
        let err =
            admit_sealed_quota(&sealed_with(&[good.clone(), timeout]), &id, &w, 1).unwrap_err();
        assert!(err.contains("Timeout"), "{}", err);

        let slow = observation(
            &w,
            &id,
            "req-002",
            "pong 2",
            2_000_001,
            VerifiedStatus::VerifiedSuccess,
        );
        let err = admit_sealed_quota(&sealed_with(&[slow]), &id, &w, 1).unwrap_err();
        assert!(err.contains("deadline"), "{}", err);

        let mut synthetic = good.clone();
        synthetic.provenance = Provenance::Synthetic;
        let err = admit_sealed_quota(&sealed_with(&[synthetic]), &id, &w, 1).unwrap_err();
        assert!(err.contains("synthetic"), "{}", err);
    }

    #[test]
    fn mismatched_identity_or_workload_is_refused() {
        let w = workload();
        let id = identity();
        let sealed = sealed_with(&[observation(
            &w,
            &id,
            "req-001",
            "pong 1",
            800,
            VerifiedStatus::VerifiedSuccess,
        )]);

        let mut other_exe = identity();
        other_exe.executable_digest = sha256_hex(b"something else that was built");
        assert!(admit_sealed_quota(&sealed, &other_exe, &w, 1)
            .unwrap_err()
            .contains("executable"));

        let mut other_gen = identity();
        other_gen.generation_id = "gen-0002".into();
        assert!(admit_sealed_quota(&sealed, &other_gen, &w, 1)
            .unwrap_err()
            .contains("generation"));

        let mut other_workload = workload();
        other_workload.requests[0].expected_output = "anything".into();
        assert!(admit_sealed_quota(&sealed, &id, &other_workload, 1)
            .unwrap_err()
            .contains("workload"));
    }

    #[test]
    fn unknown_request_or_tampered_request_digest_is_refused() {
        let w = workload();
        let id = identity();
        let mut stranger = observation(
            &w,
            &id,
            "req-001",
            "pong 1",
            800,
            VerifiedStatus::VerifiedSuccess,
        );
        stranger.request_id = "req-777".into();
        stranger.observation_id =
            crate::canary::observation_id(&id.generation_id, "req-777", &stranger.request_digest);
        let err = admit_sealed_quota(&sealed_with(&[stranger]), &id, &w, 1).unwrap_err();
        assert!(err.contains("not in the pinned workload"), "{}", err);

        let mut relabeled = observation(
            &w,
            &id,
            "req-002",
            "pong 1",
            800,
            VerifiedStatus::VerifiedSuccess,
        );
        // Keep the request id but carry the digest of another request.
        relabeled.request_digest = w.requests[0].request_digest(&w.workload_id);
        relabeled.observation_id =
            crate::canary::observation_id(&id.generation_id, "req-002", &relabeled.request_digest);
        let err = admit_sealed_quota(&sealed_with(&[relabeled]), &id, &w, 1).unwrap_err();
        assert!(err.contains("request digest"), "{}", err);
    }
}
