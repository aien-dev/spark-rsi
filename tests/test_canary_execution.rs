//! Drives the real fixture binary through the supervisor's canary executor. Every run goes over
//! a real Unix socket with a real child process; the secret reaches the child only through its
//! environment.

mod canary_fixture;

use spark_rsi::canary::identity::digest_file;
use spark_rsi::canary::{
    admit_sealed_quota, result_digest, CanaryAdapterManifest, CanaryWorkloadManifest,
    CandidateIdentity, PinnedWorkload, SealedObservationLog, VerifiedStatus,
};
use spark_rsi::supervisor::canary_exec::{
    observation_log_path, CanaryExecutor, ExecutionOutcome, ExecutorConfig,
};
use spark_rsi::supervisor::daemon::SupervisorConfig;
use spark_rsi::supervisor::{GenerationInfo, GenerationState, HostSupervisor};
use std::path::PathBuf;
use std::time::Duration;

const SECRET: &str = "test-secret-passed-through-the-environment-only";
const GEN: &str = "gen-fixture-0001";

struct Harness {
    _tmp: tempfile::TempDir,
    rsi_root: PathBuf,
    config: SupervisorConfig,
    supervisor: HostSupervisor,
    workload: PinnedWorkload,
    identity: CandidateIdentity,
    exe: PathBuf,
}

fn harness() -> Harness {
    let exe = canary_fixture::fixture_executable().to_path_buf();
    let tmp = tempfile::tempdir().unwrap();
    let rsi_root = tmp.path().join(".rsi");
    let config = SupervisorConfig {
        rsi_root: rsi_root.clone(),
        socket_path: rsi_root.join("supervisor.sock"),
        memory_limit_mb: 49152,
        canary_target: 10,
        max_latency_us: 1_000_000,
        max_error_rate: 0.0,
        shared_secret: SECRET.to_string(),
    };
    let supervisor = HostSupervisor::new(&rsi_root, config.memory_limit_mb);
    let workload =
        CanaryWorkloadManifest::load(&canary_fixture::fixture_dir().join("workload.json")).unwrap();
    let identity = CandidateIdentity::new(
        &result_digest(b"patch"),
        &result_digest(b"tree"),
        &digest_file(&exe).unwrap(),
        GEN,
    );
    Harness {
        _tmp: tmp,
        rsi_root,
        config,
        supervisor,
        workload,
        identity,
        exe,
    }
}

impl Harness {
    fn generation(&self) -> GenerationInfo {
        let src = self._tmp.path().join("artifacts");
        std::fs::create_dir_all(&src).unwrap();
        self.supervisor
            .stage_generation(GEN, &src, "manifest-digest")
            .unwrap()
    }

    fn executor(
        &self,
        mode: &str,
        extra_env: &[(&str, &str)],
        mut exec: ExecutorConfig,
    ) -> CanaryExecutor<'_> {
        exec.worker_env
            .push(("RSI_CANARY_FIXTURE_MODE".to_string(), mode.to_string()));
        for (k, v) in extra_env {
            exec.worker_env.push((k.to_string(), v.to_string()));
        }
        CanaryExecutor::new(
            &self.supervisor,
            self.config.clone(),
            self.workload.clone(),
            self.identity.clone(),
            self.exe.clone(),
            Vec::new(),
            exec,
        )
    }

    fn admit(&self, sealed: &SealedObservationLog) -> Result<(), String> {
        admit_sealed_quota(sealed, &self.identity, &self.workload.manifest, 10).map(|_| ())
    }

    fn active_sock_untouched(&self) {
        assert!(
            std::fs::symlink_metadata(self.rsi_root.join("active.sock")).is_err(),
            "the executor must never switch active.sock"
        );
    }
}

fn quick() -> ExecutorConfig {
    ExecutorConfig {
        readiness_deadline: Duration::from_secs(5),
        settle_window: Duration::from_millis(300),
        deadline_cap_ms: Some(400),
        ..ExecutorConfig::default()
    }
}

fn sealed_of(outcome: &ExecutionOutcome) -> &SealedObservationLog {
    outcome.sealed().expect("run should have sealed its log")
}

#[test]
fn the_fixture_ships_a_valid_adapter_manifest() {
    let loaded = CanaryAdapterManifest::load_from_tree(&canary_fixture::fixture_dir()).unwrap();
    assert_eq!(loaded.manifest.executable, "release/canary-target");
    assert_eq!(loaded.manifest.workload_id, "fixture-v1");
    let workload =
        CanaryWorkloadManifest::load(&canary_fixture::fixture_dir().join("workload.json")).unwrap();
    assert_eq!(workload.manifest.workload_id, loaded.manifest.workload_id);
    assert_eq!(workload.manifest.requests.len(), 10);
    assert!(workload
        .manifest
        .requests
        .iter()
        .all(|r| r.deadline_ms == 2000));
}

#[tokio::test]
async fn correct_run_yields_ten_qualifying_observations_and_passes_the_quota() {
    let h = harness();
    let mut generation = h.generation();
    let outcome = h
        .executor("correct", &[], ExecutorConfig::default())
        .run(&mut generation)
        .await
        .unwrap();
    let sealed = sealed_of(&outcome);
    assert_eq!(sealed.observations.len(), 10);
    assert_eq!(sealed.qualifying().count(), 10);
    assert!(h.admit(sealed).is_ok());
    let summary = outcome.summary();
    assert!(summary.ready && !summary.reverted);
    assert_eq!(summary.verified_success, 10);
    assert_eq!(summary.first_failure, None);
    // Elapsed time is the supervisor's, and every observation is bound to the executable.
    assert!(
        sealed
            .observations
            .iter()
            .all(|o| o.elapsed_us > 0
                && o.candidate_executable_digest == h.identity.executable_digest)
    );
    // The executor never promotes and never switches the active socket.
    assert_ne!(generation.state, GenerationState::Durable);
    assert_eq!(generation.state, GenerationState::CanaryActive);
    h.active_sock_untouched();
    // The sealed log on disk verifies independently.
    let reloaded = SealedObservationLog::load(&observation_log_path(&h.rsi_root, GEN)).unwrap();
    assert_eq!(reloaded.log_digest(), sealed.log_digest());
}

#[tokio::test]
async fn wrong_answer_is_recorded_reverts_early_and_fails_admission() {
    let h = harness();
    let mut generation = h.generation();
    let outcome = h
        .executor("wrong_answer", &[], quick())
        .run(&mut generation)
        .await
        .unwrap();
    let sealed = sealed_of(&outcome);
    assert_eq!(
        sealed.observations.len(),
        3,
        "no request after the failure is issued"
    );
    assert_eq!(sealed.observations[2].status, VerifiedStatus::WrongResult);
    assert_eq!(sealed.observations[2].request_id, "req-003");
    assert_eq!(generation.state, GenerationState::Reverting);
    assert!(outcome.summary().reverted);
    assert_eq!(
        outcome.summary().first_failure.as_deref(),
        Some("req-003: WrongResult")
    );
    assert!(h.admit(sealed).is_err());
    h.active_sock_untouched();
}

#[tokio::test]
async fn fabricated_success_cannot_qualify() {
    let h = harness();
    let mut generation = h.generation();
    let outcome = h
        .executor("fabricate_success", &[], quick())
        .run(&mut generation)
        .await
        .unwrap();
    let sealed = sealed_of(&outcome);
    // The worker's CanaryReport frames and worker_latency_us of 1 created nothing: the one
    // observation is the supervisor's own verdict on the wrong answer.
    assert_eq!(sealed.observations.len(), 1);
    assert_eq!(sealed.observations[0].status, VerifiedStatus::WrongResult);
    assert_eq!(sealed.qualifying().count(), 0);
    assert_ne!(sealed.observations[0].elapsed_us, 1);
    assert!(h.admit(sealed).is_err());
    assert_eq!(generation.state, GenerationState::Reverting);
}

#[tokio::test]
async fn duplicate_results_yield_one_observation_per_request_and_rejections() {
    let h = harness();
    let mut generation = h.generation();
    let outcome = h
        .executor("duplicate", &[], quick())
        .run(&mut generation)
        .await
        .unwrap();
    let sealed = sealed_of(&outcome);
    assert_eq!(sealed.observations.len(), 10);
    let mut ids: Vec<&str> = sealed
        .observations
        .iter()
        .map(|o| o.request_id.as_str())
        .collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 10, "exactly one observation per request");
    assert!(
        outcome.summary().rejections >= 9,
        "each extra result is a rejection, got {}",
        outcome.summary().rejections
    );
    assert_eq!(sealed.rejections.len(), outcome.summary().rejections);
    assert!(
        h.admit(sealed).is_ok(),
        "duplicates add nothing and break nothing"
    );
}

#[tokio::test]
async fn replay_on_a_new_connection_creates_no_observations_even_across_a_restart() {
    let h = harness();
    let mut generation = h.generation();

    // First run stops after 5 observations, as a supervisor crash would. The worker replays
    // earlier results on a fresh connection at request 3.
    let halted = h
        .executor(
            "replay",
            &[],
            ExecutorConfig {
                halt_after_requests: Some(5),
                ..quick()
            },
        )
        .run(&mut generation)
        .await
        .unwrap();
    assert!(matches!(halted, ExecutionOutcome::Halted { .. }));
    assert_eq!(halted.summary().verified_success, 5);

    // Restart: reopen the same log, never recount, finish the rest. The replay happens again.
    let mut generation = h.generation();
    let outcome = h
        .executor("replay", &[], quick())
        .run(&mut generation)
        .await
        .unwrap();
    let sealed = sealed_of(&outcome);
    assert_eq!(outcome.summary().recovered, 5);
    assert_eq!(outcome.summary().issued, 5);
    assert_eq!(
        sealed.observations.len(),
        10,
        "replays create no new observations"
    );
    assert!(
        sealed.rejections.len() >= 1,
        "the replayed frames are logged as rejections"
    );
    assert!(h.admit(sealed).is_ok());
}

#[tokio::test]
async fn timeout_is_recorded_as_a_timeout_and_reverts() {
    let h = harness();
    let mut generation = h.generation();
    let outcome = h
        .executor("timeout", &[], quick())
        .run(&mut generation)
        .await
        .unwrap();
    let sealed = sealed_of(&outcome);
    assert_eq!(sealed.observations.len(), 3);
    let last = &sealed.observations[2];
    assert_eq!(last.status, VerifiedStatus::Timeout);
    assert_eq!(last.result_digest, None);
    assert!(
        last.elapsed_us >= 400_000,
        "elapsed is the supervisor's: {}",
        last.elapsed_us
    );
    assert_eq!(generation.state, GenerationState::Reverting);
    assert!(h.admit(sealed).is_err());
}

#[tokio::test]
async fn an_answer_to_the_wrong_request_is_a_rejection_then_a_timeout() {
    let h = harness();
    let mut generation = h.generation();
    let outcome = h
        .executor("wrong_request", &[], quick())
        .run(&mut generation)
        .await
        .unwrap();
    let sealed = sealed_of(&outcome);
    assert_eq!(sealed.observations.len(), 3);
    assert_eq!(sealed.observations[2].status, VerifiedStatus::Timeout);
    assert_eq!(sealed.rejections.len(), 1);
    assert!(sealed.rejections[0].reason.contains("req-bogus"));
    assert!(h.admit(sealed).is_err());
}

#[tokio::test]
async fn premature_promotion_attempts_never_reach_durable_or_switch_active_sock() {
    let h = harness();
    let mut generation = h.generation();
    let outcome = h
        .executor("premature_promotion", &[], quick())
        .run(&mut generation)
        .await
        .unwrap();
    assert_ne!(generation.state, GenerationState::Durable);
    h.active_sock_untouched();
    assert!(
        outcome.summary().rejections >= 10,
        "DrainComplete and extra Ready frames are rejections, got {}",
        outcome.summary().rejections
    );
    // The answers were genuine, so the quota (the only authority) is the one that admits.
    let sealed = sealed_of(&outcome);
    assert_eq!(sealed.observations.len(), 10);
    assert!(h.admit(sealed).is_ok());
}

#[tokio::test]
async fn a_wrong_secret_is_rejected_and_closed_without_rollback() {
    let h = harness();
    let mut generation = h.generation();
    let outcome = h
        .executor(
            "correct",
            &[("SUPERVISOR_SECRET", "not-the-supervisor-secret")],
            ExecutorConfig {
                readiness_deadline: Duration::from_secs(3),
                ..quick()
            },
        )
        .run(&mut generation)
        .await
        .unwrap();
    let sealed = sealed_of(&outcome);
    assert!(!outcome.summary().ready);
    assert!(sealed.observations.is_empty());
    assert!(sealed
        .rejections
        .iter()
        .any(|r| r.reason.contains("BadHmac")));
    assert!(h.admit(sealed).is_err());
    h.active_sock_untouched();
}

#[tokio::test]
async fn old_wrong_generation_and_silent_workers_are_never_ready() {
    for (mode, env) in [
        ("old_protocol", vec![]),
        (
            "correct",
            vec![("RSI_CANARY_FIXTURE_PROTOCOL_VERSION", "0")],
        ),
        ("wrong_generation", vec![]),
        ("bare_connection", vec![]),
    ] {
        let h = harness();
        let mut generation = h.generation();
        let outcome = h
            .executor(
                mode,
                &env,
                ExecutorConfig {
                    readiness_deadline: Duration::from_millis(800),
                    ..quick()
                },
            )
            .run(&mut generation)
            .await
            .unwrap();
        let sealed = sealed_of(&outcome);
        assert!(
            !outcome.summary().ready,
            "{} {:?} must not be ready",
            mode,
            env
        );
        assert!(sealed.observations.is_empty(), "{} {:?}", mode, env);
        assert!(outcome.summary().reverted, "{} {:?}", mode, env);
        assert!(h.admit(sealed).is_err());
        h.active_sock_untouched();
    }
}

#[tokio::test]
async fn the_log_survives_a_kill_and_reopen_with_no_double_counting() {
    let h = harness();
    let mut generation = h.generation();
    let halted = h
        .executor(
            "correct",
            &[],
            ExecutorConfig {
                halt_after_requests: Some(4),
                ..quick()
            },
        )
        .run(&mut generation)
        .await
        .unwrap();
    assert!(matches!(halted, ExecutionOutcome::Halted { .. }));

    // The crash cut the next record in half.
    let log = observation_log_path(&h.rsi_root, GEN);
    let mut bytes = std::fs::read(&log).unwrap();
    bytes.extend_from_slice(b"{\"kind\":\"observation\",\"record\":{\"observation\":{\"gener");
    std::fs::write(&log, &bytes).unwrap();

    let mut generation = h.generation();
    let outcome = h
        .executor("correct", &[], quick())
        .run(&mut generation)
        .await
        .unwrap();
    let sealed = sealed_of(&outcome);
    assert_eq!(outcome.summary().recovered, 4);
    assert_eq!(outcome.summary().issued, 6);
    assert_eq!(sealed.observations.len(), 10);
    let mut ids: Vec<&str> = sealed
        .observations
        .iter()
        .map(|o| o.observation_id.as_str())
        .collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 10, "no observation counted twice");
    assert!(h.admit(sealed).is_ok());

    // Nothing may follow the seal, and a sealed log is never reopened by another run.
    let again = h
        .executor("correct", &[], quick())
        .run(&mut h.generation())
        .await;
    assert!(again.is_err());
}

#[tokio::test]
async fn a_failure_recorded_before_a_restart_stays_a_failure() {
    use spark_rsi::canary::observation::ObservationInput;
    use spark_rsi::canary::{CanaryObservationV2, LogHeader, ObservationLogWriter, Provenance};

    let h = harness();
    // A crashed run left an unsealed log whose only record is a wrong result.
    let request = &h.workload.manifest.requests[0];
    let request_digest = request.request_digest(&h.workload.manifest.workload_id);
    let mut writer = ObservationLogWriter::create(
        &observation_log_path(&h.rsi_root, GEN),
        LogHeader::new(GEN, &h.workload.digest, &h.identity.executable_digest, 1),
    )
    .unwrap();
    writer
        .append_observation(&CanaryObservationV2::new(ObservationInput {
            generation_id: GEN,
            request_id: &request.request_id,
            request_digest: &request_digest,
            workload_digest: &h.workload.digest,
            candidate_executable_digest: &h.identity.executable_digest,
            result_digest: Some(&result_digest(b"nope")),
            elapsed_us: 10,
            observed_at_ms: 1,
            status: VerifiedStatus::WrongResult,
            provenance: Provenance::Measured,
        }))
        .unwrap();
    drop(writer);

    let mut generation = h.generation();
    let outcome = h
        .executor("correct", &[], quick())
        .run(&mut generation)
        .await
        .unwrap();
    let summary = outcome.summary();
    assert!(summary.reverted);
    assert!(summary
        .first_failure
        .as_deref()
        .unwrap()
        .contains("recorded before a restart"));
    assert_eq!(
        generation.pid, None,
        "no worker is launched for a failed canary"
    );
    assert_eq!(generation.state, GenerationState::Reverting);
    assert!(h.admit(sealed_of(&outcome)).is_err());
}

#[tokio::test]
async fn a_mismatched_executable_digest_refuses_to_launch() {
    let mut h = harness();
    h.identity = CandidateIdentity::new(
        &result_digest(b"patch"),
        &result_digest(b"tree"),
        &result_digest(b"some other build"),
        GEN,
    );
    let mut generation = h.generation();
    let err = h
        .executor("correct", &[], ExecutorConfig::default())
        .run(&mut generation)
        .await
        .unwrap_err();
    assert!(err.contains("refusing to launch"), "{}", err);
    assert_eq!(generation.pid, None, "nothing was spawned");
    assert!(!observation_log_path(&h.rsi_root, GEN).exists());
}

#[tokio::test]
async fn a_workload_that_does_not_match_its_pin_is_refused() {
    let mut h = harness();
    h.workload.manifest.requests[0].expected_output = "anything the candidate likes".to_string();
    let mut generation = h.generation();
    let err = h
        .executor("correct", &[], ExecutorConfig::default())
        .run(&mut generation)
        .await
        .unwrap_err();
    assert!(err.contains("digest"), "{}", err);
}
