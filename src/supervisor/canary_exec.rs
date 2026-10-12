//! The canary executor: the supervisor drives every request itself.
//!
//! The one rule above everything: no candidate-controlled statement can independently establish
//! that a canary passed. This module issues each request, measures elapsed time on the
//! supervisor's own clock, compares the answer with the pinned workload, and durably records the
//! verified observation through `crate::canary::log`. Worker self-reports (`CanaryReport`,
//! `worker_latency_us`) are diagnostics and never become observations.
//!
//! The executor never decides `Durable` and never touches `active.sock`. It returns the sealed
//! log; the quota validator (`crate::canary::admit_sealed_quota`) is the only authority on
//! whether the evidence suffices. Sequence, from docs/CANARY-CONTRACT.md: verify the executable,
//! bind the generation socket, spawn the worker with `--socket`, wait for versioned
//! authenticated readiness, then for each request in workload order send `ExecuteRequest`, wait
//! up to its deadline for the `ExecuteResult` of that request, and append one observation. Any
//! non-success observation is an early safety revert: stop issuing, kill the worker, mark the
//! generation `Reverting`, seal.

use crate::canary::observation::ObservationInput;
use crate::canary::{
    result_digest, CanaryObservationV2, CanaryRequestSpec, CandidateIdentity, LogHeader, LogRecord,
    ObservationLogWriter, PinnedWorkload, Provenance, SealedObservationLog, VerifiedStatus,
    CANARY_PROTOCOL_VERSION,
};
use crate::supervisor::daemon::{authenticate_worker_connection, SupervisorConfig};
use crate::supervisor::ipc::{IpcConnection, IpcServer, SupervisorMessage, WorkerMessage};
use crate::supervisor::{GenerationInfo, GenerationState, HostSupervisor};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

/// How the executor behaves on top of the workload. The workload owns the requests, expected
/// outcomes and deadlines; nothing here can loosen them.
#[derive(Debug, Clone)]
pub struct ExecutorConfig {
    /// Time from spawn to a completed authenticated versioned handshake.
    pub readiness_deadline: Duration,
    /// How long to keep listening for stray connections after the last request.
    pub settle_window: Duration,
    /// Shortens, never lengthens, each request's deadline.
    pub deadline_cap_ms: Option<u64>,
    /// Runs only the first N requests of the workload. The quota target still decides whether
    /// N is enough.
    pub request_limit: Option<usize>,
    /// Fault injection for restart tests: after this many observations recorded in this run,
    /// kill the worker and return `Halted` without sealing, as a supervisor crash would.
    pub halt_after_requests: Option<usize>,
    /// Extra environment for the worker, after `SUPERVISOR_SECRET`.
    pub worker_env: Vec<(String, String)>,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            readiness_deadline: Duration::from_secs(10),
            settle_window: Duration::from_millis(150),
            deadline_cap_ms: None,
            request_limit: None,
            halt_after_requests: None,
            worker_env: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecutionSummary {
    /// Requests in scope for this run (workload size after `request_limit`).
    pub requests_planned: usize,
    /// Observations already stored by an earlier run of the same log, kept as they are.
    pub recovered: usize,
    /// Requests this run sent.
    pub issued: usize,
    pub verified_success: usize,
    pub wrong_result: usize,
    pub timeout: usize,
    pub invalid_response: usize,
    pub connection_closed: usize,
    /// Rejection records this run appended.
    pub rejections: usize,
    /// Whether the worker completed authenticated versioned readiness.
    pub ready: bool,
    /// The first failure that stopped the run, if any.
    pub first_failure: Option<String>,
    /// The generation was marked `Reverting`.
    pub reverted: bool,
}

#[derive(Debug)]
pub enum ExecutionOutcome {
    /// The log is sealed and verified. Hand it to `admit_sealed_quota`.
    Sealed {
        sealed: SealedObservationLog,
        summary: ExecutionSummary,
    },
    /// The run stopped on purpose without sealing (`halt_after_requests`). The log on disk is
    /// unsealed and can be reopened.
    Halted { summary: ExecutionSummary },
}

impl ExecutionOutcome {
    pub fn summary(&self) -> &ExecutionSummary {
        match self {
            ExecutionOutcome::Sealed { summary, .. } | ExecutionOutcome::Halted { summary } => {
                summary
            }
        }
    }

    pub fn sealed(&self) -> Option<&SealedObservationLog> {
        match self {
            ExecutionOutcome::Sealed { sealed, .. } => Some(sealed),
            ExecutionOutcome::Halted { .. } => None,
        }
    }
}

pub struct CanaryExecutor<'a> {
    supervisor: &'a HostSupervisor,
    config: SupervisorConfig,
    workload: PinnedWorkload,
    identity: CandidateIdentity,
    executable: PathBuf,
    args: Vec<String>,
    exec: ExecutorConfig,
}

/// Kills and reaps the worker when dropped, so no path leaks it.
struct WorkerProcess(Option<std::process::Child>);

impl WorkerProcess {
    fn has_exited(&mut self) -> bool {
        match self.0.as_mut() {
            Some(child) => !matches!(child.try_wait(), Ok(None)),
            None => true,
        }
    }

    fn stop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for WorkerProcess {
    fn drop(&mut self) {
        self.stop();
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The observation log path for a generation: `<rsi_root>/canary/observations/<id>.jsonl`.
pub fn observation_log_path(rsi_root: &Path, generation_id: &str) -> PathBuf {
    rsi_root
        .join("canary")
        .join("observations")
        .join(format!("{}.jsonl", generation_id))
}

/// The generation socket: `<rsi_root>/workers/<id>.sock`.
pub fn generation_socket_path(rsi_root: &Path, generation_id: &str) -> PathBuf {
    rsi_root
        .join("workers")
        .join(format!("{}.sock", generation_id))
}

/// Every complete record of an unsealed log. A partial trailing record has no newline and is
/// ignored, exactly as `ObservationLogWriter::reopen` drops it.
fn stored_records(path: &Path) -> Result<Vec<LogRecord>, String> {
    let bytes = std::fs::read(path)
        .map_err(|e| format!("cannot read observation log {:?}: {}", path, e))?;
    let mut records = Vec::new();
    let mut rest: &[u8] = &bytes;
    while let Some(pos) = rest.iter().position(|b| *b == b'\n') {
        let record: LogRecord = serde_json::from_slice(&rest[..pos])
            .map_err(|e| format!("observation log {:?} has an unreadable record: {}", path, e))?;
        records.push(record);
        rest = &rest[pos + 1..];
    }
    Ok(records)
}

/// Stray connections to the generation socket after the worker authenticated. Each one starts
/// `Unauthenticated`, so whatever it sends is a rejection and the connection is closed.
fn spawn_stray_connection_guard(
    server: IpcServer,
    rejections: Arc<StdMutex<Vec<String>>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let mut conn = match server.accept().await {
                Ok(conn) => conn,
                Err(_) => continue,
            };
            let rejections = rejections.clone();
            tokio::spawn(async move {
                let what = match tokio::time::timeout(
                    Duration::from_secs(2),
                    conn.recv::<WorkerMessage>(),
                )
                .await
                {
                    Ok(Ok(msg)) => format!("{:?}", msg),
                    Ok(Err(e)) => format!("unreadable frame ({})", e),
                    Err(_) => "no frame".to_string(),
                };
                let reason = format!("message on an unauthenticated connection: {}", what);
                if let Ok(mut list) = rejections.lock() {
                    list.push(reason);
                }
                // Dropping the connection closes it.
            });
        }
    })
}

impl<'a> CanaryExecutor<'a> {
    pub fn new(
        supervisor: &'a HostSupervisor,
        config: SupervisorConfig,
        workload: PinnedWorkload,
        identity: CandidateIdentity,
        executable: PathBuf,
        args: Vec<String>,
        exec: ExecutorConfig,
    ) -> Self {
        Self {
            supervisor,
            config,
            workload,
            identity,
            executable,
            args,
            exec,
        }
    }

    fn requests(&self) -> &[CanaryRequestSpec] {
        let all = &self.workload.manifest.requests;
        match self.exec.request_limit {
            Some(n) => &all[..n.min(all.len())],
            None => all,
        }
    }

    fn open_log(&self, path: &Path) -> Result<ObservationLogWriter, String> {
        let wanted = LogHeader::new(
            &self.identity.generation_id,
            &self.workload.digest,
            &self.identity.executable_digest,
            now_ms(),
        );
        if !path.exists() {
            return ObservationLogWriter::create(path, wanted);
        }
        // A restart: the header on disk must bind the same generation, workload and
        // executable. Its opening time is the only field that differs.
        let existing = match stored_records(path)?.into_iter().next() {
            Some(LogRecord::Header(h)) => h,
            _ => {
                return Err(format!(
                    "observation log {:?} has no header; refusing",
                    path
                ))
            }
        };
        if existing.generation_id != wanted.generation_id
            || existing.workload_digest != wanted.workload_digest
            || existing.candidate_executable_digest != wanted.candidate_executable_digest
        {
            return Err(format!(
                "observation log {:?} is bound to another generation, workload or executable; refusing",
                path
            ));
        }
        ObservationLogWriter::reopen(path, &existing)
    }

    /// Runs the whole canary for `generation` and returns the sealed log with a summary.
    /// `Err` means the canary could not be run at all (the executable is not the candidate's,
    /// the workload digest does not match, the log cannot be opened or written).
    pub async fn run(&self, generation: &mut GenerationInfo) -> Result<ExecutionOutcome, String> {
        self.identity.validate()?;
        if generation.generation_id != self.identity.generation_id {
            return Err(format!(
                "generation {} is not the candidate identity's generation {}",
                generation.generation_id, self.identity.generation_id
            ));
        }
        self.workload.manifest.validate()?;
        if self.workload.manifest.digest() != self.workload.digest {
            return Err("pinned workload does not match its own digest; refusing".to_string());
        }
        // Right before launch: the file about to run is the executable in the chain.
        self.identity.verify_executable(&self.executable)?;

        let rsi_root = &self.config.rsi_root;
        let log_path = observation_log_path(rsi_root, &self.identity.generation_id);
        let mut writer = self.open_log(&log_path)?;

        let mut summary = ExecutionSummary {
            requests_planned: self.requests().len(),
            ..Default::default()
        };

        // Earlier run of the same log: failures stay failures; only stored successes are kept.
        let mut prior_failure = None;
        for record in stored_records(&log_path)? {
            if let LogRecord::Observation(o) = record {
                summary.recovered += 1;
                if o.observation.status != VerifiedStatus::VerifiedSuccess
                    && prior_failure.is_none()
                {
                    prior_failure = Some(format!(
                        "{}: {:?} recorded before a restart",
                        o.observation.request_id, o.observation.status
                    ));
                }
            }
        }
        if let Some(reason) = prior_failure {
            summary.first_failure = Some(reason);
            return self.finish(generation, writer, summary, true);
        }

        let todo: Vec<&CanaryRequestSpec> = self
            .requests()
            .iter()
            .filter(|spec| {
                let digest = spec.request_digest(&self.workload.manifest.workload_id);
                !writer.contains(&crate::canary::observation_id(
                    &self.identity.generation_id,
                    &spec.request_id,
                    &digest,
                ))
            })
            .collect();
        if todo.is_empty() {
            summary.ready = true;
            return self.finish(generation, writer, summary, false);
        }

        // Bind before spawning, then launch.
        let socket_path = generation_socket_path(rsi_root, &self.identity.generation_id);
        let server = IpcServer::bind(&socket_path)?;
        let args: Vec<&str> = self.args.iter().map(String::as_str).collect();
        // A fresh secret for this run only. The candidate process has to hold it to answer the
        // handshake, so it must never be the supervisor's long-lived secret: possession proves
        // that this process is the one launched for this run, nothing more.
        let run_secret = format!("canary-run-{}", uuid::Uuid::new_v4().simple());
        let mut env: Vec<(&str, &str)> = vec![("SUPERVISOR_SECRET", run_secret.as_str())];
        for (k, v) in &self.exec.worker_env {
            env.push((k.as_str(), v.as_str()));
        }
        let child = self.supervisor.spawn_worker_process(
            generation,
            &self.executable,
            &args,
            &socket_path,
            &env,
        )?;
        let mut worker = WorkerProcess(Some(child));

        // Readiness: a versioned Ready, the HMAC and Ping on a connection, within the deadline.
        let ready_by = Instant::now() + self.exec.readiness_deadline;
        let mut conn: Option<IpcConnection> = None;
        while conn.is_none() {
            let now = Instant::now();
            if now >= ready_by {
                summary.first_failure = Some(format!(
                    "no authenticated versioned readiness within {:?}",
                    self.exec.readiness_deadline
                ));
                break;
            }
            let tick = (ready_by - now).min(Duration::from_millis(50));
            match tokio::time::timeout(tick, server.accept()).await {
                Ok(Ok(mut candidate)) => {
                    let remaining = ready_by.saturating_duration_since(Instant::now());
                    match authenticate_worker_connection(
                        &mut candidate,
                        &self.identity.generation_id,
                        &run_secret,
                        remaining,
                    )
                    .await
                    {
                        Ok(state) if state.can_execute_for(&self.identity.generation_id) => {
                            conn = Some(candidate);
                        }
                        Ok(_) => {}
                        Err(failure) => {
                            // Rejected and closed. No rollback; the deadline still fails the canary.
                            self.record_rejection(&mut writer, &mut summary, &failure.to_string());
                        }
                    }
                }
                Ok(Err(_)) => {}
                Err(_) => {
                    if worker.has_exited() {
                        summary.first_failure =
                            Some("worker exited before it became ready".to_string());
                        break;
                    }
                }
            }
        }
        let mut conn = match conn {
            Some(conn) => conn,
            None => {
                drop(server);
                worker.stop();
                return self.finish(generation, writer, summary, true);
            }
        };
        summary.ready = true;
        generation.state = GenerationState::CanaryActive;

        let strays = Arc::new(StdMutex::new(Vec::new()));
        let guard = spawn_stray_connection_guard(server, strays.clone());

        let mut answered: BTreeSet<String> = BTreeSet::new();
        let mut issued: BTreeSet<String> = BTreeSet::new();
        let mut recorded_this_run = 0usize;
        let mut revert = false;

        for spec in todo {
            self.drain_strays(&strays, &mut writer, &mut summary);
            let request_digest = spec.request_digest(&self.workload.manifest.workload_id);
            let deadline_ms = match self.exec.deadline_cap_ms {
                Some(cap) => spec.deadline_ms.min(cap),
                None => spec.deadline_ms,
            };
            let pid = generation.pid;

            issued.insert(spec.request_id.clone());
            summary.issued += 1;
            let started = Instant::now();
            let sent = conn
                .send(&SupervisorMessage::ExecuteRequest {
                    protocol_version: CANARY_PROTOCOL_VERSION,
                    generation_id: self.identity.generation_id.clone(),
                    request_id: spec.request_id.clone(),
                    request_digest: request_digest.clone(),
                    workload_digest: self.workload.digest.clone(),
                    input: spec.input.clone(),
                    deadline_ms,
                })
                .await;

            let (status, output, elapsed) = if sent.is_err() {
                (VerifiedStatus::ConnectionClosed, None, started.elapsed())
            } else {
                self.await_result(
                    &mut conn,
                    spec,
                    &issued,
                    &answered,
                    started,
                    deadline_ms,
                    &mut writer,
                    &mut summary,
                )
                .await
            };

            let mut status = status;
            let mut digest = output.as_ref().map(|o| result_digest(o.as_bytes()));
            if status == VerifiedStatus::VerifiedSuccess || status == VerifiedStatus::WrongResult {
                if !spec.matches_output(output.as_deref().unwrap_or("")) {
                    status = VerifiedStatus::WrongResult;
                } else {
                    status = VerifiedStatus::VerifiedSuccess;
                }
                if elapsed > Duration::from_millis(deadline_ms) {
                    status = VerifiedStatus::Timeout;
                    digest = None;
                }
            }

            // A failed resource read is not proof that memory is within budget.
            if status == VerifiedStatus::VerifiedSuccess {
                let budget = match pid {
                    Some(pid) => self.supervisor.is_memory_within_budget(pid),
                    None => Err("no worker pid to read".to_string()),
                };
                match budget {
                    Ok(true) => {}
                    other => {
                        let reason = match other {
                            Ok(_) => format!(
                                "resource budget exceeded: worker above {} MB",
                                self.supervisor.memory_limit_mb
                            ),
                            Err(e) => format!("resource budget unreadable, reverting: {}", e),
                        };
                        // The success is not recorded: the request counts as incomplete.
                        self.record_rejection(&mut writer, &mut summary, &reason);
                        summary.first_failure = Some(format!("{}: {}", spec.request_id, reason));
                        revert = true;
                        break;
                    }
                }
            }

            answered.insert(spec.request_id.clone());
            let observation = CanaryObservationV2::new(ObservationInput {
                generation_id: &self.identity.generation_id,
                request_id: &spec.request_id,
                request_digest: &request_digest,
                workload_digest: &self.workload.digest,
                candidate_executable_digest: &self.identity.executable_digest,
                result_digest: digest.as_deref(),
                elapsed_us: elapsed.as_micros() as u64,
                observed_at_ms: now_ms(),
                status,
                provenance: Provenance::Measured,
            });
            writer.append_observation(&observation)?;
            recorded_this_run += 1;
            match status {
                VerifiedStatus::VerifiedSuccess => summary.verified_success += 1,
                VerifiedStatus::WrongResult => summary.wrong_result += 1,
                VerifiedStatus::Timeout => summary.timeout += 1,
                VerifiedStatus::InvalidResponse => summary.invalid_response += 1,
                VerifiedStatus::ConnectionClosed => summary.connection_closed += 1,
            }
            if status != VerifiedStatus::VerifiedSuccess {
                summary.first_failure = Some(format!("{}: {:?}", spec.request_id, status));
                revert = true;
                break;
            }
            if self.exec.halt_after_requests == Some(recorded_this_run) {
                guard.abort();
                let _ = guard.await;
                worker.stop();
                return Ok(ExecutionOutcome::Halted { summary });
            }
        }

        if !revert {
            tokio::time::sleep(self.exec.settle_window).await;
        }
        self.drain_strays(&strays, &mut writer, &mut summary);
        guard.abort();
        let _ = guard.await;
        worker.stop();
        self.finish(generation, writer, summary, revert)
    }

    /// Waits for the result of `spec`. Only an `ExecuteResult` for this issued request on this
    /// authenticated connection ends the wait with a result; heartbeats and self-reports are
    /// diagnostics and do not.
    #[allow(clippy::too_many_arguments)]
    async fn await_result(
        &self,
        conn: &mut IpcConnection,
        spec: &CanaryRequestSpec,
        issued: &BTreeSet<String>,
        answered: &BTreeSet<String>,
        started: Instant,
        deadline_ms: u64,
        writer: &mut ObservationLogWriter,
        summary: &mut ExecutionSummary,
    ) -> (VerifiedStatus, Option<String>, Duration) {
        let generation_id = &self.identity.generation_id;
        let deadline_at =
            tokio::time::Instant::from_std(started) + Duration::from_millis(deadline_ms);
        loop {
            let msg = match tokio::time::timeout_at(deadline_at, conn.recv::<WorkerMessage>()).await
            {
                Err(_) => return (VerifiedStatus::Timeout, None, started.elapsed()),
                Ok(Err(e)) if e.contains("closed by peer") => {
                    return (VerifiedStatus::ConnectionClosed, None, started.elapsed())
                }
                Ok(Err(e)) if e.contains("Failed to read") => {
                    return (VerifiedStatus::ConnectionClosed, None, started.elapsed())
                }
                Ok(Err(e)) => {
                    // A frame arrived for the open request but could not be decoded.
                    tracing::warn!(target: "supervisor", "undecodable frame during {}: {}", spec.request_id, e);
                    return (VerifiedStatus::InvalidResponse, None, started.elapsed());
                }
                Ok(Ok(msg)) => msg,
            };
            match msg {
                WorkerMessage::ExecuteResult {
                    protocol_version,
                    generation_id: named,
                    request_id,
                    output,
                    worker_latency_us,
                } => {
                    let elapsed = started.elapsed();
                    if request_id == spec.request_id {
                        tracing::debug!(
                            target: "supervisor",
                            "diagnostic worker_latency_us={:?} for {}",
                            worker_latency_us, request_id
                        );
                        if protocol_version != CANARY_PROTOCOL_VERSION || &named != generation_id {
                            return (VerifiedStatus::InvalidResponse, None, elapsed);
                        }
                        return (VerifiedStatus::VerifiedSuccess, Some(output), elapsed);
                    }
                    let why = if answered.contains(&request_id) {
                        "already answered"
                    } else if issued.contains(&request_id) {
                        "not the open request"
                    } else {
                        "not issued"
                    };
                    self.record_rejection(
                        writer,
                        summary,
                        &format!("ExecuteResult for request {} which was {}", request_id, why),
                    );
                    if &named != generation_id {
                        return (VerifiedStatus::ConnectionClosed, None, started.elapsed());
                    }
                }
                WorkerMessage::Heartbeat {
                    generation_id: named,
                    ..
                }
                | WorkerMessage::CanaryReport {
                    generation_id: named,
                    ..
                } if &named == generation_id => {
                    tracing::debug!(target: "supervisor", "diagnostic frame during {}", spec.request_id);
                }
                WorkerMessage::Pong => {}
                WorkerMessage::Heartbeat {
                    generation_id: named,
                    ..
                }
                | WorkerMessage::CanaryReport {
                    generation_id: named,
                    ..
                }
                | WorkerMessage::DrainComplete {
                    generation_id: named,
                } if &named != generation_id => {
                    self.record_rejection(
                        writer,
                        summary,
                        &format!("message naming generation {}", named),
                    );
                    return (VerifiedStatus::ConnectionClosed, None, started.elapsed());
                }
                other => {
                    // DrainComplete, a repeated Ready, a stray AuthResponse: a worker cannot
                    // promote or re-authenticate itself. Logged, never an observation.
                    self.record_rejection(
                        writer,
                        summary,
                        &format!(
                            "unexpected frame on the authenticated connection: {:?}",
                            other
                        ),
                    );
                }
            }
        }
    }

    fn record_rejection(
        &self,
        writer: &mut ObservationLogWriter,
        summary: &mut ExecutionSummary,
        reason: &str,
    ) {
        tracing::warn!(target: "supervisor", "rejected worker message: {}", reason);
        if writer.append_rejection(reason, now_ms()).is_ok() {
            summary.rejections += 1;
        }
    }

    fn drain_strays(
        &self,
        strays: &Arc<StdMutex<Vec<String>>>,
        writer: &mut ObservationLogWriter,
        summary: &mut ExecutionSummary,
    ) {
        let reasons: Vec<String> = match strays.lock() {
            Ok(mut list) => std::mem::take(&mut *list),
            Err(_) => Vec::new(),
        };
        for reason in reasons {
            self.record_rejection(writer, summary, &reason);
        }
    }

    fn finish(
        &self,
        generation: &mut GenerationInfo,
        writer: ObservationLogWriter,
        mut summary: ExecutionSummary,
        revert: bool,
    ) -> Result<ExecutionOutcome, String> {
        if revert {
            // Early safety revert. Rolling back the active generation is the caller's job; the
            // executor only marks the candidate and never touches active.sock.
            generation.state = GenerationState::Reverting;
            summary.reverted = true;
        }
        let sealed = writer.seal(now_ms())?;
        Ok(ExecutionOutcome::Sealed { sealed, summary })
    }
}
