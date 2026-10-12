use crate::canary::{ObservationLogWriter, CANARY_PROTOCOL_VERSION};
use crate::supervisor::ipc::{
    ConnectionAuthState, IpcConnection, IpcServer, SessionAuth, SupervisorMessage, WorkerMessage,
};
use crate::supervisor::{GenerationInfo, GenerationState, HostSupervisor};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

/// How long a worker has to become ready on the legacy message loop: a versioned `Ready`, the
/// HMAC challenge and the supervisor's `Ping`, all of it. The canary executor takes its own
/// readiness deadline from its configuration.
pub const READINESS_DEADLINE: Duration = Duration::from_secs(10);

/// Why a connection did not become ready. None of these is ready, and none is a rollback by
/// itself: a worker that never becomes ready fails the canary through the deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadinessFailureKind {
    /// Nothing, or not everything, arrived before the readiness deadline.
    Timeout,
    /// The peer closed the connection first.
    Closed,
    /// `Ready` without the current protocol version (an older worker reads as version 0).
    OldProtocol,
    /// `Ready` for a generation other than the expected one.
    WrongGeneration,
    /// The HMAC answer did not verify.
    BadHmac,
    /// Any other frame where `Ready` or `AuthResponse` belonged.
    Unexpected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadinessFailure {
    pub kind: ReadinessFailureKind,
    pub detail: String,
}

impl std::fmt::Display for ReadinessFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "worker not ready ({:?}): {}", self.kind, self.detail)
    }
}

fn recv_failure(err: String) -> ReadinessFailure {
    let kind = if err.contains("closed by peer") {
        ReadinessFailureKind::Closed
    } else {
        ReadinessFailureKind::Unexpected
    };
    ReadinessFailure { kind, detail: err }
}

/// Accepts a `Ready` only if it is versioned and names the expected generation. Returns the
/// worker's pid and protocol version.
pub fn check_ready(
    expected_generation: &str,
    msg: WorkerMessage,
) -> Result<(u32, u16), ReadinessFailure> {
    match msg {
        WorkerMessage::Ready {
            generation_id,
            pid,
            protocol_version,
            ..
        } => {
            if protocol_version != CANARY_PROTOCOL_VERSION {
                return Err(ReadinessFailure {
                    kind: ReadinessFailureKind::OldProtocol,
                    detail: format!(
                        "Ready states protocol version {}, expected {}",
                        protocol_version, CANARY_PROTOCOL_VERSION
                    ),
                });
            }
            if generation_id != expected_generation {
                return Err(ReadinessFailure {
                    kind: ReadinessFailureKind::WrongGeneration,
                    detail: format!(
                        "Ready names generation {}, expected {}",
                        generation_id, expected_generation
                    ),
                });
            }
            Ok((pid, protocol_version))
        }
        other => Err(ReadinessFailure {
            kind: ReadinessFailureKind::Unexpected,
            detail: format!("expected a versioned Ready first, got {:?}", other),
        }),
    }
}

/// Sends the HMAC challenge for `generation_id` and verifies the worker's answer.
pub async fn challenge_worker(
    conn: &mut IpcConnection,
    generation_id: &str,
    shared_secret: &str,
) -> Result<(), ReadinessFailure> {
    let nonce = format!("challenge-{}", uuid::Uuid::new_v4().simple());
    conn.send(&SupervisorMessage::AuthChallenge {
        nonce: nonce.clone(),
    })
    .await
    .map_err(recv_failure)?;

    let auth_msg: WorkerMessage = conn.recv().await.map_err(recv_failure)?;
    let candidate_hmac = match auth_msg {
        WorkerMessage::AuthResponse { response } => response,
        other => {
            return Err(ReadinessFailure {
                kind: ReadinessFailureKind::Unexpected,
                detail: format!("expected AuthResponse, got {:?}", other),
            })
        }
    };
    let message_to_sign = format!("{}:{}", generation_id, nonce);
    if !SessionAuth::verify_hmac(shared_secret, &message_to_sign, &candidate_hmac) {
        return Err(ReadinessFailure {
            kind: ReadinessFailureKind::BadHmac,
            detail: format!("HMAC for generation {} did not verify", generation_id),
        });
    }
    Ok(())
}

/// Readiness, as defined in docs/CANARY-CONTRACT.md: the worker sends a versioned `Ready` for
/// the expected generation, completes the HMAC challenge, and the supervisor replies `Ping`,
/// all within `deadline`. Anything else (a bare connection, silence, an older `Ready`, another
/// generation, a failed HMAC, an unknown frame) is not ready. Only success yields
/// `Authenticated`.
pub async fn authenticate_worker_connection(
    conn: &mut IpcConnection,
    expected_generation: &str,
    shared_secret: &str,
    deadline: Duration,
) -> Result<ConnectionAuthState, ReadinessFailure> {
    let handshake = async {
        let first: WorkerMessage = conn.recv().await.map_err(recv_failure)?;
        let (pid, protocol_version) = check_ready(expected_generation, first)?;
        challenge_worker(conn, expected_generation, shared_secret).await?;
        conn.send(&SupervisorMessage::Ping)
            .await
            .map_err(recv_failure)?;
        Ok(ConnectionAuthState::Authenticated {
            generation_id: expected_generation.to_string(),
            pid,
            protocol_version,
        })
    };
    match tokio::time::timeout(deadline, handshake).await {
        Ok(result) => result,
        Err(_) => Err(ReadinessFailure {
            kind: ReadinessFailureKind::Timeout,
            detail: format!("no completed handshake within {:?}", deadline),
        }),
    }
}

#[derive(Debug, Clone)]
pub struct SupervisorConfig {
    pub rsi_root: PathBuf,
    pub socket_path: PathBuf,
    pub memory_limit_mb: u64,
    pub canary_target: u64,
    pub max_latency_us: u64,
    pub max_error_rate: f64,
    pub shared_secret: String,
}

pub fn resolve_supervisor_secret() -> String {
    if let Ok(sec) = std::env::var("SUPERVISOR_SECRET") {
        let trimmed = sec.trim().to_string();
        if !trimmed.is_empty() {
            return trimmed;
        }
    }

    if let Ok(out) = std::process::Command::new("atlas-vault")
        .args(["get", "SUPERVISOR_SECRET"])
        .output()
    {
        if out.status.success() {
            let val = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !val.is_empty() {
                return val;
            }
        }
    }

    // Ephemeral in-memory dynamic secret: strictly hardware TPM or ephemeral memory, zero disk secrets
    format!("tpm-ephemeral-{}", uuid::Uuid::new_v4().simple())
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            rsi_root: PathBuf::from(".rsi"),
            socket_path: PathBuf::from(".rsi/supervisor.sock"),
            memory_limit_mb: 49152,
            canary_target: 5000,
            max_latency_us: 1_000_000,
            max_error_rate: 0.0,
            shared_secret: resolve_supervisor_secret(),
        }
    }
}

pub struct SupervisorDaemon {
    pub config: SupervisorConfig,
    pub supervisor: HostSupervisor,
    pub active_generation: Arc<Mutex<Option<GenerationInfo>>>,
    pub canary_generation: Arc<Mutex<Option<GenerationInfo>>>,
    pub running: Arc<AtomicBool>,
    /// The open observation log of the canary generation, when one is attached. Rejections are
    /// appended to it.
    pub observation_log: Arc<Mutex<Option<ObservationLogWriter>>>,
}

impl SupervisorDaemon {
    pub fn new(config: SupervisorConfig) -> Self {
        let supervisor = HostSupervisor::new(&config.rsi_root, config.memory_limit_mb);
        Self {
            config,
            supervisor,
            active_generation: Arc::new(Mutex::new(None)),
            canary_generation: Arc::new(Mutex::new(None)),
            running: Arc::new(AtomicBool::new(true)),
            observation_log: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn stage_canary(
        &self,
        generation_id: &str,
        artifacts_dir: &Path,
        manifest_digest: &str,
    ) -> Result<GenerationInfo, String> {
        let gen =
            self.supervisor
                .stage_generation(generation_id, artifacts_dir, manifest_digest)?;

        let mut canary_lock = self.canary_generation.lock().await;
        *canary_lock = Some(gen.clone());
        Ok(gen)
    }

    /// Opens a generation's observation log to the legacy message loop so rejections are
    /// recorded in it as well as traced.
    pub async fn attach_observation_log(&self, writer: ObservationLogWriter) {
        *self.observation_log.lock().await = Some(writer);
    }

    /// Takes the log back, for sealing.
    pub async fn detach_observation_log(&self) -> Option<ObservationLogWriter> {
        self.observation_log.lock().await.take()
    }

    /// Records a refused message (tracing, plus the observation log when one is open) and
    /// returns the reason as the error that closes the connection. A rejection never triggers
    /// a rollback; a worker that stays silent still fails the canary through its deadline.
    async fn reject(&self, reason: String) -> String {
        tracing::warn!(target: "supervisor", "rejected worker message: {}", reason);
        if let Some(log) = self.observation_log.lock().await.as_mut() {
            let now_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;
            if let Err(e) = log.append_rejection(&reason, now_ms) {
                tracing::error!(target: "supervisor", "cannot record rejection: {}", e);
            }
        }
        reason
    }

    /// Handles one frame on a connection whose state is `auth`. `Err` means the connection must
    /// be closed. A connection starts `Unauthenticated`; only a versioned `Ready` for the
    /// canary generation plus a verified HMAC makes it `Authenticated`. Every other frame is
    /// checked against that state first.
    ///
    /// Nothing here grants `Durable`, and nothing here switches `active.sock` on `Ready`.
    /// `CanaryReport` is a diagnostic that can only make the supervisor more cautious.
    pub async fn process_worker_message(
        &self,
        conn: &mut IpcConnection,
        auth: &mut ConnectionAuthState,
        msg: WorkerMessage,
        active_socket_link: &Path,
    ) -> Result<Option<SupervisorMessage>, String> {
        if let WorkerMessage::Ready { .. } = msg {
            if *auth != ConnectionAuthState::Unauthenticated {
                return Err(self
                    .reject("repeated Ready on an authenticated connection".to_string())
                    .await);
            }
            let expected = {
                let canary_lock = self.canary_generation.lock().await;
                canary_lock.as_ref().map(|c| c.generation_id.clone())
            };
            let expected = match expected {
                Some(id) => id,
                None => {
                    return Err(self
                        .reject("Ready while no canary generation is staged".to_string())
                        .await)
                }
            };
            let (pid, protocol_version) = match check_ready(&expected, msg) {
                Ok(v) => v,
                Err(failure) => return Err(self.reject(failure.to_string()).await),
            };
            let challenged = tokio::time::timeout(
                READINESS_DEADLINE,
                challenge_worker(conn, &expected, &self.config.shared_secret),
            )
            .await;
            match challenged {
                Ok(Ok(())) => {}
                Ok(Err(failure)) => return Err(self.reject(failure.to_string()).await),
                Err(_) => {
                    return Err(self
                        .reject("HMAC challenge not answered before the readiness deadline".into())
                        .await)
                }
            }

            let mut canary_lock = self.canary_generation.lock().await;
            if let Some(ref mut canary) = *canary_lock {
                if canary.generation_id == expected {
                    canary.state = GenerationState::Ready;
                    canary.pid = Some(pid);
                }
            }
            *auth = ConnectionAuthState::Authenticated {
                generation_id: expected,
                pid,
                protocol_version,
            };
            return Ok(Some(SupervisorMessage::Ping));
        }

        let claimed: Option<&str> = match &msg {
            WorkerMessage::Heartbeat { generation_id, .. }
            | WorkerMessage::DrainComplete { generation_id }
            | WorkerMessage::CanaryReport { generation_id, .. }
            | WorkerMessage::ExecuteResult { generation_id, .. } => Some(generation_id),
            _ => None,
        };
        let generation_id = match auth {
            ConnectionAuthState::Unauthenticated => {
                return Err(self
                    .reject(format!(
                        "message on an unauthenticated connection: {:?}",
                        msg
                    ))
                    .await)
            }
            ConnectionAuthState::Authenticated { generation_id, .. } => generation_id.clone(),
        };
        if let Some(named) = claimed {
            if named != generation_id {
                return Err(self
                    .reject(format!(
                        "connection authenticated for generation {} sent a message naming generation {}",
                        generation_id, named
                    ))
                    .await);
            }
        }

        match msg {
            WorkerMessage::Ready { .. } => unreachable!("Ready is handled above"),

            WorkerMessage::Heartbeat {
                memory_mb,
                active_requests: _,
                timestamp_secs: _,
                ..
            } => {
                let memory_exceeded;
                {
                    let mut canary_lock = self.canary_generation.lock().await;
                    if let Some(ref mut canary) = *canary_lock {
                        if canary.generation_id == generation_id
                            && memory_mb > self.config.memory_limit_mb
                        {
                            canary.state = GenerationState::Reverting;
                            memory_exceeded = true;
                        } else {
                            memory_exceeded = false;
                        }
                    } else {
                        memory_exceeded = false;
                    }
                }

                if memory_exceeded {
                    self.trigger_instant_rollback(active_socket_link).await?;
                    return Ok(Some(SupervisorMessage::RevertOrder {
                        reason: format!(
                            "Memory budget exceeded: {} MB > {} MB limit",
                            memory_mb, self.config.memory_limit_mb
                        ),
                    }));
                }
                Ok(Some(SupervisorMessage::Ping))
            }

            WorkerMessage::CanaryReport {
                transaction_id,
                success,
                latency_us,
                error,
                ..
            } => {
                // A self-report is a diagnostic. It is logged and may trigger an early safety
                // revert, but it never counts toward admission and never promotes.
                tracing::info!(
                    target: "supervisor",
                    "diagnostic CanaryReport {} from {}: success={} latency_us={}",
                    transaction_id, generation_id, success, latency_us
                );
                let mut revert_reason = error.clone();
                let should_revert;
                {
                    let mut canary_lock = self.canary_generation.lock().await;
                    match *canary_lock {
                        Some(ref mut canary) if canary.generation_id == generation_id => {
                            match self.supervisor.record_canary_transaction(
                                canary,
                                success,
                                latency_us,
                                self.config.max_latency_us,
                                self.config.max_error_rate,
                            ) {
                                Ok(_) => should_revert = false,
                                Err(budget_err) => {
                                    should_revert = true;
                                    revert_reason = Some(match error {
                                        Some(ref orig) => format!("{}: {}", orig, budget_err),
                                        None => budget_err,
                                    });
                                }
                            }
                        }
                        _ => should_revert = false,
                    }
                }

                if should_revert {
                    self.trigger_instant_rollback(active_socket_link).await?;
                    return Ok(Some(SupervisorMessage::RevertOrder {
                        reason: revert_reason
                            .unwrap_or_else(|| "Canary transaction failure".to_string()),
                    }));
                }
                Ok(None)
            }

            // The worker saying it has drained changes nothing: a generation becomes Durable
            // only after quota admission, the safety envelope and the promotion gate.
            WorkerMessage::DrainComplete { .. } => Ok(None),
            WorkerMessage::Pong => Ok(None),
            WorkerMessage::AuthResponse { .. } => Err(self
                .reject("AuthResponse outside a handshake".to_string())
                .await),
            // Execute results are consumed by the supervisor-driven request loop that issued
            // the request (`canary_exec`). This loop issued none, so a result here is
            // unsolicited and creates nothing.
            WorkerMessage::ExecuteResult { request_id, .. } => {
                let _ = self
                    .reject(format!(
                        "unsolicited ExecuteResult for request {}",
                        request_id
                    ))
                    .await;
                Ok(None)
            }
        }
    }

    pub async fn trigger_instant_rollback(&self, active_socket_link: &Path) -> Result<(), String> {
        let active_lock = self.active_generation.lock().await;
        if let Some(ref parent) = *active_lock {
            let parent_sock = self
                .config
                .rsi_root
                .join(format!("workers/{}.sock", parent.generation_id));
            self.supervisor.rollback_to_parent(
                &parent.generation_id,
                Some(active_socket_link),
                Some(&parent_sock),
            )?;
        }
        let mut canary_lock = self.canary_generation.lock().await;
        if let Some(ref mut canary) = *canary_lock {
            canary.state = GenerationState::Reverted;
        }
        Ok(())
    }

    pub async fn run_server(&self, active_socket_link: PathBuf) -> Result<(), String> {
        let server = IpcServer::bind(&self.config.socket_path)?;
        while self.running.load(Ordering::Relaxed) {
            match tokio::time::timeout(Duration::from_millis(500), server.accept()).await {
                Ok(Ok(mut conn)) => {
                    let active_link = active_socket_link.clone();
                    let mut auth = ConnectionAuthState::Unauthenticated;
                    loop {
                        // An unauthenticated connection has the readiness deadline to speak;
                        // silence must not hold the server.
                        let received = if auth == ConnectionAuthState::Unauthenticated {
                            match tokio::time::timeout(
                                READINESS_DEADLINE,
                                conn.recv::<WorkerMessage>(),
                            )
                            .await
                            {
                                Ok(r) => r,
                                Err(_) => {
                                    let _ = self
                                        .reject(
                                            "connection silent past the readiness deadline".into(),
                                        )
                                        .await;
                                    break;
                                }
                            }
                        } else {
                            conn.recv::<WorkerMessage>().await
                        };
                        let msg = match received {
                            Ok(msg) => msg,
                            Err(_) => break,
                        };
                        match self
                            .process_worker_message(&mut conn, &mut auth, msg, &active_link)
                            .await
                        {
                            Ok(Some(reply)) => {
                                let _ = conn.send(&reply).await;
                            }
                            Ok(None) => {}
                            Err(_) => {
                                break;
                            }
                        }
                    }
                }
                Ok(Err(_)) => continue,
                Err(_) => continue,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canary::{LogHeader, LogRecord};
    use crate::supervisor::ipc::ConnectionAuthState as Auth;

    const SECRET: &str = "secret-key";

    fn config(tmp: &Path, max_latency_us: u64) -> SupervisorConfig {
        let rsi_root = tmp.join(".rsi");
        SupervisorConfig {
            rsi_root: rsi_root.clone(),
            socket_path: rsi_root.join("supervisor.sock"),
            memory_limit_mb: 49152,
            canary_target: 3,
            max_latency_us,
            max_error_rate: 0.0,
            shared_secret: SECRET.to_string(),
        }
    }

    async fn daemon_with_canary(tmp: &Path, gen: &str, max_latency_us: u64) -> SupervisorDaemon {
        let daemon = SupervisorDaemon::new(config(tmp, max_latency_us));
        let src = tmp.join("art_cand");
        std::fs::create_dir_all(&src).unwrap();
        daemon.stage_canary(gen, &src, "sha-cand").await.unwrap();
        daemon
    }

    /// Runs a real worker handshake against the daemon over a socket pair and returns the
    /// supervisor side, its authentication state and the worker side (kept open).
    async fn authenticated(
        daemon: &SupervisorDaemon,
        gen: &str,
        active_link: &Path,
    ) -> (IpcConnection, Auth, IpcConnection) {
        let (stream_worker, stream_sup) = tokio::net::UnixStream::pair().unwrap();
        let mut conn_worker = IpcConnection::new(stream_worker);
        let mut conn_sup = IpcConnection::new(stream_sup);
        let gen_owned = gen.to_string();
        let worker = tokio::spawn(async move {
            let reply = conn_worker
                .perform_worker_handshake(&gen_owned, std::process::id(), SECRET)
                .await;
            (conn_worker, reply)
        });
        let ready: WorkerMessage = conn_sup.recv().await.unwrap();
        let mut auth = Auth::Unauthenticated;
        let reply = daemon
            .process_worker_message(&mut conn_sup, &mut auth, ready, active_link)
            .await
            .unwrap();
        assert_eq!(reply, Some(SupervisorMessage::Ping));
        conn_sup.send(&reply.unwrap()).await.unwrap();
        let (conn_worker, worker_reply) = worker.await.unwrap();
        assert_eq!(worker_reply.unwrap(), SupervisorMessage::Ping);
        (conn_sup, auth, conn_worker)
    }

    fn report(gen: &str, id: u64, success: bool, latency_us: u64) -> WorkerMessage {
        WorkerMessage::CanaryReport {
            generation_id: gen.to_string(),
            transaction_id: id,
            success,
            latency_us,
            error: if success {
                None
            } else {
                Some("Inference assertion panicked".to_string())
            },
        }
    }

    #[tokio::test]
    async fn ready_needs_versioned_hmac_and_never_switches_active_sock() {
        let tmp = tempfile::tempdir().unwrap();
        let active_link = tmp.path().join(".rsi").join("active.sock");
        let daemon = daemon_with_canary(tmp.path(), "gen-002", 1_000_000).await;

        let (_conn, auth, _worker) = authenticated(&daemon, "gen-002", &active_link).await;
        assert_eq!(
            auth,
            Auth::Authenticated {
                generation_id: "gen-002".to_string(),
                pid: std::process::id(),
                protocol_version: CANARY_PROTOCOL_VERSION,
            }
        );
        let state = daemon
            .canary_generation
            .lock()
            .await
            .as_ref()
            .unwrap()
            .state;
        assert_eq!(state, GenerationState::Ready);
        assert!(
            std::fs::symlink_metadata(&active_link).is_err(),
            "Ready must not switch active.sock to the candidate"
        );
    }

    #[tokio::test]
    async fn old_protocol_other_generation_and_forged_hmac_are_never_ready() {
        let tmp = tempfile::tempdir().unwrap();
        let active_link = tmp.path().join(".rsi").join("active.sock");
        let daemon = daemon_with_canary(tmp.path(), "gen-002", 1_000_000).await;

        for (ready_gen, version) in [("gen-002", 0u16), ("gen-other", CANARY_PROTOCOL_VERSION)] {
            let (a, b) = tokio::net::UnixStream::pair().unwrap();
            let mut conn_sup = IpcConnection::new(b);
            let _keep = a;
            let mut auth = Auth::Unauthenticated;
            let err = daemon
                .process_worker_message(
                    &mut conn_sup,
                    &mut auth,
                    WorkerMessage::Ready {
                        generation_id: ready_gen.to_string(),
                        pid: 1,
                        auth_token: String::new(),
                        protocol_version: version,
                    },
                    &active_link,
                )
                .await
                .unwrap_err();
            assert!(err.contains("not ready"), "{}", err);
            assert_eq!(auth, Auth::Unauthenticated);
        }

        // Forged HMAC: the worker answers the challenge with garbage.
        let (a, b) = tokio::net::UnixStream::pair().unwrap();
        let mut worker = IpcConnection::new(a);
        let mut conn_sup = IpcConnection::new(b);
        let forged = tokio::spawn(async move {
            worker
                .send(&WorkerMessage::AuthResponse {
                    response: "forged".to_string(),
                })
                .await
                .unwrap();
            worker
        });
        let mut auth = Auth::Unauthenticated;
        let err = daemon
            .process_worker_message(
                &mut conn_sup,
                &mut auth,
                WorkerMessage::Ready {
                    generation_id: "gen-002".to_string(),
                    pid: 1,
                    auth_token: String::new(),
                    protocol_version: CANARY_PROTOCOL_VERSION,
                },
                &active_link,
            )
            .await
            .unwrap_err();
        assert!(err.contains("BadHmac"), "{}", err);
        assert_eq!(auth, Auth::Unauthenticated);
        let _ = forged.await;
        let state = daemon
            .canary_generation
            .lock()
            .await
            .as_ref()
            .unwrap()
            .state;
        assert_eq!(
            state,
            GenerationState::Staged,
            "a failed handshake changes nothing"
        );
    }

    #[tokio::test]
    async fn authenticate_worker_connection_fails_closed_on_silence_close_and_bad_frames() {
        let deadline = Duration::from_millis(200);

        // Silence: connected, never speaks.
        let (a, b) = tokio::net::UnixStream::pair().unwrap();
        let mut sup = IpcConnection::new(b);
        let silent = authenticate_worker_connection(&mut sup, "gen-1", SECRET, deadline)
            .await
            .unwrap_err();
        assert_eq!(silent.kind, ReadinessFailureKind::Timeout);
        drop(a);

        // Bare connection that closes.
        let (a, b) = tokio::net::UnixStream::pair().unwrap();
        drop(a);
        let mut sup = IpcConnection::new(b);
        let closed = authenticate_worker_connection(&mut sup, "gen-1", SECRET, deadline)
            .await
            .unwrap_err();
        assert_eq!(closed.kind, ReadinessFailureKind::Closed);

        // A frame that is not Ready.
        let (a, b) = tokio::net::UnixStream::pair().unwrap();
        let mut worker = IpcConnection::new(a);
        let mut sup = IpcConnection::new(b);
        worker.send(&WorkerMessage::Pong).await.unwrap();
        let unexpected = authenticate_worker_connection(&mut sup, "gen-1", SECRET, deadline)
            .await
            .unwrap_err();
        assert_eq!(unexpected.kind, ReadinessFailureKind::Unexpected);

        // Older Ready (protocol version 0).
        let (a, b) = tokio::net::UnixStream::pair().unwrap();
        let mut worker = IpcConnection::new(a);
        let mut sup = IpcConnection::new(b);
        worker
            .send(&WorkerMessage::Ready {
                generation_id: "gen-1".to_string(),
                pid: 1,
                auth_token: String::new(),
                protocol_version: 0,
            })
            .await
            .unwrap();
        let old = authenticate_worker_connection(&mut sup, "gen-1", SECRET, deadline)
            .await
            .unwrap_err();
        assert_eq!(old.kind, ReadinessFailureKind::OldProtocol);

        // The full handshake succeeds and ends with Ping.
        let (a, b) = tokio::net::UnixStream::pair().unwrap();
        let mut worker = IpcConnection::new(a);
        let mut sup = IpcConnection::new(b);
        let w = tokio::spawn(async move {
            let reply = worker.perform_worker_handshake("gen-1", 7, SECRET).await;
            (worker, reply)
        });
        let state =
            authenticate_worker_connection(&mut sup, "gen-1", SECRET, Duration::from_secs(5))
                .await
                .unwrap();
        assert!(state.can_execute_for("gen-1"));
        let (_worker, reply) = w.await.unwrap();
        assert_eq!(reply.unwrap(), SupervisorMessage::Ping);
    }

    #[tokio::test]
    async fn unauthenticated_and_wrong_generation_messages_are_rejected_without_rollback() {
        let tmp = tempfile::tempdir().unwrap();
        let rsi_root = tmp.path().join(".rsi");
        let active_link = rsi_root.join("active.sock");
        let daemon = daemon_with_canary(tmp.path(), "gen-002", 1_000_000).await;

        // Open a real observation log so the rejection is recorded in it.
        let log_path = rsi_root.join("canary/observations/gen-002.jsonl");
        let header = LogHeader::new(
            "gen-002",
            &crate::canary::sha256_hex(b"workload"),
            &crate::canary::sha256_hex(b"exe"),
            1,
        );
        daemon
            .attach_observation_log(ObservationLogWriter::create(&log_path, header).unwrap())
            .await;

        // 1. A CanaryReport on a connection that never authenticated.
        let (_a, b) = tokio::net::UnixStream::pair().unwrap();
        let mut conn = IpcConnection::new(b);
        let mut unauth = Auth::Unauthenticated;
        let err = daemon
            .process_worker_message(
                &mut conn,
                &mut unauth,
                report("gen-002", 1, true, 10),
                &active_link,
            )
            .await
            .unwrap_err();
        assert!(err.contains("unauthenticated"), "{}", err);

        // 2. An authenticated connection naming another generation.
        let (mut conn_sup, mut auth, _worker) =
            authenticated(&daemon, "gen-002", &active_link).await;
        let err = daemon
            .process_worker_message(
                &mut conn_sup,
                &mut auth,
                report("gen-parent", 2, true, 10),
                &active_link,
            )
            .await
            .unwrap_err();
        assert!(err.contains("naming generation gen-parent"), "{}", err);

        // 3. A repeated Ready.
        let err = daemon
            .process_worker_message(
                &mut conn_sup,
                &mut auth,
                WorkerMessage::Ready {
                    generation_id: "gen-002".to_string(),
                    pid: 1,
                    auth_token: String::new(),
                    protocol_version: CANARY_PROTOCOL_VERSION,
                },
                &active_link,
            )
            .await
            .unwrap_err();
        assert!(err.contains("repeated Ready"), "{}", err);

        // No rollback: the canary is still Ready, not Reverted, and active.sock untouched.
        let state = daemon
            .canary_generation
            .lock()
            .await
            .as_ref()
            .unwrap()
            .state;
        assert_eq!(state, GenerationState::Ready);
        assert!(std::fs::symlink_metadata(&active_link).is_err());

        // The rejections are in the log; no observation exists.
        let writer = daemon.detach_observation_log().await.unwrap();
        assert_eq!(writer.stored_count(), 0);
        let sealed = writer.seal(2).unwrap();
        assert_eq!(sealed.rejections.len(), 3);
        assert!(sealed.observations.is_empty());
        let _ = LogRecord::Seal(sealed.seal.clone());
    }

    #[tokio::test]
    async fn self_reports_never_reach_durable_however_many_arrive() {
        let tmp = tempfile::tempdir().unwrap();
        let rsi_root = tmp.path().join(".rsi");
        let active_link = rsi_root.join("active.sock");
        let daemon = daemon_with_canary(tmp.path(), "gen-002", 1_000_000).await;

        let src_parent = tmp.path().join("art_parent");
        std::fs::create_dir_all(&src_parent).unwrap();
        let parent = daemon
            .supervisor
            .stage_generation("gen-001", &src_parent, "sha-parent")
            .unwrap();
        *daemon.active_generation.lock().await = Some(parent);

        let (mut conn, mut auth, _worker) = authenticated(&daemon, "gen-002", &active_link).await;
        for i in 1..=25 {
            let reply = daemon
                .process_worker_message(
                    &mut conn,
                    &mut auth,
                    report("gen-002", i, true, 10),
                    &active_link,
                )
                .await
                .unwrap();
            assert_eq!(reply, None, "a self-report earns no reply and no drain");
        }
        // A replayed transaction id changes nothing either.
        let reply = daemon
            .process_worker_message(
                &mut conn,
                &mut auth,
                report("gen-002", 1, true, 10),
                &active_link,
            )
            .await
            .unwrap();
        assert_eq!(reply, None);
        // DrainComplete is not a promotion request.
        let reply = daemon
            .process_worker_message(
                &mut conn,
                &mut auth,
                WorkerMessage::DrainComplete {
                    generation_id: "gen-002".to_string(),
                },
                &active_link,
            )
            .await
            .unwrap();
        assert_eq!(reply, None);

        let canary_state = daemon
            .canary_generation
            .lock()
            .await
            .as_ref()
            .unwrap()
            .state;
        assert_eq!(canary_state, GenerationState::CanaryActive);
        let active = daemon.active_generation.lock().await;
        assert_eq!(active.as_ref().unwrap().generation_id, "gen-001");
        assert!(std::fs::symlink_metadata(&active_link).is_err());
    }

    #[tokio::test]
    async fn reported_latency_violation_still_triggers_the_early_revert() {
        let tmp = tempfile::tempdir().unwrap();
        let active_link = tmp.path().join(".rsi").join("active.sock");
        let daemon = daemon_with_canary(tmp.path(), "gen-slow", 50_000).await;
        let (mut conn, mut auth, _worker) = authenticated(&daemon, "gen-slow", &active_link).await;

        let reply = daemon
            .process_worker_message(
                &mut conn,
                &mut auth,
                report("gen-slow", 1, true, 75_000),
                &active_link,
            )
            .await
            .unwrap();
        match reply {
            Some(SupervisorMessage::RevertOrder { reason }) => {
                assert!(reason.contains("Latency budget exceeded"), "{}", reason);
            }
            other => panic!("Expected RevertOrder for latency budget, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn reported_failure_triggers_instant_rollback_to_the_parent() {
        let tmp = tempfile::tempdir().unwrap();
        let rsi_root = tmp.path().join(".rsi");
        let active_link = rsi_root.join("active.sock");
        let daemon = daemon_with_canary(tmp.path(), "gen-canary", 1_000_000).await;

        let src_parent = tmp.path().join("art_parent");
        std::fs::create_dir_all(&src_parent).unwrap();
        let parent = daemon
            .supervisor
            .stage_generation("gen-parent", &src_parent, "sha-parent")
            .unwrap();
        daemon.supervisor.atomic_symlink_swap("gen-parent").unwrap();
        *daemon.active_generation.lock().await = Some(parent);

        let (mut conn, mut auth, _worker) =
            authenticated(&daemon, "gen-canary", &active_link).await;
        let reply = daemon
            .process_worker_message(
                &mut conn,
                &mut auth,
                report("gen-canary", 1, false, 9999),
                &active_link,
            )
            .await
            .unwrap();
        match reply {
            Some(SupervisorMessage::RevertOrder { reason }) => {
                assert!(
                    reason.contains("Inference assertion panicked"),
                    "{}",
                    reason
                );
            }
            _ => panic!("Expected RevertOrder"),
        }
        let state = daemon
            .canary_generation
            .lock()
            .await
            .as_ref()
            .unwrap()
            .state;
        assert_eq!(state, GenerationState::Reverted);
    }

    #[tokio::test]
    async fn unreadable_memory_budget_reverts_the_canary() {
        let tmp = tempfile::tempdir().unwrap();
        let active_link = tmp.path().join(".rsi").join("active.sock");
        let daemon = daemon_with_canary(tmp.path(), "gen-mem", 1_000_000).await;
        let (mut conn, mut auth, _worker) = authenticated(&daemon, "gen-mem", &active_link).await;
        // Point the generation at a pid that has no /proc entry, so the
        // memory read fails. A failed read must revert, never pass.
        let pid = 4_000_000_000u32;
        daemon.canary_generation.lock().await.as_mut().unwrap().pid = Some(pid);

        let reply = daemon
            .process_worker_message(
                &mut conn,
                &mut auth,
                report("gen-mem", 1, true, 10),
                &active_link,
            )
            .await
            .unwrap();
        match reply {
            Some(SupervisorMessage::RevertOrder { reason }) => {
                assert!(reason.contains("unreadable"), "{}", reason);
            }
            other => panic!("Expected RevertOrder, got {:?}", other),
        }
    }
}
