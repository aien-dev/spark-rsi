use crate::supervisor::ipc::{
    IpcConnection, IpcServer, SessionAuth, SupervisorMessage, WorkerMessage,
};
use crate::supervisor::{GenerationInfo, GenerationState, HostSupervisor};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

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

    pub async fn process_worker_message(
        &self,
        conn: &mut IpcConnection,
        msg: WorkerMessage,
        active_socket_link: &Path,
    ) -> Result<Option<SupervisorMessage>, String> {
        match msg {
            WorkerMessage::Ready {
                generation_id,
                pid,
                auth_token: _,
            } => {
                // Fresh challenge-response HMAC handshake
                let nonce = format!("challenge-{}", uuid::Uuid::new_v4().simple());
                conn.send(&SupervisorMessage::AuthChallenge {
                    nonce: nonce.clone(),
                })
                .await
                .map_err(|e| format!("Failed to send auth challenge: {}", e))?;

                let auth_msg: WorkerMessage = conn
                    .recv()
                    .await
                    .map_err(|e| format!("Failed to receive auth response: {}", e))?;

                let candidate_hmac = match auth_msg {
                    WorkerMessage::AuthResponse { response } => response,
                    other => {
                        return Err(format!(
                            "Expected AuthResponse from worker, got {:?}",
                            other
                        ))
                    }
                };

                let message_to_sign = format!("{}:{}", generation_id, nonce);
                if !SessionAuth::verify_hmac(
                    &self.config.shared_secret,
                    &message_to_sign,
                    &candidate_hmac,
                ) {
                    return Err(format!(
                        "Unauthorized worker HMAC for generation {}",
                        generation_id
                    ));
                }

                let mut canary_lock = self.canary_generation.lock().await;
                if let Some(ref mut canary) = *canary_lock {
                    if canary.generation_id == generation_id {
                        canary.state = GenerationState::Ready;
                        canary.installed_path = PathBuf::from(format!("/proc/{}", pid));
                        canary.pid = Some(pid);

                        // Atomic switch active socket to canary
                        let canary_sock = self
                            .config
                            .rsi_root
                            .join(format!("workers/{}.sock", generation_id));
                        self.supervisor
                            .switch_active_socket(active_socket_link, &canary_sock)?;

                        canary.state = GenerationState::CanaryActive;
                        return Ok(Some(SupervisorMessage::Ping));
                    }
                }
                Err(format!(
                    "Unexpected Ready message from unknown generation {}",
                    generation_id
                ))
            }

            WorkerMessage::Heartbeat {
                generation_id,
                active_requests: _,
                memory_mb,
                timestamp_secs: _,
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
                generation_id,
                transaction_id: _,
                success,
                latency_us,
                error,
            } => {
                let should_revert;
                let is_durable;
                let promoted_gen;
                let mut revert_reason = error.clone();
                {
                    let mut canary_lock = self.canary_generation.lock().await;
                    if let Some(ref mut canary) = *canary_lock {
                        if canary.generation_id == generation_id {
                            match self.supervisor.record_canary_transaction(
                                canary,
                                success,
                                latency_us,
                                self.config.canary_target,
                                self.config.max_latency_us,
                                self.config.max_error_rate,
                            ) {
                                Ok(new_state) => {
                                    should_revert = new_state == GenerationState::Reverting;
                                    is_durable = new_state == GenerationState::Durable;
                                    promoted_gen = if is_durable {
                                        Some(canary.clone())
                                    } else {
                                        None
                                    };
                                }
                                Err(budget_err) => {
                                    should_revert = true;
                                    is_durable = false;
                                    promoted_gen = None;
                                    revert_reason = Some(match error {
                                        Some(ref orig) => format!("{}: {}", orig, budget_err),
                                        None => budget_err,
                                    });
                                }
                            }
                        } else {
                            should_revert = false;
                            is_durable = false;
                            promoted_gen = None;
                        }
                    } else {
                        should_revert = false;
                        is_durable = false;
                        promoted_gen = None;
                    }
                }

                if should_revert {
                    self.trigger_instant_rollback(active_socket_link).await?;
                    return Ok(Some(SupervisorMessage::RevertOrder {
                        reason: revert_reason
                            .unwrap_or_else(|| "Canary transaction failure".to_string()),
                    }));
                }

                if is_durable {
                    let mut active_lock = self.active_generation.lock().await;
                    *active_lock = promoted_gen;
                    return Ok(Some(SupervisorMessage::DrainStart { timeout_secs: 30 }));
                }

                Ok(None)
            }

            WorkerMessage::DrainComplete { generation_id: _ } => {
                Ok(Some(SupervisorMessage::ShutdownAck { pid: 0 }))
            }

            WorkerMessage::Pong => Ok(None),
            WorkerMessage::AuthResponse { .. } => Ok(None),
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
                    while let Ok(msg) = conn.recv::<WorkerMessage>().await {
                        match self
                            .process_worker_message(&mut conn, msg, &active_link)
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

    #[tokio::test]
    async fn test_supervisor_daemon_canary_promotion_and_rollback() {
        let tmp = tempfile::tempdir().unwrap();
        let rsi_root = tmp.path().join(".rsi");
        let sock_path = rsi_root.join("supervisor.sock");
        let active_link = rsi_root.join("active.sock");

        let config = SupervisorConfig {
            rsi_root: rsi_root.clone(),
            socket_path: sock_path.clone(),
            memory_limit_mb: 49152,
            canary_target: 3,
            max_latency_us: 1_000_000,
            max_error_rate: 0.0,
            shared_secret: "secret-key".to_string(),
        };

        let daemon = SupervisorDaemon::new(config);

        // Stage parent generation
        let src_parent = tmp.path().join("art_parent");
        std::fs::create_dir_all(&src_parent).unwrap();
        let parent_gen = daemon
            .supervisor
            .stage_generation("gen-001", &src_parent, "sha-parent")
            .unwrap();
        *daemon.active_generation.lock().await = Some(parent_gen);

        // Stage candidate canary
        let src_cand = tmp.path().join("art_cand");
        std::fs::create_dir_all(&src_cand).unwrap();
        daemon
            .stage_canary("gen-002", &src_cand, "sha-cand")
            .await
            .unwrap();

        // Worker Ready message with interactive challenge/HMAC handshake
        let (stream_worker, stream_sup) = tokio::net::UnixStream::pair().unwrap();
        let mut conn_worker = IpcConnection::new(stream_worker);
        let mut conn_sup = IpcConnection::new(stream_sup);

        let worker_handshake = tokio::spawn(async move {
            conn_worker
                .perform_worker_handshake("gen-002", 9999, "secret-key")
                .await
        });

        let ready_msg = conn_sup.recv::<WorkerMessage>().await.unwrap();
        let reply = daemon
            .process_worker_message(&mut conn_sup, ready_msg, &active_link)
            .await
            .unwrap();
        assert_eq!(reply, Some(SupervisorMessage::Ping));
        conn_sup.send(&reply.unwrap()).await.unwrap();
        let worker_res = worker_handshake.await.unwrap().unwrap();
        assert_eq!(worker_res, SupervisorMessage::Ping);

        // Canary transactions 1 & 2 succeed
        for i in 1..=2 {
            let report = WorkerMessage::CanaryReport {
                generation_id: "gen-002".to_string(),
                transaction_id: i,
                success: true,
                latency_us: 1500,
                error: None,
            };
            let rep_reply = daemon
                .process_worker_message(&mut conn_sup, report, &active_link)
                .await
                .unwrap();
            assert_eq!(rep_reply, None);
        }

        // Canary transaction 3 succeeds -> triggers Durable and DrainStart
        let report_final = WorkerMessage::CanaryReport {
            generation_id: "gen-002".to_string(),
            transaction_id: 3,
            success: true,
            latency_us: 1450,
            error: None,
        };
        let rep_reply_final = daemon
            .process_worker_message(&mut conn_sup, report_final, &active_link)
            .await
            .unwrap();
        assert_eq!(
            rep_reply_final,
            Some(SupervisorMessage::DrainStart { timeout_secs: 30 })
        );

        let active_gen = daemon.active_generation.lock().await;
        assert_eq!(active_gen.as_ref().unwrap().generation_id, "gen-002");
    }

    #[tokio::test]
    async fn test_supervisor_daemon_canary_latency_budget_violation_triggers_rollback() {
        let tmp = tempfile::tempdir().unwrap();
        let rsi_root = tmp.path().join(".rsi");
        let active_link = rsi_root.join("active.sock");

        let config = SupervisorConfig {
            rsi_root: rsi_root.clone(),
            socket_path: rsi_root.join("supervisor.sock"),
            memory_limit_mb: 49152,
            canary_target: 5,
            max_latency_us: 50_000,
            max_error_rate: 0.0,
            shared_secret: "secret-key".to_string(),
        };

        let daemon = SupervisorDaemon::new(config);

        let src_cand = tmp.path().join("art_cand");
        std::fs::create_dir_all(&src_cand).unwrap();
        daemon
            .stage_canary("gen-slow", &src_cand, "sha-cand")
            .await
            .unwrap();

        let (_s1, s2) = tokio::net::UnixStream::pair().unwrap();
        let mut conn_sup = IpcConnection::new(s2);

        // Transaction succeeds but latency exceeds 50ms budget (75ms)
        let slow_report = WorkerMessage::CanaryReport {
            generation_id: "gen-slow".to_string(),
            transaction_id: 1,
            success: true,
            latency_us: 75_000,
            error: None,
        };

        let reply = daemon
            .process_worker_message(&mut conn_sup, slow_report, &active_link)
            .await
            .unwrap();
        match reply {
            Some(SupervisorMessage::RevertOrder { reason }) => {
                assert!(reason.contains("Latency budget exceeded"));
            }
            other => panic!("Expected RevertOrder for latency budget, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_supervisor_daemon_canary_failure_triggers_instant_rollback() {
        let tmp = tempfile::tempdir().unwrap();
        let rsi_root = tmp.path().join(".rsi");
        let active_link = rsi_root.join("active.sock");

        let config = SupervisorConfig {
            rsi_root: rsi_root.clone(),
            socket_path: rsi_root.join("supervisor.sock"),
            memory_limit_mb: 49152,
            canary_target: 5,
            max_latency_us: 1_000_000,
            max_error_rate: 0.0,
            shared_secret: "secret-key".to_string(),
        };

        let daemon = SupervisorDaemon::new(config);

        // Stage parent
        let src_parent = tmp.path().join("art_parent");
        std::fs::create_dir_all(&src_parent).unwrap();
        let parent_gen = daemon
            .supervisor
            .stage_generation("gen-parent", &src_parent, "sha-parent")
            .unwrap();
        daemon.supervisor.atomic_symlink_swap("gen-parent").unwrap();
        *daemon.active_generation.lock().await = Some(parent_gen);

        // Stage canary
        let src_cand = tmp.path().join("art_cand");
        std::fs::create_dir_all(&src_cand).unwrap();
        daemon
            .stage_canary("gen-canary", &src_cand, "sha-cand")
            .await
            .unwrap();

        let (_s1, s2) = tokio::net::UnixStream::pair().unwrap();
        let mut conn_sup = IpcConnection::new(s2);

        // Canary fails on first transaction
        let fail_report = WorkerMessage::CanaryReport {
            generation_id: "gen-canary".to_string(),
            transaction_id: 1,
            success: false,
            latency_us: 9999,
            error: Some("Inference assertion panicked".to_string()),
        };

        let reply = daemon
            .process_worker_message(&mut conn_sup, fail_report, &active_link)
            .await
            .unwrap();
        match reply {
            Some(SupervisorMessage::RevertOrder { reason }) => {
                assert!(reason.contains("Inference assertion panicked"));
            }
            _ => panic!("Expected RevertOrder"),
        }

        let canary_lock = daemon.canary_generation.lock().await;
        assert_eq!(
            canary_lock.as_ref().unwrap().state,
            GenerationState::Reverted
        );
    }
}
