use crate::supervisor::GenerationState;
use crate::supervisor::ipc::{IpcConnection, IpcServer, SessionAuth, SupervisorMessage, WorkerMessage};
use crate::supervisor::{GenerationInfo, HostSupervisor};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

pub struct SupervisorConfig {
    pub rsi_root: PathBuf,
    pub socket_path: PathBuf,
    pub memory_limit_mb: u64,
    pub canary_target: u64,
    pub shared_secret: String,
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            rsi_root: PathBuf::from(".rsi"),
            socket_path: PathBuf::from(".rsi/supervisor.sock"),
            memory_limit_mb: 49152,
            canary_target: 5000,
            shared_secret: "sovereign-spark-tpm-key".to_string(),
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
        let gen = self
            .supervisor
            .stage_generation(generation_id, artifacts_dir, manifest_digest)?;

        let mut canary_lock = self.canary_generation.lock().await;
        *canary_lock = Some(gen.clone());
        Ok(gen)
    }

    pub async fn process_worker_message(
        &self,
        _conn: &mut IpcConnection,
        msg: WorkerMessage,
        active_socket_link: &Path,
    ) -> Result<Option<SupervisorMessage>, String> {
        match msg {
            WorkerMessage::Ready {
                generation_id,
                pid,
                auth_token,
            } => {
                if !SessionAuth::verify_token(&generation_id, &self.config.shared_secret, &auth_token) {
                    return Err(format!("Unauthorized worker token for generation {}", generation_id));
                }

                let mut canary_lock = self.canary_generation.lock().await;
                if let Some(ref mut canary) = *canary_lock {
                    if canary.generation_id == generation_id {
                        canary.state = GenerationState::Ready;
                        canary.installed_path = PathBuf::from(format!("/proc/{}", pid));

                        // Atomic switch active socket to canary
                        let canary_sock = self.config.rsi_root.join(format!("workers/{}.sock", generation_id));
                        self.supervisor.switch_active_socket(active_socket_link, &canary_sock)?;

                        canary.state = GenerationState::CanaryActive;
                        return Ok(Some(SupervisorMessage::Ping));
                    }
                }
                Err(format!("Unexpected Ready message from unknown generation {}", generation_id))
            }

            WorkerMessage::Heartbeat {
                generation_id,
                active_requests: _,
                memory_mb,
                timestamp_secs: _,
            } => {
                let over_budget = memory_mb > self.config.memory_limit_mb;
                let is_active_canary = {
                    let canary_lock = self.canary_generation.lock().await;
                    matches!(canary_lock.as_ref(), Some(canary) if canary.generation_id == generation_id)
                };

                if over_budget && is_active_canary {
                    // Mark the canary as reverting, then release the lock before
                    // trigger_instant_rollback re-acquires it (tokio Mutex is not reentrant).
                    {
                        let mut canary_lock = self.canary_generation.lock().await;
                        if let Some(ref mut canary) = *canary_lock {
                            if canary.generation_id == generation_id {
                                canary.state = GenerationState::Reverting;
                            }
                        }
                    }
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
                latency_us: _,
                error,
            } => {
                enum CanaryOutcome {
                    Ignore,
                    Rollback(String),
                    Promote(GenerationInfo),
                }

                // Decide under the canary lock, then release it before touching the
                // active generation or trigger_instant_rollback to avoid self-deadlock.
                let outcome = {
                    let mut canary_lock = self.canary_generation.lock().await;
                    match canary_lock.as_mut() {
                        Some(canary) if canary.generation_id == generation_id => {
                            let new_state = self.supervisor.record_canary_transaction(
                                canary,
                                success,
                                self.config.canary_target,
                            )?;

                            if new_state == GenerationState::Reverting {
                                CanaryOutcome::Rollback(
                                    error.unwrap_or_else(|| "Canary transaction failure".to_string()),
                                )
                            } else if new_state == GenerationState::Durable {
                                CanaryOutcome::Promote(canary.clone())
                            } else {
                                CanaryOutcome::Ignore
                            }
                        }
                        _ => CanaryOutcome::Ignore,
                    }
                };

                match outcome {
                    CanaryOutcome::Rollback(reason) => {
                        self.trigger_instant_rollback(active_socket_link).await?;
                        Ok(Some(SupervisorMessage::RevertOrder { reason }))
                    }
                    CanaryOutcome::Promote(canary) => {
                        let mut active_lock = self.active_generation.lock().await;
                        *active_lock = Some(canary);
                        Ok(Some(SupervisorMessage::DrainStart { timeout_secs: 30 }))
                    }
                    CanaryOutcome::Ignore => Ok(None),
                }
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
            let parent_sock = self.config.rsi_root.join(format!("workers/{}.sock", parent.generation_id));
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
                        if let Ok(Some(reply)) = self.process_worker_message(&mut conn, msg, &active_link).await {
                            let _ = conn.send(&reply).await;
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
            shared_secret: "secret-key".to_string(),
        };

        let daemon = SupervisorDaemon::new(config);

        // Stage parent generation
        let src_parent = tmp.path().join("art_parent");
        std::fs::create_dir_all(&src_parent).unwrap();
        let parent_gen = daemon.supervisor.stage_generation("gen-001", &src_parent, "sha-parent").unwrap();
        *daemon.active_generation.lock().await = Some(parent_gen);

        // Stage candidate canary
        let src_cand = tmp.path().join("art_cand");
        std::fs::create_dir_all(&src_cand).unwrap();
        daemon.stage_canary("gen-002", &src_cand, "sha-cand").await.unwrap();

        // Worker Ready message
        let (stream_worker, stream_sup) = tokio::net::UnixStream::pair().unwrap();
        let _conn_worker = IpcConnection::new(stream_worker);
        let mut conn_sup = IpcConnection::new(stream_sup);

        let auth_token = SessionAuth::compute_token("gen-002", "secret-key");
        let ready_msg = WorkerMessage::Ready {
            generation_id: "gen-002".to_string(),
            pid: 9999,
            auth_token,
        };

        let reply = daemon.process_worker_message(&mut conn_sup, ready_msg, &active_link).await.unwrap();
        assert_eq!(reply, Some(SupervisorMessage::Ping));

        // Canary transactions 1 & 2 succeed
        for i in 1..=2 {
            let report = WorkerMessage::CanaryReport {
                generation_id: "gen-002".to_string(),
                transaction_id: i,
                success: true,
                latency_us: 1500,
                error: None,
            };
            let rep_reply = daemon.process_worker_message(&mut conn_sup, report, &active_link).await.unwrap();
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
        let rep_reply_final = daemon.process_worker_message(&mut conn_sup, report_final, &active_link).await.unwrap();
        assert_eq!(rep_reply_final, Some(SupervisorMessage::DrainStart { timeout_secs: 30 }));

        let active_gen = daemon.active_generation.lock().await;
        assert_eq!(active_gen.as_ref().unwrap().generation_id, "gen-002");
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
            shared_secret: "secret-key".to_string(),
        };

        let daemon = SupervisorDaemon::new(config);

        // Stage parent
        let src_parent = tmp.path().join("art_parent");
        std::fs::create_dir_all(&src_parent).unwrap();
        let parent_gen = daemon.supervisor.stage_generation("gen-parent", &src_parent, "sha-parent").unwrap();
        daemon.supervisor.atomic_symlink_swap("gen-parent").unwrap();
        *daemon.active_generation.lock().await = Some(parent_gen);

        // Stage canary
        let src_cand = tmp.path().join("art_cand");
        std::fs::create_dir_all(&src_cand).unwrap();
        daemon.stage_canary("gen-canary", &src_cand, "sha-cand").await.unwrap();

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

        let reply = daemon.process_worker_message(&mut conn_sup, fail_report, &active_link).await.unwrap();
        match reply {
            Some(SupervisorMessage::RevertOrder { reason }) => {
                assert!(reason.contains("Inference assertion panicked"));
            }
            _ => panic!("Expected RevertOrder"),
        }

        let canary_lock = daemon.canary_generation.lock().await;
        assert_eq!(canary_lock.as_ref().unwrap().state, GenerationState::Reverted);
    }
}
