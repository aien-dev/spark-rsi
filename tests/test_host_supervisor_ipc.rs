use spark_rsi::supervisor::GenerationState;
use spark_rsi::supervisor::daemon::{SupervisorConfig, SupervisorDaemon};
use spark_rsi::supervisor::ipc::{IpcClient, SessionAuth, SupervisorMessage, WorkerMessage};
use std::sync::atomic::Ordering;
use std::time::Duration;

#[tokio::test]
async fn test_end_to_end_supervisor_ipc_handshake_and_canary_promotion() {
    let tmp = tempfile::tempdir().unwrap();
    let rsi_root = tmp.path().join(".rsi");
    let socket_path = rsi_root.join("supervisor.sock");
    let active_link = rsi_root.join("active.sock");

    let config = SupervisorConfig {
        rsi_root: rsi_root.clone(),
        socket_path: socket_path.clone(),
        memory_limit_mb: 49152,
        canary_target: 3,
        shared_secret: "tpm-verified-secret-token".to_string(),
    };

    let daemon = std::sync::Arc::new(SupervisorDaemon::new(config));

    // Stage parent generation
    let src_parent = tmp.path().join("art_parent");
    std::fs::create_dir_all(&src_parent).unwrap();
    std::fs::write(src_parent.join("bin"), "parent v1").unwrap();
    let parent_gen = daemon.supervisor.stage_generation("gen-001", &src_parent, "sha-parent").unwrap();
    daemon.supervisor.atomic_symlink_swap("gen-001").unwrap();
    *daemon.active_generation.lock().await = Some(parent_gen);

    // Stage canary generation
    let src_cand = tmp.path().join("art_cand");
    std::fs::create_dir_all(&src_cand).unwrap();
    std::fs::write(src_cand.join("bin"), "canary v2").unwrap();
    daemon.stage_canary("gen-002", &src_cand, "sha-cand").await.unwrap();

    // Spawn supervisor server loop
    let daemon_clone = daemon.clone();
    let active_link_clone = active_link.clone();
    let server_handle = tokio::spawn(async move {
        let _ = daemon_clone.run_server(active_link_clone).await;
    });

    // Worker simulation
    let mut client = IpcClient::connect(&socket_path, Duration::from_secs(5))
        .await
        .expect("Worker failed to connect to supervisor socket");

    let auth_token = SessionAuth::compute_token("gen-002", "tpm-verified-secret-token");
    client
        .send(&WorkerMessage::Ready {
            generation_id: "gen-002".to_string(),
            pid: std::process::id(),
            auth_token,
        })
        .await
        .unwrap();

    let reply: SupervisorMessage = client.recv().await.unwrap();
    assert_eq!(reply, SupervisorMessage::Ping);

    // Send Heartbeat
    client
        .send(&WorkerMessage::Heartbeat {
            generation_id: "gen-002".to_string(),
            timestamp_secs: 100,
            active_requests: 1,
            memory_mb: 2048,
        })
        .await
        .unwrap();

    let ping: SupervisorMessage = client.recv().await.unwrap();
    assert_eq!(ping, SupervisorMessage::Ping);

    // Send successful canary transactions up to quota K = 3
    for i in 1..=2 {
        client
            .send(&WorkerMessage::CanaryReport {
                generation_id: "gen-002".to_string(),
                transaction_id: i,
                success: true,
                latency_us: 1200,
                error: None,
            })
            .await
            .unwrap();
    }

    // Transaction 3 promotes canary to Durable
    client
        .send(&WorkerMessage::CanaryReport {
            generation_id: "gen-002".to_string(),
            transaction_id: 3,
            success: true,
            latency_us: 1100,
            error: None,
        })
        .await
        .unwrap();

    let drain_msg: SupervisorMessage = client.recv().await.unwrap();
    assert_eq!(drain_msg, SupervisorMessage::DrainStart { timeout_secs: 30 });

    // Worker sends DrainComplete
    client
        .send(&WorkerMessage::DrainComplete {
            generation_id: "gen-002".to_string(),
        })
        .await
        .unwrap();

    let ack: SupervisorMessage = client.recv().await.unwrap();
    assert_eq!(ack, SupervisorMessage::ShutdownAck { pid: 0 });

    // Verify final state
    let active_gen = daemon.active_generation.lock().await;
    assert_eq!(active_gen.as_ref().unwrap().generation_id, "gen-002");
    assert_eq!(active_gen.as_ref().unwrap().state, GenerationState::Durable);

    // Stop daemon
    daemon.running.store(false, Ordering::Relaxed);
    let _ = server_handle.abort();
}

#[tokio::test]
async fn test_end_to_end_supervisor_instant_rollback_on_canary_defect() {
    let tmp = tempfile::tempdir().unwrap();
    let rsi_root = tmp.path().join(".rsi");
    let socket_path = rsi_root.join("supervisor.sock");
    let active_link = rsi_root.join("active.sock");

    let config = SupervisorConfig {
        rsi_root: rsi_root.clone(),
        socket_path: socket_path.clone(),
        memory_limit_mb: 49152,
        canary_target: 5,
        shared_secret: "tpm-verified-secret-token".to_string(),
    };

    let daemon = std::sync::Arc::new(SupervisorDaemon::new(config));

    // Stage parent
    let src_parent = tmp.path().join("art_parent");
    std::fs::create_dir_all(&src_parent).unwrap();
    std::fs::write(src_parent.join("bin"), "parent v1").unwrap();
    let parent_gen = daemon.supervisor.stage_generation("gen-001", &src_parent, "sha-parent").unwrap();
    daemon.supervisor.atomic_symlink_swap("gen-001").unwrap();
    *daemon.active_generation.lock().await = Some(parent_gen);

    // Stage canary
    let src_cand = tmp.path().join("art_cand");
    std::fs::create_dir_all(&src_cand).unwrap();
    std::fs::write(src_cand.join("bin"), "canary v2").unwrap();
    daemon.stage_canary("gen-002", &src_cand, "sha-cand").await.unwrap();

    let daemon_clone = daemon.clone();
    let active_link_clone = active_link.clone();
    let server_handle = tokio::spawn(async move {
        let _ = daemon_clone.run_server(active_link_clone).await;
    });

    let mut client = IpcClient::connect(&socket_path, Duration::from_secs(5))
        .await
        .expect("Worker failed to connect");

    let auth_token = SessionAuth::compute_token("gen-002", "tpm-verified-secret-token");
    client
        .send(&WorkerMessage::Ready {
            generation_id: "gen-002".to_string(),
            pid: std::process::id(),
            auth_token,
        })
        .await
        .unwrap();

    let _ = client.recv::<SupervisorMessage>().await.unwrap();

    // Report canary failure
    client
        .send(&WorkerMessage::CanaryReport {
            generation_id: "gen-002".to_string(),
            transaction_id: 1,
            success: false,
            latency_us: 9999,
            error: Some("Inference regression exceeded threshold".to_string()),
        })
        .await
        .unwrap();

    let revert_msg: SupervisorMessage = client.recv().await.unwrap();
    match revert_msg {
        SupervisorMessage::RevertOrder { reason } => {
            assert!(reason.contains("Inference regression exceeded threshold"));
        }
        _ => panic!("Expected RevertOrder"),
    }

    // Verify rollback
    let canary_lock = daemon.canary_generation.lock().await;
    assert_eq!(canary_lock.as_ref().unwrap().state, GenerationState::Reverted);

    let active_content = std::fs::read_to_string(daemon.supervisor.active_symlink.join("bin")).unwrap();
    assert_eq!(active_content, "parent v1");

    daemon.running.store(false, Ordering::Relaxed);
    let _ = server_handle.abort();
}

#[tokio::test]
async fn test_unauthenticated_worker_rejected_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let rsi_root = tmp.path().join(".rsi");
    let socket_path = rsi_root.join("supervisor.sock");
    let active_link = rsi_root.join("active.sock");

    let config = SupervisorConfig {
        rsi_root: rsi_root.clone(),
        socket_path: socket_path.clone(),
        memory_limit_mb: 49152,
        canary_target: 5,
        shared_secret: "legitimate-secret".to_string(),
    };

    let daemon = std::sync::Arc::new(SupervisorDaemon::new(config));

    let src_cand = tmp.path().join("art_cand");
    std::fs::create_dir_all(&src_cand).unwrap();
    daemon.stage_canary("gen-002", &src_cand, "sha-cand").await.unwrap();

    let daemon_clone = daemon.clone();
    let active_link_clone = active_link.clone();
    let server_handle = tokio::spawn(async move {
        let _ = daemon_clone.run_server(active_link_clone).await;
    });

    let mut client = IpcClient::connect(&socket_path, Duration::from_secs(5))
        .await
        .unwrap();

    // Send invalid token
    client
        .send(&WorkerMessage::Ready {
            generation_id: "gen-002".to_string(),
            pid: 12345,
            auth_token: "invalid-forged-token".to_string(),
        })
        .await
        .unwrap();

    // Should be disconnected or fail to receive Ping
    let res = client.recv::<SupervisorMessage>().await;
    assert!(res.is_err());

    daemon.running.store(false, Ordering::Relaxed);
    let _ = server_handle.abort();
}
