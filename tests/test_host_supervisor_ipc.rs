use spark_rsi::supervisor::daemon::{SupervisorConfig, SupervisorDaemon};
use spark_rsi::supervisor::ipc::{IpcClient, SupervisorMessage, WorkerMessage};
use spark_rsi::supervisor::GenerationState;
use std::sync::atomic::Ordering;
use std::time::Duration;

#[tokio::test]
async fn test_end_to_end_supervisor_canary_probation_and_promotion() {
    let tmp = tempfile::tempdir().unwrap();
    let rsi_root = tmp.path().join(".rsi");
    let socket_path = rsi_root.join("supervisor.sock");
    let active_link = rsi_root.join("active.sock");

    let config = SupervisorConfig {
        rsi_root: rsi_root.clone(),
        socket_path: socket_path.clone(),
        memory_limit_mb: 49152,
        canary_target: 3,
        max_latency_us: 1_000_000,
        max_error_rate: 0.0,
        shared_secret: "tpm-verified-secret-token".to_string(),
    };

    let daemon = std::sync::Arc::new(SupervisorDaemon::new(config));

    // Stage parent generation
    let src_parent = tmp.path().join("art_parent");
    std::fs::create_dir_all(&src_parent).unwrap();
    std::fs::write(src_parent.join("bin"), "parent v1").unwrap();
    let parent_gen = daemon
        .supervisor
        .stage_generation("gen-001", &src_parent, "sha-parent")
        .unwrap();
    daemon.supervisor.atomic_symlink_swap("gen-001").unwrap();
    *daemon.active_generation.lock().await = Some(parent_gen);

    // Stage canary generation
    let src_cand = tmp.path().join("art_cand");
    std::fs::create_dir_all(&src_cand).unwrap();
    std::fs::write(src_cand.join("bin"), "canary v2").unwrap();
    daemon
        .stage_canary("gen-002", &src_cand, "sha-cand")
        .await
        .unwrap();

    // Spawn supervisor server loop
    let daemon_clone = daemon.clone();
    let active_link_clone = active_link.clone();
    let server_handle = tokio::spawn(async move {
        let _ = daemon_clone.run_server(active_link_clone).await;
    });

    // Worker simulation with interactive challenge/HMAC handshake
    let mut client = IpcClient::connect(&socket_path, Duration::from_secs(5))
        .await
        .expect("Worker failed to connect to supervisor socket");

    let reply = client
        .perform_worker_handshake("gen-002", std::process::id(), "tpm-verified-secret-token")
        .await
        .unwrap();
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
    assert_eq!(
        drain_msg,
        SupervisorMessage::DrainStart { timeout_secs: 30 }
    );

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
        max_latency_us: 1_000_000,
        max_error_rate: 0.0,
        shared_secret: "tpm-verified-secret-token".to_string(),
    };

    let daemon = std::sync::Arc::new(SupervisorDaemon::new(config));

    // Stage parent
    let src_parent = tmp.path().join("art_parent");
    std::fs::create_dir_all(&src_parent).unwrap();
    std::fs::write(src_parent.join("bin"), "parent v1").unwrap();
    let parent_gen = daemon
        .supervisor
        .stage_generation("gen-001", &src_parent, "sha-parent")
        .unwrap();
    daemon.supervisor.atomic_symlink_swap("gen-001").unwrap();
    *daemon.active_generation.lock().await = Some(parent_gen);

    // Stage canary
    let src_cand = tmp.path().join("art_cand");
    std::fs::create_dir_all(&src_cand).unwrap();
    std::fs::write(src_cand.join("bin"), "canary v2").unwrap();
    daemon
        .stage_canary("gen-002", &src_cand, "sha-cand")
        .await
        .unwrap();

    let daemon_clone = daemon.clone();
    let active_link_clone = active_link.clone();
    let server_handle = tokio::spawn(async move {
        let _ = daemon_clone.run_server(active_link_clone).await;
    });

    let mut client = IpcClient::connect(&socket_path, Duration::from_secs(5))
        .await
        .expect("Worker failed to connect");

    let reply = client
        .perform_worker_handshake("gen-002", std::process::id(), "tpm-verified-secret-token")
        .await
        .unwrap();
    assert_eq!(reply, SupervisorMessage::Ping);

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
    assert_eq!(
        canary_lock.as_ref().unwrap().state,
        GenerationState::Reverted
    );

    let active_content =
        std::fs::read_to_string(daemon.supervisor.active_symlink.join("bin")).unwrap();
    assert_eq!(active_content, "parent v1");

    daemon.running.store(false, Ordering::Relaxed);
    let _ = server_handle.abort();
}

#[tokio::test]
async fn test_end_to_end_supervisor_instant_rollback_on_latency_budget_exceeded() {
    let tmp = tempfile::tempdir().unwrap();
    let rsi_root = tmp.path().join(".rsi");
    let socket_path = rsi_root.join("supervisor.sock");
    let active_link = rsi_root.join("active.sock");

    let config = SupervisorConfig {
        rsi_root: rsi_root.clone(),
        socket_path: socket_path.clone(),
        memory_limit_mb: 49152,
        canary_target: 5,
        max_latency_us: 50_000, // 50ms budget
        max_error_rate: 0.0,
        shared_secret: "tpm-verified-secret-token".to_string(),
    };

    let daemon = std::sync::Arc::new(SupervisorDaemon::new(config));

    // Stage parent
    let src_parent = tmp.path().join("art_parent");
    std::fs::create_dir_all(&src_parent).unwrap();
    std::fs::write(src_parent.join("bin"), "parent v1").unwrap();
    let parent_gen = daemon
        .supervisor
        .stage_generation("gen-001", &src_parent, "sha-parent")
        .unwrap();
    daemon.supervisor.atomic_symlink_swap("gen-001").unwrap();
    *daemon.active_generation.lock().await = Some(parent_gen);

    // Stage canary
    let src_cand = tmp.path().join("art_cand");
    std::fs::create_dir_all(&src_cand).unwrap();
    std::fs::write(src_cand.join("bin"), "canary v2").unwrap();
    daemon
        .stage_canary("gen-002", &src_cand, "sha-cand")
        .await
        .unwrap();

    let daemon_clone = daemon.clone();
    let active_link_clone = active_link.clone();
    let server_handle = tokio::spawn(async move {
        let _ = daemon_clone.run_server(active_link_clone).await;
    });

    let mut client = IpcClient::connect(&socket_path, Duration::from_secs(5))
        .await
        .expect("Worker failed to connect");

    let reply = client
        .perform_worker_handshake("gen-002", std::process::id(), "tpm-verified-secret-token")
        .await
        .unwrap();
    assert_eq!(reply, SupervisorMessage::Ping);

    // Transaction succeeds functionally, but violates latency budget (75ms > 50ms)
    client
        .send(&WorkerMessage::CanaryReport {
            generation_id: "gen-002".to_string(),
            transaction_id: 1,
            success: true,
            latency_us: 75_000,
            error: None,
        })
        .await
        .unwrap();

    let revert_msg: SupervisorMessage = client.recv().await.unwrap();
    match revert_msg {
        SupervisorMessage::RevertOrder { reason } => {
            assert!(reason.contains("Latency budget exceeded"));
            assert!(reason.contains("75000 us > 50000 us"));
        }
        _ => panic!("Expected RevertOrder for latency budget violation"),
    }

    // Verify rollback
    let canary_lock = daemon.canary_generation.lock().await;
    assert_eq!(
        canary_lock.as_ref().unwrap().state,
        GenerationState::Reverted
    );

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
        max_latency_us: 1_000_000,
        max_error_rate: 0.0,
        shared_secret: "legitimate-secret".to_string(),
    };

    let daemon = std::sync::Arc::new(SupervisorDaemon::new(config));

    let src_cand = tmp.path().join("art_cand");
    std::fs::create_dir_all(&src_cand).unwrap();
    daemon
        .stage_canary("gen-002", &src_cand, "sha-cand")
        .await
        .unwrap();

    let daemon_clone = daemon.clone();
    let active_link_clone = active_link.clone();
    let server_handle = tokio::spawn(async move {
        let _ = daemon_clone.run_server(active_link_clone).await;
    });

    let mut client = IpcClient::connect(&socket_path, Duration::from_secs(5))
        .await
        .unwrap();

    // Send Ready message
    client
        .send(&WorkerMessage::Ready {
            generation_id: "gen-002".to_string(),
            pid: 12345,
            auth_token: String::new(),
        })
        .await
        .unwrap();

    // Receive challenge
    let challenge: SupervisorMessage = client.recv().await.unwrap();
    match challenge {
        SupervisorMessage::AuthChallenge { .. } => {}
        other => panic!("Expected AuthChallenge, got {:?}", other),
    }

    // Send forged HMAC response
    client
        .send(&WorkerMessage::AuthResponse {
            response: "invalid-forged-hmac-digest".to_string(),
        })
        .await
        .unwrap();

    // Should be rejected / disconnected
    let res = client.recv::<SupervisorMessage>().await;
    assert!(res.is_err());

    daemon.running.store(false, Ordering::Relaxed);
    let _ = server_handle.abort();
}
