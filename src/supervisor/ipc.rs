use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SupervisorMessage {
    DrainStart { timeout_secs: u64 },
    RevertOrder { reason: String },
    ShutdownAck { pid: u32 },
    Ping,
    AuthChallenge { nonce: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WorkerMessage {
    Ready {
        generation_id: String,
        pid: u32,
        auth_token: String,
    },
    Heartbeat {
        generation_id: String,
        timestamp_secs: u64,
        active_requests: u32,
        memory_mb: u64,
    },
    DrainComplete {
        generation_id: String,
    },
    CanaryReport {
        generation_id: String,
        transaction_id: u64,
        success: bool,
        latency_us: u64,
        error: Option<String>,
    },
    Pong,
    AuthResponse {
        response: String,
    },
}

pub struct IpcConnection {
    reader: BufReader<tokio::net::unix::OwnedReadHalf>,
    writer: tokio::net::unix::OwnedWriteHalf,
}

impl IpcConnection {
    pub fn new(stream: UnixStream) -> Self {
        let (read_half, write_half) = stream.into_split();
        Self {
            reader: BufReader::new(read_half),
            writer: write_half,
        }
    }

    pub async fn send<T: Serialize>(&mut self, message: &T) -> Result<(), String> {
        let mut data = serde_json::to_string(message)
            .map_err(|e| format!("Failed to serialize IPC message: {}", e))?;
        data.push('\n');
        self.writer
            .write_all(data.as_bytes())
            .await
            .map_err(|e| format!("Failed to write IPC frame: {}", e))?;
        self.writer
            .flush()
            .await
            .map_err(|e| format!("Failed to flush IPC stream: {}", e))?;
        Ok(())
    }

    pub async fn recv<T: serde::de::DeserializeOwned>(&mut self) -> Result<T, String> {
        let mut line = String::new();
        let bytes_read = self
            .reader
            .read_line(&mut line)
            .await
            .map_err(|e| format!("Failed to read IPC frame: {}", e))?;

        if bytes_read == 0 {
            return Err("IPC connection closed by peer".to_string());
        }

        serde_json::from_str(line.trim())
            .map_err(|e| format!("Failed to deserialize IPC message: {}", e))
    }

    pub async fn perform_worker_handshake(
        &mut self,
        generation_id: &str,
        pid: u32,
        shared_secret: &str,
    ) -> Result<SupervisorMessage, String> {
        self.send(&WorkerMessage::Ready {
            generation_id: generation_id.to_string(),
            pid,
            auth_token: String::new(),
        })
        .await?;

        let challenge_msg: SupervisorMessage = self.recv().await?;
        let nonce = match challenge_msg {
            SupervisorMessage::AuthChallenge { nonce } => nonce,
            other => {
                return Err(format!(
                    "Expected AuthChallenge from supervisor, got {:?}",
                    other
                ))
            }
        };

        let message = format!("{}:{}", generation_id, nonce);
        let hmac = SessionAuth::compute_hmac(shared_secret, &message);

        self.send(&WorkerMessage::AuthResponse { response: hmac })
            .await?;
        self.recv().await
    }
}

pub struct IpcServer {
    listener: UnixListener,
    socket_path: PathBuf,
}

impl IpcServer {
    pub fn bind(socket_path: &Path) -> Result<Self, String> {
        if socket_path.exists() {
            let _ = std::fs::remove_file(socket_path);
        }
        if let Some(parent) = socket_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let listener = UnixListener::bind(socket_path)
            .map_err(|e| format!("Failed to bind Unix socket at {:?}: {}", socket_path, e))?;

        Ok(Self {
            listener,
            socket_path: socket_path.to_path_buf(),
        })
    }

    pub async fn accept(&self) -> Result<IpcConnection, String> {
        let (stream, _addr) = self
            .listener
            .accept()
            .await
            .map_err(|e| format!("Failed to accept IPC connection: {}", e))?;

        #[cfg(target_os = "linux")]
        {
            let cred = stream
                .peer_cred()
                .map_err(|e| format!("Failed to get peer credentials: {}", e))?;
            let current_uid = unsafe { libc::getuid() };
            if cred.uid() != current_uid {
                return Err(format!(
                    "Unauthorized peer UID: {} != expected current UID {}",
                    cred.uid(),
                    current_uid
                ));
            }
        }

        Ok(IpcConnection::new(stream))
    }

    pub fn path(&self) -> &Path {
        &self.socket_path
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        if self.socket_path.exists() {
            let _ = std::fs::remove_file(&self.socket_path);
        }
    }
}

pub struct IpcClient;

impl IpcClient {
    pub async fn connect(socket_path: &Path, timeout: Duration) -> Result<IpcConnection, String> {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            if socket_path.exists() {
                if let Ok(stream) = UnixStream::connect(socket_path).await {
                    return Ok(IpcConnection::new(stream));
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        Err(format!(
            "Timed out connecting to IPC socket at {:?} after {:?}",
            socket_path, timeout
        ))
    }
}

pub struct SessionAuth;

impl SessionAuth {
    /// Computes RFC 2104 HMAC-SHA256 of `message` using `shared_secret`.
    pub fn compute_hmac(shared_secret: &str, message: &str) -> String {
        let key = shared_secret.as_bytes();
        let mut key_block = [0u8; 64];
        if key.len() > 64 {
            let mut hasher = Sha256::new();
            hasher.update(key);
            let digest = hasher.finalize();
            key_block[..32].copy_from_slice(&digest);
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }

        let mut ipad = [0x36u8; 64];
        let mut opad = [0x5cu8; 64];
        for i in 0..64 {
            ipad[i] ^= key_block[i];
            opad[i] ^= key_block[i];
        }

        let mut inner = Sha256::new();
        inner.update(&ipad);
        inner.update(message.as_bytes());
        let inner_hash = inner.finalize();

        let mut outer = Sha256::new();
        outer.update(&opad);
        outer.update(&inner_hash);
        hex::encode(outer.finalize())
    }

    /// Verifies candidate HMAC in constant time against expected HMAC.
    pub fn verify_hmac(shared_secret: &str, message: &str, candidate: &str) -> bool {
        let expected = Self::compute_hmac(shared_secret, message);
        if expected.len() != candidate.len() {
            return false;
        }
        let mut diff = 0u8;
        for (a, b) in expected.as_bytes().iter().zip(candidate.as_bytes().iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }

    /// Backward-compatible alias for compute_hmac.
    pub fn compute_token(nonce: &str, shared_secret: &str) -> String {
        Self::compute_hmac(shared_secret, nonce)
    }

    /// Backward-compatible alias for verify_hmac.
    pub fn verify_token(nonce: &str, shared_secret: &str, candidate_token: &str) -> bool {
        Self::verify_hmac(shared_secret, nonce, candidate_token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ipc_roundtrip_message_exchange() {
        let tmp = tempfile::tempdir().unwrap();
        let sock_path = tmp.path().join("test_ipc.sock");

        let server = IpcServer::bind(&sock_path).unwrap();

        let client_task = tokio::spawn({
            let path = sock_path.clone();
            async move {
                let mut client = IpcClient::connect(&path, Duration::from_secs(5))
                    .await
                    .unwrap();

                client
                    .send(&WorkerMessage::Ready {
                        generation_id: "gen-001".to_string(),
                        pid: 12345,
                        auth_token: "auth-token-xyz".to_string(),
                    })
                    .await
                    .unwrap();

                let sup_msg: SupervisorMessage = client.recv().await.unwrap();
                assert_eq!(sup_msg, SupervisorMessage::Ping);

                client.send(&WorkerMessage::Pong).await.unwrap();
            }
        });

        let mut server_conn = server.accept().await.unwrap();
        let worker_msg: WorkerMessage = server_conn.recv().await.unwrap();
        match worker_msg {
            WorkerMessage::Ready {
                generation_id,
                pid,
                auth_token,
            } => {
                assert_eq!(generation_id, "gen-001");
                assert_eq!(pid, 12345);
                assert_eq!(auth_token, "auth-token-xyz");
            }
            _ => panic!("Expected Ready message"),
        }

        server_conn.send(&SupervisorMessage::Ping).await.unwrap();
        let pong: WorkerMessage = server_conn.recv().await.unwrap();
        assert_eq!(pong, WorkerMessage::Pong);

        client_task.await.unwrap();
    }

    #[test]
    fn test_session_auth_verification() {
        let nonce = "random-nonce-123";
        let secret = "tpm-bound-cluster-secret";
        let token = SessionAuth::compute_token(nonce, secret);

        assert!(SessionAuth::verify_token(nonce, secret, &token));
        assert!(!SessionAuth::verify_token(nonce, "wrong-secret", &token));
        assert!(!SessionAuth::verify_token("wrong-nonce", secret, &token));
    }
}
