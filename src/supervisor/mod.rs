pub mod canary_exec;
pub mod daemon;

pub mod ipc;

use crate::evaluator::metrics::system_page_size_kb;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GenerationState {
    Staged,
    Starting,
    Ready,
    CanaryActive,
    Durable,
    Reverting,
    Reverted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerationInfo {
    pub generation_id: String,
    pub installed_path: PathBuf,
    pub manifest_digest: String,
    pub state: GenerationState,
    pub pid: Option<u32>,
    pub socket_path: Option<PathBuf>,
    pub canary_transactions: u64,
    pub canary_errors: u64,
    pub max_latency_us: u64,
    pub total_latency_us: u64,
    pub staged_timestamp: String,
}

pub struct HostSupervisor {
    pub active_symlink: PathBuf,
    pub generations_root: PathBuf,
    pub memory_limit_mb: u64,
}

impl HostSupervisor {
    pub const DEFAULT_CANARY_QUOTA: u64 = 5_000;

    pub fn new(rsi_root: &Path, memory_limit_mb: u64) -> Self {
        Self {
            active_symlink: rsi_root.join("active"),
            generations_root: rsi_root.join("generations"),
            memory_limit_mb,
        }
    }

    pub fn stage_generation(
        &self,
        generation_id: &str,
        source_dir: &Path,
        manifest_digest: &str,
    ) -> Result<GenerationInfo, String> {
        let dest = self.generations_root.join(generation_id);
        if dest.exists() {
            fs::remove_dir_all(&dest).map_err(|e| e.to_string())?;
        }
        fs::create_dir_all(&dest).map_err(|e| e.to_string())?;

        copy_dir_all(source_dir, &dest)?;

        Ok(GenerationInfo {
            generation_id: generation_id.to_string(),
            installed_path: dest,
            manifest_digest: manifest_digest.to_string(),
            state: GenerationState::Staged,
            pid: None,
            socket_path: None,
            canary_transactions: 0,
            canary_errors: 0,
            max_latency_us: 0,
            total_latency_us: 0,
            staged_timestamp: chrono::Utc::now().to_rfc3339(),
        })
    }

    pub fn atomic_symlink_swap(&self, generation_id: &str) -> Result<(), String> {
        let target_dir = self.generations_root.join(generation_id);
        if !target_dir.exists() {
            return Err(format!(
                "Target generation directory does not exist: {:?}",
                target_dir
            ));
        }

        let parent = self
            .active_symlink
            .parent()
            .ok_or_else(|| "No parent dir for active symlink".to_string())?;
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;

        let tmp_link = parent.join(format!(".active.tmp.{}", uuid::Uuid::new_v4().simple()));
        if tmp_link.exists() {
            let _ = fs::remove_file(&tmp_link);
        }

        #[cfg(unix)]
        std::os::unix::fs::symlink(&target_dir, &tmp_link)
            .map_err(|e| format!("Failed to create temporary symlink: {}", e))?;

        fs::rename(&tmp_link, &self.active_symlink)
            .map_err(|e| format!("Failed atomic symlink swap: {}", e))?;

        Ok(())
    }

    /// Launches the worker and returns its pid. The child handle is dropped, so the caller
    /// cannot stop it; the canary executor uses [`Self::spawn_worker_process`] instead.
    pub fn spawn_worker(
        &self,
        gen_info: &mut GenerationInfo,
        executable: &Path,
        args: &[&str],
        socket_path: &Path,
    ) -> Result<u32, String> {
        self.spawn_worker_process(gen_info, executable, args, socket_path, &[])
            .map(|child| child.id())
    }

    /// Launches the worker with `--socket <socket_path>` appended to `args` and `env` added to
    /// its environment, and returns the child handle so the supervisor can stop and reap it.
    /// Readiness is not decided here: a spawned process is `Starting` until it completes the
    /// authenticated versioned handshake (`daemon::authenticate_worker_connection`).
    pub fn spawn_worker_process(
        &self,
        gen_info: &mut GenerationInfo,
        executable: &Path,
        args: &[&str],
        socket_path: &Path,
        env: &[(&str, &str)],
    ) -> Result<std::process::Child, String> {
        let mut cmd = Command::new(executable);
        cmd.args(args).arg("--socket").arg(socket_path);
        cmd.stdin(std::process::Stdio::null());
        for (key, value) in env {
            cmd.env(key, value);
        }

        let child = cmd
            .spawn()
            .map_err(|e| format!("Failed to spawn worker executable {:?}: {}", executable, e))?;

        gen_info.pid = Some(child.id());
        gen_info.socket_path = Some(socket_path.to_path_buf());
        gen_info.state = GenerationState::Starting;

        Ok(child)
    }

    pub fn switch_active_socket(
        &self,
        active_socket_link: &Path,
        target_socket: &Path,
    ) -> Result<(), String> {
        let parent = active_socket_link
            .parent()
            .ok_or_else(|| "No parent directory for active socket link".to_string())?;
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;

        let tmp_link = parent.join(format!(
            ".active_sock.tmp.{}",
            uuid::Uuid::new_v4().simple()
        ));
        if tmp_link.exists() {
            let _ = fs::remove_file(&tmp_link);
        }

        #[cfg(unix)]
        std::os::unix::fs::symlink(target_socket, &tmp_link)
            .map_err(|e| format!("Failed to create temporary socket symlink: {}", e))?;

        fs::rename(&tmp_link, active_socket_link)
            .map_err(|e| format!("Failed atomic socket swap: {}", e))?;

        Ok(())
    }

    pub fn drain_parent(&self, parent_pid: u32, timeout: Duration) -> Result<(), String> {
        #[cfg(unix)]
        unsafe {
            // Signal graceful drain via SIGQUIT
            libc::kill(parent_pid as i32, libc::SIGQUIT);
        }

        let start = Instant::now();
        let poll_interval = Duration::from_millis(50);

        while start.elapsed() < timeout {
            #[cfg(unix)]
            unsafe {
                if libc::kill(parent_pid as i32, 0) != 0 {
                    return Ok(()); // Process exited cleanly
                }
            }
            std::thread::sleep(poll_interval);
        }

        // Force kill if graceful drain exceeded timeout window
        #[cfg(unix)]
        unsafe {
            libc::kill(parent_pid as i32, libc::SIGKILL);
        }

        Ok(())
    }

    /// Applies the early safety budgets to one worker self-report. The counters it keeps are
    /// diagnostics: this function never returns `Durable`, however many reports arrive.
    /// Whether a canary has enough evidence is decided only by the quota validator over a
    /// sealed observation log.
    pub fn record_canary_transaction(
        &self,
        gen_info: &mut GenerationInfo,
        success: bool,
        latency_us: u64,
        max_latency_us: u64,
        max_error_rate: f64,
    ) -> Result<GenerationState, String> {
        gen_info.canary_transactions += 1;
        if !success {
            gen_info.canary_errors += 1;
        }
        if latency_us > gen_info.max_latency_us {
            gen_info.max_latency_us = latency_us;
        }
        gen_info.total_latency_us += latency_us;

        // 1. Latency budget check
        if max_latency_us > 0 && latency_us > max_latency_us {
            gen_info.state = GenerationState::Reverting;
            return Err(format!(
                "Latency budget exceeded: {} us > {} us limit (transaction {})",
                latency_us, max_latency_us, gen_info.canary_transactions
            ));
        }

        // 2. Error budget check
        let error_rate = gen_info.canary_errors as f64 / gen_info.canary_transactions as f64;
        if error_rate > max_error_rate {
            gen_info.state = GenerationState::Reverting;
            return Err(format!(
                "Error budget exceeded: {:.2}% errors ({}/{}) > {:.2}% limit",
                error_rate * 100.0,
                gen_info.canary_errors,
                gen_info.canary_transactions,
                max_error_rate * 100.0
            ));
        }

        // 3. Resource budget check
        // A failed read is not proof that memory is within budget: it reverts.
        if let Some(pid) = gen_info.pid {
            match self.is_memory_within_budget(pid) {
                Ok(true) => {}
                Ok(false) => {
                    gen_info.state = GenerationState::Reverting;
                    return Err(format!(
                        "Resource budget exceeded: PID {} exceeded {} MB limit",
                        pid, self.memory_limit_mb
                    ));
                }
                Err(read_err) => {
                    gen_info.state = GenerationState::Reverting;
                    return Err(format!(
                        "Resource budget unreadable for PID {}, reverting: {}",
                        pid, read_err
                    ));
                }
            }
        }

        gen_info.state = GenerationState::CanaryActive;
        Ok(gen_info.state)
    }

    pub fn rollback_to_parent(
        &self,
        parent_generation_id: &str,
        active_socket_link: Option<&Path>,
        parent_socket: Option<&Path>,
    ) -> Result<(), String> {
        self.atomic_symlink_swap(parent_generation_id)?;

        if let (Some(active_sock), Some(parent_sock)) = (active_socket_link, parent_socket) {
            self.switch_active_socket(active_sock, parent_sock)?;
        }

        Ok(())
    }

    pub fn check_unified_memory_mb(pid: u32) -> Result<u64, String> {
        let statm_path = format!("/proc/{}/statm", pid);
        let content = fs::read_to_string(&statm_path)
            .map_err(|e| format!("Failed to read statm for pid {}: {}", pid, e))?;

        let parts: Vec<&str> = content.split_whitespace().collect();
        if parts.len() < 2 {
            return Err("Malformed statm output".to_string());
        }

        let resident_pages: u64 = parts[1]
            .parse()
            .map_err(|e| format!("Failed to parse resident pages: {}", e))?;

        let page_size_kb = system_page_size_kb();
        let rss_mb = (resident_pages * page_size_kb) / 1024;
        Ok(rss_mb)
    }

    pub fn is_memory_within_budget(&self, pid: u32) -> Result<bool, String> {
        let current_mb = Self::check_unified_memory_mb(pid)?;
        Ok(current_mb <= self.memory_limit_mb)
    }
}

fn copy_dir_all(src: &Path, dst: &Path) -> Result<(), String> {
    if !dst.exists() {
        fs::create_dir_all(dst).map_err(|e| e.to_string())?;
    }
    for entry in fs::read_dir(src).map_err(|e| e.to_string())?.flatten() {
        let path = entry.path();
        let dest = dst.join(entry.file_name());
        if path.is_dir() {
            copy_dir_all(&path, &dest)?;
        } else {
            fs::copy(&path, &dest).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stage_and_atomic_symlink_swap() {
        let tmp = tempfile::tempdir().unwrap();
        let rsi_root = tmp.path().join(".rsi");
        let src = tmp.path().join("src_art");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("bin"), "generation binary v1").unwrap();

        let supervisor = HostSupervisor::new(&rsi_root, 49152);
        let gen_info = supervisor
            .stage_generation("gen-001", &src, "manifest-sha-001")
            .unwrap();

        assert_eq!(gen_info.state, GenerationState::Staged);
        assert!(gen_info.installed_path.exists());

        supervisor.atomic_symlink_swap("gen-001").unwrap();
        assert!(supervisor.active_symlink.exists());

        let content = fs::read_to_string(supervisor.active_symlink.join("bin")).unwrap();
        assert_eq!(content, "generation binary v1");

        // Stage and swap to gen-002
        let src2 = tmp.path().join("src_art2");
        fs::create_dir_all(&src2).unwrap();
        fs::write(src2.join("bin"), "generation binary v2").unwrap();

        supervisor
            .stage_generation("gen-002", &src2, "manifest-sha-002")
            .unwrap();
        supervisor.atomic_symlink_swap("gen-002").unwrap();

        let content2 = fs::read_to_string(supervisor.active_symlink.join("bin")).unwrap();
        assert_eq!(content2, "generation binary v2");

        // Rollback swap to gen-001
        supervisor.atomic_symlink_swap("gen-001").unwrap();
        let content_rollback = fs::read_to_string(supervisor.active_symlink.join("bin")).unwrap();
        assert_eq!(content_rollback, "generation binary v1");
    }

    #[test]
    fn test_memory_budget_check_own_pid() {
        let pid = std::process::id();
        let tmp = tempfile::tempdir().unwrap();
        let supervisor = HostSupervisor::new(tmp.path(), 49152);

        let within_budget = supervisor.is_memory_within_budget(pid).unwrap();
        assert!(within_budget);
    }

    #[test]
    fn test_socket_switch_and_self_reports_never_promote() {
        let tmp = tempfile::tempdir().unwrap();
        let rsi_root = tmp.path().join(".rsi");
        let supervisor = HostSupervisor::new(&rsi_root, 49152);

        let active_sock = tmp.path().join("active.sock");
        let target_sock = tmp.path().join("gen2.sock");
        fs::write(&target_sock, "socket stub").unwrap();

        supervisor
            .switch_active_socket(&active_sock, &target_sock)
            .unwrap();
        assert!(active_sock.exists());

        let src = tmp.path().join("src_art");
        fs::create_dir_all(&src).unwrap();
        let mut gen = supervisor
            .stage_generation("gen-canary", &src, "digest")
            .unwrap();
        gen.state = GenerationState::Ready;

        // Any number of clean self-reports leaves the generation on probation. Counters never
        // promote: only a sealed observation log through the quota validator can.
        for _ in 0..50 {
            let state = supervisor
                .record_canary_transaction(&mut gen, true, 1000, 1_000_000, 0.0)
                .unwrap();
            assert_eq!(state, GenerationState::CanaryActive);
        }
        assert_eq!(gen.state, GenerationState::CanaryActive);
        assert_eq!(gen.canary_transactions, 50);

        // Failure during canary triggers Reverting
        assert!(supervisor
            .record_canary_transaction(&mut gen, false, 1000, 1_000_000, 0.0)
            .is_err());
        assert_eq!(gen.state, GenerationState::Reverting);
    }

    #[test]
    fn test_unreadable_memory_budget_reverts_instead_of_passing() {
        let tmp = tempfile::tempdir().unwrap();
        let supervisor = HostSupervisor::new(&tmp.path().join(".rsi"), 49152);
        let src = tmp.path().join("src_art");
        fs::create_dir_all(&src).unwrap();
        let mut gen = supervisor
            .stage_generation("gen-canary", &src, "digest")
            .unwrap();
        // No process has this pid, so the resource read fails.
        gen.pid = Some(u32::MAX - 1);
        let err = supervisor
            .record_canary_transaction(&mut gen, true, 1000, 1_000_000, 0.0)
            .unwrap_err();
        assert!(err.contains("unreadable"), "{}", err);
        assert_eq!(gen.state, GenerationState::Reverting);
    }

    #[test]
    fn test_memory_over_limit_reverts() {
        let tmp = tempfile::tempdir().unwrap();
        // A one MB limit is below any live process.
        let supervisor = HostSupervisor::new(&tmp.path().join(".rsi"), 1);
        let src = tmp.path().join("src_art");
        fs::create_dir_all(&src).unwrap();
        let mut gen = supervisor
            .stage_generation("gen-canary", &src, "digest")
            .unwrap();
        gen.pid = Some(std::process::id());
        let err = supervisor
            .record_canary_transaction(&mut gen, true, 1000, 1_000_000, 0.0)
            .unwrap_err();
        assert!(err.contains("Resource budget exceeded"), "{}", err);
        assert_eq!(gen.state, GenerationState::Reverting);
    }
}
