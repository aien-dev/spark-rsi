use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

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
    pub canary_transactions: u64,
    pub staged_timestamp: String,
}

pub struct HostSupervisor {
    pub active_symlink: PathBuf,
    pub generations_root: PathBuf,
    pub memory_limit_mb: u64,
}

impl HostSupervisor {
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

        // Copy artifacts into immutable generation directory
        copy_dir_all(source_dir, &dest)?;

        Ok(GenerationInfo {
            generation_id: generation_id.to_string(),
            installed_path: dest,
            manifest_digest: manifest_digest.to_string(),
            state: GenerationState::Staged,
            pid: None,
            canary_transactions: 0,
            staged_timestamp: chrono::Utc::now().to_rfc3339(),
        })
    }

    pub fn atomic_symlink_swap(&self, generation_id: &str) -> Result<(), String> {
        let target_dir = self.generations_root.join(generation_id);
        if !target_dir.exists() {
            return Err(format!("Target generation directory does not exist: {:?}", target_dir));
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

        let page_size_kb = 4; // standard 4KB pages on Linux ARM64
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
}
