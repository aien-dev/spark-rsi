use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct RollbackCheckpoint {
    pub repo_root: PathBuf,
    pub cycle_id: String,
    pub base_commit_sha: String,
    pub worktree_dir: PathBuf,
    pub branch_name: String,
    pub ref_name: String,
}

impl RollbackCheckpoint {
    pub fn create(repo_root: &Path, cycle_id: &str) -> Result<Self, String> {
        let head_out = Command::new("git")
            .arg("-C")
            .arg(repo_root)
            .args(["rev-parse", "HEAD"])
            .output()
            .map_err(|e| format!("Failed to resolve HEAD in {:?}: {}", repo_root, e))?;

        if !head_out.status.success() {
            return Err(format!(
                "git rev-parse HEAD failed: {}",
                String::from_utf8_lossy(&head_out.stderr)
            ));
        }

        let base_commit_sha = String::from_utf8_lossy(&head_out.stdout).trim().to_string();
        let worktree_dir = PathBuf::from(format!("/tmp/spark-rsi-worktree-{}", cycle_id));
        let branch_name = format!("rsi/candidate-{}", cycle_id);
        let ref_name = format!("refs/rsi/checkpoints/{}", cycle_id);

        if worktree_dir.exists() {
            let _ = Command::new("git")
                .arg("-C")
                .arg(repo_root)
                .args(["worktree", "remove", "--force", worktree_dir.to_str().unwrap()])
                .output();
            let _ = std::fs::remove_dir_all(&worktree_dir);
        }

        let wt_out = Command::new("git")
            .arg("-C")
            .arg(repo_root)
            .args([
                "worktree",
                "add",
                "-b",
                &branch_name,
                worktree_dir.to_str().unwrap(),
                "HEAD",
            ])
            .output()
            .map_err(|e| format!("Failed to spawn git worktree add: {}", e))?;

        if !wt_out.status.success() {
            return Err(format!(
                "Failed to create git worktree: {}",
                String::from_utf8_lossy(&wt_out.stderr)
            ));
        }

        let _ = Command::new("git")
            .arg("-C")
            .arg(repo_root)
            .args(["update-ref", &ref_name, &base_commit_sha])
            .output();

        Ok(Self {
            repo_root: repo_root.to_path_buf(),
            cycle_id: cycle_id.to_string(),
            base_commit_sha,
            worktree_dir,
            branch_name,
            ref_name,
        })
    }

    pub fn teardown(&self) -> Result<(), String> {
        let _ = Command::new("git")
            .arg("-C")
            .arg(&self.repo_root)
            .args(["worktree", "remove", "--force", self.worktree_dir.to_str().unwrap()])
            .output();

        let _ = Command::new("git")
            .arg("-C")
            .arg(&self.repo_root)
            .args(["branch", "-D", &self.branch_name])
            .output();

        if self.worktree_dir.exists() {
            let _ = std::fs::remove_dir_all(&self.worktree_dir);
        }

        Ok(())
    }
}
