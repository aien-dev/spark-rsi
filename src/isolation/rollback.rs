use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct RollbackCheckpoint {
    pub repo_root: PathBuf,
    pub cycle_id: String,
    pub base_commit_sha: String,
    pub worktree_dir: PathBuf,
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
        let ref_name = format!("refs/rsi/checkpoints/{}", cycle_id);

        if worktree_dir.exists() {
            let _ = Command::new("git")
                .arg("-C")
                .arg(repo_root)
                .args([
                    "worktree",
                    "remove",
                    "--force",
                    worktree_dir.to_str().unwrap(),
                ])
                .output();
            let _ = std::fs::remove_dir_all(&worktree_dir);
        }

        // Use detached HEAD to avoid branch namespace pollution
        let wt_out = Command::new("git")
            .arg("-C")
            .arg(repo_root)
            .args([
                "worktree",
                "add",
                "--detach",
                worktree_dir.to_str().unwrap(),
                &base_commit_sha,
            ])
            .output()
            .map_err(|e| format!("Failed to spawn git worktree add: {}", e))?;

        if !wt_out.status.success() {
            return Err(format!(
                "Failed to create detached git worktree: {}",
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
            ref_name,
        })
    }

    pub fn teardown(&self) -> Result<(), String> {
        let _ = Command::new("git")
            .arg("-C")
            .arg(&self.repo_root)
            .args([
                "worktree",
                "remove",
                "--force",
                self.worktree_dir.to_str().unwrap(),
            ])
            .output();

        let _ = Command::new("git")
            .arg("-C")
            .arg(&self.repo_root)
            .args(["update-ref", "-d", &self.ref_name])
            .output();

        if self.worktree_dir.exists() {
            let _ = std::fs::remove_dir_all(&self.worktree_dir);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rollback_checkpoint_lifecycle() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_path = tmp.path();

        // Initialize mock git repo
        Command::new("git")
            .arg("init")
            .current_dir(repo_path)
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(repo_path)
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.email", "test@test.local"])
            .current_dir(repo_path)
            .output()
            .unwrap();

        std::fs::write(repo_path.join("test.txt"), "genesis").unwrap();
        Command::new("git")
            .args(["add", "."])
            .current_dir(repo_path)
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "initial"])
            .current_dir(repo_path)
            .output()
            .unwrap();

        let cycle_id = format!("test-{}", uuid::Uuid::new_v4().simple());
        let cp = RollbackCheckpoint::create(repo_path, &cycle_id).unwrap();

        assert!(cp.worktree_dir.exists());
        assert_eq!(cp.cycle_id, cycle_id);
        assert!(!cp.base_commit_sha.is_empty());

        // Verify git branch list does NOT contain any rsi/candidate branch
        let branches = Command::new("git")
            .arg("-C")
            .arg(repo_path)
            .arg("branch")
            .output()
            .unwrap();
        let branch_str = String::from_utf8_lossy(&branches.stdout);
        assert!(
            !branch_str.contains("rsi/candidate"),
            "Detached worktree should not create a named branch: {}",
            branch_str
        );

        // Teardown
        cp.teardown().unwrap();
        assert!(!cp.worktree_dir.exists());
    }
}
