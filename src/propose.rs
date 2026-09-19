use crate::models::{ImprovementProposal, ProposalKind};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub struct ProposalGenerator;

impl ProposalGenerator {
    pub fn create_proposal(
        title: &str,
        description: &str,
        target_file: &str,
        proposed_patch: &str,
        kind: ProposalKind,
    ) -> ImprovementProposal {
        let id = format!("prop-{}", Uuid::new_v4().simple());
        ImprovementProposal {
            id,
            title: title.to_string(),
            description: description.to_string(),
            target_file: target_file.to_string(),
            proposed_patch: proposed_patch.to_string(),
            kind,
            created_at: chrono::Utc::now().to_rfc3339(),
            sandbox_path: None,
        }
    }

    /// Prepares an isolated sandbox worktree directory to evaluate the proposal safely.
    pub fn stage_in_sandbox(
        proposal: &mut ImprovementProposal,
        repo_root: &Path,
        sandbox_base: &Path,
    ) -> Result<PathBuf, String> {
        let sandbox_dir = sandbox_base.join(&proposal.id);
        if sandbox_dir.exists() {
            let _ = fs::remove_dir_all(&sandbox_dir);
        }
        fs::create_dir_all(&sandbox_dir)
            .map_err(|e| format!("Failed to create sandbox dir: {}", e))?;

        // Copy source files excluding target and .git
        copy_dir_recursive(repo_root, &sandbox_dir, 0)?;

        // Apply proposed patch to target file in sandbox
        let target_in_sandbox = sandbox_dir.join(&proposal.target_file);
        if let Some(parent) = target_in_sandbox.parent() {
            let _ = fs::create_dir_all(parent);
        }

        fs::write(&target_in_sandbox, &proposal.proposed_patch)
            .map_err(|e| format!("Failed to write proposed patch in sandbox: {}", e))?;

        proposal.sandbox_path = Some(sandbox_dir.display().to_string());
        Ok(sandbox_dir)
    }

    /// Automatically inspects a repository for unslop violations and proposes atomic sanitization.
    pub fn scan_and_propose_unslop(repo_root: &Path) -> Option<ImprovementProposal> {
        let candidate_files = ["README.md", "docs/PHILOSOPHY.md", "CONTRIBUTING.md"];
        for rel in &candidate_files {
            let full_path = repo_root.join(rel);
            if full_path.exists() {
                if let Ok(content) = fs::read_to_string(&full_path) {
                    if content.contains('\u{2014}') || content.contains('\u{2013}') {
                        let cleaned = content
                            .replace('\u{2014}', ", ")
                            .replace('\u{2013}', "-");
                        return Some(Self::create_proposal(
                            &format!("sanitize unslop punctuation in {}", rel),
                            "Remove em dashes and en dashes in accordance with unslop standard",
                            rel,
                            &cleaned,
                            ProposalKind::UnslopSanitization,
                        ));
                    }
                }
            }
        }
        None
    }
}

fn copy_dir_recursive(src: &Path, dst: &Path, depth: usize) -> Result<(), String> {
    if depth > 8 {
        return Ok(());
    }
    if !dst.exists() {
        fs::create_dir_all(dst).map_err(|e| format!("Failed to create dir {:?}: {}", dst, e))?;
    }
    let entries = fs::read_dir(src).map_err(|e| format!("Failed to read dir {:?}: {}", src, e))?;
    for entry in entries.flatten() {
        let path = entry.path();
        let file_name = entry.file_name();
        let name = file_name.to_str().unwrap_or_default();

        if name == "target" || name == ".git" || name.starts_with(".") {
            continue;
        }

        let target_path = dst.join(&file_name);
        if path.is_dir() {
            copy_dir_recursive(&path, &target_path, depth + 1)?;
        } else if path.is_file() {
            let _ = fs::copy(&path, &target_path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_proposal() {
        let prop = ProposalGenerator::create_proposal(
            "add verified test",
            "Improve verification test coverage",
            "tests/verify.rs",
            "// new test content",
            ProposalKind::Refactor,
        );
        assert!(prop.id.starts_with("prop-"));
        assert_eq!(prop.kind, ProposalKind::Refactor);
    }
}
