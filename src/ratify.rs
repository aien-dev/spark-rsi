use crate::config::SovereignConfig;
use crate::diff_gate;
use crate::models::{ImprovementProposal, InvariantReport, RatificationRecord};
use reqwest::Client;
use serde_json::json;
use std::fs;
use std::path::Path;
use uuid::Uuid;

pub struct Ratifier;

impl Ratifier {
    /// Turns an admitted proposal into a review branch plus a PR-ready patch.
    ///
    /// The ratifier never commits to the target's default branch and never
    /// touches its working tree or index. It builds the candidate commit with
    /// a temporary index, runs every protected-file check on the REAL git diff
    /// of that commit, and only if all checks pass creates `rsi/<proposal id>`
    /// (create-only) and writes `<patch_dir>/<proposal id>.patch`. A human
    /// opens and merges the pull request.
    #[allow(clippy::too_many_arguments)]
    pub async fn ratify_proposal(
        proposal: &ImprovementProposal,
        invariants: &InvariantReport,
        target_repo: &Path,
        ratify_roots: &[String],
        patch_dir: &Path,
        ledger_block_hash: Option<&str>,
        cortex_url: &str,
        cortex_space: &str,
    ) -> Result<RatificationRecord, String> {
        let now = chrono::Utc::now().to_rfc3339();
        let config = SovereignConfig::load();
        let author_str = config.author_string();

        let rejected = |message: String| RatificationRecord {
            proposal_id: proposal.id.clone(),
            commit_hash: None,
            branch: None,
            patch_path: None,
            author: author_str.clone(),
            cortex_receipt_id: None,
            cortex_recorded: false,
            timestamp: now.clone(),
            status: "Rejected".to_string(),
            message,
        };

        if !invariants.passed {
            return Ok(rejected(format!(
                "Invariant checks failed: {:?}",
                invariants.notes
            )));
        }

        // 1. Declared target: normalized, inside the declared roots, not protected.
        let target = match diff_gate::check_declared_target(&proposal.target_file, ratify_roots) {
            Ok(t) => t,
            Err(e) => return Ok(rejected(format!("Declared target refused: {}", e))),
        };
        let branch = match diff_gate::review_branch_name(&proposal.id) {
            Ok(b) => b,
            Err(e) => return Ok(rejected(e)),
        };

        // 2. Build the candidate commit off to the side. No branch moves.
        let commit_msg = format!("rsi: {} ({})", proposal.title, proposal.id);
        let staged = match diff_gate::stage_candidate_commit(
            target_repo,
            &target,
            proposal.proposed_patch.as_bytes(),
            &config.operator.name,
            &config.operator.email,
            &commit_msg,
        ) {
            Ok(s) => s,
            Err(e) => return Ok(rejected(format!("Candidate commit refused: {}", e))),
        };

        // 3. Protected-file checks on the REAL diff, not the declared name.
        let violations =
            diff_gate::check_real_diff(&staged.entries, &staged.patch_text, &target, ratify_roots);
        if !violations.is_empty() {
            return Ok(rejected(format!(
                "Real diff refused: {}",
                violations.join("; ")
            )));
        }

        // 4. Review branch (create-only, never a default branch) and patch file.
        if let Err(e) = diff_gate::create_review_branch(target_repo, &branch, &staged.commit) {
            return Ok(rejected(format!("Review branch refused: {}", e)));
        }
        let patch = diff_gate::format_patch(target_repo, &staged.commit)?;
        fs::create_dir_all(patch_dir)
            .map_err(|e| format!("Failed to create patch dir {:?}: {}", patch_dir, e))?;
        let patch_path = patch_dir.join(format!("{}.patch", proposal.id));
        fs::write(&patch_path, format!("{}\n", patch))
            .map_err(|e| format!("Failed to write patch {:?}: {}", patch_path, e))?;

        // 5. Record lesson in Cortex memory, tied to the review commit.
        let (cortex_receipt_id, cortex_recorded) = Self::record_cortex_lesson(
            proposal,
            Some(&staged.commit),
            ledger_block_hash,
            cortex_url,
            cortex_space,
        )
        .await;

        Ok(RatificationRecord {
            proposal_id: proposal.id.clone(),
            commit_hash: Some(staged.commit.clone()),
            branch: Some(branch.clone()),
            patch_path: Some(patch_path.display().to_string()),
            author: author_str.clone(),
            cortex_receipt_id,
            cortex_recorded,
            timestamp: now.clone(),
            status: "ProposedForReview".to_string(),
            message: format!(
                "Proposal '{}' is on review branch {} with patch {}. The default branch is unchanged; a human merges it.",
                proposal.title,
                branch,
                patch_path.display()
            ),
        })
    }

    pub async fn record_cortex_lesson(
        proposal: &ImprovementProposal,
        commit_hash: Option<&str>,
        ledger_block_hash: Option<&str>,
        cortex_url: &str,
        cortex_space: &str,
    ) -> (Option<String>, bool) {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/drakestapleton".to_string());
        let token_path = format!("{}/.config/cortex/token", home);
        let token = std::env::var("CORTEX_TOKEN")
            .unwrap_or_else(|_| fs::read_to_string(&token_path).unwrap_or_default())
            .trim()
            .to_string();

        let client = Client::new();
        let entity_id = format!("lesson-rsi-{}", Uuid::new_v4().simple());
        let canonical_name = format!("RSI Lesson: {}", proposal.title);
        let commit_info = commit_hash.unwrap_or("uncommitted");
        let ledger_info = ledger_block_hash.unwrap_or("unrecorded");
        let content = format!(
            "Proposal ID: {}. Target File: {}. Kind: {:?}. Commit: {}. Ledger Hash: {}. Description: {}",
            proposal.id, proposal.target_file, proposal.kind, commit_info, ledger_info, proposal.description
        );

        let payload = json!({
            "kind": "entity",
            "value": {
                "canonicalName": canonical_name,
                "content": content,
                "confidence": 1.0,
                "metadata": {
                    "proposal_id": proposal.id,
                    "target_file": proposal.target_file,
                    "kind": format!("{:?}", proposal.kind),
                    "commit": commit_info,
                    "ledger_block_hash": ledger_info
                }
            }
        });

        let url = format!(
            "{}/api/cortex/write?space={}",
            cortex_url.trim_end_matches('/'),
            cortex_space
        );
        let mut req = client.post(&url).json(&payload);
        if !token.is_empty() {
            req = req.header("Authorization", format!("Bearer {}", token));
        }

        match req.send().await {
            Ok(resp) if resp.status().is_success() => {
                let body: serde_json::Value = resp.json().await.unwrap_or(json!({}));
                let receipt_id = body
                    .get("receipt")
                    .and_then(|r| r.get("id"))
                    .and_then(|id| id.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or(entity_id);
                (Some(receipt_id), true)
            }
            _ => (None, false),
        }
    }
}
