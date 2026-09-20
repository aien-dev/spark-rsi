use crate::config::SovereignConfig;
use crate::models::{ImprovementProposal, InvariantReport, RatificationRecord};
use reqwest::Client;
use serde_json::json;
use std::fs;
use std::path::Path;
use std::process::Command;
use uuid::Uuid;

pub struct Ratifier;

impl Ratifier {
    pub async fn ratify_proposal(
        proposal: &ImprovementProposal,
        invariants: &InvariantReport,
        target_repo: &Path,
        ledger_block_hash: Option<&str>,
        cortex_url: &str,
        cortex_space: &str,
    ) -> Result<RatificationRecord, String> {
        let now = chrono::Utc::now().to_rfc3339();
        let config = SovereignConfig::load();
        let author_str = config.author_string();

        if !invariants.passed {
            return Ok(RatificationRecord {
                proposal_id: proposal.id.clone(),
                commit_hash: None,
                author: author_str,
                cortex_receipt_id: None,
                cortex_recorded: false,
                timestamp: now,
                status: "Rejected".to_string(),
                message: format!("Invariant checks failed: {:?}", invariants.notes),
            });
        }

        // 1. Apply patch to target file in repository
        let target_file_path = target_repo.join(&proposal.target_file);
        if let Some(parent) = target_file_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        fs::write(&target_file_path, &proposal.proposed_patch)
            .map_err(|e| format!("Failed to apply patch to {:?}: {}", target_file_path, e))?;

        // 2. Commit to git using dynamic operator profile
        let commit_msg = format!("rsi: {} ({})", proposal.title, proposal.id);
        let _ = Command::new("git")
            .arg("-C")
            .arg(target_repo)
            .args(["add", &proposal.target_file])
            .output();

        let commit_out = Command::new("git")
            .arg("-C")
            .arg(target_repo)
            .args([
                "-c",
                &format!("user.name={}", config.operator.name),
                "-c",
                &format!("user.email={}", config.operator.email),
                "commit",
                "-m",
                &commit_msg,
            ])
            .output();

        let commit_hash = match commit_out {
            Ok(out) if out.status.success() => {
                let rev = Command::new("git")
                    .arg("-C")
                    .arg(target_repo)
                    .args(["rev-parse", "--short", "HEAD"])
                    .output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .ok();
                rev
            }
            _ => None,
        };

        // 3. Record lesson in Cortex memory
        let (cortex_receipt_id, cortex_recorded) = Self::record_cortex_lesson(
            proposal,
            commit_hash.as_deref(),
            ledger_block_hash,
            cortex_url,
            cortex_space,
        )
        .await;

        Ok(RatificationRecord {
            proposal_id: proposal.id.clone(),
            commit_hash,
            author: author_str,
            cortex_receipt_id,
            cortex_recorded,
            timestamp: now,
            status: "Ratified".to_string(),
            message: format!(
                "Proposal '{}' ratified and committed to git.",
                proposal.title
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
