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
        cortex_url: &str,
        cortex_space: &str,
    ) -> Result<RatificationRecord, String> {
        let now = chrono::Utc::now().to_rfc3339();

        if !invariants.passed {
            return Ok(RatificationRecord {
                proposal_id: proposal.id.clone(),
                commit_hash: None,
                author: "AIEN <aien.atlas@proton.me>".to_string(),
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

        // 2. Commit to git
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
                "user.name=AIEN",
                "-c",
                "user.email=aien.atlas@proton.me",
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
        let (cortex_receipt_id, cortex_recorded) =
            Self::record_cortex_lesson(proposal, commit_hash.as_deref(), cortex_url, cortex_space).await;

        Ok(RatificationRecord {
            proposal_id: proposal.id.clone(),
            commit_hash,
            author: "AIEN <aien.atlas@proton.me>".to_string(),
            cortex_receipt_id,
            cortex_recorded,
            timestamp: now,
            status: "Ratified".to_string(),
            message: format!("Proposal '{}' ratified and committed to git.", proposal.title),
        })
    }

    async fn record_cortex_lesson(
        proposal: &ImprovementProposal,
        commit_hash: Option<&str>,
        cortex_url: &str,
        cortex_space: &str,
    ) -> (Option<String>, bool) {
        let token_path = "/home/drakestapleton/.config/cortex/token";
        let token = fs::read_to_string(token_path)
            .unwrap_or_default()
            .trim()
            .to_string();

        let client = Client::new();
        let entity_id = format!("lesson-rsi-{}", Uuid::new_v4().simple());
        let canonical_name = format!("RSI Lesson: {}", proposal.title);
        let commit_info = commit_hash.unwrap_or("uncommitted");
        let content = format!(
            "Proposal ID: {}. Target File: {}. Kind: {:?}. Commit: {}. Description: {}",
            proposal.id, proposal.target_file, proposal.kind, commit_info, proposal.description
        );

        let body = json!({
            "entity": {
                "id": entity_id,
                "spaceId": cortex_space,
                "spaceSlug": cortex_space,
                "entityType": "lesson",
                "canonicalName": canonical_name,
                "content": content,
                "aliases": [format!("rsi-prop-{}", proposal.id)],
                "metadata": {
                    "proposal_id": proposal.id,
                    "target_file": proposal.target_file,
                    "engine": "spark-rsi",
                    "harness": "native-rust-mojo"
                },
                "confidence": 1.0,
                "revision": 1,
                "retracted": false,
                "createdAt": chrono::Utc::now().to_rfc3339()
            }
        });

        let mut req = client.post(format!("{}/api/cortex/write", cortex_url));
        if !token.is_empty() {
            req = req.header("Authorization", format!("Bearer {}", token));
        }

        match req.json(&body).send().await {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(json_resp) = resp.json::<serde_json::Value>().await {
                    let receipt_id = json_resp
                        .get("receipt")
                        .and_then(|r| r.get("id"))
                        .and_then(|id| id.as_str())
                        .map(|s| s.to_string());
                    (receipt_id, true)
                } else {
                    (None, true)
                }
            }
            _ => (None, false),
        }
    }
}
