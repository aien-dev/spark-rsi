use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ThermalSnapshot {
    pub timestamp: String,
    pub gpu_temp_c: Option<f32>,
    pub power_draw_w: Option<f32>,
    pub gpu_util_pct: Option<f32>,
    pub graphics_clock_mhz: Option<u32>,
    pub memory_clock_mhz: Option<u32>,
}

impl ThermalSnapshot {
    pub fn capture() -> Option<Self> {
        let output = Command::new("nvidia-smi")
            .args([
                "--query-gpu=temperature.gpu,power.draw,utilization.gpu,clocks.current.graphics,clocks.current.memory",
                "--format=csv,noheader,nounits",
            ])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let raw = String::from_utf8_lossy(&output.stdout);
        let first_line = raw.lines().next()?;
        let parts: Vec<&str> = first_line.split(',').map(|s| s.trim()).collect();
        if parts.len() < 5 {
            return None;
        }

        Some(Self {
            timestamp: Utc::now().to_rfc3339(),
            gpu_temp_c: parts[0].parse::<f32>().ok(),
            power_draw_w: parts[1].parse::<f32>().ok(),
            gpu_util_pct: parts[2].parse::<f32>().ok(),
            graphics_clock_mhz: parts[3].parse::<u32>().ok(),
            memory_clock_mhz: parts[4].parse::<u32>().ok(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EngineNSnapshot {
    pub commit_sha: String,
    pub evaluator_version: String,
    pub holdout_bundle_digest: String,
    pub builder_digest: String,
    pub max_model: String,
    pub cortex_snapshot_ref: String,
    pub operator_verifying_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HypothesisQuarantineTracker {
    pub failure_counts: HashMap<String, usize>,
    pub exhausted_pairings: HashSet<String>,
}

impl HypothesisQuarantineTracker {
    pub fn new() -> Self {
        Self {
            failure_counts: HashMap::new(),
            exhausted_pairings: HashSet::new(),
        }
    }

    fn pairing_key(node_name: &str, problem_summary: &str) -> String {
        let mut hasher = sha2::Sha256::new();
        hasher.update(problem_summary.as_bytes());
        let digest = hasher.finalize();
        format!("{}:{}", node_name, &hex::encode(digest)[..12])
    }

    pub fn is_exhausted(&self, node_name: &str, problem_summary: &str) -> bool {
        let key = Self::pairing_key(node_name, problem_summary);
        self.exhausted_pairings.contains(&key)
    }

    pub fn record_failure(&mut self, node_name: &str, problem_summary: &str, _reason: &str) -> bool {
        let key = Self::pairing_key(node_name, problem_summary);
        let count = self.failure_counts.entry(key.clone()).or_insert(0);
        *count += 1;
        if *count >= 3 {
            self.exhausted_pairings.insert(key);
            true
        } else {
            false
        }
    }

    pub fn record_success(&mut self, node_name: &str, problem_summary: &str) {
        let key = Self::pairing_key(node_name, problem_summary);
        self.failure_counts.remove(&key);
        self.exhausted_pairings.remove(&key);
    }

    pub fn exhausted_list(&self) -> Vec<String> {
        let mut list: Vec<String> = self.exhausted_pairings.iter().cloned().collect();
        list.sort();
        list
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CycleCandidateRecord {
    pub candidate_id: String,
    pub candidate_index: usize,
    pub target_file: String,
    pub proposed_patch_digest: String,
    pub compilation_passed: bool,
    pub invariants_passed: bool,
    pub judge_admitted: bool,
    pub primary_metric_name: String,
    pub primary_metric_value: f64,
    pub rejection_reason: Option<String>,
    pub ledger_block_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CycleRecord {
    pub cycle_index: usize,
    pub cycle_id: String,
    pub bottleneck_node: String,
    pub hypothesis_id: String,
    pub hypothesis_problem: String,
    pub candidates: Vec<CycleCandidateRecord>,
    pub winning_candidate_id: Option<String>,
    pub merkle_checkpoint_hash: Option<String>,
    pub thermal_before: Option<ThermalSnapshot>,
    pub thermal_after: Option<ThermalSnapshot>,
    pub cortex_receipt_id: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AdmittedMetaCandidate {
    pub candidate_id: String,
    pub ledger_block_hash: String,
    pub staging_dir: String,
    pub patch_digest: String,
    pub criteria_1_novel_discovery: bool,
    pub criteria_2_self_capability_gain: bool,
    pub classification: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SoakRunManifest {
    pub manifest_version: String,
    pub run_id: String,
    pub started_at: String,
    pub completed_at: String,
    pub engine_n_snapshot: EngineNSnapshot,
    pub cycles: Vec<CycleRecord>,
    pub admitted_candidates: Vec<AdmittedMetaCandidate>,
    pub exhausted_hypotheses: Vec<String>,
    pub final_merkle_checkpoint: Option<String>,
    pub total_candidates_evaluated: usize,
    pub total_candidates_admitted: usize,
    pub preflight_passed: bool,
    pub overall_status: String,
}

impl SoakRunManifest {
    pub fn save_to_file(&self, path: &Path) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize manifest: {}", e))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create manifest directory: {}", e))?;
        }
        std::fs::write(path, json)
            .map_err(|e| format!("Failed to write manifest to {:?}: {}", path, e))
    }
}
