use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetrySnapshot {
    pub repo_path: String,
    pub git_branch: String,
    pub git_clean: bool,
    pub uncommitted_files: Vec<String>,
    pub crumbs_detected: usize,
    pub tests_passing: bool,
    pub soul_tension: SoulTension,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoulTension {
    pub drive_score: f64,
    pub humanity_score: f64,
    pub drive_terms_matched: Vec<String>,
    pub humanity_terms_matched: Vec<String>,
    pub tension_ratio: f64,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProposalKind {
    Refactor,
    Documentation,
    Optimization,
    UnslopSanitization,
    InvariantFix,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImprovementProposal {
    pub id: String,
    pub title: String,
    pub description: String,
    pub target_file: String,
    pub proposed_patch: String,
    pub kind: ProposalKind,
    pub created_at: String,
    pub sandbox_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantReport {
    pub passed: bool,
    pub unslop_clean: bool,
    pub em_dash_detected: usize,
    pub en_dash_detected: usize,
    pub forbidden_buzzwords_detected: Vec<String>,
    pub antithesis_tropes_detected: Vec<String>,
    pub zero_disk_secrets_clean: bool,
    pub secret_leaks: Vec<String>,
    pub compilation_passed: bool,
    pub compilation_error: Option<String>,
    pub tests_passed: bool,
    pub test_output_summary: Option<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceVerdict {
    pub kernel: String,
    pub mode: String,
    pub drive: f64,
    pub humanity: f64,
    pub ratio: f64,
    pub score: f64,
    pub verdict: String,
    pub guidance: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatificationRecord {
    pub proposal_id: String,
    pub commit_hash: Option<String>,
    pub author: String,
    pub cortex_receipt_id: Option<String>,
    pub cortex_recorded: bool,
    pub timestamp: String,
    pub status: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RsiConfig {
    pub target_repo: String,
    pub cortex_url: String,
    pub cortex_space: String,
    pub mojo_kernel_path: String,
    pub loop_interval_secs: u64,
    pub sandbox_root: String,
    #[serde(default = "default_rsi_root")]
    pub rsi_root: String,
    #[serde(default)]
    pub holdouts_dir: Option<String>,
    #[serde(default)]
    pub signing_key_hex: Option<String>,
    #[serde(default)]
    pub require_latency_improvement: bool,
    #[serde(default = "default_max_url")]
    pub max_url: String,
    #[serde(default = "default_max_model")]
    pub max_model: String,
    #[serde(default = "default_canary_target")]
    pub canary_target: u64,
}

fn default_max_url() -> String {
    "http://127.0.0.1:18006/v1".to_string()
}

fn default_max_model() -> String {
    "atlas-lightning-omni".to_string()
}

fn default_rsi_root() -> String {
    ".rsi".to_string()
}

fn default_canary_target() -> u64 {
    5000
}

impl Default for RsiConfig {
    fn default() -> Self {
        Self {
            target_repo: ".".to_string(),
            cortex_url: "http://127.0.0.1:18080".to_string(),
            cortex_space: "atlas-memory".to_string(),
            mojo_kernel_path: "mojo/balance_bin".to_string(),
            loop_interval_secs: 60,
            sandbox_root: "/tmp/spark-rsi-sandbox".to_string(),
            rsi_root: ".rsi".to_string(),
            holdouts_dir: None,
            signing_key_hex: None,
            require_latency_improvement: false,
            max_url: default_max_url(),
            max_model: default_max_model(),
            canary_target: 5000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RsiCycleResult {
    pub cycle_id: String,
    pub telemetry: TelemetrySnapshot,
    pub proposal: Option<ImprovementProposal>,
    pub invariants: Option<InvariantReport>,
    pub balance: Option<BalanceVerdict>,
    pub receipt: Option<crate::evaluator::EvaluationReceipt>,
    pub generation: Option<crate::supervisor::GenerationInfo>,
    pub ledger_block: Option<crate::ledger::LedgerBlock>,
    pub ratification: Option<RatificationRecord>,
    pub success: bool,
    pub elapsed_ms: f64,
}
