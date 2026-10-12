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
    MetaEngineImprovement,
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
    #[serde(default)]
    pub operator_signature: Option<String>,
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
    /// Review branch holding the candidate commit. Never the default branch.
    #[serde(default)]
    pub branch: Option<String>,
    /// PR-ready patch (git format-patch) of the candidate commit.
    #[serde(default)]
    pub patch_path: Option<String>,
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
    #[serde(default)]
    pub operator_key_hex: Option<String>,
    #[serde(default)]
    pub non_inferiority_margin: Option<f64>,
    /// Repository-relative roots a proposal may change. Anything else is refused.
    #[serde(default = "crate::diff_gate::default_ratify_roots")]
    pub ratify_roots: Vec<String>,
    /// Directory holding a DUAL price vector (`price_vector.bin`, `*.constraint.bin`,
    /// optional `price_vector.sha256`). Read as a diagnostic signal only (ADR 0031
    /// section 7.5); it grants no authority and changes no gate. None = not configured.
    #[serde(default)]
    pub dual_price_vector_dir: Option<String>,
    /// SEC1 hex public key of the separate judge. Promotion requires a version 2 receipt signed
    /// by this key; it must differ from the daemon's own key. None = promotion fails closed.
    #[serde(default)]
    pub judge_public_key_hex: Option<String>,
    /// Operator-owned evaluation policy the judge receipt must be bound to. None = fails closed.
    #[serde(default)]
    pub judge_policy_file: Option<String>,
    /// Minimum compatible completed samples a stage needs before its latency counts as measured.
    #[serde(default = "default_measure_min_samples")]
    pub measure_min_samples: usize,
    /// How many of the most recent compatible completed cycles are considered per stage.
    #[serde(default = "default_measure_window_cycles")]
    pub measure_window_cycles: usize,
    /// Minimum valid compatible samples before an empirical p95 is reported.
    #[serde(default = "default_measure_p95_min_samples")]
    pub measure_p95_min_samples: usize,
    /// Operator-declared latency goal, in percent below the measured median. A goal, not a forecast.
    #[serde(default = "default_measure_target_improvement_pct")]
    pub measure_target_improvement_pct: f64,
    /// Where the operator's canary workload lives. None = `<rsi_root>/canary/workload.json`.
    /// The candidate never writes it: it is read from the operator's state directory, not from
    /// the evaluated tree.
    #[serde(default)]
    pub canary_workload_path: Option<String>,
    /// SHA-256 pin of the canary workload (the digest `CanaryWorkloadManifest::digest` reports).
    /// None = canary admission fails closed: the operator must pin the workload.
    #[serde(default)]
    pub canary_workload_sha256: Option<String>,
    /// Canary applicability policy. A change that is executable (a target file ending in `.rs`,
    /// `.toml` or `Cargo.lock`, or a tree that builds an executable or declares a canary
    /// adapter) always goes through canary admission, whatever its kind. Only kinds listed here
    /// are exempt, and only when the change is not executable. The default is empty: nothing is
    /// exempt. An exempt change still goes through the safety envelope and the promotion gate.
    #[serde(default)]
    pub canary_exempt_kinds: Vec<ProposalKind>,
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

fn default_measure_min_samples() -> usize {
    3
}

fn default_measure_window_cycles() -> usize {
    20
}

fn default_measure_p95_min_samples() -> usize {
    20
}

fn default_measure_target_improvement_pct() -> f64 {
    5.0
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
            operator_key_hex: None,
            non_inferiority_margin: None,
            ratify_roots: crate::diff_gate::default_ratify_roots(),
            dual_price_vector_dir: None,
            judge_public_key_hex: None,
            judge_policy_file: None,
            measure_min_samples: default_measure_min_samples(),
            measure_window_cycles: default_measure_window_cycles(),
            measure_p95_min_samples: default_measure_p95_min_samples(),
            measure_target_improvement_pct: default_measure_target_improvement_pct(),
            canary_workload_path: None,
            canary_workload_sha256: None,
            canary_exempt_kinds: Vec::new(),
        }
    }
}

/// What the supervisor-driven run did, copied from the executor's summary.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryExecutionRecord {
    pub requests_planned: usize,
    pub issued: usize,
    pub verified_success: usize,
    pub wrong_result: usize,
    pub timeout: usize,
    pub invalid_response: usize,
    pub connection_closed: usize,
    pub rejections: usize,
    pub ready: bool,
    pub reverted: bool,
    pub first_failure: Option<String>,
}

/// The quota validator's decision: counted against target, or the refusal reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotaDecisionRecord {
    pub admitted: bool,
    pub counted: Option<u64>,
    pub target: u64,
    pub refusal: Option<String>,
}

/// A pass or refusal of one gate, with the detail the gate gave.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateDecisionRecord {
    pub passed: bool,
    pub detail: String,
}

/// The reference-backend caveat recorded with every safety envelope decision.
pub const ENVELOPE_REFERENCE_NOTE: &str = "the safety envelope evaluated through aien_probe::DeterministicReferenceBackend; this is a reference evaluation and does not establish production safety";

/// Canary admission as one cycle saw it. Every digest is lowercase hex SHA-256.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanarySummary {
    /// Canary admission applied to the change (false only for a configured exemption).
    pub applicable: bool,
    /// Why the change was exempt, when it was.
    pub exemption: Option<String>,
    /// The target ships a valid adapter manifest and the operator's workload is pinned.
    pub eligible: bool,
    /// Why the candidate was refused before or during execution, when it was.
    pub refusal: Option<String>,
    pub identity_binding_digest: Option<String>,
    pub executable_digest: Option<String>,
    pub workload_digest: Option<String>,
    pub log_digest: Option<String>,
    /// Hash of the ledger block that committed the sealed log before admission.
    pub commitment_block_hash: Option<String>,
    pub execution: Option<CanaryExecutionRecord>,
    pub quota: Option<QuotaDecisionRecord>,
    pub envelope: Option<GateDecisionRecord>,
    /// Present whenever the envelope ran: it is a reference evaluation, not production safety.
    pub envelope_note: Option<String>,
    pub promotion_gate: Option<GateDecisionRecord>,
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
    /// DUAL scarcity reading (ADR 0031 section 7.5). Diagnostic only: it never
    /// enters bottleneck ranking, hard invariants, admission, ratification or
    /// promotion. Defaults to `Unavailable { Missing }` when not configured.
    #[serde(default)]
    pub scarcity: crate::dual::ScarcityDiagnostic,
    /// Canary admission summary. None when no candidate reached the canary stage.
    #[serde(default)]
    pub canary: Option<CanarySummary>,
}
