use clap::Parser;
use p256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use spark_rsi::evaluator::layers::{
    CorrectnessLayer, DefectTestResult, LongitudinalReplayLayer, PerformanceLayer,
    ResourceEfficiencyLayer, SecurityLayer, StyleLayer,
};
use spark_rsi::evaluator::metrics::{LatencyTimer, RusageMetrics, StatmMetrics};
use spark_rsi::evaluator::{EvaluationReceipt, ObjectiveEvaluator};
use spark_rsi::isolation::CandidateJailRunner;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "spark-rsi-judge",
    about = "Unprivileged Blind Judge binary executing holdouts and emitting EvaluationReceipt"
)]
pub struct JudgeCli {
    #[arg(long, default_value = "cycle-genesis")]
    pub cycle_id: String,

    #[arg(long, default_value = "cand-001")]
    pub candidate_id: String,

    #[arg(long, default_value = "parent-000")]
    pub parent_id: String,

    #[arg(long, default_value = ".")]
    pub candidate_path: String,

    #[arg(long, default_value = ".")]
    pub parent_path: String,

    #[arg(long, default_value = ".rsi/holdouts")]
    pub holdouts_dir: String,

    #[arg(long, default_value = ".rsi/eval_outputs")]
    pub output_dir: String,

    #[arg(long, default_value_t = 1.0)]
    pub non_inferiority_margin_pct: f64,

    #[arg(long)]
    pub signing_key_hex: Option<String>,

    #[arg(long)]
    pub signing_key_file: Option<String>,

    #[arg(long)]
    pub require_latency_improvement: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HoldoutCase {
    pub id: String,
    pub name: String,
    pub input: String,
    pub expected_output: String,
    pub category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HoldoutSuite {
    pub suite_id: String,
    pub name: String,
    pub cases: Vec<HoldoutCase>,
}

impl HoldoutSuite {
    pub fn builtin_suites() -> Vec<Self> {
        vec![
            HoldoutSuite {
                suite_id: "HOLD-INV-001".to_string(),
                name: "Invariant & Boundary Holdouts".to_string(),
                cases: vec![
                    HoldoutCase {
                        id: "INV-01".to_string(),
                        name: "Empty input handling".to_string(),
                        input: "".to_string(),
                        expected_output: "EMPTY_OK".to_string(),
                        category: "boundary".to_string(),
                    },
                    HoldoutCase {
                        id: "INV-02".to_string(),
                        name: "Zero latency divide by zero protection".to_string(),
                        input: "0".to_string(),
                        expected_output: "DIV0_GUARDED".to_string(),
                        category: "robustness".to_string(),
                    },
                ],
            },
            HoldoutSuite {
                suite_id: "HOLD-STY-002".to_string(),
                name: "Sovereign Voice Style Holdouts".to_string(),
                cases: vec![
                    HoldoutCase {
                        id: "STY-01".to_string(),
                        name: "Zero em and en dashes".to_string(),
                        input: "check_unicode_dashes".to_string(),
                        expected_output: "DASHES_PROHIBITED".to_string(),
                        category: "style".to_string(),
                    },
                    HoldoutCase {
                        id: "STY-02".to_string(),
                        name: "Zero forbidden buzzwords".to_string(),
                        input: "scan_forbidden_lexicon".to_string(),
                        expected_output: "BUZZWORDS_CLEARED".to_string(),
                        category: "style".to_string(),
                    },
                ],
            },
        ]
    }

    pub fn load_from_dir(dir: &Path) -> Result<Vec<Self>, String> {
        if !dir.exists() {
            return Err(format!(
                "Holdouts directory does not exist: {:?}. Production evaluation fails closed.",
                dir
            ));
        }

        let mut suites = Vec::new();
        let entries = fs::read_dir(dir)
            .map_err(|e| format!("Failed to read holdouts directory {:?}: {}", dir, e))?;

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(suite) = serde_json::from_str::<HoldoutSuite>(&content) {
                        suites.push(suite);
                    }
                }
            }
        }

        if suites.is_empty() {
            return Err(format!(
                "No valid holdout suites found in {:?}. Production evaluation fails closed.",
                dir
            ));
        }

        Ok(suites)
    }

    pub fn save_to_dir(&self, dir: &Path) -> Result<(), String> {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let filename = format!("{}.json", self.suite_id);
        let path = dir.join(filename);
        let content = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        fs::write(path, content).map_err(|e| e.to_string())?;
        Ok(())
    }
}

pub struct BlindJudge {
    pub holdouts_dir: PathBuf,
    pub output_dir: PathBuf,
    pub signing_key: Option<SigningKey>,
    pub require_latency_improvement: bool,
    pub non_inferiority_margin_pct: f64,
}

impl BlindJudge {
    pub fn new(holdouts_dir: PathBuf, output_dir: PathBuf) -> Self {
        Self {
            holdouts_dir,
            output_dir,
            signing_key: None,
            require_latency_improvement: false,
            non_inferiority_margin_pct: 5.0,
        }
    }

    pub fn with_non_inferiority_margin(mut self, margin: f64) -> Self {
        self.non_inferiority_margin_pct = margin;
        self
    }

    pub fn with_signing_key(mut self, key: SigningKey) -> Self {
        self.signing_key = Some(key);
        self
    }

    pub fn with_require_latency_improvement(mut self, req: bool) -> Self {
        self.require_latency_improvement = req;
        self
    }

    pub fn evaluate_cycle(
        &self,
        cycle_id: &str,
        candidate_id: &str,
        parent_id: &str,
        candidate_path: &Path,
        parent_path: &Path,
    ) -> Result<EvaluationReceipt, String> {
        // 0. Production evaluation fails closed if no authorized cryptographic signing key is configured
        let signing_key = self.signing_key.as_ref().ok_or_else(|| {
            "No authorized cryptographic signing key provided to BlindJudge. Production evaluation fails closed.".to_string()
        })?;

        // 1. Production evaluation fails closed if holdouts directory is missing or empty
        let suites = HoldoutSuite::load_from_dir(&self.holdouts_dir)?;

        let mut total_holdouts: usize = 0;
        let mut passed_holdouts = 0;
        let mut holdout_violations = Vec::new();

        // 2. Candidate binary must exist; production evaluation fails closed if not built
        let candidate_bin = find_executable(candidate_path).ok_or_else(|| {
            format!(
                "Candidate executable not found at {:?}. Candidates must be compiled before evaluation.",
                candidate_path
            )
        })?;

        // 3. Execute actual holdout cases strictly through Bubblewrap jail
        let jail_runner = CandidateJailRunner::new(&candidate_bin);

        for suite in &suites {
            for case in &suite.cases {
                total_holdouts += 1;
                let actual_output = match jail_runner.execute(&["holdout", &case.input]) {
                    Ok((true, stdout, _)) => stdout.trim().to_string(),
                    Ok((false, _, stderr)) => format!("EXEC_FAIL:{}", stderr.trim()),
                    Err(e) => format!("JAIL_ERR:{}", e),
                };

                if actual_output == case.expected_output {
                    passed_holdouts += 1;
                } else {
                    holdout_violations.push(format!(
                        "Holdout '{}' ({}) assertion failed: expected '{}', got '{}'",
                        case.name, case.id, case.expected_output, actual_output
                    ));
                }
            }
        }

        // 4. Extract real diff and changed files between parent and candidate
        let (modified_files, patch_diff, style_text) =
            compute_candidate_diff(parent_path, candidate_path)?;

        let correctness = if candidate_path.join("Cargo.toml").exists() {
            CorrectnessLayer::evaluate_repo(candidate_path)
        } else {
            CorrectnessLayer::evaluate_synthetic(
                true,
                passed_holdouts,
                total_holdouts.saturating_sub(passed_holdouts),
                8,
                0,
                true,
            )
        };

        let security = SecurityLayer::evaluate_candidate(&modified_files, &patch_diff, 0);

        let style = StyleLayer::evaluate_text(if style_text.is_empty() {
            "Native compiled Rust and Mojo execution running on DGX Spark GB10."
        } else {
            &style_text
        });

        // 5. Paired-workload benchmark execution for latency & resource metrics
        let (parent_latencies, candidate_latencies, parent_rusage, candidate_rusage) =
            run_paired_benchmarks(parent_path, candidate_path, 20)?;

        let performance = PerformanceLayer::evaluate_latencies_with_policy(
            &parent_latencies,
            &candidate_latencies,
            true,
            self.require_latency_improvement,
            self.non_inferiority_margin_pct,
            5000,
            Some(42),
        )?;

        let candidate_statm = StatmMetrics::read_self().ok();
        let resource_efficiency = ResourceEfficiencyLayer::evaluate(
            &parent_rusage,
            &candidate_rusage,
            candidate_statm.as_ref(),
            Some(49_152),
        );

        let mut replay_cases = LongitudinalReplayLayer::builtin_regression_corpus();
        if !holdout_violations.is_empty() {
            for v in holdout_violations {
                replay_cases.push(DefectTestResult {
                    defect_id: "HOLD-FAIL".to_string(),
                    title: "Blind holdout test suite assertion failure".to_string(),
                    passed: false,
                    details: Some(v),
                });
            }
        }
        let longitudinal_replay = LongitudinalReplayLayer::evaluate_results(&replay_cases);

        let mut receipt = ObjectiveEvaluator::evaluate_candidate(
            cycle_id,
            candidate_id,
            parent_id,
            correctness,
            security,
            style,
            performance,
            resource_efficiency,
            longitudinal_replay,
        );

        // 6. Sign receipt with authorized cryptographic key
        receipt.sign(signing_key);

        let out_path = self.output_dir.join(format!("{}.json", cycle_id));
        receipt.save_to_file(&out_path)?;

        Ok(receipt)
    }
}

pub fn find_executable(base: &Path) -> Option<PathBuf> {
    if base.is_file() {
        return Some(base.to_path_buf());
    }
    let cand1 = base.join("spark-rsi");
    if cand1.is_file() {
        return Some(cand1);
    }
    let cand2 = base.join("target/release/spark-rsi");
    if cand2.is_file() {
        return Some(cand2);
    }
    let cand3 = base.join("target/debug/spark-rsi");
    if cand3.is_file() {
        return Some(cand3);
    }

    None
}

pub fn compute_candidate_diff(
    parent_path: &Path,
    candidate_path: &Path,
) -> Result<(Vec<String>, String, String), String> {
    let mut modified_files = Vec::new();
    let mut patch_diff = String::new();
    let mut style_text = String::new();

    if parent_path == candidate_path {
        if candidate_path.join(".git").exists() || Path::new(".git").exists() {
            let diff_out = Command::new("git")
                .arg("-C")
                .arg(candidate_path)
                .args(["diff", "HEAD"])
                .output();
            if let Ok(out) = diff_out {
                patch_diff = String::from_utf8_lossy(&out.stdout).to_string();
            }
            let files_out = Command::new("git")
                .arg("-C")
                .arg(candidate_path)
                .args(["diff", "--name-only", "HEAD"])
                .output();
            if let Ok(out) = files_out {
                let stdout = String::from_utf8_lossy(&out.stdout);
                for line in stdout.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        modified_files.push(trimmed.to_string());
                    }
                }
            }
        }
        style_text = patch_diff.clone();
        return Ok((modified_files, patch_diff, style_text));
    }

    let mut cand_files = Vec::new();
    collect_files_recursive(candidate_path, candidate_path, &mut cand_files)?;

    for (rel_path, abs_cand) in &cand_files {
        let abs_parent = parent_path.join(rel_path);
        if !abs_parent.exists() {
            modified_files.push(rel_path.clone());
            let cand_content = fs::read_to_string(abs_cand).unwrap_or_default();
            patch_diff.push_str(&format!(
                "+++ {}
",
                rel_path
            ));
            for line in cand_content.lines() {
                patch_diff.push_str(&format!(
                    "+ {}
",
                    line
                ));
            }
            style_text.push_str(&cand_content);
            style_text.push('\n');
        } else {
            let cand_bytes = fs::read(abs_cand).unwrap_or_default();
            let parent_bytes = fs::read(&abs_parent).unwrap_or_default();
            if cand_bytes != parent_bytes {
                modified_files.push(rel_path.clone());
                let cand_content = String::from_utf8_lossy(&cand_bytes);
                let parent_content = String::from_utf8_lossy(&parent_bytes);
                patch_diff.push_str(&format!(
                    "--- a/{}
+++ b/{}
",
                    rel_path, rel_path
                ));
                for line in cand_content.lines() {
                    if !parent_content.contains(line) {
                        patch_diff.push_str(&format!(
                            "+ {}
",
                            line
                        ));
                    }
                }
                style_text.push_str(&cand_content);
                style_text.push('\n');
            }
        }
    }

    let mut parent_files = Vec::new();
    collect_files_recursive(parent_path, parent_path, &mut parent_files)?;
    for (rel_path, _) in parent_files {
        if !candidate_path.join(&rel_path).exists() {
            modified_files.push(rel_path.clone());
            patch_diff.push_str(&format!(
                "--- a/{}
",
                rel_path
            ));
        }
    }

    Ok((modified_files, patch_diff, style_text))
}

fn collect_files_recursive(
    base: &Path,
    current: &Path,
    acc: &mut Vec<(String, PathBuf)>,
) -> Result<(), String> {
    if !current.exists() {
        return Ok(());
    }
    let mut entries = Vec::new();
    for entry in fs::read_dir(current).map_err(|e| e.to_string())?.flatten() {
        entries.push(entry.path());
    }
    entries.sort();

    for path in entries {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if name == "target" || name == ".git" || name == "node_modules" || name.starts_with(".") {
            continue;
        }
        if path.is_dir() {
            collect_files_recursive(base, &path, acc)?;
        } else if path.is_file() {
            let rel = path
                .strip_prefix(base)
                .map_err(|e| e.to_string())?
                .to_string_lossy()
                .to_string();
            acc.push((rel, path));
        }
    }
    Ok(())
}

pub fn run_paired_benchmarks(
    parent_path: &Path,
    candidate_path: &Path,
    iterations: usize,
) -> Result<(Vec<f64>, Vec<f64>, RusageMetrics, RusageMetrics), String> {
    let parent_bin = find_executable(parent_path).ok_or_else(|| {
        format!(
            "Parent executable binary not found in {:?}. Paired benchmarks require compiled binaries.",
            parent_path
        )
    })?;
    let candidate_bin = find_executable(candidate_path).ok_or_else(|| {
        format!(
            "Candidate executable binary not found in {:?}. Paired benchmarks require compiled binaries.",
            candidate_path
        )
    })?;

    let parent_runner = CandidateJailRunner::new(&parent_bin);
    let candidate_runner = CandidateJailRunner::new(&candidate_bin);

    // Execute warm-up runs outside the measurement window to prime page caches and namespaces
    for w in 0..2 {
        let warm_arg = format!("warmup-case-{}", w);
        let _ = parent_runner.execute(&["holdout", &warm_arg]);
        let _ = candidate_runner.execute(&["holdout", &warm_arg]);
    }

    let mut parent_latencies = Vec::with_capacity(iterations);
    let mut candidate_latencies = Vec::with_capacity(iterations);
    let mut parent_rusage = RusageMetrics::default();
    let mut candidate_rusage = RusageMetrics::default();

    for i in 0..iterations {
        let input_arg = format!("benchmark-case-{}", i);

        // Interleave execution with A/B/B/A alternating order to eliminate order and thermal bias
        if i % 2 == 0 {
            // Parent then Candidate
            let p_before = RusageMetrics::capture_children()
                .map_err(|e| format!("Failed to capture parent baseline: {}", e))?;
            let timer = LatencyTimer::start();
            let (p_ok, _, p_err) =
                parent_runner
                    .execute(&["holdout", &input_arg])
                    .map_err(|e| {
                        format!("Jail execution failed for parent on iteration {}: {}", i, e)
                    })?;
            if !p_ok {
                return Err(format!(
                    "Parent execution exited with error on iteration {}: {}",
                    i, p_err
                ));
            }
            parent_latencies.push(timer.elapsed_us());
            let p_after = RusageMetrics::capture_children()
                .map_err(|e| format!("Failed to capture parent child rusage: {}", e))?;
            parent_rusage.accumulate(&p_after.diff(&p_before));

            let c_before = RusageMetrics::capture_children()
                .map_err(|e| format!("Failed to capture candidate baseline: {}", e))?;
            let timer = LatencyTimer::start();
            let (c_ok, _, c_err) =
                candidate_runner
                    .execute(&["holdout", &input_arg])
                    .map_err(|e| {
                        format!(
                            "Jail execution failed for candidate on iteration {}: {}",
                            i, e
                        )
                    })?;
            if !c_ok {
                return Err(format!(
                    "Candidate execution exited with error on iteration {}: {}",
                    i, c_err
                ));
            }
            candidate_latencies.push(timer.elapsed_us());
            let c_after = RusageMetrics::capture_children()
                .map_err(|e| format!("Failed to capture candidate child rusage: {}", e))?;
            candidate_rusage.accumulate(&c_after.diff(&c_before));
        } else {
            // Candidate then Parent
            let c_before = RusageMetrics::capture_children()
                .map_err(|e| format!("Failed to capture candidate baseline: {}", e))?;
            let timer = LatencyTimer::start();
            let (c_ok, _, c_err) =
                candidate_runner
                    .execute(&["holdout", &input_arg])
                    .map_err(|e| {
                        format!(
                            "Jail execution failed for candidate on iteration {}: {}",
                            i, e
                        )
                    })?;
            if !c_ok {
                return Err(format!(
                    "Candidate execution exited with error on iteration {}: {}",
                    i, c_err
                ));
            }
            candidate_latencies.push(timer.elapsed_us());
            let c_after = RusageMetrics::capture_children()
                .map_err(|e| format!("Failed to capture candidate child rusage: {}", e))?;
            candidate_rusage.accumulate(&c_after.diff(&c_before));

            let p_before = RusageMetrics::capture_children()
                .map_err(|e| format!("Failed to capture parent baseline: {}", e))?;
            let timer = LatencyTimer::start();
            let (p_ok, _, p_err) =
                parent_runner
                    .execute(&["holdout", &input_arg])
                    .map_err(|e| {
                        format!("Jail execution failed for parent on iteration {}: {}", i, e)
                    })?;
            if !p_ok {
                return Err(format!(
                    "Parent execution exited with error on iteration {}: {}",
                    i, p_err
                ));
            }
            parent_latencies.push(timer.elapsed_us());
            let p_after = RusageMetrics::capture_children()
                .map_err(|e| format!("Failed to capture parent child rusage: {}", e))?;
            parent_rusage.accumulate(&p_after.diff(&p_before));
        }
    }

    Ok((
        parent_latencies,
        candidate_latencies,
        parent_rusage,
        candidate_rusage,
    ))
}

pub fn run_judge_cli(cli: JudgeCli) -> Result<EvaluationReceipt, Box<dyn std::error::Error>> {
    let mut judge = BlindJudge::new(
        PathBuf::from(&cli.holdouts_dir),
        PathBuf::from(&cli.output_dir),
    )
    .with_require_latency_improvement(cli.require_latency_improvement)
    .with_non_inferiority_margin(cli.non_inferiority_margin_pct);

    let key_opt = if let Some(ref hex_str) = cli.signing_key_hex {
        let bytes = hex::decode(hex_str.trim())?;
        Some(SigningKey::from_slice(&bytes)?)
    } else if let Some(ref file_path) = cli.signing_key_file {
        let content = fs::read_to_string(file_path)?;
        let bytes = hex::decode(content.trim())?;
        Some(SigningKey::from_slice(&bytes)?)
    } else if let Ok(hex_str) = std::env::var("RSI_JUDGE_SIGNING_KEY") {
        let bytes = hex::decode(hex_str.trim())?;
        Some(SigningKey::from_slice(&bytes)?)
    } else {
        None
    };

    if let Some(key) = key_opt {
        judge = judge.with_signing_key(key);
    }

    let receipt = judge.evaluate_cycle(
        &cli.cycle_id,
        &cli.candidate_id,
        &cli.parent_id,
        Path::new(&cli.candidate_path),
        Path::new(&cli.parent_path),
    )?;

    println!("{}", serde_json::to_string_pretty(&receipt)?);

    if !receipt.admitted {
        std::process::exit(1);
    }

    Ok(receipt)
}

#[allow(dead_code)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = JudgeCli::parse();
    run_judge_cli(cli)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::VerifyingKey;

    fn find_test_executable() -> PathBuf {
        if let Ok(cargo_bin) = std::env::var("CARGO_BIN_EXE_spark-rsi") {
            let p = PathBuf::from(cargo_bin);
            if p.is_file() {
                return p;
            }
        }
        let cand1 = Path::new("target/release/spark-rsi");
        if cand1.is_file() {
            return cand1.to_path_buf();
        }
        let cand2 = Path::new("target/debug/spark-rsi");
        if cand2.is_file() {
            return cand2.to_path_buf();
        }
        let cand3 = Path::new("/home/drakestapleton/workspace/spark-rsi/target/release/spark-rsi");
        if cand3.is_file() {
            return cand3.to_path_buf();
        }
        panic!("Test executable not found");
    }

    #[test]
    fn test_holdout_suite_builtin_and_save_load() {
        let tmp = tempfile::tempdir().unwrap();
        let suites = HoldoutSuite::builtin_suites();
        assert_eq!(suites.len(), 2);

        suites[0].save_to_dir(tmp.path()).unwrap();
        let loaded = HoldoutSuite::load_from_dir(tmp.path()).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].suite_id, "HOLD-INV-001");
    }

    #[test]
    fn test_holdout_suite_load_missing_fails_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let non_existent = tmp.path().join("non_existent");
        assert!(HoldoutSuite::load_from_dir(&non_existent).is_err());

        let empty = tmp.path().join("empty");
        fs::create_dir_all(&empty).unwrap();
        assert!(HoldoutSuite::load_from_dir(&empty).is_err());
    }

    #[test]
    fn test_blind_judge_fails_closed_without_signing_key() {
        let tmp = tempfile::tempdir().unwrap();
        let holdouts = tmp.path().join("holdouts");
        let outputs = tmp.path().join("eval_outputs");
        let candidate = tmp.path().join("candidate");
        fs::create_dir_all(&candidate).unwrap();
        let parent = tmp.path().join("parent");
        fs::create_dir_all(&parent).unwrap();

        for s in HoldoutSuite::builtin_suites() {
            s.save_to_dir(&holdouts).unwrap();
        }

        // Copy spark-rsi executable so find_executable finds it
        if let Some(exe) = find_executable(Path::new(".")) {
            let _ = fs::copy(&exe, candidate.join("spark-rsi"));
            let _ = fs::copy(&exe, parent.join("spark-rsi"));
        }

        let judge = BlindJudge::new(holdouts, outputs);
        let res = judge.evaluate_cycle("cycle-no-key", "cand-01", "parent-00", &candidate, &parent);

        assert!(res.is_err());
        assert!(res.unwrap_err().contains("signing key"));
    }

    #[test]
    fn test_blind_judge_evaluate_cycle_admission_and_verification() {
        let tmp = tempfile::tempdir().unwrap();
        let holdouts = tmp.path().join("holdouts");
        let outputs = tmp.path().join("eval_outputs");
        let candidate = tmp.path().join("candidate");
        fs::create_dir_all(&candidate).unwrap();
        let parent = tmp.path().join("parent");
        fs::create_dir_all(&parent).unwrap();

        for s in HoldoutSuite::builtin_suites() {
            s.save_to_dir(&holdouts).unwrap();
        }

        let exe = find_test_executable();
        fs::copy(&exe, candidate.join("spark-rsi")).unwrap();
        fs::copy(&exe, parent.join("spark-rsi")).unwrap();

        let signing_key = SigningKey::from_bytes(&[88u8; 32].into()).unwrap();
        let verifying_key = VerifyingKey::from(&signing_key);

        let judge = BlindJudge::new(holdouts, outputs.clone())
            .with_signing_key(signing_key)
            .with_non_inferiority_margin(1000.0);

        let receipt = judge
            .evaluate_cycle("cycle-test-01", "cand-01", "parent-00", &candidate, &parent)
            .unwrap();

        assert!(
            receipt.admitted,
            "Failed layers: {:?}",
            receipt.layer_results
        );
        assert!(receipt.passed_all_hard_invariants);
        assert!(receipt.passed_statistical_gates);
        assert!(receipt.verify_digest());
        assert!(receipt.signature.is_some());
        assert!(receipt.verify_signature(&verifying_key));

        let output_file = outputs.join("cycle-test-01.json");
        assert!(output_file.exists());

        let loaded = EvaluationReceipt::load_from_file(&output_file).unwrap();
        assert_eq!(loaded.cycle_id, "cycle-test-01");
        assert!(loaded.verify_digest());
        assert!(loaded.verify_signature(&verifying_key));
    }

    #[test]
    fn test_blind_judge_rejects_candidate_with_failing_holdout() {
        let tmp = tempfile::tempdir().unwrap();
        let holdouts = tmp.path().join("holdouts");
        let outputs = tmp.path().join("eval_outputs");
        let candidate = tmp.path().join("candidate");
        fs::create_dir_all(&candidate).unwrap();
        let parent = tmp.path().join("parent");
        fs::create_dir_all(&parent).unwrap();

        // Create a custom holdout case that fails
        let failing_suite = HoldoutSuite {
            suite_id: "HOLD-FAIL-01".to_string(),
            name: "Impossible Holdout".to_string(),
            cases: vec![HoldoutCase {
                id: "IMP-01".to_string(),
                name: "Unattainable response".to_string(),
                input: "impossible_query".to_string(),
                expected_output: "EXPECT_MAGIC_STRING".to_string(),
                category: "robustness".to_string(),
            }],
        };
        failing_suite.save_to_dir(&holdouts).unwrap();

        let exe = find_test_executable();
        fs::copy(&exe, candidate.join("spark-rsi")).unwrap();
        fs::copy(&exe, parent.join("spark-rsi")).unwrap();

        let signing_key = SigningKey::from_bytes(&[88u8; 32].into()).unwrap();
        let judge = BlindJudge::new(holdouts, outputs).with_signing_key(signing_key);
        let receipt = judge
            .evaluate_cycle("cycle-fail-01", "cand-01", "parent-00", &candidate, &parent)
            .unwrap();

        assert!(!receipt.admitted);
        assert!(!receipt.passed_all_hard_invariants);
    }
}
