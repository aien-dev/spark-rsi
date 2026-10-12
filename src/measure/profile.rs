//! Workload key and execution-profile fingerprint.
//!
//! Effective execution configuration: the `RsiConfig` fields that change what the stages do or
//! which services they call, so two cycles with different values are not comparable:
//! - `max_url` (the inference endpoint Propose calls)
//! - `mojo_kernel_path` (the balance kernel the evaluation runs)
//! - the effective holdouts directory (the judge's workload)
//! - `canary_target` (how many canary observations the canary stage needs)
//! - `cortex_url` and `cortex_space` (what CortexCommit writes to)
//! - `ratify_roots` (sorted; the scope of candidates that reach the stages)
//!
//! Left out on purpose: secrets (signing and operator keys), `require_latency_improvement`,
//! `non_inferiority_margin` and the judge policy fields (evaluation policy, not execution
//! mode), `loop_interval_secs` (scheduling), `sandbox_root` and `rsi_root` (locations), the
//! `measure_*` fields (how to read samples) and `dual_price_vector_dir` (diagnostic only).

use crate::models::RsiConfig;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionConfig {
    pub max_url: String,
    pub mojo_kernel_path: String,
    pub holdouts_dir: String,
    pub canary_target: u64,
    pub cortex_url: String,
    pub cortex_space: String,
    pub ratify_roots: Vec<String>,
}

impl ExecutionConfig {
    pub fn from_config(config: &RsiConfig) -> Self {
        let mut ratify_roots = config.ratify_roots.clone();
        ratify_roots.sort();
        ratify_roots.dedup();
        Self {
            max_url: config.max_url.clone(),
            mojo_kernel_path: config.mojo_kernel_path.clone(),
            holdouts_dir: config
                .holdouts_dir
                .clone()
                .unwrap_or_else(|| format!("{}/holdouts", config.rsi_root)),
            canary_target: config.canary_target,
            cortex_url: config.cortex_url.clone(),
            cortex_space: config.cortex_space.clone(),
            ratify_roots,
        }
    }

    fn canonical(&self) -> String {
        format!(
            "max_url={}\nmojo_kernel_path={}\nholdouts_dir={}\ncanary_target={}\ncortex_url={}\ncortex_space={}\nratify_roots={}\n",
            self.max_url,
            self.mojo_kernel_path,
            self.holdouts_dir,
            self.canary_target,
            self.cortex_url,
            self.cortex_space,
            self.ratify_roots.join(",")
        )
    }
}

/// Machine and configuration identity stamped on every sample.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionProfile {
    pub model: String,
    pub execution_config: ExecutionConfig,
    /// None when the platform would not say. Distinct from every real count.
    pub cpu_count: Option<usize>,
    pub memory_total_kib: Option<u64>,
    /// GPU names from nvidia-smi joined with ";", or the literal "none".
    pub gpu: String,
}

fn digest_hex(domain: &str, body: &str) -> String {
    let mut h = Sha256::new();
    h.update(domain.as_bytes());
    h.update(b"\n");
    h.update(body.as_bytes());
    hex::encode(h.finalize())
}

fn opt<T: ToString>(v: &Option<T>) -> String {
    v.as_ref()
        .map(|x| x.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

impl ExecutionProfile {
    pub fn fingerprint(&self) -> String {
        digest_hex(
            "spark-rsi/measure/execution-profile/v1",
            &format!(
                "model={}\n{}cpu_count={}\nmemory_total_kib={}\ngpu={}\n",
                self.model,
                self.execution_config.canonical(),
                opt(&self.cpu_count),
                opt(&self.memory_total_kib),
                self.gpu
            ),
        )
    }

    pub fn detect(config: &RsiConfig) -> Self {
        Self {
            model: config.max_model.clone(),
            execution_config: ExecutionConfig::from_config(config),
            cpu_count: std::thread::available_parallelism().ok().map(|n| n.get()),
            memory_total_kib: read_mem_total_kib("/proc/meminfo"),
            gpu: probe_gpu(Duration::from_secs(3)),
        }
    }
}

/// MemTotal in KiB from a meminfo-format file.
pub fn read_mem_total_kib(path: &str) -> Option<u64> {
    let text = std::fs::read_to_string(path).ok()?;
    let line = text.lines().find(|l| l.starts_with("MemTotal:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

/// GPU identity from nvidia-smi, or "none" when absent, failing or slower than `timeout`.
pub fn probe_gpu(timeout: Duration) -> String {
    let Ok(mut child) = Command::new("nvidia-smi")
        .args(["--query-gpu=name", "--format=csv,noheader"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return "none".to_string();
    };
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return "none".to_string();
                }
                let mut out = String::new();
                if let Some(mut so) = child.stdout.take() {
                    let _ = so.read_to_string(&mut out);
                }
                let names: Vec<&str> = out
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .collect();
                return if names.is_empty() {
                    "none".to_string()
                } else {
                    names.join(";")
                };
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return "none".to_string();
            }
        }
    }
}

/// Remote URL without credentials or trailing `.git` and `/`, or the canonical absolute path.
pub fn repo_identity(repo: &Path) -> String {
    let remote = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["config", "--get", "remote.origin.url"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|u| !u.is_empty());
    match remote {
        Some(url) => format!("remote:{}", normalize_remote(&url)),
        None => {
            let abs = std::fs::canonicalize(repo).unwrap_or_else(|_| repo.to_path_buf());
            format!("path:{}", abs.display())
        }
    }
}

pub fn normalize_remote(url: &str) -> String {
    let mut u = url.trim().to_string();
    if let Some(scheme_end) = u.find("://") {
        let rest_start = scheme_end + 3;
        let authority_end = u[rest_start..]
            .find('/')
            .map(|i| rest_start + i)
            .unwrap_or(u.len());
        if let Some(at) = u[rest_start..authority_end].rfind('@') {
            u.replace_range(rest_start..rest_start + at + 1, "");
        }
    }
    while u.ends_with('/') {
        u.pop();
    }
    if let Some(stripped) = u.strip_suffix(".git") {
        u = stripped.to_string();
    }
    u
}

pub fn head_commit(repo: &Path) -> Option<String> {
    Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "HEAD"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|c| !c.is_empty())
}

/// What a cycle needs to read prior samples and write its own.
#[derive(Debug, Clone)]
pub struct MeasureContext {
    pub workload_key: String,
    pub profile: ExecutionProfile,
    pub fingerprint: String,
    pub source_commit: Option<String>,
}

impl MeasureContext {
    pub fn for_config(config: &RsiConfig, repo: &Path) -> Self {
        Self::from_parts(
            &repo_identity(repo),
            ExecutionProfile::detect(config),
            head_commit(repo),
        )
    }

    /// Workload key: repository identity, effective execution configuration, model name.
    /// The target commit is deliberately absent.
    pub fn from_parts(
        repo_identity: &str,
        profile: ExecutionProfile,
        source_commit: Option<String>,
    ) -> Self {
        let workload_key = digest_hex(
            "spark-rsi/measure/workload-key/v1",
            &format!(
                "repo={}\n{}model={}\n",
                repo_identity,
                profile.execution_config.canonical(),
                profile.model
            ),
        );
        let fingerprint = profile.fingerprint();
        Self {
            workload_key,
            profile,
            fingerprint,
            source_commit,
        }
    }
}
