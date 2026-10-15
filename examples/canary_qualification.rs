//! Qualification run for the M1+M2 cut (docs/plans/2026-10-12-evidence-driven-rsi-cut.md,
//! sections "Qualification fixture" and "Evidence package").
//!
//! Builds a target repository from `fixtures/canary-target`, runs one real RSI cycle through the
//! build jail, the supervisor-driven canary and admission, and writes the evidence package to
//! `--out`: the cycle result, the pinned workload and its digest, the adapter manifest, the
//! sealed observation log and its verified summary, every ledger block and the chain audit, the
//! stage samples, the environment, and a human-readable summary.
//!
//! Usage:
//!   cargo run --release --example canary_qualification -- --out <dir> [--mode <fixture mode>]
//!
//! `--mode` sets `RSI_CANARY_FIXTURE_MODE` for the worker (`correct` by default, or any mode the
//! fixture understands, for example `wrong_answer`). The process exits 0 when the quota decision
//! is the one the mode predicts (admitted for `correct`, refused otherwise) and 1 when it is not.
//!
//! A passing correct run qualifies the canary execution pipeline. It does not qualify RSI's
//! ability to improve itself, and it does not qualify the safety envelope as a production
//! evaluator: that evaluation runs through a reference backend and is recorded as such.

use p256::ecdsa::SigningKey;
use spark_rsi::actor::judge::{find_executable, HoldoutSuite};
use spark_rsi::canary::{CanaryWorkloadManifest, SealedObservationLog};
use spark_rsi::daemon::RsiEngine;
use spark_rsi::ledger::ImprovementLedger;
use spark_rsi::models::RsiConfig;
use std::path::{Path, PathBuf};
use std::process::Command;

fn arg(name: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn git(dir: &Path, args: &[&str]) -> Result<(), String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .map_err(|e| format!("git {:?}: {}", args, e))?;
    if !out.status.success() {
        return Err(format!(
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

fn capture(cmd: &str, args: &[&str], dir: &Path) -> String {
    Command::new(cmd)
        .args(args)
        .current_dir(dir)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    std::fs::write(path, bytes).map_err(|e| format!("cannot write {:?}: {}", path, e))
}

fn engine_executable(manifest_dir: &Path) -> Result<PathBuf, String> {
    // Built alongside this example (target/<profile>/spark-rsi), else the judge's own finder.
    if let Ok(me) = std::env::current_exe() {
        if let Some(profile_dir) = me.parent().and_then(Path::parent) {
            let sibling = profile_dir.join("spark-rsi");
            if sibling.is_file() {
                return Ok(sibling);
            }
        }
    }
    find_executable(manifest_dir)
        .ok_or_else(|| "spark-rsi executable not found; build it first".to_string())
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let out = PathBuf::from(arg("--out").ok_or("--out <dir> is required")?);
    let mode = arg("--mode").unwrap_or_else(|| "correct".to_string());
    std::env::set_var("RSI_CANARY_FIXTURE_MODE", &mode);
    std::fs::create_dir_all(&out).map_err(|e| format!("cannot create {:?}: {}", out, e))?;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixture = manifest_dir.join("fixtures/canary-target");
    let engine = engine_executable(manifest_dir)?;
    let started_at = chrono::Utc::now().to_rfc3339();

    // The target repository: the fixture crate with its adapter manifest, a README whose em
    // dash makes the unslop proposal, the engine executable the judge benchmarks, and the
    // operator state: holdouts, the pinned workload, a test signing key.
    let work = tempfile::tempdir().map_err(|e| e.to_string())?;
    let repo = work.path().join("repo");
    let sandbox = work.path().join("sandbox");
    std::fs::create_dir_all(repo.join("src")).map_err(|e| e.to_string())?;
    for f in ["Cargo.toml", "Cargo.lock", "canary-adapter.toml"] {
        std::fs::copy(fixture.join(f), repo.join(f)).map_err(|e| format!("copy {}: {}", f, e))?;
    }
    std::fs::copy(fixture.join("src/main.rs"), repo.join("src/main.rs"))
        .map_err(|e| e.to_string())?;
    write(
        &repo.join("README.md"),
        "# Canary target\n\nWe build, fix, finish, and optimize systems with love, honor, and discipline\u{2014}with an em dash.\n".as_bytes(),
    )?;
    std::fs::copy(&engine, repo.join("spark-rsi")).map_err(|e| e.to_string())?;
    write(&repo.join(".gitignore"), b"target\n")?;
    git(&repo, &["init", "-b", "main"])?;
    git(&repo, &["config", "user.name", "Qualification Operator"])?;
    git(&repo, &["config", "user.email", "qualification@local"])?;
    git(&repo, &["add", "."])?;
    git(&repo, &["commit", "-q", "-m", "canary target"])?;

    let rsi_root = repo.join(".rsi");
    let holdouts = rsi_root.join("holdouts");
    std::fs::create_dir_all(&holdouts).map_err(|e| e.to_string())?;
    for suite in HoldoutSuite::builtin_suites() {
        suite.save_to_dir(&holdouts)?;
    }
    let workload_path = rsi_root.join("canary/workload.json");
    std::fs::create_dir_all(workload_path.parent().unwrap()).map_err(|e| e.to_string())?;
    std::fs::copy(fixture.join("workload.json"), &workload_path).map_err(|e| e.to_string())?;
    let workload = CanaryWorkloadManifest::load(&workload_path)?;

    // A fixed test key: never production authority, kept fixed so the run is reproducible.
    let signing_key = SigningKey::from_slice(&[0x51u8; 32]).map_err(|e| e.to_string())?;
    let config = RsiConfig {
        target_repo: repo.to_string_lossy().to_string(),
        cortex_url: "http://127.0.0.1:9".to_string(),
        cortex_space: "qualification".to_string(),
        loop_interval_secs: 60,
        sandbox_root: sandbox.to_string_lossy().to_string(),
        rsi_root: ".rsi".to_string(),
        holdouts_dir: None,
        signing_key_hex: Some(hex::encode(signing_key.to_bytes())),
        require_latency_improvement: false,
        non_inferiority_margin: Some(250.0),
        model_url: "http://127.0.0.1:9".to_string(),
        canary_target: 10,
        canary_workload_sha256: Some(workload.digest.clone()),
        ..Default::default()
    };

    let result = RsiEngine::run_cycle(&config).await?;
    let finished_at = chrono::Utc::now().to_rfc3339();

    // Evidence package.
    write(
        &out.join("cycle-result.json"),
        serde_json::to_string_pretty(&result)
            .map_err(|e| e.to_string())?
            .as_bytes(),
    )?;
    std::fs::copy(&workload_path, out.join("workload.json")).map_err(|e| e.to_string())?;
    write(&out.join("workload.sha256"), workload.digest.as_bytes())?;
    std::fs::copy(
        fixture.join("canary-adapter.toml"),
        out.join("canary-adapter.toml"),
    )
    .map_err(|e| e.to_string())?;
    write(
        &out.join("config.json"),
        serde_json::to_string_pretty(&config)
            .map_err(|e| e.to_string())?
            .as_bytes(),
    )?;

    let canary = result.canary.clone().unwrap_or_default();
    let mut sealed_summary = serde_json::json!({ "sealed_log": null });
    if let Some(proposal) = &result.proposal {
        let log = rsi_root.join(format!("canary/observations/{}.jsonl", proposal.id));
        if log.is_file() {
            std::fs::copy(&log, out.join("observations.jsonl")).map_err(|e| e.to_string())?;
            let sealed = SealedObservationLog::load(&log)?;
            sealed_summary = serde_json::json!({
                "sealed_log": {
                    "verified": true,
                    "header": sealed.header,
                    "seal": sealed.seal,
                    "observations": sealed.observations.len(),
                    "qualifying": sealed.qualifying().count(),
                    "rejections": sealed.rejections.len(),
                }
            });
        }
    }
    write(
        &out.join("sealed-log.json"),
        serde_json::to_string_pretty(&sealed_summary)
            .map_err(|e| e.to_string())?
            .as_bytes(),
    )?;

    let ledger = ImprovementLedger::open(&rsi_root)?;
    let blocks = ledger.all_blocks()?;
    write(
        &out.join("ledger-blocks.json"),
        serde_json::to_string_pretty(&blocks)
            .map_err(|e| e.to_string())?
            .as_bytes(),
    )?;
    let audit = ledger.verify_chain_integrity(Some(signing_key.verifying_key()))?;
    write(
        &out.join("ledger-audit.json"),
        serde_json::to_string_pretty(&audit)
            .map_err(|e| e.to_string())?
            .as_bytes(),
    )?;
    for name in ["stage-samples.jsonl", "partial-cycles.jsonl"] {
        let src = rsi_root.join("measure").join(name);
        if src.is_file() {
            std::fs::copy(&src, out.join(name)).map_err(|e| e.to_string())?;
        }
    }

    let environment = serde_json::json!({
        "spark_rsi_revision": capture("git", &["rev-parse", "HEAD"], manifest_dir),
        "spark_rsi_branch": capture("git", &["rev-parse", "--abbrev-ref", "HEAD"], manifest_dir),
        "rustc": capture("rustc", &["--version"], manifest_dir),
        "cargo": capture("cargo", &["--version"], manifest_dir),
        "host": capture("uname", &["-a"], manifest_dir),
        "fixture_mode": mode,
        "started_at": started_at,
        "finished_at": finished_at,
        "engine_executable": engine.display().to_string(),
    });
    write(
        &out.join("environment.json"),
        serde_json::to_string_pretty(&environment)
            .map_err(|e| e.to_string())?
            .as_bytes(),
    )?;

    let quota_admitted = canary.quota.as_ref().map(|q| q.admitted).unwrap_or(false);
    let expected_admitted = mode == "correct";
    let verdict = if quota_admitted == expected_admitted {
        "AS PREDICTED"
    } else {
        "NOT AS PREDICTED"
    };
    let summary = format!(
        "# Canary qualification run\n\n\
         Mode: {mode}\n\
         Revision: {rev}\n\
         Verdict: {verdict} (quota admitted = {quota_admitted}, predicted = {expected_admitted})\n\n\
         | Item | Value |\n|---|---|\n\
         | cycle id | {cycle} |\n\
         | proposal | {proposal} |\n\
         | canary applicable / eligible | {applicable} / {eligible} |\n\
         | refusal | {refusal} |\n\
         | identity binding digest | {binding} |\n\
         | executable digest | {exe} |\n\
         | workload digest | {wl} |\n\
         | sealed log digest | {log} |\n\
         | commitment block hash | {commit} |\n\
         | execution | {exec} |\n\
         | quota | {quota} |\n\
         | safety envelope | {env} |\n\
         | envelope note | {note} |\n\
         | promotion gate | {gate} |\n\
         | cycle success | {success} |\n\
         | durable generation | {durable} |\n\n\
         A passing correct run qualifies the canary execution pipeline. It does not qualify RSI's \
         ability to improve itself, and it does not qualify the safety envelope as a production \
         evaluator.\n",
        mode = mode,
        rev = environment["spark_rsi_revision"].as_str().unwrap_or("unknown"),
        verdict = verdict,
        quota_admitted = quota_admitted,
        expected_admitted = expected_admitted,
        cycle = result.cycle_id,
        proposal = result
            .proposal
            .as_ref()
            .map(|p| format!("{} ({:?}, {})", p.id, p.kind, p.target_file))
            .unwrap_or_else(|| "none".to_string()),
        applicable = canary.applicable,
        eligible = canary.eligible,
        refusal = canary.refusal.clone().unwrap_or_else(|| "none".to_string()),
        binding = canary.identity_binding_digest.clone().unwrap_or_else(|| "none".to_string()),
        exe = canary.executable_digest.clone().unwrap_or_else(|| "none".to_string()),
        wl = canary.workload_digest.clone().unwrap_or_else(|| "none".to_string()),
        log = canary.log_digest.clone().unwrap_or_else(|| "none".to_string()),
        commit = canary.commitment_block_hash.clone().unwrap_or_else(|| "none".to_string()),
        exec = canary
            .execution
            .as_ref()
            .map(|e| format!(
                "planned {}, issued {}, verified {}, wrong {}, timeout {}, invalid {}, closed {}, rejections {}, ready {}, reverted {}, first failure {:?}",
                e.requests_planned, e.issued, e.verified_success, e.wrong_result, e.timeout, e.invalid_response, e.connection_closed, e.rejections, e.ready, e.reverted, e.first_failure
            ))
            .unwrap_or_else(|| "none".to_string()),
        quota = canary
            .quota
            .as_ref()
            .map(|q| format!("admitted {} (counted {:?} of target {}){}", q.admitted, q.counted, q.target, q.refusal.as_ref().map(|r| format!(": {}", r)).unwrap_or_default()))
            .unwrap_or_else(|| "not reached".to_string()),
        env = canary
            .envelope
            .as_ref()
            .map(|g| format!("passed {}: {}", g.passed, g.detail))
            .unwrap_or_else(|| "not reached".to_string()),
        note = canary.envelope_note.clone().unwrap_or_else(|| "none".to_string()),
        gate = canary
            .promotion_gate
            .as_ref()
            .map(|g| format!("passed {}: {}", g.passed, g.detail))
            .unwrap_or_else(|| "not reached".to_string()),
        success = result.success,
        durable = result.generation.is_some(),
    );
    write(&out.join("summary.md"), summary.as_bytes())?;
    println!("{}", summary);
    println!("evidence written to {}", out.display());
    if quota_admitted != expected_admitted {
        std::process::exit(1);
    }
    Ok(())
}
