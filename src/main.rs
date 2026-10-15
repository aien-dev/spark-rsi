use clap::{Parser, Subcommand};
use spark_rsi::balance::BalanceKernel;
use spark_rsi::config::SovereignConfig;
use spark_rsi::daemon::RsiEngine;
use spark_rsi::models::RsiConfig;
use spark_rsi::observe::observe_codebase;
use spark_rsi::propose::ProposalGenerator;
use spark_rsi::verifier::InvariantVerifier;
use std::path::Path;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Parser, Debug)]
#[command(
    name = "spark-rsi",
    about = "AIEN Sovereign Recursive Self-Improvement Engine on NVIDIA DGX Spark",
    version = spark_rsi::version()
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum LedgerCommands {
    /// Print recent ledger blocks
    Log {
        #[arg(default_value = ".rsi")]
        rsi_root: String,
        #[arg(short, long, default_value = "20")]
        limit: usize,
    },
    /// Verify ledger integrity, SHA-256 hash chaining, Merkle roots, and blob digests
    Verify {
        #[arg(default_value = ".rsi")]
        rsi_root: String,
        #[arg(long)]
        verifying_key_hex: Option<String>,
    },
    /// Compute Merkle root checkpoint and optionally sign with P-256 ECDSA key
    Checkpoint {
        #[arg(default_value = ".rsi")]
        rsi_root: String,
        /// Signing key as hex. Other processes can read command-line arguments; prefer
        /// `--signing-key-file` or `RSI_LEDGER_SIGNING_KEY`.
        #[arg(long)]
        signing_key_hex: Option<String>,
        /// File holding the signing key as hex. Falls back to `RSI_LEDGER_SIGNING_KEY`.
        #[arg(long)]
        signing_key_file: Option<String>,
    },
    /// Record append-only PromotionEvidence block proving downstream compounding
    Evidence {
        #[arg(default_value = ".rsi")]
        rsi_root: String,
        #[arg(long)]
        candidate_hash: String,
        #[arg(long)]
        downstream_cycle: String,
        #[arg(long)]
        downstream_hash: String,
        #[arg(long)]
        proof: String,
    },
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialize operator profile and model engine configuration
    Init {
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        email: Option<String>,
        #[arg(long)]
        mode: Option<String>,
        #[arg(long)]
        api_url: Option<String>,
        #[arg(long)]
        model_id: Option<String>,
    },
    /// Display current sovereign operator profile and engine configuration
    Profile,
    /// Observe codebase telemetry, git state, crumbs, and soul tension
    Observe {
        #[arg(default_value = ".")]
        path: String,
    },
    /// Generate an atomic improvement proposal in an isolated sandbox
    Propose {
        #[arg(default_value = ".")]
        path: String,
    },
    /// Verify sovereign invariants: unslop standard, zero disk secrets, compile, and tests
    Verify {
        #[arg(default_value = ".")]
        path: String,
    },
    /// Evaluate drive versus humanity tension via the native balance kernel
    Balance { drive: f64, humanity: f64 },
    /// Evaluate 4-lane drive and humanity vectors (each side summed) via the native balance kernel
    BalanceSimd {
        d0: f32,
        d1: f32,
        d2: f32,
        d3: f32,
        h0: f32,
        h1: f32,
        h2: f32,
        h3: f32,
    },
    /// Execute unprivileged Blind Judge evaluation over candidate generation
    Judge {
        #[arg(long, default_value = "cycle-genesis")]
        cycle_id: String,
        #[arg(long, default_value = "cand-001")]
        candidate_id: String,
        #[arg(long, default_value = "parent-000")]
        parent_id: String,
        #[arg(long, default_value = ".")]
        candidate_path: String,
        #[arg(long, default_value = ".")]
        parent_path: String,
        #[arg(long, default_value = ".rsi/holdouts")]
        holdouts_dir: String,
        #[arg(long, default_value = ".rsi/eval_outputs")]
        output_dir: String,
        #[arg(long)]
        signing_key_hex: Option<String>,
        #[arg(long)]
        signing_key_file: Option<String>,
        #[arg(long)]
        require_latency_improvement: bool,
        #[arg(long, default_value_t = 1.0)]
        non_inferiority_margin_pct: f64,
        /// The one file (relative to the candidate tree) whose exact bytes a version 2 receipt
        /// binds. Required whenever a policy is configured.
        #[arg(long)]
        subject_path: Option<String>,
        /// Evaluation policy for version 2 receipts. Falls back to `RSI_JUDGE_POLICY_FILE`; with a
        /// policy configured every receipt is version 2, and a malformed policy is refused.
        #[arg(long)]
        policy_file: Option<String>,
        /// Executable to run for holdouts and benchmarks, relative to each tree (version 2 names
        /// it, never searches for it).
        #[arg(long)]
        executable: Option<String>,
        /// Build both trees into a fresh judge-owned target directory before evaluating.
        #[arg(long, requires = "executable")]
        build_release: bool,
    },
    /// Execute a holdout test case against internal logic
    Holdout {
        #[arg(default_value = "")]
        input: String,
    },
    /// Run a single end-to-end RSI cycle (Observe, Propose, Verify, Balance, Ratify)
    Cycle {
        #[arg(default_value = ".")]
        path: String,
        #[arg(long, default_value = "http://127.0.0.1:18080")]
        cortex_url: String,
        #[arg(long, default_value = "http://127.0.0.1:18006/v1")]
        model_url: String,
        #[arg(long, default_value = "atlas-lightning-omni")]
        model_id: String,
        /// Directory with a DUAL price vector, read as a diagnostic signal only (ADR 0031 s7.5)
        #[arg(long)]
        dual_price_vector_dir: Option<String>,
        /// SEC1 hex public key of the separate judge, pinned for the promotion gate. Falls back to
        /// `RSI_JUDGE_PUBLIC_KEY`. A malformed key is refused at startup.
        #[arg(long)]
        judge_public_key: Option<String>,
        /// Evaluation policy promotion receipts must be bound to. Falls back to
        /// `RSI_JUDGE_POLICY_FILE`. A malformed policy is refused at startup.
        #[arg(long)]
        judge_policy_file: Option<String>,
    },
    /// Run the continuous recursive self-improvement daemon loop
    Daemon {
        #[arg(default_value = ".")]
        path: String,
        #[arg(short, long, default_value = "60")]
        interval: u64,
        #[arg(long, default_value = "http://127.0.0.1:18080")]
        cortex_url: String,
        #[arg(long, default_value = "http://127.0.0.1:18006/v1")]
        model_url: String,
        #[arg(long, default_value = "atlas-lightning-omni")]
        model_id: String,
        /// Directory with a DUAL price vector, read as a diagnostic signal only (ADR 0031 s7.5)
        #[arg(long)]
        dual_price_vector_dir: Option<String>,
        /// SEC1 hex public key of the separate judge, pinned for the promotion gate. Falls back to
        /// `RSI_JUDGE_PUBLIC_KEY`. A malformed key is refused at startup.
        #[arg(long)]
        judge_public_key: Option<String>,
        /// Evaluation policy promotion receipts must be bound to. Falls back to
        /// `RSI_JUDGE_POLICY_FILE`. A malformed policy is refused at startup.
        #[arg(long)]
        judge_policy_file: Option<String>,
    },
    /// Manage the append-only cryptographic improvement ledger
    Ledger {
        #[command(subcommand)]
        action: LedgerCommands,
    },
    /// Execute Tier 2 autonomous soak run (5 cycles, multi-candidate isolation, strict staging)
    Soak {
        #[arg(long, default_value = ".")]
        path: String,
        #[arg(long, default_value = ".rsi")]
        rsi_root: String,
        #[arg(long, default_value = "5")]
        cycles: usize,
        #[arg(long, default_value = "3")]
        candidates: usize,
        #[arg(long, default_value = "http://127.0.0.1:18080")]
        cortex_url: String,
        #[arg(long, default_value = "http://127.0.0.1:18006/v1")]
        model_url: String,
        #[arg(long, default_value = "atlas-lightning-omni")]
        model_id: String,
        /// Signing key as hex. Other processes can read command-line arguments; prefer
        /// `--signing-key-file` or `RSI_SOAK_SIGNING_KEY`.
        #[arg(long)]
        signing_key_hex: Option<String>,
        /// File holding the signing key as hex. Falls back to `RSI_SOAK_SIGNING_KEY`.
        #[arg(long)]
        signing_key_file: Option<String>,
        #[arg(long)]
        operator_key_hex: Option<String>,
        #[arg(long)]
        holdouts_dir: Option<String>,
        #[arg(long)]
        margin: Option<f64>,
    },
    /// Display the sovereign programming philosophy manifesto
    Philosophy,
}

/// Environment variable holding the operator's evaluation policy for version 2 receipts.
const JUDGE_POLICY_ENV: &str = "RSI_JUDGE_POLICY_FILE";
/// Environment variable holding the separate judge's SEC1 hex public key.
const JUDGE_PUBLIC_KEY_ENV: &str = "RSI_JUDGE_PUBLIC_KEY";

/// Environment variable holding the `ledger checkpoint` signing key as hex.
const LEDGER_SIGNING_KEY_ENV: &str = "RSI_LEDGER_SIGNING_KEY";
/// Environment variable holding the `soak` signing key as hex.
const SOAK_SIGNING_KEY_ENV: &str = "RSI_SOAK_SIGNING_KEY";

/// The flag when given, otherwise the non-empty environment variable.
fn flag_or_env(flag: Option<String>, var: &str) -> Option<String> {
    flag.or_else(|| std::env::var(var).ok().filter(|v| !v.trim().is_empty()))
}

/// Key hex from the hex flag, else the key file, else the environment variable: the order the
/// judge uses. An unreadable or empty key file is an error, never a fallback.
fn key_hex(
    hex_flag: Option<String>,
    key_file: Option<String>,
    var: &str,
) -> Result<Option<String>, String> {
    if let Some(hex_str) = hex_flag {
        return Ok(Some(hex_str.trim().to_string()));
    }
    if let Some(path) = key_file {
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read key file {}: {}", path, e))?;
        let text = text.trim();
        if text.is_empty() {
            return Err(format!("key file {} is empty", path));
        }
        return Ok(Some(text.to_string()));
    }
    Ok(flag_or_env(None, var).map(|v| v.trim().to_string()))
}

/// Loads the judge pins `cycle` and `daemon` hand the promotion gate, so a malformed policy or
/// key stops the command at startup instead of surfacing as a refusal cycles later.
fn validated_judge_pins(
    public_key: Option<String>,
    policy_file: Option<String>,
) -> Result<(Option<String>, Option<String>), String> {
    let public_key = flag_or_env(public_key, JUDGE_PUBLIC_KEY_ENV);
    let policy_file = flag_or_env(policy_file, JUDGE_POLICY_ENV);
    if let Some(p) = &policy_file {
        spark_rsi::actor::judge::EvaluationPolicy::load(Path::new(p))?;
    }
    if let Some(k) = &public_key {
        let bytes =
            hex::decode(k.trim()).map_err(|e| format!("judge public key is not hex: {}", e))?;
        p256::ecdsa::VerifyingKey::from_sec1_bytes(&bytes)
            .map_err(|e| format!("judge public key is invalid: {}", e))?;
    }
    Ok((public_key, policy_file))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init {
            name,
            email,
            mode,
            api_url,
            model_id,
        } => {
            let mut cfg = SovereignConfig::load();
            if let Some(n) = name {
                cfg.operator.name = n;
            }
            if let Some(e) = email {
                cfg.operator.email = e;
            }
            if let Some(m) = mode {
                cfg.engine.mode = m;
            }
            if let Some(u) = api_url {
                cfg.engine.api_base_url = u;
            }
            if let Some(mid) = model_id {
                cfg.engine.model_id = mid;
            }

            cfg.save()
                .map_err(|e| format!("Failed to save config: {}", e))?;
            println!("⚡ Sovereign operator profile initialized successfully.");
            println!(
                "Configuration saved to: {:?}",
                SovereignConfig::config_path()
            );
            println!("Author signature: {}", cfg.author_string());
            println!(
                "Engine mode: {} ({})",
                cfg.engine.mode, cfg.engine.api_base_url
            );
        }
        Commands::Profile => {
            let cfg = SovereignConfig::load();
            println!("{}", toml::to_string_pretty(&cfg)?);
        }
        Commands::Observe { path } => {
            let snap = observe_codebase(Path::new(&path))
                .map_err(|e| format!("Failed to observe codebase: {}", e))?;
            println!("{}", serde_json::to_string_pretty(&snap)?);
        }
        Commands::Propose { path } => {
            let repo_path = Path::new(&path);
            if let Some(prop) = ProposalGenerator::scan_and_propose_unslop(repo_path) {
                println!("{}", serde_json::to_string_pretty(&prop)?);
            } else {
                println!(
                    "{}",
                    serde_json::json!({"status": "no_improvements_proposed", "note": "Working tree conforms to invariants."})
                );
            }
        }
        Commands::Verify { path } => {
            let report = InvariantVerifier::run_full_verification(Path::new(&path));
            println!("{}", serde_json::to_string_pretty(&report)?);
            if !report.passed {
                std::process::exit(1);
            }
        }
        Commands::Balance { drive, humanity } => {
            let verdict = BalanceKernel::evaluate(drive, humanity);
            println!("{}", serde_json::to_string_pretty(&verdict)?);
        }
        Commands::BalanceSimd {
            d0,
            d1,
            d2,
            d3,
            h0,
            h1,
            h2,
            h3,
        } => {
            let verdict = BalanceKernel::evaluate_simd([d0, d1, d2, d3], [h0, h1, h2, h3]);
            println!("{}", serde_json::to_string_pretty(&verdict)?);
        }
        Commands::Judge {
            cycle_id,
            candidate_id,
            parent_id,
            candidate_path,
            parent_path,
            holdouts_dir,
            output_dir,
            signing_key_hex,
            signing_key_file,
            require_latency_improvement,
            non_inferiority_margin_pct,
            subject_path,
            policy_file,
            executable,
            build_release,
        } => {
            let policy_file = flag_or_env(policy_file, JUDGE_POLICY_ENV);
            match (&policy_file, &subject_path) {
                (Some(_), None) => {
                    return Err(
                        "a judge policy is configured but --subject-path is missing; \
                                refusing to fall back to a version 1 receipt"
                            .into(),
                    )
                }
                (None, Some(_)) => {
                    return Err(format!(
                        "--subject-path needs a policy (--policy-file or {})",
                        JUDGE_POLICY_ENV
                    )
                    .into())
                }
                (None, None) => eprintln!(
                    "no judge policy (--policy-file or {}): writing a version 1 receipt, \
                     which is history only and never promotes",
                    JUDGE_POLICY_ENV
                ),
                (Some(_), Some(_)) => {}
            }
            let judge_cli = spark_rsi::actor::JudgeCli {
                cycle_id,
                candidate_id,
                parent_id,
                candidate_path,
                parent_path,
                holdouts_dir,
                output_dir,
                signing_key_hex,
                signing_key_file,
                require_latency_improvement,
                non_inferiority_margin_pct,
                subject_path,
                policy_file,
                executable,
                build_release,
                public_key: false,
                print_holdout_digest: false,
            };
            spark_rsi::actor::judge::run_judge_cli(judge_cli)?;
        }
        Commands::Holdout { input } => {
            let res = spark_rsi::evaluate_holdout_case(&input);
            println!("{}", res);
        }
        Commands::Cycle {
            path,
            cortex_url,
            model_url,
            model_id,
            dual_price_vector_dir,
            judge_public_key,
            judge_policy_file,
        } => {
            let (judge_public_key_hex, judge_policy_file) =
                validated_judge_pins(judge_public_key, judge_policy_file)?;
            let config = RsiConfig {
                target_repo: path,
                cortex_url,
                cortex_space: "atlas-memory".to_string(),
                loop_interval_secs: 60,
                sandbox_root: "/tmp/spark-rsi-sandbox".to_string(),
                rsi_root: ".rsi".to_string(),
                holdouts_dir: None,
                signing_key_hex: None,
                require_latency_improvement: false,
                model_url,
                model_id,
                canary_target: 5000,
                operator_key_hex: None,
                non_inferiority_margin: None,
                ratify_roots: spark_rsi::diff_gate::default_ratify_roots(),
                dual_price_vector_dir,
                judge_public_key_hex,
                judge_policy_file,
                ..RsiConfig::default()
            };
            let result = RsiEngine::run_cycle(&config).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Commands::Daemon {
            path,
            interval,
            cortex_url,
            model_url,
            model_id,
            dual_price_vector_dir,
            judge_public_key,
            judge_policy_file,
        } => {
            let (judge_public_key_hex, judge_policy_file) =
                validated_judge_pins(judge_public_key, judge_policy_file)?;
            let config = RsiConfig {
                target_repo: path,
                cortex_url,
                cortex_space: "atlas-memory".to_string(),
                loop_interval_secs: interval,
                sandbox_root: "/tmp/spark-rsi-sandbox".to_string(),
                rsi_root: ".rsi".to_string(),
                holdouts_dir: None,
                signing_key_hex: None,
                require_latency_improvement: false,
                model_url,
                model_id,
                canary_target: 5000,
                operator_key_hex: None,
                non_inferiority_margin: None,
                ratify_roots: spark_rsi::diff_gate::default_ratify_roots(),
                dual_price_vector_dir,
                judge_public_key_hex,
                judge_policy_file,
                ..RsiConfig::default()
            };
            RsiEngine::run_daemon(config).await?;
        }
        Commands::Ledger { action } => match action {
            LedgerCommands::Log { rsi_root, limit } => {
                let ledger = spark_rsi::ledger::ImprovementLedger::open(Path::new(&rsi_root))?;
                let blocks = ledger.all_blocks()?;
                let start_idx = blocks.len().saturating_sub(limit);
                println!(
                    "=== Improvement Ledger Log ({} blocks total) ===",
                    blocks.len()
                );
                for b in &blocks[start_idx..] {
                    println!(
                        "[#{:04}] {:<18} | Hash: {}.. | Prev: {}.. | Blobs: {}",
                        b.sequence,
                        b.block_type.to_string(),
                        &b.block_hash[..12],
                        &b.prev_block_hash[..12],
                        b.blob_hashes.len()
                    );
                }
            }
            LedgerCommands::Verify {
                rsi_root,
                verifying_key_hex,
            } => {
                let ledger = spark_rsi::ledger::ImprovementLedger::open(Path::new(&rsi_root))?;
                let mut vk = None;
                if let Some(ref hex_str) = verifying_key_hex {
                    let bytes = hex::decode(hex_str)?;
                    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&bytes)?;
                    vk = Some(key);
                }
                match ledger.verify_chain_integrity(vk.as_ref()) {
                    Ok(report) => {
                        let gaps = report.unchecked(vk.is_some());
                        if gaps.is_empty() {
                            println!("⚡ Ledger Verification: PASS");
                        } else {
                            println!(
                                "⚠️ Ledger Verification: PARTIAL. Hash chain and blobs verified; not checked: {}",
                                gaps.join("; ")
                            );
                        }
                        println!("{}", serde_json::to_string_pretty(&report)?);
                    }
                    Err(e) => {
                        eprintln!("❌ Ledger Verification FAILED: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            LedgerCommands::Checkpoint {
                rsi_root,
                signing_key_hex,
                signing_key_file,
            } => {
                let signing_key_hex =
                    key_hex(signing_key_hex, signing_key_file, LEDGER_SIGNING_KEY_ENV)?;
                let ledger = spark_rsi::ledger::ImprovementLedger::open(Path::new(&rsi_root))?;
                let mut sk = None;
                if let Some(ref hex_str) = signing_key_hex {
                    let bytes = hex::decode(hex_str)?;
                    let key = p256::ecdsa::SigningKey::from_slice(&bytes)?;
                    sk = Some(key);
                }
                let cp = ledger.checkpoint(sk.as_ref())?;
                println!("⚡ Merkle Checkpoint Created");
                println!("{}", serde_json::to_string_pretty(&cp)?);
            }
            LedgerCommands::Evidence {
                rsi_root,
                candidate_hash,
                downstream_cycle,
                downstream_hash,
                proof,
            } => {
                let ledger = spark_rsi::ledger::ImprovementLedger::open(Path::new(&rsi_root))?;
                let payload = spark_rsi::ledger::PromotionEvidencePayload {
                    meta_candidate_block_hash: candidate_hash,
                    downstream_cycle_id: downstream_cycle,
                    downstream_ledger_block_hash: downstream_hash,
                    capability_improvement_proof: proof,
                    final_classification: "TRUE_RSI".to_string(),
                };
                let blk = ledger.append_promotion_evidence(&payload)?;
                println!("⚡ PromotionEvidence Block Appended: #{}", blk.sequence);
                println!("{}", serde_json::to_string_pretty(&blk)?);
            }
        },
        Commands::Soak {
            path,
            rsi_root,
            cycles,
            candidates,
            cortex_url,
            model_url,
            model_id,
            signing_key_hex,
            signing_key_file,
            operator_key_hex,
            holdouts_dir,
            margin,
        } => {
            let signing_key_hex = key_hex(signing_key_hex, signing_key_file, SOAK_SIGNING_KEY_ENV)?;
            let config = spark_rsi::soak::SoakConfig {
                target_repo: path,
                rsi_root,
                sandbox_root: "/tmp/spark-rsi-soak".to_string(),
                holdouts_dir,
                signing_key_hex,
                operator_key_hex,
                cortex_url,
                cortex_space: "atlas-memory".to_string(),
                model_url,
                model_id,
                total_cycles: cycles,
                candidates_per_cycle: candidates,
                canary_target: 5000,
                non_inferiority_margin: margin.or(Some(10.0)),
                writable_prefixes: vec![
                    "src/propose/".to_string(),
                    "src/graph/".to_string(),
                    "src/observe.rs".to_string(),
                ],
            };
            let manifest = spark_rsi::soak::SoakRunner::run_batch(&config)
                .await
                .map_err(|e| format!("Soak run failed: {}", e))?;
            println!("{}", serde_json::to_string_pretty(&manifest)?);
        }
        Commands::Philosophy => {
            let philosophy_file = Path::new("docs/PHILOSOPHY.md");
            if philosophy_file.exists() {
                let content = std::fs::read_to_string(philosophy_file)?;
                println!("{}", content);
            } else {
                println!("# Sovereign Programming Philosophy\n\nSee docs/PHILOSOPHY.md for full manifesto.");
            }
        }
    }

    Ok(())
}
