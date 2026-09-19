use clap::{Parser, Subcommand};
use spark_rsi::balance::BalanceKernel;
use spark_rsi::config::SovereignConfig;
use spark_rsi::daemon::RsiEngine;
use spark_rsi::models::RsiConfig;
use spark_rsi::observe::observe_codebase;
use spark_rsi::propose::ProposalGenerator;
use spark_rsi::verifier::InvariantVerifier;
use std::path::Path;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser, Debug)]
#[command(
    name = "spark-rsi",
    about = "Native Rust and Mojo Recursive Self-Improvement Engine on SparkOS",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
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
    /// Evaluate drive versus humanity tension via the Mojo balance kernel
    Balance {
        drive: f64,
        humanity: f64,
        #[arg(long, default_value = "mojo/balance_bin")]
        kernel: String,
    },
    /// Evaluate 4-lane SIMD drive and humanity vectors via the Mojo balance kernel
    BalanceSimd {
        d0: f32,
        d1: f32,
        d2: f32,
        d3: f32,
        h0: f32,
        h1: f32,
        h2: f32,
        h3: f32,
        #[arg(long, default_value = "mojo/balance_bin")]
        kernel: String,
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
    },
    /// Run a single end-to-end RSI cycle (Observe, Propose, Verify, Balance, Ratify)
    Cycle {
        #[arg(default_value = ".")]
        path: String,
        #[arg(long, default_value = "mojo/balance_bin")]
        kernel: String,
        #[arg(long, default_value = "http://127.0.0.1:18080")]
        cortex_url: String,
    },
    /// Run the continuous recursive self-improvement daemon loop
    Daemon {
        #[arg(default_value = ".")]
        path: String,
        #[arg(short, long, default_value = "60")]
        interval: u64,
        #[arg(long, default_value = "mojo/balance_bin")]
        kernel: String,
        #[arg(long, default_value = "http://127.0.0.1:18080")]
        cortex_url: String,
    },
    /// Display the sovereign programming philosophy manifesto
    Philosophy,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init { name, email, mode, api_url, model_id } => {
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

            cfg.save().map_err(|e| format!("Failed to save config: {}", e))?;
            println!("⚡ Sovereign operator profile initialized successfully.");
            println!("Configuration saved to: {:?}", SovereignConfig::config_path());
            println!("Author signature: {}", cfg.author_string());
            println!("Engine mode: {} ({})", cfg.engine.mode, if cfg.engine.mode == "max" { "Deploy over Modular MAX (Rust/Mojo)" } else { &cfg.engine.api_base_url });
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
                println!("{}", serde_json::json!({"status": "no_improvements_proposed", "note": "Working tree conforms to invariants."}));
            }
        }
        Commands::Verify { path } => {
            let report = InvariantVerifier::run_full_verification(Path::new(&path));
            println!("{}", serde_json::to_string_pretty(&report)?);
            if !report.passed {
                std::process::exit(1);
            }
        }
        Commands::Balance { drive, humanity, kernel } => {
            let verdict = BalanceKernel::evaluate(drive, humanity, Some(&kernel))?;
            println!("{}", serde_json::to_string_pretty(&verdict)?);
        }
        Commands::BalanceSimd { d0, d1, d2, d3, h0, h1, h2, h3, kernel } => {
            let verdict = BalanceKernel::evaluate_simd([d0, d1, d2, d3], [h0, h1, h2, h3], Some(&kernel))?;
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
        } => {
            let judge_cli = spark_rsi::actor::JudgeCli {
                cycle_id,
                candidate_id,
                parent_id,
                candidate_path,
                parent_path,
                holdouts_dir,
                output_dir,
            };
            spark_rsi::actor::judge::run_judge_cli(judge_cli)?;
        }
        Commands::Cycle { path, kernel, cortex_url } => {
            let config = RsiConfig {
                target_repo: path,
                cortex_url,
                cortex_space: "atlas-memory".to_string(),
                mojo_kernel_path: kernel,
                loop_interval_secs: 60,
                sandbox_root: "/tmp/spark-rsi-sandbox".to_string(),
            };
            let result = RsiEngine::run_cycle(&config).await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Commands::Daemon { path, interval, kernel, cortex_url } => {
            let config = RsiConfig {
                target_repo: path,
                cortex_url,
                cortex_space: "atlas-memory".to_string(),
                mojo_kernel_path: kernel,
                loop_interval_secs: interval,
                sandbox_root: "/tmp/spark-rsi-sandbox".to_string(),
            };
            RsiEngine::run_daemon(config).await?;
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
