use clap::Parser;
use spark_rsi::supervisor::daemon::{resolve_supervisor_secret, SupervisorConfig, SupervisorDaemon};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "spark-rsi-supervisor")]
#[command(about = "Standalone host supervisor daemon for spark-rsi generations on NVIDIA DGX Spark")]
struct Args {
    #[arg(long, default_value = ".rsi")]
    rsi_root: PathBuf,

    #[arg(long, default_value = ".rsi/supervisor.sock")]
    socket_path: PathBuf,

    #[arg(long, default_value = ".rsi/active.sock")]
    active_link: PathBuf,

    #[arg(long, default_value_t = 49152)]
    memory_limit_mb: u64,

    #[arg(long, default_value_t = 5000)]
    canary_target: u64,

    #[arg(long, default_value_t = 1_000_000)]
    max_latency_us: u64,

    #[arg(long, default_value_t = 0.0)]
    max_error_rate: f64,

    #[arg(long)]
    shared_secret: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    tracing::info!(
        rsi_root = ?args.rsi_root,
        socket = ?args.socket_path,
        "Starting spark-rsi Host Supervisor daemon"
    );

    let shared_secret = match args.shared_secret {
        Some(s) if !s.trim().is_empty() => s.trim().to_string(),
        _ => resolve_supervisor_secret(),
    };

    let config = SupervisorConfig {
        rsi_root: args.rsi_root,
        socket_path: args.socket_path,
        memory_limit_mb: args.memory_limit_mb,
        canary_target: args.canary_target,
        max_latency_us: args.max_latency_us,
        max_error_rate: args.max_error_rate,
        shared_secret,
    };

    let daemon = SupervisorDaemon::new(config);
    daemon.run_server(args.active_link).await?;

    Ok(())
}
