use clap::Parser;
use spark_rsi::supervisor::daemon::{SupervisorConfig, SupervisorDaemon};
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

    #[arg(long, default_value = "sovereign-spark-tpm-key")]
    shared_secret: String,
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

    let config = SupervisorConfig {
        rsi_root: args.rsi_root,
        socket_path: args.socket_path,
        memory_limit_mb: args.memory_limit_mb,
        canary_target: args.canary_target,
        shared_secret: args.shared_secret,
    };

    let daemon = SupervisorDaemon::new(config);
    daemon.run_server(args.active_link).await?;

    Ok(())
}
