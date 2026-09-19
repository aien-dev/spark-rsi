pub mod balance;
pub mod config;
pub mod daemon;
pub mod isolation;
pub mod models;
pub mod observe;
pub mod propose;
pub mod ratify;
pub mod supervisor;
pub mod verifier;

pub use balance::BalanceKernel;
pub use config::{EngineConfig, OperatorProfile, SovereignConfig};
pub use daemon::RsiEngine;
pub use isolation::{
    ArtifactManifest, ArtifactRecord, BuildJail, CandidateManifest, GpuEvaluationJail,
    RollbackCheckpoint, RootOfTrust, SandboxLimits,
};
pub use models::*;
pub use observe::observe_codebase;
pub use propose::ProposalGenerator;
pub use ratify::Ratifier;
pub use supervisor::{GenerationInfo, GenerationState, HostSupervisor};
pub use verifier::InvariantVerifier;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
