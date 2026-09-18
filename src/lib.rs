pub mod balance;
pub mod daemon;
pub mod models;
pub mod observe;
pub mod propose;
pub mod ratify;
pub mod verifier;

pub use balance::BalanceKernel;
pub use daemon::RsiEngine;
pub use models::*;
pub use observe::observe_codebase;
pub use propose::ProposalGenerator;
pub use ratify::Ratifier;
pub use verifier::InvariantVerifier;

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
