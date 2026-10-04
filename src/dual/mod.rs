//! DUAL constraint-pricing reader for RSI (ADR 0031 / ARCH-0031, section 7.5).
//!
//! Diagnostic only. RSI reads `DualPriceVector` records as scarcity
//! telemetry and gains no authority from them:
//!
//! - nothing here is consulted by `CapabilityGraph::rank_bottlenecks`, whose
//!   fixed weights are unchanged;
//! - nothing here touches `LayerResult.is_hard_invariant`, admission,
//!   ratification or promotion;
//! - a missing, stale, frozen, refused or uncalibrated price is reported as
//!   `ScarcityDiagnostic::Unavailable`, never as zero scarcity;
//! - CAPACITY prices carry `diagnostic_only: true` and are never a relaxable
//!   scarcity.
//!
//! `records` ports the omega C checker and codec byte for byte (omega branch
//! `dual/0a-records`, commit f056b77f64ee94a80f4ed2899b5f9495aa3ef840) and
//! recomputes SHA-256 digests with the crate's existing `sha2` dependency.

pub mod diagnostic;
pub mod records;

pub use diagnostic::{FreshState, ScarcityDiagnostic, UnavailableReason};
pub use records::{
    decode_constraint, decode_controller, decode_price_vector, decode_resource, digest_constraint,
    digest_controller, digest_price_vector, digest_resource, domain_digest, encode_constraint,
    encode_controller, encode_price_vector, encode_resource, verify_digest, Class, ConstraintState,
    Controller, Digest32, EstimateKind, Kind, LambdaState, PriceVector, Refusal, Resource, Unit,
    VerifyError,
};
