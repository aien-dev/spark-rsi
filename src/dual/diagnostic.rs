//! Scarcity diagnostic for RSI (ADR 0031 section 7.5 and 10).
//!
//! RSI may read a verified `DualPriceVector` as telemetry: the resource with
//! the largest FRESH, calibrated lambda is the dominant current scarcity.
//! That is all this type says. It never feeds `rank_bottlenecks`, a layer's
//! `is_hard_invariant`, admission, ratification or promotion. A missing,
//! stale, refused or uncalibrated price is reported as unavailable, never as
//! zero scarcity.

use super::records::{
    decode_constraint, decode_price_vector, digest_constraint, digest_price_vector, Class,
    ConstraintState, Digest32, LambdaState, PriceVector, Refusal, Unit,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Why no dominant scarcity can be stated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UnavailableReason {
    /// No price vector configured, or a referenced constraint record absent.
    Missing,
    /// Verified vector, no FRESH price, at least one STALE.
    Stale,
    /// Verified vector, no FRESH or STALE price, at least one FROZEN.
    Frozen,
    /// Verified vector, every price UNCALIBRATED.
    Uncalibrated,
    /// A record failed the DUAL checker, or a state carries REFUSED and nothing fresher.
    Refused,
    /// A supplied digest did not match the record it names.
    DigestMismatch,
    /// Bytes are not a well-formed record (kind, version, length).
    Malformed,
}

impl UnavailableReason {
    pub fn name(self) -> &'static str {
        match self {
            UnavailableReason::Missing => "MISSING",
            UnavailableReason::Stale => "STALE",
            UnavailableReason::Frozen => "FROZEN",
            UnavailableReason::Uncalibrated => "UNCALIBRATED",
            UnavailableReason::Refused => "REFUSED",
            UnavailableReason::DigestMismatch => "DIGEST_MISMATCH",
            UnavailableReason::Malformed => "MALFORMED",
        }
    }
}

/// The only lambda state an `Available` diagnostic can carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FreshState {
    #[serde(rename = "FRESH")]
    Fresh,
}

/// Diagnostic telemetry only. Two shapes, nothing else.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ScarcityDiagnostic {
    Available {
        resource_id: u32,
        unit: Unit,
        class: Class,
        /// True for CAPACITY: the price says what more capacity would be
        /// worth; it is never a relaxable scarcity.
        diagnostic_only: bool,
        lambda: f64,
        generation: u64,
        /// Hex of the constraint state's evidence root.
        evidence_root: String,
        state: FreshState,
    },
    Unavailable {
        reason: UnavailableReason,
        detail: String,
    },
}

impl Default for ScarcityDiagnostic {
    fn default() -> Self {
        ScarcityDiagnostic::Unavailable {
            reason: UnavailableReason::Missing,
            detail: "no price vector configured".to_string(),
        }
    }
}

impl ScarcityDiagnostic {
    fn unavailable(reason: UnavailableReason, detail: impl Into<String>) -> Self {
        ScarcityDiagnostic::Unavailable {
            reason,
            detail: detail.into(),
        }
    }

    pub fn is_available(&self) -> bool {
        matches!(self, ScarcityDiagnostic::Available { .. })
    }

    /// One plain sentence for a report or proposal rationale.
    pub fn summary(&self) -> String {
        match self {
            ScarcityDiagnostic::Available {
                resource_id,
                unit,
                class,
                diagnostic_only,
                lambda,
                generation,
                evidence_root,
                ..
            } => format!(
                "dominant fresh calibrated scarcity: resource {} ({}), class {}{}, lambda {}, generation {}, evidence root {}, state FRESH",
                resource_id,
                unit.name(),
                match class {
                    Class::Capacity => "CAPACITY",
                    Class::Soft => "SOFT",
                },
                if *diagnostic_only {
                    " (diagnostic only, never relaxable)"
                } else {
                    ""
                },
                lambda,
                generation,
                evidence_root
            ),
            ScarcityDiagnostic::Unavailable { reason, detail } => format!(
                "scarcity telemetry unavailable: price is {} ({})",
                reason.name(),
                detail
            ),
        }
    }

    /// Verify a price vector against the supplied constraint records and
    /// select the dominant scarcity.
    ///
    /// `expected_vector_digest`, when given, must equal the canonical digest
    /// of the decoded vector. Every `state[i]` digest in the vector must name
    /// one of `constraints` (compared by recomputed digest), that record's
    /// `resource_id` must equal `resource_id[i]`, and its `generation` must
    /// equal the vector's.
    ///
    /// Selection: among states that are FRESH with a nonzero calibration
    /// receipt, the largest lambda wins; on an exact tie the lowest
    /// `resource_id` wins (ids are strictly ascending, so the first such
    /// entry). Non-FRESH states are ignored for selection. If nothing is
    /// FRESH the reason is chosen by precedence REFUSED, STALE, FROZEN,
    /// UNCALIBRATED over the states present.
    pub fn from_records(
        price_vector: &[u8],
        constraints: &[&[u8]],
        expected_vector_digest: Option<&Digest32>,
    ) -> ScarcityDiagnostic {
        let vector = match decode_price_vector(price_vector) {
            Ok(v) => v,
            Err(r) => return Self::refusal("price vector", r),
        };
        if let Some(expected) = expected_vector_digest {
            let actual = digest_price_vector(&vector);
            if &actual != expected {
                return Self::unavailable(
                    UnavailableReason::DigestMismatch,
                    format!(
                        "price vector digest {} does not match expected {}",
                        hex::encode(actual),
                        hex::encode(expected)
                    ),
                );
            }
        }

        let mut decoded: Vec<(Digest32, ConstraintState)> = Vec::with_capacity(constraints.len());
        for (i, bytes) in constraints.iter().enumerate() {
            match decode_constraint(bytes) {
                Ok(s) => {
                    let d = digest_constraint(&s);
                    decoded.push((d, s));
                }
                Err(r) => return Self::refusal(&format!("constraint record {}", i), r),
            }
        }

        let mut states: Vec<&ConstraintState> = Vec::with_capacity(vector.entries.len());
        for (resource_id, state_digest) in &vector.entries {
            let found = decoded.iter().find(|(d, _)| d == state_digest);
            let Some((_, s)) = found else {
                return Self::unavailable(
                    UnavailableReason::Missing,
                    format!(
                        "no supplied constraint record has digest {} (resource {})",
                        hex::encode(state_digest),
                        resource_id
                    ),
                );
            };
            if s.resource_id != *resource_id {
                return Self::unavailable(
                    UnavailableReason::DigestMismatch,
                    format!(
                        "state digest for resource {} names a record for resource {}",
                        resource_id, s.resource_id
                    ),
                );
            }
            if s.generation != vector.generation {
                return Self::unavailable(
                    UnavailableReason::Refused,
                    format!(
                        "resource {} generation {} differs from vector generation {} ({})",
                        resource_id,
                        s.generation,
                        vector.generation,
                        Refusal::Generation
                    ),
                );
            }
            states.push(s);
        }

        Self::select_dominant(&vector, &states)
    }

    fn refusal(what: &str, r: Refusal) -> ScarcityDiagnostic {
        let reason = match r {
            Refusal::Kind | Refusal::Encoding => UnavailableReason::Malformed,
            _ => UnavailableReason::Refused,
        };
        Self::unavailable(reason, format!("{} refused: {}", what, r))
    }

    fn select_dominant(vector: &PriceVector, states: &[&ConstraintState]) -> ScarcityDiagnostic {
        let mut best: Option<&ConstraintState> = None;
        for s in states {
            if !s.is_fresh_calibrated() {
                continue;
            }
            best = match best {
                None => Some(s),
                Some(b) => {
                    if s.lambda > b.lambda
                        || (s.lambda == b.lambda && s.resource_id < b.resource_id)
                    {
                        Some(s)
                    } else {
                        Some(b)
                    }
                }
            };
        }
        if let Some(b) = best {
            return ScarcityDiagnostic::Available {
                resource_id: b.resource_id,
                unit: b.unit,
                class: b.class,
                diagnostic_only: b.class == Class::Capacity,
                lambda: b.lambda,
                generation: vector.generation,
                evidence_root: hex::encode(b.evidence_root),
                state: FreshState::Fresh,
            };
        }
        let has = |st: LambdaState| states.iter().any(|s| s.lambda_state == st);
        let (reason, state_name) = if has(LambdaState::Refused) {
            (UnavailableReason::Refused, "REFUSED")
        } else if has(LambdaState::Stale) {
            (UnavailableReason::Stale, "STALE")
        } else if has(LambdaState::Frozen) {
            (UnavailableReason::Frozen, "FROZEN")
        } else {
            (UnavailableReason::Uncalibrated, "UNCALIBRATED")
        };
        Self::unavailable(
            reason,
            format!(
                "no FRESH calibrated price in a verified vector of {} at generation {}; states include {}",
                states.len(),
                vector.generation,
                state_name
            ),
        )
    }

    /// Read a price vector from a directory laid out as:
    /// `price_vector.bin` (required), any number of `*.constraint.bin`, and
    /// an optional `price_vector.sha256` holding the expected digest as hex.
    /// A missing directory or missing `price_vector.bin` is `Missing`.
    pub fn load_from_dir(dir: &Path) -> ScarcityDiagnostic {
        let pv_path = dir.join("price_vector.bin");
        let pv_bytes = match std::fs::read(&pv_path) {
            Ok(b) => b,
            Err(e) => {
                return Self::unavailable(
                    UnavailableReason::Missing,
                    format!("cannot read {}: {}", pv_path.display(), e),
                )
            }
        };
        let expected: Option<Digest32> =
            match std::fs::read_to_string(dir.join("price_vector.sha256")) {
                Ok(text) => match hex::decode(text.trim()) {
                    Ok(v) if v.len() == 32 => {
                        let mut d = [0u8; 32];
                        d.copy_from_slice(&v);
                        Some(d)
                    }
                    _ => {
                        return Self::unavailable(
                            UnavailableReason::Malformed,
                            "price_vector.sha256 is not 32 bytes of hex",
                        )
                    }
                },
                Err(_) => None,
            };
        let mut constraint_files: Vec<Vec<u8>> = Vec::new();
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                return Self::unavailable(
                    UnavailableReason::Missing,
                    format!("cannot list {}: {}", dir.display(), e),
                )
            }
        };
        let mut names: Vec<std::path::PathBuf> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.ends_with(".constraint.bin"))
                    .unwrap_or(false)
            })
            .collect();
        names.sort();
        for p in names {
            match std::fs::read(&p) {
                Ok(b) => constraint_files.push(b),
                Err(e) => {
                    return Self::unavailable(
                        UnavailableReason::Missing,
                        format!("cannot read {}: {}", p.display(), e),
                    )
                }
            }
        }
        let refs: Vec<&[u8]> = constraint_files.iter().map(|v| v.as_slice()).collect();
        Self::from_records(&pv_bytes, &refs, expected.as_ref())
    }
}
