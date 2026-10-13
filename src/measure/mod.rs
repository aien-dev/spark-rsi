//! M1 Measurement: stage samples from completed cycles, never constants.
//!
//! Vocabulary follows CONTEXT.md: stage, stage sample, partial cycle, workload key,
//! execution-profile fingerprint, measured, unavailable, cold start.
//!
//! A cycle that ends with an error is a partial cycle: its samples go to
//! `partial-cycles.jsonl` and are never ranked. A cycle that ends early for a normal reason
//! (no candidate, judge refused, canary quota refused) is complete for the stages it ran.

pub mod claims;
pub mod log;
pub mod profile;
pub mod select;
pub mod stats;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;

pub use claims::{check_claim, requires_measured_diagnosis};
pub use log::{SampleLog, COMPLETE_FILE, MEASURE_DIR, PARTIAL_FILE};
pub use profile::{ExecutionConfig, ExecutionProfile, MeasureContext};
pub use select::{build_capability_graph, measure_stages, StageMeasurement};
pub use stats::{median, p95_if_sufficient, percentile_nearest_rank, validate_samples};

pub const SCHEMA_VERSION: u32 = 1;

/// The six RSI pipeline stages, in pipeline order. These are the capability graph nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Stage {
    Observe,
    Propose,
    BuildJail,
    JudgeEvaluation,
    SupervisorCanary,
    CortexCommit,
}

impl Stage {
    pub const ALL: [Stage; 6] = [
        Stage::Observe,
        Stage::Propose,
        Stage::BuildJail,
        Stage::JudgeEvaluation,
        Stage::SupervisorCanary,
        Stage::CortexCommit,
    ];

    /// The capability graph node id.
    pub fn id(self) -> &'static str {
        match self {
            Stage::Observe => "Observe",
            Stage::Propose => "Propose",
            Stage::BuildJail => "BuildJail",
            Stage::JudgeEvaluation => "JudgeEvaluation",
            Stage::SupervisorCanary => "SupervisorCanary",
            Stage::CortexCommit => "CortexCommit",
        }
    }
}

/// How a stage ended. Worst outcome wins when a stage runs once per candidate:
/// `Failed` over `Refused` over `Ok`. Only `Failed` counts toward the error rate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StageOutcome {
    Ok,
    /// A normal refusal: invariants or judge said no, the canary quota was not met.
    Refused,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageSample {
    pub stage: Stage,
    pub duration_us: u64,
    pub outcome: StageOutcome,
    /// Recorded on SupervisorCanary samples only. Not part of the fingerprint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canary_protocol_version: Option<u16>,
}

/// One record per cycle in `stage-samples.jsonl` (complete) or `partial-cycles.jsonl` (partial).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CycleSampleRecord {
    pub schema_version: u32,
    pub cycle_id: String,
    pub workload_key: String,
    pub execution_profile_fingerprint: String,
    pub execution_profile: ExecutionProfile,
    /// Every stage that ran, in pipeline order.
    pub stages: Vec<StageSample>,
    /// Target repository HEAD when the cycle began. Provenance only, never part of the key.
    pub source_commit: Option<String>,
    pub recorded_at: String,
}

/// Collects per-stage wall time inside one cycle. A stage that runs more than once (once per
/// candidate) has its durations summed and its worst outcome kept.
#[derive(Debug, Default)]
pub struct StageClock {
    stages: BTreeMap<Stage, (u64, StageOutcome)>,
}

/// Records a stage on drop: `Failed` unless [`StageGuard::complete`] ran first. A stage that
/// ends with an early `?` return still leaves its sample in the partial-cycle set.
pub struct StageGuard<'a> {
    clock: &'a mut StageClock,
    stage: Stage,
    started: std::time::Instant,
    armed: bool,
}

impl StageGuard<'_> {
    pub fn complete(mut self, outcome: StageOutcome) {
        self.armed = false;
        self.clock
            .record(self.stage, self.started.elapsed(), outcome);
    }
}

impl Drop for StageGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.clock
                .record(self.stage, self.started.elapsed(), StageOutcome::Failed);
        }
    }
}

impl StageClock {
    pub fn new() -> Self {
        Self::default()
    }

    /// Starts timing `stage`; the guard records `Failed` if dropped before `complete`.
    pub fn guard(&mut self, stage: Stage) -> StageGuard<'_> {
        StageGuard {
            clock: self,
            stage,
            started: std::time::Instant::now(),
            armed: true,
        }
    }

    pub fn record(&mut self, stage: Stage, elapsed: Duration, outcome: StageOutcome) {
        let us = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        let entry = self.stages.entry(stage).or_insert((0, outcome));
        entry.0 = entry.0.saturating_add(us);
        entry.1 = entry.1.max(outcome);
    }

    /// Wall time recorded so far for a stage.
    pub fn duration(&self, stage: Stage) -> Duration {
        Duration::from_micros(self.stages.get(&stage).map(|s| s.0).unwrap_or(0))
    }

    pub fn is_empty(&self) -> bool {
        self.stages.is_empty()
    }

    pub fn samples(&self) -> Vec<StageSample> {
        self.stages
            .iter()
            .map(|(stage, (duration_us, outcome))| StageSample {
                stage: *stage,
                duration_us: *duration_us,
                outcome: *outcome,
                canary_protocol_version: (*stage == Stage::SupervisorCanary)
                    .then_some(crate::canary::CANARY_PROTOCOL_VERSION),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_records_failed_on_early_return_and_the_outcome_on_complete() {
        fn early(clock: &mut StageClock) -> Result<(), String> {
            let _guard = clock.guard(Stage::Observe);
            Err("boom".to_string())
        }
        let mut clock = StageClock::new();
        assert!(early(&mut clock).is_err());
        let samples = clock.samples();
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].stage, Stage::Observe);
        assert_eq!(samples[0].outcome, StageOutcome::Failed);

        let mut clock = StageClock::new();
        clock.guard(Stage::Propose).complete(StageOutcome::Ok);
        assert_eq!(clock.samples()[0].outcome, StageOutcome::Ok);
    }
}
