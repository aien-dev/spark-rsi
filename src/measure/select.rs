//! Picks compatible completed samples and turns them into per-stage measurements.

use super::profile::MeasureContext;
use super::stats;
use super::{CycleSampleRecord, Stage, StageOutcome};
use crate::graph::{CapabilityGraph, CapabilityNode};
use crate::models::RsiConfig;
use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Clone, PartialEq)]
pub enum StageMeasurement {
    Measured {
        latency_median_us: f64,
        /// None until `measure_p95_min_samples` valid compatible samples exist.
        latency_p95_us: Option<f64>,
        /// Share of compatible samples whose outcome was `failed`.
        error_rate: f64,
        sample_count: usize,
    },
    Unavailable {
        reason: String,
        sample_count: usize,
    },
}

fn node_meta(stage: Stage) -> (&'static str, &'static str) {
    match stage {
        Stage::Observe => ("Observe Subsystem", "observe"),
        Stage::Propose => ("Propose Subsystem", "propose"),
        Stage::BuildJail => ("Build Jail", "isolation"),
        Stage::JudgeEvaluation => ("Judge Evaluation", "actor"),
        Stage::SupervisorCanary => ("Supervisor Canary", "supervisor"),
        Stage::CortexCommit => ("Cortex Commit", "ratify"),
    }
}

/// Measurements for all six stages from completed prior cycles. Never reads the current cycle.
/// A rejected (non-finite or negative) or unreadable input makes every stage unavailable with
/// the reason; nothing is clamped or defaulted.
pub fn measure_stages(
    records: Result<Vec<CycleSampleRecord>, String>,
    current_cycle_id: &str,
    ctx: &MeasureContext,
    config: &RsiConfig,
) -> BTreeMap<Stage, StageMeasurement> {
    let attempt = records.and_then(|r| {
        try_measure(
            &r,
            current_cycle_id,
            ctx,
            config.measure_min_samples,
            config.measure_window_cycles,
            config.measure_p95_min_samples,
        )
    });
    match attempt {
        Ok(m) => m,
        Err(e) => Stage::ALL
            .iter()
            .map(|s| {
                (
                    *s,
                    StageMeasurement::Unavailable {
                        reason: format!("stage samples were rejected: {e}"),
                        sample_count: 0,
                    },
                )
            })
            .collect(),
    }
}

pub fn try_measure(
    records: &[CycleSampleRecord],
    current_cycle_id: &str,
    ctx: &MeasureContext,
    min_samples: usize,
    window_cycles: usize,
    p95_min_samples: usize,
) -> Result<BTreeMap<Stage, StageMeasurement>, String> {
    let mut seen = HashSet::new();
    let compatible: Vec<&CycleSampleRecord> = records
        .iter()
        .filter(|r| r.cycle_id != current_cycle_id)
        .filter(|r| r.workload_key == ctx.workload_key)
        .filter(|r| r.execution_profile_fingerprint == ctx.fingerprint)
        .filter(|r| seen.insert(r.cycle_id.clone()))
        .collect();
    let start = compatible.len().saturating_sub(window_cycles);
    let window = &compatible[start..];

    let mut out = BTreeMap::new();
    for stage in Stage::ALL {
        let mut durations = Vec::new();
        let mut failed = 0usize;
        for rec in window {
            let mut hits = rec.stages.iter().filter(|s| s.stage == stage);
            if let Some(sample) = hits.next() {
                if hits.next().is_some() {
                    return Err(format!(
                        "cycle {} records stage {} twice",
                        rec.cycle_id,
                        stage.id()
                    ));
                }
                durations.push(sample.duration_us as f64);
                if sample.outcome == StageOutcome::Failed {
                    failed += 1;
                }
            }
        }
        let n = durations.len();
        let m = if n < min_samples {
            StageMeasurement::Unavailable {
                reason: format!(
                    "fewer than {min_samples} compatible completed samples in the last {window_cycles} cycles (found {n})"
                ),
                sample_count: n,
            }
        } else {
            StageMeasurement::Measured {
                latency_median_us: stats::median(&durations)?,
                latency_p95_us: stats::p95_if_sufficient(&durations, p95_min_samples)?,
                error_rate: failed as f64 / n as f64,
                sample_count: n,
            }
        };
        out.insert(stage, m);
    }
    Ok(out)
}

/// The six-node pipeline graph. Edges are topology only; no edge latency feeds any score.
pub fn build_capability_graph(
    measurements: &BTreeMap<Stage, StageMeasurement>,
) -> Result<CapabilityGraph, String> {
    let mut graph = CapabilityGraph::new();
    for stage in Stage::ALL {
        let (name, subsystem) = node_meta(stage);
        let node = CapabilityNode::new(stage.id(), name, subsystem);
        let node = match measurements.get(&stage) {
            Some(StageMeasurement::Measured {
                latency_median_us,
                latency_p95_us,
                error_rate,
                sample_count,
            }) => node.with_measured_latency(
                *latency_median_us,
                *latency_p95_us,
                *error_rate,
                *sample_count,
            )?,
            Some(StageMeasurement::Unavailable {
                reason,
                sample_count,
            }) => node.with_unavailable(reason, *sample_count),
            None => node.with_unavailable("stage was not measured", 0),
        };
        graph.add_node(node);
    }
    for pair in Stage::ALL.windows(2) {
        graph.add_edge(pair[0].id(), pair[1].id(), 0.0, 1.0);
    }
    Ok(graph)
}
