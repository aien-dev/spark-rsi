//! "Why does RSI want to change this?" as an evidence graph.
//!
//! This module turns the real artifacts of one RSI cycle (capability graph,
//! bottleneck ranking, hypothesis contract, diagnostic context, evaluation receipt,
//! ratification record) into the language-neutral evidence-graph contract
//! `aien.explain.evidence-graph` v1. The aienos `aienos-explain` crate builds the
//! grounded explanation path from that document and renders it; spark-rsi has no
//! compile-time dependency on aienos.
//!
//! Rules kept here:
//! - only explicit fields become links (ids, cycle ids, candidate ids); where RSI has
//!   no artifact for a link, the link is declared missing instead of invented;
//! - nothing here changes evaluation, safety, ratification or promotion; the
//!   explanation is observational and authorizes nothing;
//! - free-text "lessons" from the outside memory service and model output are not
//!   evidence and are never included.

use crate::evaluator::EvaluationReceipt;
use crate::graph::{BottleneckRank, CapabilityGraph};
use crate::models::RatificationRecord;
use crate::propose::diagnose::DiagnosticContext;
use crate::propose::hypothesis::HypothesisContract;
use serde::{Deserialize, Serialize};

pub const FORMAT: &str = "aien.explain.evidence-graph";
pub const VERSION: u16 = 1;
pub const PRODUCER: &str = "spark-rsi/explain";

// Contract codes (see aienos docs/EXPLAIN_EVIDENCE_GRAPH_V1.md).
pub const STATUS_UNCLASSIFIED: u8 = 0;
pub const STATUS_DIRECT_OBSERVATION: u8 = 1;
pub const STATUS_VERIFIED_FACT: u8 = 2;
pub const STATUS_INFERENCE: u8 = 3;
pub const STATUS_HYPOTHESIS: u8 = 4;

pub const KIND_CAPABILITY_METRIC: u16 = 2;
pub const KIND_CAPABILITY_ANALYSIS: u16 = 3;
pub const KIND_DIAGNOSTIC: u16 = 4;
pub const KIND_HYPOTHESIS: u16 = 5;
pub const KIND_PREDICTION: u16 = 6;
pub const KIND_FALSIFICATION: u16 = 7;
pub const KIND_EVALUATION_RECEIPT: u16 = 8;
pub const KIND_PROMOTION_STATE: u16 = 9;
pub const KIND_CONCLUSION: u16 = 12;
pub const KIND_ALTERNATIVE: u16 = 13;

pub const REL_SUPPORTED_BY: u16 = 1;
pub const REL_PART_OF: u16 = 3;
pub const REL_ALTERNATIVE_TO: u16 = 5;
pub const REL_REFERENCES: u16 = 6;

/// Most alternatives listed from the bottleneck ranking (rank 2 onward).
pub const MAX_ALTERNATIVES: usize = 3;
/// Contract cap on parents per node (`MAX_PARENTS_PER_NODE` in the contract).
pub const MAX_PARENTS: usize = 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRefDoc {
    pub system: String,
    pub artifact: String,
    pub reference: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeasurementDoc {
    pub name: String,
    pub value: String,
    #[serde(default)]
    pub unit: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeDoc {
    pub to: String,
    pub relation: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissingDoc {
    pub expected: String,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeDoc {
    pub id: String,
    pub kind: u16,
    pub status: u8,
    pub statement: String,
    pub source: SourceRefDoc,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence_permille: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence_basis: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded_at_utc: Option<u64>,
    #[serde(default)]
    pub parents: Vec<EdgeDoc>,
    #[serde(default)]
    pub measurements: Vec<MeasurementDoc>,
    #[serde(default)]
    pub missing: Vec<MissingDoc>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceGraphDoc {
    pub format: String,
    pub version: u16,
    pub producer: String,
    pub nodes: Vec<NodeDoc>,
    #[serde(default)]
    pub truncated_at: Vec<String>,
}

impl EvidenceGraphDoc {
    /// Canonical JSON bytes (struct field order, node order as built).
    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("evidence graph serializes")
    }

    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).expect("evidence graph serializes")
    }
}

/// Whether capability metrics were measured or written in by hand. The daemon's
/// current capability graph uses fixed constants, which are `Declared`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetricsOrigin {
    Measured,
    Declared,
}

/// The artifacts of one RSI cycle, all optional except the cycle id.
pub struct RsiCycleEvidence<'a> {
    pub cycle_id: &'a str,
    pub graph: Option<&'a CapabilityGraph>,
    pub metrics_origin: MetricsOrigin,
    /// Bottleneck ranking as returned by `CapabilityGraph::rank_bottlenecks`.
    pub bottlenecks: &'a [BottleneckRank],
    pub hypothesis: Option<&'a HypothesisContract>,
    pub diagnostic: Option<&'a DiagnosticContext>,
    pub receipt: Option<&'a EvaluationReceipt>,
    pub ratification: Option<&'a RatificationRecord>,
}

fn src(artifact: &str, reference: &str, digest: Option<String>) -> SourceRefDoc {
    SourceRefDoc {
        system: "spark-rsi".into(),
        artifact: artifact.into(),
        reference: reference.into(),
        digest,
    }
}

fn m(name: &str, value: String, unit: &str) -> MeasurementDoc {
    MeasurementDoc {
        name: name.into(),
        value,
        unit: unit.into(),
    }
}

fn node(id: String, kind: u16, status: u8, statement: String, source: SourceRefDoc) -> NodeDoc {
    NodeDoc {
        id,
        kind,
        status,
        statement,
        source,
        confidence_permille: None,
        confidence_basis: None,
        recorded_at_utc: None,
        parents: Vec::new(),
        measurements: Vec::new(),
        missing: Vec::new(),
        notes: Vec::new(),
    }
}

fn edge(to: &str, relation: u16) -> EdgeDoc {
    EdgeDoc {
        to: to.to_string(),
        relation,
    }
}

pub fn capability_node_id(node_id: &str) -> String {
    format!("rsi:capability:{node_id}")
}
pub fn analysis_id(cycle_id: &str) -> String {
    format!("rsi:bottleneck:{cycle_id}")
}
pub fn hypothesis_node_id(h: &HypothesisContract) -> String {
    format!("rsi:hypothesis:{}", h.id)
}
pub fn diagnostic_id(cycle_id: &str) -> String {
    format!("rsi:diagnostic:{cycle_id}")
}
pub fn receipt_node_id(r: &EvaluationReceipt) -> String {
    format!("rsi:receipt:{}:{}", r.cycle_id, r.candidate_id)
}
pub fn ratification_id(r: &RatificationRecord) -> String {
    format!("rsi:ratification:{}", r.proposal_id)
}
/// Id of the node to explain: "why does RSI want to change this?"
pub fn conclusion_id(cycle_id: &str) -> String {
    format!("rsi:conclusion:{cycle_id}")
}

/// True when the hypothesis was built from this bottleneck the way the daemon builds
/// it: the node name appears quoted in the problem or root cause text, and the
/// baseline is the bottleneck's p95 latency. This is a deterministic check on
/// explicit fields, not a guess; when it fails the link is declared missing.
pub fn hypothesis_derived_from(h: &HypothesisContract, b: &BottleneckRank) -> bool {
    let quoted = format!("'{}'", b.node_name);
    (h.observed_problem.contains(&quoted) || h.suspected_root_cause.contains(&quoted))
        && h.baseline_value == b.latency_p95_us
}

/// Build the evidence graph for one RSI cycle. Deterministic: node order is fixed,
/// capability nodes are sorted by id, numbers use fixed decimal formats.
pub fn evidence_graph(ev: &RsiCycleEvidence<'_>) -> EvidenceGraphDoc {
    let mut nodes: Vec<NodeDoc> = Vec::new();
    let cycle = ev.cycle_id;
    // Artifacts from another cycle are never attached; each mismatch is declared.
    let mut foreign: Vec<MissingDoc> = Vec::new();
    let mut same_cycle = |what: &str, id: &str, their_cycle: &str| -> bool {
        if their_cycle == cycle {
            true
        } else {
            foreign.push(MissingDoc {
                expected: format!("the {what} for cycle {cycle}"),
                reason: format!(
                    "the supplied {what} {id} belongs to cycle {their_cycle}; it was left out"
                ),
            });
            false
        }
    };
    let hypothesis = ev
        .hypothesis
        .filter(|h| same_cycle("hypothesis", &h.id, &h.cycle_id));
    let diagnostic = ev
        .diagnostic
        .filter(|d| same_cycle("diagnostic", &d.target_file, &d.cycle_id));
    let receipt = ev
        .receipt
        .filter(|r| same_cycle("evaluation receipt", &r.candidate_id, &r.cycle_id));
    let metric_status = match ev.metrics_origin {
        MetricsOrigin::Measured => STATUS_DIRECT_OBSERVATION,
        MetricsOrigin::Declared => STATUS_UNCLASSIFIED,
    };

    // Observed: capability metrics.
    let mut metric_ids: Vec<String> = Vec::new();
    if let Some(g) = ev.graph {
        let mut caps: Vec<_> = g.nodes.values().collect();
        caps.sort_by(|a, b| a.id.cmp(&b.id));
        for c in caps {
            let id = capability_node_id(&c.id);
            let mut n = node(
                id.clone(),
                KIND_CAPABILITY_METRIC,
                metric_status,
                format!(
                    "'{}' ({}) has p95 latency {:.1} us, error rate {:.2}%, resident memory {} KiB",
                    c.name,
                    c.subsystem,
                    c.latency_p95_us,
                    c.error_rate * 100.0,
                    c.memory_rss_kb
                ),
                src("CapabilityNode", &c.id, None),
            );
            n.measurements = vec![
                m("latency_p95_us", format!("{:.3}", c.latency_p95_us), "us"),
                m("error_rate", format!("{:.6}", c.error_rate), "fraction"),
                m("memory_rss_kb", c.memory_rss_kb.to_string(), "KiB"),
            ];
            if ev.metrics_origin == MetricsOrigin::Declared {
                n.notes.push(format!(
                    "metric values for '{}' were declared in the capability graph, not measured",
                    c.name
                ));
            }
            metric_ids.push(id);
            nodes.push(n);
        }
    }

    // System analysis: bottleneck ranking.
    let top = ev.bottlenecks.first();
    let analysis = top.map(|b| {
        let id = analysis_id(cycle);
        let mut n = node(
            id.clone(),
            KIND_CAPABILITY_ANALYSIS,
            STATUS_INFERENCE,
            format!(
                "The capability graph ranks '{}' ({}) as bottleneck #{} of {} ({})",
                b.node_name,
                b.subsystem,
                b.rank,
                ev.bottlenecks.len(),
                b.causal_explanation
            ),
            src("BottleneckRank", &b.node_id, None),
        );
        n.measurements = vec![
            m("bottleneck_score", format!("{:.4}", b.bottleneck_score), ""),
            m("centrality", format!("{:.4}", b.centrality), ""),
            m("latency_p95_us", format!("{:.3}", b.latency_p95_us), "us"),
            m("error_rate", format!("{:.6}", b.error_rate), "fraction"),
        ];
        if metric_ids.is_empty() {
            n.missing.push(MissingDoc {
                expected: "capability metrics the ranking was computed from".into(),
                reason: "no capability graph was supplied with this cycle".into(),
            });
        } else {
            n.parents = metric_ids
                .iter()
                .take(MAX_PARENTS)
                .map(|i| edge(i, REL_SUPPORTED_BY))
                .collect();
            if metric_ids.len() > MAX_PARENTS {
                n.notes.push(format!(
                    "only the first {MAX_PARENTS} of {} capability metrics are linked (contract cap)",
                    metric_ids.len()
                ));
            }
        }
        n.notes
            .push("ranking computed by CapabilityGraph::rank_bottlenecks".into());
        nodes.push(n);
        id
    });

    // Alternatives explicitly present in the ranking.
    if let Some(aid) = &analysis {
        for b in ev.bottlenecks.iter().skip(1).take(MAX_ALTERNATIVES) {
            let mut n = node(
                format!("rsi:alternative:{cycle}:{}", b.node_id),
                KIND_ALTERNATIVE,
                STATUS_INFERENCE,
                format!(
                    "Alternative bottleneck candidate #{}: '{}' ({}), score {:.4}",
                    b.rank, b.node_name, b.subsystem, b.bottleneck_score
                ),
                src("BottleneckRank", &b.node_id, None),
            );
            n.parents = vec![edge(aid, REL_ALTERNATIVE_TO)];
            n.measurements = vec![m(
                "bottleneck_score",
                format!("{:.4}", b.bottleneck_score),
                "",
            )];
            nodes.push(n);
        }
    }

    // Hypothesis, prediction, falsification.
    let mut hyp_ids: Option<(String, String, String)> = None;
    if let Some(h) = hypothesis {
        let hid = hypothesis_node_id(h);
        let mut n = node(
            hid.clone(),
            KIND_HYPOTHESIS,
            STATUS_HYPOTHESIS,
            format!(
                "Suspected root cause: {}. Observed problem: {}",
                h.suspected_root_cause, h.observed_problem
            ),
            src("HypothesisContract", &h.id, None),
        );
        if h.confidence_score.is_finite() {
            n.confidence_permille =
                Some((h.confidence_score.clamp(0.0, 1.0) * 1000.0).round() as u16);
            n.confidence_basis = Some("declared in the HypothesisContract, not measured".into());
        }
        match (top, &analysis) {
            (Some(b), Some(aid)) if hypothesis_derived_from(h, b) => {
                // A text and value match, not a recorded id: kept as a weak
                // "references" link and the missing id is declared.
                n.parents = vec![edge(aid, REL_REFERENCES)];
                n.missing.push(MissingDoc {
                    expected: "a recorded reference from the hypothesis to the bottleneck ranking"
                        .into(),
                    reason: format!(
                        "linked only because the hypothesis text names '{}' and its baseline \
                         equals that bottleneck's p95 latency",
                        b.node_name
                    ),
                });
            }
            _ => n.missing.push(MissingDoc {
                expected: "the system analysis this hypothesis was derived from".into(),
                reason: "the HypothesisContract carries no bottleneck reference and does not \
                         match the top-ranked bottleneck"
                    .into(),
            }),
        }
        if let Err(e) = h.validate() {
            n.notes
                .push(format!("hypothesis contract fails validation: {e}"));
        }
        nodes.push(n);

        let pid = format!("{hid}:prediction");
        let mut p = node(
            pid.clone(),
            KIND_PREDICTION,
            STATUS_HYPOTHESIS,
            format!(
                "Predicts {} improves by {:.1}% from baseline {:.3}",
                h.target_metric, h.predicted_delta_pct, h.baseline_value
            ),
            src("HypothesisContract", &h.id, None),
        );
        p.parents = vec![edge(&hid, REL_PART_OF)];
        p.measurements = vec![
            m("target_metric", h.target_metric.clone(), ""),
            m("baseline_value", format!("{:.3}", h.baseline_value), ""),
            m(
                "predicted_delta_pct",
                format!("{:.3}", h.predicted_delta_pct),
                "%",
            ),
        ];
        nodes.push(p);

        let fid = format!("{hid}:falsification");
        let protected: Vec<String> = h
            .protected_metrics
            .iter()
            .map(|pm| {
                format!(
                    "{} may degrade at most {:.1}%",
                    pm.name, pm.max_allowed_degradation_pct
                )
            })
            .collect();
        let mut f = node(
            fid.clone(),
            KIND_FALSIFICATION,
            STATUS_HYPOTHESIS,
            if h.falsification_test.is_empty() {
                format!("Protected metrics: {}", protected.join("; "))
            } else {
                format!(
                    "Refuted if this check fails: {}. Protected metrics: {}",
                    h.falsification_test,
                    protected.join("; ")
                )
            },
            src("HypothesisContract", &h.id, None),
        );
        f.parents = vec![edge(&hid, REL_PART_OF)];
        f.measurements = h
            .protected_metrics
            .iter()
            .map(|pm| {
                m(
                    &format!("protected.{}.max_degradation_pct", pm.name),
                    format!("{:.3}", pm.max_allowed_degradation_pct),
                    "%",
                )
            })
            .collect();
        if h.falsification_test.is_empty() {
            f.missing.push(MissingDoc {
                expected: "a falsification test".into(),
                reason: "the HypothesisContract has an empty falsification_test".into(),
            });
        }
        nodes.push(f);
        hyp_ids = Some((hid, pid, fid));
    }

    // Diagnostic context (explicitly carries the hypothesis it was built with).
    let diag_id = diagnostic.map(|d| {
        let id = diagnostic_id(cycle);
        let mut n = node(
            id.clone(),
            KIND_DIAGNOSTIC,
            STATUS_INFERENCE,
            format!(
                "Diagnosis for {}: primary defect {:?}; {}",
                d.target_file,
                d.primary_defect,
                if d.violations.is_empty() {
                    "no violations listed".to_string()
                } else {
                    d.violations.join("; ")
                }
            ),
            src("DiagnosticContext", &d.cycle_id, None),
        );
        match (&d.hypothesis, &hyp_ids) {
            (Some(dh), Some((hid, _, _))) if hypothesis.map(|h| h.id == dh.id) == Some(true) => {
                n.parents = vec![edge(hid, REL_SUPPORTED_BY)];
            }
            (Some(dh), _) => n.missing.push(MissingDoc {
                expected: format!("hypothesis {}", dh.id),
                reason: "the diagnostic names a hypothesis that was not supplied".into(),
            }),
            (None, _) => n.missing.push(MissingDoc {
                expected: "the hypothesis behind this diagnosis".into(),
                reason: "the DiagnosticContext carries no hypothesis".into(),
            }),
        }
        if !d.past_lessons.is_empty() {
            n.notes.push(format!(
                "{} recalled lesson(s) from the outside memory service were left out: they are \
                 free text, not evidence",
                d.past_lessons.len()
            ));
        }
        nodes.push(n);
        id
    });

    // Evaluation receipt. The receipt digest covers cycle, candidate, parent, the
    // admitted flag and the layer results only, so only those are stated on the
    // receipt node (verified when the digest matches). The gate flags and the metrics
    // summary are not covered by the digest; they go on a separate node whose status
    // stays unknown.
    let receipt_ids = receipt.map(|r| {
        let id = receipt_node_id(r);
        let digest_ok = r.verify_digest();
        let mut n = node(
            id.clone(),
            KIND_EVALUATION_RECEIPT,
            if digest_ok {
                STATUS_VERIFIED_FACT
            } else {
                STATUS_UNCLASSIFIED
            },
            format!(
                "Evaluation of candidate {} (parent {}): admitted={}, {} evaluation layer \
                 result(s)",
                r.candidate_id,
                r.parent_id,
                r.admitted,
                r.layer_results.len()
            ),
            src(
                "EvaluationReceipt",
                &r.candidate_id,
                Some(r.receipt_digest.clone()),
            ),
        );
        for l in &r.layer_results {
            n.measurements.push(m(
                &format!("layer.{}.passed", l.layer_name),
                l.passed.to_string(),
                "",
            ));
            n.measurements.push(m(
                &format!("layer.{}.score", l.layer_name),
                format!("{:.4}", l.score),
                "",
            ));
        }
        if !digest_ok {
            n.notes
                .push("the receipt digest does not match its contents".into());
        }
        n.notes.push(if r.signature.is_some() {
            "receipt is signed; the signature was not checked here (needs the evaluator public key)"
                .into()
        } else {
            "receipt is unsigned".into()
        });
        nodes.push(n);

        let sid = format!("{id}:summary");
        let mut s = node(
            sid.clone(),
            KIND_EVALUATION_RECEIPT,
            STATUS_UNCLASSIFIED,
            format!(
                "The evaluator reports: hard invariants passed={}, statistical gates passed={}",
                r.passed_all_hard_invariants, r.passed_statistical_gates
            ),
            src("EvaluationReceipt", &r.candidate_id, None),
        );
        s.parents = vec![edge(&id, REL_PART_OF)];
        if let Some(ms) = &r.metrics_summary {
            s.measurements.extend([
                m(
                    "latency_delta_pct",
                    format!("{:.3}", ms.latency_delta_pct),
                    "%",
                ),
                m("p_value", format!("{:.6}", ms.p_value), ""),
                m(
                    "p95_ci_upper_degradation_pct",
                    format!("{:.3}", ms.p95_ci_upper_degradation_pct),
                    "%",
                ),
                m(
                    "p99_ci_upper_degradation_pct",
                    format!("{:.3}", ms.p99_ci_upper_degradation_pct),
                    "%",
                ),
                m("rss_growth_pct", format!("{:.3}", ms.rss_growth_pct), "%"),
            ]);
        }
        s.notes.push(
            "these fields are not covered by the receipt digest, so they are reported, not \
             verified"
                .into(),
        );
        nodes.push(s);
        (id, sid)
    });

    // Promotion / ratification state.
    // A ratification carries no cycle id; it belongs to this cycle only through a
    // same-cycle receipt for the same candidate. Otherwise it is left out.
    let ratification = ev.ratification.filter(|r| match receipt {
        Some(rc) if rc.candidate_id == r.proposal_id => true,
        _ => {
            foreign.push(MissingDoc {
                expected: format!(
                    "an evaluation receipt of cycle {cycle} for proposal {}",
                    r.proposal_id
                ),
                reason:
                    "the supplied ratification matches no receipt of this cycle; it was left out"
                        .into(),
            });
            false
        }
    });
    let rat_id = ratification.map(|r| {
        let id = ratification_id(r);
        let mut n = node(
            id.clone(),
            KIND_PROMOTION_STATE,
            STATUS_DIRECT_OBSERVATION,
            format!(
                "Ratification record for proposal {}: status {} ({})",
                r.proposal_id, r.status, r.message
            ),
            src("RatificationRecord", &r.proposal_id, r.commit_hash.clone()),
        );
        if let Some(rc) = receipt {
            n.parents = vec![edge(&receipt_node_id(rc), REL_SUPPORTED_BY)];
        }
        nodes.push(n);
        id
    });

    // Conclusion: the change RSI wants.
    let ratified = ratification.map(|r| r.status == "Ratified") == Some(true);
    let statement = match (diagnostic, hypothesis) {
        (Some(d), _) => format!(
            "RSI proposes changing {} to address {:?} (cycle {cycle})",
            d.target_file, d.primary_defect
        ),
        (None, Some(h)) => format!("RSI proposes improving {} (cycle {cycle})", h.target_metric),
        (None, None) => format!("RSI recorded no proposal rationale for cycle {cycle}"),
    };
    let mut c = node(
        conclusion_id(cycle),
        KIND_CONCLUSION,
        if ratified {
            STATUS_INFERENCE
        } else {
            STATUS_HYPOTHESIS
        },
        statement,
        src("RsiCycle", cycle, None),
    );
    if let Some(d) = &diag_id {
        c.parents.push(edge(d, REL_SUPPORTED_BY));
    } else if let Some((hid, _, _)) = &hyp_ids {
        c.parents.push(edge(hid, REL_SUPPORTED_BY));
    }
    if let Some((_, pid, fid)) = &hyp_ids {
        c.parents.push(edge(pid, REL_SUPPORTED_BY));
        c.parents.push(edge(fid, REL_SUPPORTED_BY));
    }
    if let Some((r, s)) = &receipt_ids {
        c.parents.push(edge(r, REL_SUPPORTED_BY));
        c.parents.push(edge(s, REL_SUPPORTED_BY));
    }
    if let Some(r) = &rat_id {
        c.parents.push(edge(r, REL_SUPPORTED_BY));
    }
    match (receipt, hypothesis) {
        (Some(r), Some(h)) => c.missing.push(MissingDoc {
            expected: format!(
                "an artifact linking candidate {} to hypothesis {}",
                r.candidate_id, h.id
            ),
            reason: format!(
                "both belong to cycle {}, but no RSI artifact records that the candidate was \
                 generated from this hypothesis, so the evaluation is not shown as testing it",
                r.cycle_id
            ),
        }),
        (None, _) => c.missing.push(MissingDoc {
            expected: format!("an evaluation receipt for cycle {cycle}"),
            reason: "none was supplied; the evaluation is incomplete".into(),
        }),
        _ => {}
    }
    c.missing.extend(foreign);
    if hypothesis.is_none() {
        c.missing.push(MissingDoc {
            expected: "a hypothesis contract".into(),
            reason: "none was supplied for this cycle".into(),
        });
    }
    c.notes.push(
        "this explanation is observational; it does not authorize promotion or any change".into(),
    );
    nodes.push(c);

    EvidenceGraphDoc {
        format: FORMAT.into(),
        version: VERSION,
        producer: PRODUCER.into(),
        nodes,
        truncated_at: Vec::new(),
    }
}
