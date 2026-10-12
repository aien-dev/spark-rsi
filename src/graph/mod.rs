use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

/// Whether a node carries a measurement. Unavailable is an explicit state; zero never means missing.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Measurement {
    Measured,
    #[default]
    Unavailable,
}

/// What the bottleneck score was computed from.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RankingBasis {
    /// Betweenness centrality only: at least one node has no measurement (cold start).
    #[default]
    Structural,
    /// Centrality, measured median latency and measured error rate. Every node is measured.
    Measured,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CapabilityNode {
    pub id: String,
    pub name: String,
    pub subsystem: String,
    /// Legacy compatibility field. Ranking and explanation never read it; they read `measurement`.
    pub latency_p95_us: f64,
    pub memory_rss_kb: u64,
    /// Legacy compatibility field. Ranking and explanation read `error_rate_measured`.
    pub error_rate: f64,
    pub weight: f64,
    #[serde(default)]
    pub measurement: Measurement,
    #[serde(default)]
    pub latency_median_us: Option<f64>,
    #[serde(default)]
    pub latency_p95_us_measured: Option<f64>,
    #[serde(default)]
    pub error_rate_measured: Option<f64>,
    #[serde(default)]
    pub sample_count: usize,
    /// Why the node is unavailable (or why p95 is unavailable), in plain words.
    #[serde(default)]
    pub unavailable_reason: Option<String>,
}

fn check_finite_nonneg(name: &str, v: f64) -> Result<(), String> {
    if v.is_finite() && v >= 0.0 {
        Ok(())
    } else {
        Err(format!("{name} must be finite and not negative, got {v}"))
    }
}

impl CapabilityNode {
    pub fn new(id: &str, name: &str, subsystem: &str) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            subsystem: subsystem.to_string(),
            latency_p95_us: 0.0,
            memory_rss_kb: 0,
            error_rate: 0.0,
            weight: 1.0,
            measurement: Measurement::Unavailable,
            latency_median_us: None,
            latency_p95_us_measured: None,
            error_rate_measured: None,
            sample_count: 0,
            unavailable_reason: Some("no measurement was supplied for this node".to_string()),
        }
    }

    /// Fills the legacy compatibility fields only. The node stays unavailable: a caller-supplied
    /// number is not a measurement, so the ranking does not read it.
    pub fn with_resource_metrics(mut self, p95_us: f64, rss_kb: u64, error_rate: f64) -> Self {
        self.latency_p95_us = p95_us;
        self.memory_rss_kb = rss_kb;
        self.error_rate = error_rate;
        self
    }

    /// Marks the node measured. Non-finite or negative values are rejected, never clamped.
    pub fn with_measured_latency(
        mut self,
        median_us: f64,
        p95_us: Option<f64>,
        error_rate: f64,
        sample_count: usize,
    ) -> Result<Self, String> {
        check_finite_nonneg("latency_median_us", median_us)?;
        if let Some(p) = p95_us {
            check_finite_nonneg("latency_p95_us_measured", p)?;
        }
        check_finite_nonneg("error_rate_measured", error_rate)?;
        if error_rate > 1.0 {
            return Err(format!(
                "error_rate_measured must be at most 1, got {error_rate}"
            ));
        }
        self.measurement = Measurement::Measured;
        self.latency_median_us = Some(median_us);
        self.latency_p95_us_measured = p95_us;
        self.error_rate_measured = Some(error_rate);
        self.sample_count = sample_count;
        self.unavailable_reason = if p95_us.is_some() {
            None
        } else {
            Some("p95 is unavailable: too few valid compatible samples".to_string())
        };
        Ok(self)
    }

    /// Marks the node unavailable with the reason in plain words.
    pub fn with_unavailable(mut self, reason: &str, sample_count: usize) -> Self {
        self.measurement = Measurement::Unavailable;
        self.latency_median_us = None;
        self.latency_p95_us_measured = None;
        self.error_rate_measured = None;
        self.sample_count = sample_count;
        self.unavailable_reason = Some(reason.to_string());
        self
    }

    /// The measured values the ranking may read, or the reason there are none.
    fn scoring_inputs(&self) -> Result<(f64, f64), String> {
        if self.measurement != Measurement::Measured {
            return Err(self
                .unavailable_reason
                .clone()
                .unwrap_or_else(|| "no measurement".to_string()));
        }
        let (Some(median), Some(err)) = (self.latency_median_us, self.error_rate_measured) else {
            return Err("measured state without a median latency or error rate".to_string());
        };
        check_finite_nonneg("latency_median_us", median)?;
        check_finite_nonneg("error_rate_measured", err)?;
        if err > 1.0 {
            return Err(format!("error_rate_measured must be at most 1, got {err}"));
        }
        Ok((median, err))
    }
}

/// A call-order link between two nodes. In the pipeline graph the edges carry topology only;
/// `latency_impact_us` is not a measurement and no score reads it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CapabilityEdge {
    pub from: String,
    pub to: String,
    pub latency_impact_us: f64,
    pub call_frequency: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BottleneckRank {
    pub rank: usize,
    pub node_id: String,
    pub node_name: String,
    pub subsystem: String,
    pub bottleneck_score: f64,
    pub centrality: f64,
    /// Legacy compatibility field, copied from the node. Not a measurement.
    pub latency_p95_us: f64,
    /// Legacy compatibility field, copied from the node. Not a measurement.
    pub error_rate: f64,
    pub causal_explanation: String,
    #[serde(default)]
    pub measurement: Measurement,
    #[serde(default)]
    pub latency_median_us: Option<f64>,
    #[serde(default)]
    pub latency_p95_us_measured: Option<f64>,
    #[serde(default)]
    pub error_rate_measured: Option<f64>,
    #[serde(default)]
    pub sample_count: usize,
    #[serde(default)]
    pub unavailable_reason: Option<String>,
    #[serde(default)]
    pub ranking_basis: RankingBasis,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CapabilityGraph {
    pub nodes: HashMap<String, CapabilityNode>,
    pub edges: Vec<CapabilityEdge>,
}

impl CapabilityGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_node(&mut self, node: CapabilityNode) {
        self.nodes.insert(node.id.clone(), node);
    }

    pub fn add_edge(&mut self, from: &str, to: &str, latency_impact_us: f64, call_frequency: f64) {
        self.edges.push(CapabilityEdge {
            from: from.to_string(),
            to: to.to_string(),
            latency_impact_us,
            call_frequency,
        });
    }

    pub fn adjacency_list(&self) -> HashMap<String, Vec<String>> {
        let mut adj: HashMap<String, Vec<String>> = HashMap::new();
        for id in self.nodes.keys() {
            adj.insert(id.clone(), Vec::new());
        }
        for edge in &self.edges {
            if let Some(neighbors) = adj.get_mut(&edge.from) {
                neighbors.push(edge.to.clone());
            }
        }
        adj
    }

    /// Computes shortest-path betweenness centrality for all nodes
    pub fn calculate_betweenness_centrality(&self) -> HashMap<String, f64> {
        let mut centrality: HashMap<String, f64> = HashMap::new();
        for id in self.nodes.keys() {
            centrality.insert(id.clone(), 0.0);
        }

        let n = self.nodes.len();
        if n <= 2 {
            return centrality;
        }

        let adj = self.adjacency_list();

        // Sorted so float accumulation order, and so every score, is the same on every run.
        let mut sources: Vec<&String> = self.nodes.keys().collect();
        sources.sort();
        for s in sources {
            let mut stack: Vec<String> = Vec::new();
            let mut pred: HashMap<String, Vec<String>> = HashMap::new();
            let mut sigma: HashMap<String, f64> = HashMap::new();
            let mut dist: HashMap<String, i64> = HashMap::new();

            for id in self.nodes.keys() {
                pred.insert(id.clone(), Vec::new());
                sigma.insert(id.clone(), 0.0);
                dist.insert(id.clone(), -1);
            }

            sigma.insert(s.clone(), 1.0);
            dist.insert(s.clone(), 0);

            let mut queue: VecDeque<String> = VecDeque::new();
            queue.push_back(s.clone());

            while let Some(v) = queue.pop_front() {
                stack.push(v.clone());
                let d_v = dist[&v];

                if let Some(neighbors) = adj.get(&v) {
                    for w in neighbors {
                        if dist[w] < 0 {
                            dist.insert(w.clone(), d_v + 1);
                            queue.push_back(w.clone());
                        }
                        if dist[w] == d_v + 1 {
                            let sigma_v = sigma[&v];
                            *sigma.get_mut(w).unwrap() += sigma_v;
                            pred.get_mut(w).unwrap().push(v.clone());
                        }
                    }
                }
            }

            let mut delta: HashMap<String, f64> = HashMap::new();
            for id in self.nodes.keys() {
                delta.insert(id.clone(), 0.0);
            }

            while let Some(w) = stack.pop() {
                for v in &pred[&w] {
                    let c = (sigma[v] / sigma[&w]) * (1.0 + delta[&w]);
                    *delta.get_mut(v).unwrap() += c;
                }
                if &w != s {
                    *centrality.get_mut(&w).unwrap() += delta[&w];
                }
            }
        }

        // Normalize betweenness centrality by (N-1)(N-2)
        let scale = 1.0 / (((n - 1) * (n - 2)) as f64);
        for val in centrality.values_mut() {
            *val *= scale;
        }

        centrality
    }

    /// Ranks system capabilities by composite bottleneck severity score.
    ///
    /// When every node is measured the score combines centrality, the measured median latency
    /// ratio and the measured error rate. If any node is unavailable (cold start) the score is the
    /// betweenness centrality alone and the latency and error terms are unavailable. Missing is
    /// never read as zero. Order: score descending, then node id ascending (byte order). Scores
    /// are compared at 1e-9 resolution so float rounding cannot override the id tie-break.
    pub fn rank_bottlenecks(&self) -> Vec<BottleneckRank> {
        let centrality = self.calculate_betweenness_centrality();
        let inputs: HashMap<&String, Result<(f64, f64), String>> = self
            .nodes
            .iter()
            .map(|(id, n)| (id, n.scoring_inputs()))
            .collect();
        let measured_basis = !self.nodes.is_empty() && inputs.values().all(|r| r.is_ok());
        let basis = if measured_basis {
            RankingBasis::Measured
        } else {
            RankingBasis::Structural
        };

        let avg_latency = if measured_basis {
            let mut ids: Vec<&String> = self.nodes.keys().collect();
            ids.sort();
            let sum: f64 = ids
                .iter()
                .filter_map(|id| inputs[*id].as_ref().ok().map(|(m, _)| *m))
                .sum();
            (sum / (self.nodes.len() as f64)).max(1.0)
        } else {
            1.0
        };

        let mut ranks = Vec::new();
        for (id, node) in &self.nodes {
            let c = centrality.get(id).copied().unwrap_or(0.0);
            let (score, explanation) = match (&inputs[id], measured_basis) {
                (Ok((median, err)), true) => {
                    let lat_ratio = (median / avg_latency).clamp(0.0, 10.0);
                    let err_factor = (err * 5.0).clamp(0.0, 5.0);
                    // Composite bottleneck score combining network centrality, latency, and defects
                    let score = (c * 0.4) + (lat_ratio * 0.4) + (err_factor * 0.2);
                    (
                        score,
                        format!(
                            "Centrality={:.3}, LatencyRatio={:.2}x (median), ErrorRate={:.1}%",
                            c,
                            lat_ratio,
                            err * 100.0
                        ),
                    )
                }
                _ => (
                    c,
                    format!(
                        "Centrality={:.3}; latency and error terms unavailable (structural ranking)",
                        c
                    ),
                ),
            };

            ranks.push(BottleneckRank {
                rank: 0,
                node_id: id.clone(),
                node_name: node.name.clone(),
                subsystem: node.subsystem.clone(),
                bottleneck_score: score,
                centrality: c,
                latency_p95_us: node.latency_p95_us,
                error_rate: node.error_rate,
                causal_explanation: explanation,
                measurement: if inputs[id].is_ok() {
                    Measurement::Measured
                } else {
                    Measurement::Unavailable
                },
                latency_median_us: node.latency_median_us.filter(|_| inputs[id].is_ok()),
                latency_p95_us_measured: node
                    .latency_p95_us_measured
                    .filter(|_| inputs[id].is_ok()),
                error_rate_measured: node.error_rate_measured.filter(|_| inputs[id].is_ok()),
                sample_count: node.sample_count,
                unavailable_reason: match &inputs[id] {
                    Err(reason) => Some(reason.clone()),
                    Ok(_) => node.unavailable_reason.clone(),
                },
                ranking_basis: basis,
            });
        }

        let quantize = |s: f64| (s * 1e9).round() as i64;
        ranks.sort_by(|a, b| {
            quantize(b.bottleneck_score)
                .cmp(&quantize(a.bottleneck_score))
                .then_with(|| a.node_id.as_bytes().cmp(b.node_id.as_bytes()))
        });

        for (idx, item) in ranks.iter_mut().enumerate() {
            item.rank = idx + 1;
        }

        ranks
    }

    pub fn top_bottleneck(&self) -> Option<BottleneckRank> {
        self.rank_bottlenecks().into_iter().next()
    }

    /// Exports graph topology in Graphviz DOT format for visual analysis
    pub fn to_dot(&self) -> String {
        let mut dot =
            String::from("digraph CapabilityGraph {\n    node [shape=box, style=rounded];\n");
        let mut ids: Vec<&String> = self.nodes.keys().collect();
        ids.sort();
        for id in ids {
            let node = &self.nodes[id];
            let label = match (node.measurement, node.latency_median_us) {
                (Measurement::Measured, Some(median)) => format!("median {:.0}us", median),
                _ => "unavailable".to_string(),
            };
            dot.push_str(&format!(
                "    \"{}\" [label=\"{}\\n{}\"];\n",
                id, node.name, label
            ));
        }
        for edge in &self.edges {
            dot.push_str(&format!("    \"{}\" -> \"{}\";\n", edge.from, edge.to));
        }
        dot.push_str("}\n");
        dot
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_graph_bottleneck_detection() {
        let mut graph = CapabilityGraph::new();
        graph.add_node(
            CapabilityNode::new("sched", "Inference Scheduler", "runtime")
                .with_measured_latency(500.0, None, 0.0, 5)
                .unwrap(),
        );
        graph.add_node(
            CapabilityNode::new("kv", "KV Cache Allocator", "memory")
                .with_measured_latency(2500.0, None, 0.05, 5)
                .unwrap(),
        );
        graph.add_node(
            CapabilityNode::new("kernel", "Mojo Balance Kernel", "compute")
                .with_measured_latency(100.0, None, 0.0, 5)
                .unwrap(),
        );

        graph.add_edge("sched", "kv", 2000.0, 1.0);
        graph.add_edge("kv", "kernel", 100.0, 1.0);

        let ranks = graph.rank_bottlenecks();
        assert_eq!(ranks.len(), 3);
        assert_eq!(
            ranks[0].node_id, "kv",
            "KV Cache Allocator should be detected as top bottleneck"
        );
        assert!(ranks[0].bottleneck_score > ranks[1].bottleneck_score);

        let dot = graph.to_dot();
        assert!(dot.contains("KV Cache Allocator"));
        assert!(dot.contains("sched\" -> \"kv"));
    }

    #[test]
    fn unavailable_nodes_rank_structurally_and_ties_break_by_id() {
        let mut graph = CapabilityGraph::new();
        for id in ["b", "a", "c", "d"] {
            graph.add_node(CapabilityNode::new(id, id, "s").with_resource_metrics(9999.0, 1, 0.9));
        }
        graph.add_edge("a", "b", 0.0, 1.0);
        graph.add_edge("a", "c", 0.0, 1.0);
        graph.add_edge("b", "d", 0.0, 1.0);
        graph.add_edge("c", "d", 0.0, 1.0);
        let first = graph.rank_bottlenecks();
        assert!(first
            .iter()
            .all(|r| r.ranking_basis == RankingBasis::Structural));
        assert!(first
            .iter()
            .all(|r| r.measurement == Measurement::Unavailable));
        // b and c tie on centrality, so id order decides.
        assert_eq!(first[0].node_id, "b");
        assert_eq!(first[1].node_id, "c");
        for _ in 0..20 {
            assert_eq!(graph.rank_bottlenecks(), first);
        }
    }

    #[test]
    fn non_finite_and_negative_measurements_are_rejected() {
        let n = CapabilityNode::new("x", "x", "s");
        assert!(n
            .clone()
            .with_measured_latency(f64::NAN, None, 0.0, 3)
            .is_err());
        assert!(n.clone().with_measured_latency(-1.0, None, 0.0, 3).is_err());
        assert!(n
            .clone()
            .with_measured_latency(1.0, Some(f64::INFINITY), 0.0, 3)
            .is_err());
        assert!(n.with_measured_latency(1.0, None, 1.5, 3).is_err());
    }
}
