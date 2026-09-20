use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CapabilityNode {
    pub id: String,
    pub name: String,
    pub subsystem: String,
    pub latency_p95_us: f64,
    pub memory_rss_kb: u64,
    pub error_rate: f64,
    pub weight: f64,
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
        }
    }

    pub fn with_resource_metrics(mut self, p95_us: f64, rss_kb: u64, error_rate: f64) -> Self {
        self.latency_p95_us = p95_us;
        self.memory_rss_kb = rss_kb;
        self.error_rate = error_rate;
        self
    }
}

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
    pub latency_p95_us: f64,
    pub error_rate: f64,
    pub causal_explanation: String,
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

        for s in self.nodes.keys() {
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

    /// Ranks system capabilities by composite bottleneck severity score
    pub fn rank_bottlenecks(&self) -> Vec<BottleneckRank> {
        let centrality = self.calculate_betweenness_centrality();
        let mut ranks = Vec::new();

        let avg_latency = if self.nodes.is_empty() {
            1.0
        } else {
            let sum: f64 = self.nodes.values().map(|n| n.latency_p95_us).sum();
            (sum / (self.nodes.len() as f64)).max(1.0)
        };

        for (id, node) in &self.nodes {
            let c = centrality.get(id).copied().unwrap_or(0.0);
            let lat_ratio = (node.latency_p95_us / avg_latency).clamp(0.0, 10.0);
            let err_factor = (node.error_rate * 5.0).clamp(0.0, 5.0);

            // Composite bottleneck score combining network centrality, latency, and defects
            let score = (c * 0.4) + (lat_ratio * 0.4) + (err_factor * 0.2);

            let explanation = format!(
                "Centrality={:.3}, LatencyRatio={:.2}x, ErrorRate={:.1}%",
                c,
                lat_ratio,
                node.error_rate * 100.0
            );

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
            });
        }

        ranks.sort_by(|a, b| {
            b.bottleneck_score
                .partial_cmp(&a.bottleneck_score)
                .unwrap_or(std::cmp::Ordering::Equal)
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
        for (id, node) in &self.nodes {
            dot.push_str(&format!(
                "    \"{}\" [label=\"{}\\n{}us\\nerr: {:.1}%\"];\n",
                id,
                node.name,
                node.latency_p95_us as u64,
                node.error_rate * 100.0
            ));
        }
        for edge in &self.edges {
            dot.push_str(&format!(
                "    \"{}\" -> \"{}\" [label=\"{:.0}us\"];\n",
                edge.from, edge.to, edge.latency_impact_us
            ));
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
                .with_resource_metrics(500.0, 1024, 0.0),
        );
        graph.add_node(
            CapabilityNode::new("kv", "KV Cache Allocator", "memory")
                .with_resource_metrics(2500.0, 4096, 0.05),
        );
        graph.add_node(
            CapabilityNode::new("kernel", "Mojo Balance Kernel", "compute")
                .with_resource_metrics(100.0, 512, 0.0),
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
}
