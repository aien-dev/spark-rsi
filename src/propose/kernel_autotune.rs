//! Parameterized Kernel Autotuning for Blackwell sm_121.
//! Drives bounded, causal optimization over paged_attention_bf16.cu on DGX Spark GB10.

use crate::models::{ImprovementProposal, ProposalKind};
use crate::propose::hypothesis::{HypothesisContract, ProtectedMetric};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PagedAttentionConfig {
    pub page_size: usize,
    pub threads_per_block: usize,
    pub warps_per_block: usize,
    pub query_heads_per_block: usize,
    pub vector_width: usize,
    pub smem_staging_depth: usize,
    pub prefetch_distance: usize,
}

impl Default for PagedAttentionConfig {
    fn default() -> Self {
        Self {
            page_size: 16,
            threads_per_block: 128,
            warps_per_block: 4,
            query_heads_per_block: 7,
            vector_width: 2,
            smem_staging_depth: 1,
            prefetch_distance: 1,
        }
    }
}

impl PagedAttentionConfig {
    pub fn is_valid(&self) -> bool {
        (self.page_size == 16 || self.page_size == 32)
            && (self.threads_per_block == 64
                || self.threads_per_block == 128
                || self.threads_per_block == 256
                || self.threads_per_block == 512)
            && (self.warps_per_block == 2 || self.warps_per_block == 4 || self.warps_per_block == 8)
            && (self.query_heads_per_block == 1
                || self.query_heads_per_block == 2
                || self.query_heads_per_block == 4
                || self.query_heads_per_block == 7)
            && (self.vector_width == 1 || self.vector_width == 2 || self.vector_width == 4)
            && (self.smem_staging_depth == 1 || self.smem_staging_depth == 2)
            && (self.prefetch_distance <= 2)
    }

    /// Renders compile-time macro overrides for paged_attention_bf16.cu
    pub fn render_macro_defines(&self) -> String {
        format!(
            "#define PAGE_SIZE {}\n#define BLOCK_THREADS {}\n#define Q_HEADS_PER_BLOCK {}\n#define VECTOR_WIDTH {}\n#define PREFETCH_DISTANCE {}\n",
            self.page_size,
            self.threads_per_block,
            self.query_heads_per_block,
            self.vector_width,
            self.prefetch_distance
        )
    }

    /// Injects macro overrides into the baseline kernel source
    pub fn apply_to_kernel_source(&self, base_source: &str) -> String {
        let mut out = String::new();
        out.push_str("// Autotuned Blackwell sm_121 Configuration by spark-rsi\n");
        out.push_str(&self.render_macro_defines());
        out.push_str("\n");

        let mut in_initial_macros = false;
        for line in base_source.lines() {
            if line.contains("Parameterized autotuning search space") {
                in_initial_macros = true;
                continue;
            }
            if in_initial_macros {
                if line.starts_with("#define WARP_SIZE") {
                    in_initial_macros = false;
                } else {
                    continue;
                }
            }
            out.push_str(line);
            out.push('\n');
        }
        out
    }

    /// Returns the required KV cache pool block size corresponding to this autotuned kernel
    pub fn recommended_kv_pool_block_size(&self) -> usize {
        self.page_size
    }
}

pub struct KernelAutotuneManager;

impl KernelAutotuneManager {
    /// Formulates the formal HypothesisContract for PagedAttention autotuning on GB10
    pub fn create_contract(
        candidate_config: &PagedAttentionConfig,
        baseline_p95_ms: f64,
    ) -> HypothesisContract {
        let id = format!("hyp-kernel-{}", Uuid::new_v4().simple());
        let cycle_id = format!("cycle-kernel-{}", chrono::Utc::now().timestamp());

        HypothesisContract {
            id,
            cycle_id,
            observed_problem: "Attention decode latency under multi-agent branch pressure".to_string(),
            suspected_root_cause: format!(
                "Non-optimal GB10 warp geometry and prefetch distance (page_size={}, threads={}, warps={})",
                candidate_config.page_size, candidate_config.threads_per_block, candidate_config.warps_per_block
            ),
            target_metric: "p95_decode_step_latency".to_string(),
            baseline_value: baseline_p95_ms,
            predicted_delta_pct: -5.0, // target >= 5% reduction
            protected_metrics: vec![
                ProtectedMetric {
                    name: "p99_latency".to_string(),
                    max_allowed_degradation_pct: 1.0,
                },
                ProtectedMetric {
                    name: "energy_joules_per_token".to_string(),
                    max_allowed_degradation_pct: 2.0,
                },
                ProtectedMetric {
                    name: "physical_kv_bytes_per_token".to_string(),
                    max_allowed_degradation_pct: 0.0,
                },
            ],
            falsification_test: "paired_workload_bootstrap_permutation_test_p001".to_string(),
            confidence_score: 0.95,
        }
    }

    /// Emits an ImprovementProposal for the candidate configuration
    pub fn create_proposal(
        config: &PagedAttentionConfig,
        target_file: &str,
        base_source: &str,
    ) -> ImprovementProposal {
        let id = format!("prop-attn-{}", Uuid::new_v4().simple());
        let mutated = config.apply_to_kernel_source(base_source);

        ImprovementProposal {
            id,
            title: format!(
                "autotune sm_121 paged_attention (p={}, t={}, w={}, v={})",
                config.page_size, config.threads_per_block, config.warps_per_block, config.vector_width
            ),
            description: "Autonomous Blackwell GB10 PagedAttention kernel parameter exploration".to_string(),
            target_file: target_file.to_string(),
            proposed_patch: mutated,
            kind: ProposalKind::Optimization,
            created_at: chrono::Utc::now().to_rfc3339(),
            sandbox_path: None,
            operator_signature: None,
        }
    }

    /// Enumerates candidate configurations within the bounded search space
    pub fn enumerate_search_space() -> Vec<PagedAttentionConfig> {
        let mut configs = Vec::new();
        let page_sizes = [16, 32];
        let thread_counts = [64, 128, 256];
        let heads = [1, 2, 4, 7];
        let vec_widths = [1, 2, 4];
        let prefetches = [0, 1, 2];

        for &p in &page_sizes {
            for &t in &thread_counts {
                for &h in &heads {
                    for &v in &vec_widths {
                        for &pf in &prefetches {
                            let cfg = PagedAttentionConfig {
                                page_size: p,
                                threads_per_block: t,
                                warps_per_block: t / 32,
                                query_heads_per_block: h,
                                vector_width: v,
                                smem_staging_depth: 1,
                                prefetch_distance: pf,
                            };
                            if cfg.is_valid() {
                                configs.push(cfg);
                            }
                        }
                    }
                }
            }
        }
        configs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_validity() {
        let def = PagedAttentionConfig::default();
        assert!(def.is_valid());
        assert_eq!(def.page_size, 16);
        assert_eq!(def.threads_per_block, 128);
        assert_eq!(def.warps_per_block, 4);
    }

    #[test]
    fn test_render_macro_defines() {
        let mut cfg = PagedAttentionConfig::default();
        cfg.page_size = 32;
        cfg.threads_per_block = 256;
        let rendered = cfg.render_macro_defines();
        assert!(rendered.contains("#define PAGE_SIZE 32"));
        assert!(rendered.contains("#define BLOCK_THREADS 256"));
    }

    #[test]
    fn test_create_contract_and_protected_metrics() {
        let cfg = PagedAttentionConfig::default();
        let contract = KernelAutotuneManager::create_contract(&cfg, 12.5);

        assert_eq!(contract.target_metric, "p95_decode_step_latency");
        assert_eq!(contract.baseline_value, 12.5);
        assert_eq!(contract.predicted_delta_pct, -5.0);
        assert_eq!(contract.protected_metrics.len(), 3);
        assert_eq!(contract.protected_metrics[0].name, "p99_latency");
        assert_eq!(contract.protected_metrics[0].max_allowed_degradation_pct, 1.0);
        assert_eq!(contract.protected_metrics[1].name, "energy_joules_per_token");
        assert_eq!(contract.protected_metrics[1].max_allowed_degradation_pct, 2.0);
    }

    #[test]
    fn test_apply_to_kernel_source_preserves_internal_directives() {
        let sample = "#include <cuda_runtime.h>\n// Parameterized autotuning search space with compile-time overrides\n#ifndef PAGE_SIZE\n#define PAGE_SIZE 16\n#endif\n#ifndef BLOCK_THREADS\n#define BLOCK_THREADS 128\n#endif\n#define WARP_SIZE 32\n#if PREFETCH_DISTANCE > 0\nprefetch_global_l2(next_k);\n#endif\n";
        let mut cfg = PagedAttentionConfig::default();
        cfg.page_size = 32;
        cfg.prefetch_distance = 2;
        let mutated = cfg.apply_to_kernel_source(sample);
        assert!(mutated.contains("#define PAGE_SIZE 32"));
        assert!(mutated.contains("#define PREFETCH_DISTANCE 2"));
        assert!(mutated.contains("#define WARP_SIZE 32"));
        assert!(mutated.contains("#if PREFETCH_DISTANCE > 0"));
        assert!(mutated.contains("#endif"));
        assert_eq!(cfg.recommended_kv_pool_block_size(), 32);
    }

    #[test]
    fn test_search_space_enumeration() {
        let space = KernelAutotuneManager::enumerate_search_space();
        assert!(!space.is_empty());
        for cfg in &space {
            assert!(cfg.is_valid());
        }
    }
}
