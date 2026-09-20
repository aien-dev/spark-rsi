use crate::evaluator::metrics::LatencyDistribution;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct FastPrng {
    s: [u64; 4],
}

impl FastPrng {
    pub fn new(seed: u64) -> Self {
        let mut sm = seed;
        let mut next_u64 = || {
            sm = sm.wrapping_add(0x9e3779b97f4a7c15);
            let mut z = sm;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
            z ^ (z >> 31)
        };
        let s0 = next_u64();
        let s1 = next_u64();
        let s2 = next_u64();
        let s3 = next_u64();
        Self {
            s: [
                if s0 == 0 { 1 } else { s0 },
                if s1 == 0 { 2 } else { s1 },
                if s2 == 0 { 3 } else { s2 },
                if s3 == 0 { 4 } else { s3 },
            ],
        }
    }

    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        let res = (self.s[0].wrapping_add(self.s[3]))
            .rotate_left(23)
            .wrapping_add(self.s[0]);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);
        res
    }

    #[inline]
    pub fn gen_range(&mut self, upper: usize) -> usize {
        if upper <= 1 {
            return 0;
        }
        (self.next_u64() as usize) % upper
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PairedSample {
    pub iteration: usize,
    pub seed: u64,
    pub parent_metric: f64,
    pub candidate_metric: f64,
    pub delta: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BootstrapEstimate {
    pub sample_size: usize,
    pub resamples_count: usize,
    pub observed_parent_mean: f64,
    pub observed_candidate_mean: f64,
    pub observed_delta_mean: f64,
    pub delta_pct: f64,
    pub ci_99_lower: f64,
    pub ci_99_upper: f64,
    pub p_value: f64,
    pub is_statistically_significant: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TailNonInferiorityResult {
    pub percentile: f64,
    pub parent_val: f64,
    pub candidate_val: f64,
    pub observed_degradation_pct: f64,
    pub ci_95_upper_pct: f64,
    pub non_inferiority_margin_pct: f64,
    pub passes_non_inferiority: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FishersExactResult {
    pub parent_successes: u64,
    pub parent_failures: u64,
    pub candidate_successes: u64,
    pub candidate_failures: u64,
    pub parent_rate: f64,
    pub candidate_rate: f64,
    pub p_value_two_sided: f64,
    pub p_value_greater: f64,
    pub p_value_less: f64,
    pub is_significant: bool,
}

pub struct StatisticalEngine;

impl StatisticalEngine {
    pub const DEFAULT_BOOTSTRAP_RESAMPLES: usize = 10_000;
    pub const DEFAULT_PAIRED_ITERATIONS: usize = 30;

    pub fn bootstrap_paired_comparison(
        parent_samples: &[f64],
        candidate_samples: &[f64],
        resamples_count: usize,
        seed: Option<u64>,
    ) -> Result<BootstrapEstimate, String> {
        let m = parent_samples.len();
        if m == 0 || m != candidate_samples.len() {
            return Err(format!(
                "Invalid paired sample lengths: parent={}, candidate={}",
                m,
                candidate_samples.len()
            ));
        }

        let mut diffs = Vec::with_capacity(m);
        let mut sum_parent = 0.0;
        let mut sum_candidate = 0.0;
        let mut sum_diff = 0.0;

        for i in 0..m {
            let p = parent_samples[i];
            let c = candidate_samples[i];
            let d = c - p;
            diffs.push(d);
            sum_parent += p;
            sum_candidate += c;
            sum_diff += d;
        }

        let observed_parent_mean = sum_parent / (m as f64);
        let observed_candidate_mean = sum_candidate / (m as f64);
        let observed_delta_mean = sum_diff / (m as f64);

        let delta_pct = if observed_parent_mean.abs() > 1e-9 {
            (observed_delta_mean / observed_parent_mean) * 100.0
        } else {
            0.0
        };

        let b = if resamples_count > 0 {
            resamples_count
        } else {
            Self::DEFAULT_BOOTSTRAP_RESAMPLES
        };

        let mut prng = FastPrng::new(seed.unwrap_or(0x1337_c0d3_beef));
        let mut boot_means = Vec::with_capacity(b);

        for _ in 0..b {
            let mut boot_sum = 0.0;
            for _ in 0..m {
                let idx = prng.gen_range(m);
                boot_sum += diffs[idx];
            }
            boot_means.push(boot_sum / (m as f64));
        }

        boot_means.sort_by(|a, b_val| a.partial_cmp(b_val).unwrap_or(std::cmp::Ordering::Equal));

        let lower_idx = ((0.005 * (b as f64)).floor() as usize).min(b - 1);
        let upper_idx = ((0.995 * (b as f64)).ceil() as usize).min(b - 1);
        let ci_99_lower = boot_means[lower_idx];
        let ci_99_upper = boot_means[upper_idx];

        let count_leq_zero = boot_means.iter().filter(|&&v| v <= 0.0).count();
        let count_geq_zero = boot_means.iter().filter(|&&v| v >= 0.0).count();
        let p_val_two_sided =
            (2.0 * ((count_leq_zero.min(count_geq_zero) as f64) / (b as f64))).min(1.0);

        let is_statistically_significant =
            p_val_two_sided < 0.01 && (ci_99_lower > 0.0 || ci_99_upper < 0.0);

        Ok(BootstrapEstimate {
            sample_size: m,
            resamples_count: b,
            observed_parent_mean,
            observed_candidate_mean,
            observed_delta_mean,
            delta_pct,
            ci_99_lower,
            ci_99_upper,
            p_value: p_val_two_sided,
            is_statistically_significant,
        })
    }

    pub fn evaluate_tail_non_inferiority(
        parent_latencies: &[f64],
        candidate_latencies: &[f64],
        percentile: f64,
        margin_pct: f64,
        resamples_count: usize,
        seed: Option<u64>,
    ) -> Result<TailNonInferiorityResult, String> {
        let n_p = parent_latencies.len();
        let n_c = candidate_latencies.len();
        if n_p == 0 || n_c == 0 {
            return Err("Latency sample vectors must not be empty".to_string());
        }

        let mut sorted_parent = parent_latencies.to_vec();
        sorted_parent.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let parent_val = LatencyDistribution::calculate_percentile(&sorted_parent, percentile);

        let mut sorted_cand = candidate_latencies.to_vec();
        sorted_cand.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let candidate_val = LatencyDistribution::calculate_percentile(&sorted_cand, percentile);

        let observed_degradation_pct = if parent_val > 1e-9 {
            ((candidate_val - parent_val) / parent_val) * 100.0
        } else {
            0.0
        };

        let b = if resamples_count > 0 {
            resamples_count
        } else {
            Self::DEFAULT_BOOTSTRAP_RESAMPLES
        };

        let mut prng = FastPrng::new(seed.unwrap_or(0x42_cafe_babe));
        let mut degradation_samples = Vec::with_capacity(b);

        let mut boot_p = vec![0.0; n_p];
        let mut boot_c = vec![0.0; n_c];
        let paired = n_p == n_c;

        for _ in 0..b {
            if paired {
                for i in 0..n_p {
                    let idx = prng.gen_range(n_p);
                    boot_p[i] = parent_latencies[idx];
                    boot_c[i] = candidate_latencies[idx];
                }
            } else {
                for i in 0..n_p {
                    boot_p[i] = parent_latencies[prng.gen_range(n_p)];
                }
                for i in 0..n_c {
                    boot_c[i] = candidate_latencies[prng.gen_range(n_c)];
                }
            }

            boot_p.sort_by(|a, b_val| a.partial_cmp(b_val).unwrap_or(std::cmp::Ordering::Equal));
            boot_c.sort_by(|a, b_val| a.partial_cmp(b_val).unwrap_or(std::cmp::Ordering::Equal));

            let p_val_boot = LatencyDistribution::calculate_percentile(&boot_p, percentile);
            let c_val_boot = LatencyDistribution::calculate_percentile(&boot_c, percentile);

            let deg = if p_val_boot > 1e-9 {
                ((c_val_boot - p_val_boot) / p_val_boot) * 100.0
            } else {
                0.0
            };
            degradation_samples.push(deg);
        }

        degradation_samples
            .sort_by(|a, b_val| a.partial_cmp(b_val).unwrap_or(std::cmp::Ordering::Equal));
        let p95_idx = ((0.95 * (b as f64)).ceil() as usize).min(b - 1);
        let ci_95_upper_pct = degradation_samples[p95_idx];

        let passes_non_inferiority = ci_95_upper_pct <= margin_pct;

        Ok(TailNonInferiorityResult {
            percentile,
            parent_val,
            candidate_val,
            observed_degradation_pct,
            ci_95_upper_pct,
            non_inferiority_margin_pct: margin_pct,
            passes_non_inferiority,
        })
    }

    pub fn fishers_exact_test(
        parent_successes: u64,
        parent_failures: u64,
        candidate_successes: u64,
        candidate_failures: u64,
    ) -> Result<FishersExactResult, String> {
        let a = parent_successes as f64;
        let b = parent_failures as f64;
        let c = candidate_successes as f64;
        let d = candidate_failures as f64;

        let r1 = a + b;
        let r2 = c + d;
        let c1 = a + c;
        let c2 = b + d;
        let n = r1 + r2;

        if n == 0.0 {
            return Err("Total observations in contingency table cannot be zero".to_string());
        }

        let parent_rate = if r1 > 0.0 { a / r1 } else { 0.0 };
        let candidate_rate = if r2 > 0.0 { c / r2 } else { 0.0 };

        let max_k = r1.min(c1) as usize;
        let min_k = (0.0f64).max(r1 + c1 - n) as usize;

        let mut ln_fact = vec![0.0f64; (n as usize) + 1];
        for i in 2..=n as usize {
            ln_fact[i] = ln_fact[i - 1] + (i as f64).ln();
        }

        let prob_k = |k: usize| -> f64 {
            let k_f = k as f64;
            let log_p = ln_fact[r1 as usize]
                + ln_fact[r2 as usize]
                + ln_fact[c1 as usize]
                + ln_fact[c2 as usize]
                - ln_fact[n as usize]
                - ln_fact[k]
                - ln_fact[(r1 - k_f) as usize]
                - ln_fact[(c1 - k_f) as usize]
                - ln_fact[(r2 - c1 + k_f) as usize];
            log_p.exp()
        };

        let observed_k = a as usize;
        let p_obs = prob_k(observed_k);

        let mut p_two_sided = 0.0;
        let mut p_greater = 0.0;
        let mut p_less = 0.0;

        for k in min_k..=max_k {
            let p = prob_k(k);
            if p <= p_obs * (1.0 + 1e-7) {
                p_two_sided += p;
            }
            if k <= observed_k {
                p_greater += p;
            }
            if k >= observed_k {
                p_less += p;
            }
        }

        let p_value_two_sided = p_two_sided.min(1.0);
        let p_value_greater = p_greater.min(1.0);
        let p_value_less = p_less.min(1.0);
        let is_significant = p_value_two_sided < 0.05;

        Ok(FishersExactResult {
            parent_successes,
            parent_failures,
            candidate_successes,
            candidate_failures,
            parent_rate,
            candidate_rate,
            p_value_two_sided,
            p_value_greater,
            p_value_less,
            is_significant,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fast_prng_distribution() {
        let mut prng = FastPrng::new(12345);
        let mut counts = [0usize; 10];
        let n = 10_000;
        for _ in 0..n {
            let idx = prng.gen_range(10);
            counts[idx] += 1;
        }
        for count in counts.iter() {
            assert!(*count > 800 && *count < 1200);
        }
    }

    #[test]
    fn test_bootstrap_paired_identical_samples() {
        let parent = vec![10.0; 30];
        let candidate = vec![10.0; 30];
        let res =
            StatisticalEngine::bootstrap_paired_comparison(&parent, &candidate, 1000, Some(42))
                .unwrap();

        assert_eq!(res.sample_size, 30);
        assert!((res.observed_delta_mean - 0.0).abs() < 1e-9);
        assert!((res.delta_pct - 0.0).abs() < 1e-9);
        assert!(!res.is_statistically_significant);
    }

    #[test]
    fn test_bootstrap_paired_significant_improvement() {
        let parent = vec![
            100.0, 102.0, 101.0, 99.0, 100.5, 101.2, 98.9, 100.1, 102.3, 100.8, 100.0, 102.0,
            101.0, 99.0, 100.5, 101.2, 98.9, 100.1, 102.3, 100.8, 100.0, 102.0, 101.0, 99.0, 100.5,
            101.2, 98.9, 100.1, 102.3, 100.8,
        ];
        let candidate = vec![
            120.0, 122.0, 121.0, 119.0, 120.5, 121.2, 118.9, 120.1, 122.3, 120.8, 120.0, 122.0,
            121.0, 119.0, 120.5, 121.2, 118.9, 120.1, 122.3, 120.8, 120.0, 122.0, 121.0, 119.0,
            120.5, 121.2, 118.9, 120.1, 122.3, 120.8,
        ];

        let res =
            StatisticalEngine::bootstrap_paired_comparison(&parent, &candidate, 5000, Some(42))
                .unwrap();
        assert!(res.observed_delta_mean > 19.0);
        assert!(res.is_statistically_significant);
        assert!(res.p_value < 0.01);
        assert!(res.ci_99_lower > 15.0);
    }

    #[test]
    fn test_tail_non_inferiority_passes() {
        let parent: Vec<f64> = (1..=100).map(|x| x as f64).collect();
        let candidate: Vec<f64> = (1..=100).map(|x| (x as f64) * 1.002).collect();

        let res = StatisticalEngine::evaluate_tail_non_inferiority(
            &parent,
            &candidate,
            95.0,
            1.0,
            2000,
            Some(42),
        )
        .unwrap();

        assert_eq!(res.percentile, 95.0);
        assert!(res.passes_non_inferiority);
        assert!(res.ci_95_upper_pct <= 1.0);
    }

    #[test]
    fn test_tail_non_inferiority_fails_on_regression() {
        let parent: Vec<f64> = (1..=100).map(|x| x as f64).collect();
        let candidate: Vec<f64> = (1..=100).map(|x| (x as f64) * 1.05).collect();

        let res = StatisticalEngine::evaluate_tail_non_inferiority(
            &parent,
            &candidate,
            95.0,
            1.0,
            2000,
            Some(42),
        )
        .unwrap();

        assert!(!res.passes_non_inferiority);
        assert!(res.ci_95_upper_pct > 1.0);
    }

    #[test]
    fn test_fishers_exact_test_known_distribution() {
        let res = StatisticalEngine::fishers_exact_test(1, 9, 11, 3).unwrap();
        assert!(res.p_value_two_sided < 0.05);
        assert!(res.is_significant);
    }

    #[test]
    fn test_fishers_exact_test_identical_rates() {
        let res = StatisticalEngine::fishers_exact_test(10, 10, 10, 10).unwrap();
        assert!(!res.is_significant);
        assert!((res.p_value_two_sided - 1.0).abs() < 1e-6);
    }
}
