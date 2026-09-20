use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time::Instant;

pub fn system_page_size_kb() -> u64 {
    #[cfg(unix)]
    {
        let ps = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if ps > 0 {
            return (ps as u64) / 1024;
        }
    }
    4
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RusageMetrics {
    pub user_time_us: u64,
    pub system_time_us: u64,
    pub max_rss_kb: i64,
    pub voluntary_context_switches: i64,
    pub involuntary_context_switches: i64,
}

impl RusageMetrics {
    pub fn capture_self() -> Result<Self, String> {
        Self::capture(libc::RUSAGE_SELF)
    }

    pub fn capture_children() -> Result<Self, String> {
        Self::capture(libc::RUSAGE_CHILDREN)
    }

    fn capture(who: libc::c_int) -> Result<Self, String> {
        unsafe {
            let mut usage: libc::rusage = std::mem::zeroed();
            let ret = libc::getrusage(who, &mut usage);
            if ret != 0 {
                return Err(format!("libc::getrusage failed with exit code {}", ret));
            }
            let user_us = (usage.ru_utime.tv_sec as u64)
                .saturating_mul(1_000_000)
                .saturating_add(usage.ru_utime.tv_usec as u64);
            let sys_us = (usage.ru_stime.tv_sec as u64)
                .saturating_mul(1_000_000)
                .saturating_add(usage.ru_stime.tv_usec as u64);

            Ok(Self {
                user_time_us: user_us,
                system_time_us: sys_us,
                max_rss_kb: usage.ru_maxrss as i64,
                voluntary_context_switches: usage.ru_nvcsw as i64,
                involuntary_context_switches: usage.ru_nivcsw as i64,
            })
        }
    }

    pub fn diff(&self, baseline: &Self) -> Self {
        Self {
            user_time_us: self.user_time_us.saturating_sub(baseline.user_time_us),
            system_time_us: self.system_time_us.saturating_sub(baseline.system_time_us),
            max_rss_kb: self.max_rss_kb.max(baseline.max_rss_kb),
            voluntary_context_switches: self
                .voluntary_context_switches
                .saturating_sub(baseline.voluntary_context_switches),
            involuntary_context_switches: self
                .involuntary_context_switches
                .saturating_sub(baseline.involuntary_context_switches),
        }
    }

    pub fn accumulate(&mut self, delta: &Self) {
        self.user_time_us = self.user_time_us.saturating_add(delta.user_time_us);
        self.system_time_us = self.system_time_us.saturating_add(delta.system_time_us);
        self.max_rss_kb = self.max_rss_kb.max(delta.max_rss_kb);
        self.voluntary_context_switches = self
            .voluntary_context_switches
            .saturating_add(delta.voluntary_context_switches);
        self.involuntary_context_switches = self
            .involuntary_context_switches
            .saturating_add(delta.involuntary_context_switches);
    }
}

impl Default for RusageMetrics {
    fn default() -> Self {
        Self {
            user_time_us: 0,
            system_time_us: 0,
            max_rss_kb: 0,
            voluntary_context_switches: 0,
            involuntary_context_switches: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatmMetrics {
    pub total_pages: u64,
    pub resident_pages: u64,
    pub shared_pages: u64,
    pub text_pages: u64,
    pub data_pages: u64,
    pub resident_kb: u64,
}

impl StatmMetrics {
    pub fn read_pid(pid: u32) -> Result<Self, String> {
        let path = format!("/proc/{}/statm", pid);
        Self::read_path(Path::new(&path))
    }

    pub fn read_self() -> Result<Self, String> {
        Self::read_path(Path::new("/proc/self/statm"))
    }

    pub fn read_path(path: &Path) -> Result<Self, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read statm file at {:?}: {}", path, e))?;
        Self::parse_statm(&content)
    }

    pub fn parse_statm(content: &str) -> Result<Self, String> {
        let tokens: Vec<&str> = content.split_whitespace().collect();
        if tokens.len() < 6 {
            return Err("Malformed statm content: expected at least 6 tokens".to_string());
        }

        let total_pages: u64 = tokens[0]
            .parse()
            .map_err(|e| format!("Invalid total_pages: {}", e))?;
        let resident_pages: u64 = tokens[1]
            .parse()
            .map_err(|e| format!("Invalid resident_pages: {}", e))?;
        let shared_pages: u64 = tokens[2]
            .parse()
            .map_err(|e| format!("Invalid shared_pages: {}", e))?;
        let text_pages: u64 = tokens[3]
            .parse()
            .map_err(|e| format!("Invalid text_pages: {}", e))?;
        let data_pages: u64 = tokens[5]
            .parse()
            .map_err(|e| format!("Invalid data_pages: {}", e))?;

        let page_size_kb = system_page_size_kb();
        let resident_kb = resident_pages.saturating_mul(page_size_kb);

        Ok(Self {
            total_pages,
            resident_pages,
            shared_pages,
            text_pages,
            data_pages,
            resident_kb,
        })
    }
}

pub struct LatencyTimer {
    start: Instant,
}

impl LatencyTimer {
    pub fn start() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    pub fn elapsed_us(&self) -> f64 {
        self.start.elapsed().as_nanos() as f64 / 1_000.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LatencyDistribution {
    pub count: usize,
    pub min_us: f64,
    pub max_us: f64,
    pub mean_us: f64,
    pub stddev_us: f64,
    pub p50_us: f64,
    pub p95_us: f64,
    pub p99_us: f64,
    pub throughput_ops_per_sec: f64,
    pub total_wall_time_us: u64,
}

impl LatencyDistribution {
    pub fn from_samples(samples: &[f64], total_wall_time_us: u64) -> Result<Self, String> {
        if samples.is_empty() {
            return Err("Cannot construct LatencyDistribution from zero samples".to_string());
        }

        let mut sorted = samples.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let count = sorted.len();
        let min_us = sorted[0];
        let max_us = sorted[count - 1];

        let sum: f64 = sorted.iter().sum();
        let mean_us = sum / (count as f64);

        let variance: f64 = sorted
            .iter()
            .map(|val| {
                let diff = val - mean_us;
                diff * diff
            })
            .sum::<f64>()
            / (count as f64);
        let stddev_us = variance.sqrt();

        let p50_us = Self::calculate_percentile(&sorted, 50.0);
        let p95_us = Self::calculate_percentile(&sorted, 95.0);
        let p99_us = Self::calculate_percentile(&sorted, 99.0);

        let throughput_ops_per_sec = if total_wall_time_us > 0 {
            ((count as f64) * 1_000_000.0) / (total_wall_time_us as f64)
        } else {
            0.0
        };

        Ok(Self {
            count,
            min_us,
            max_us,
            mean_us,
            stddev_us,
            p50_us,
            p95_us,
            p99_us,
            throughput_ops_per_sec,
            total_wall_time_us,
        })
    }

    pub fn calculate_percentile(sorted_samples: &[f64], pct: f64) -> f64 {
        let n = sorted_samples.len();
        if n == 0 {
            return 0.0;
        }
        if n == 1 {
            return sorted_samples[0];
        }

        let clamped_pct = pct.clamp(0.0, 100.0);
        let rank = (clamped_pct / 100.0) * ((n - 1) as f64);
        let low_idx = rank.floor() as usize;
        let high_idx = rank.ceil() as usize;

        if low_idx == high_idx {
            sorted_samples[low_idx]
        } else {
            let weight = rank - (low_idx as f64);
            sorted_samples[low_idx] * (1.0 - weight) + sorted_samples[high_idx] * weight
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProcessMetricsSnapshot {
    pub rusage: RusageMetrics,
    pub statm: Option<StatmMetrics>,
    pub latencies: Option<LatencyDistribution>,
    pub timestamp_utc: String,
}

impl ProcessMetricsSnapshot {
    pub fn capture_current() -> Result<Self, String> {
        let rusage = RusageMetrics::capture_self()?;
        let statm = StatmMetrics::read_self().ok();
        Ok(Self {
            rusage,
            statm,
            latencies: None,
            timestamp_utc: chrono::Utc::now().to_rfc3339(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rusage_capture_self() {
        let metrics = RusageMetrics::capture_self().expect("capture_self should succeed");
        assert!(metrics.max_rss_kb > 0);
    }

    #[test]
    fn test_statm_parse() {
        let sample = "12345 6789 1234 500 0 4500 0\n";
        let statm = StatmMetrics::parse_statm(sample).expect("parse_statm should succeed");
        assert_eq!(statm.total_pages, 12345);
        assert_eq!(statm.resident_pages, 6789);
        assert_eq!(statm.shared_pages, 1234);
        assert_eq!(statm.text_pages, 500);
        assert_eq!(statm.data_pages, 4500);
        let expected_kb = 6789 * system_page_size_kb();
        assert_eq!(statm.resident_kb, expected_kb);
    }

    #[test]
    fn test_statm_read_self() {
        let statm = StatmMetrics::read_self();
        assert!(statm.is_ok());
        let val = statm.unwrap();
        assert!(val.resident_pages > 0);
    }

    #[test]
    fn test_latency_distribution_empty() {
        let res = LatencyDistribution::from_samples(&[], 1000);
        assert!(res.is_err());
    }

    #[test]
    fn test_latency_distribution_single() {
        let res = LatencyDistribution::from_samples(&[150.0], 1000).unwrap();
        assert_eq!(res.count, 1);
        assert_eq!(res.min_us, 150.0);
        assert_eq!(res.max_us, 150.0);
        assert_eq!(res.mean_us, 150.0);
        assert_eq!(res.p50_us, 150.0);
        assert_eq!(res.p95_us, 150.0);
        assert_eq!(res.p99_us, 150.0);
    }

    #[test]
    fn test_latency_distribution_multiple() {
        let mut samples = Vec::new();
        for i in 1..=100 {
            samples.push(i as f64);
        }
        let res = LatencyDistribution::from_samples(&samples, 1_000_000).unwrap();
        assert_eq!(res.count, 100);
        assert_eq!(res.min_us, 1.0);
        assert_eq!(res.max_us, 100.0);
        assert!((res.mean_us - 50.5).abs() < 1e-6);
        assert!((res.p50_us - 50.5).abs() < 1e-6);
        assert!((res.p95_us - 95.05).abs() < 1e-6);
        assert!((res.p99_us - 99.01).abs() < 1e-6);
        assert!((res.throughput_ops_per_sec - 100.0).abs() < 1e-6);
    }
}
