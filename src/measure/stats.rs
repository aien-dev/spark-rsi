//! The one percentile function used for both the median and the empirical p95.

/// Rejects empty input and any non-finite or negative value. Never clamps.
pub fn validate_samples(values: &[f64]) -> Result<(), String> {
    if values.is_empty() {
        return Err("no samples".to_string());
    }
    for (i, v) in values.iter().enumerate() {
        if !v.is_finite() {
            return Err(format!("sample {i} is not finite: {v}"));
        }
        if *v < 0.0 {
            return Err(format!("sample {i} is negative: {v}"));
        }
    }
    Ok(())
}

/// Nearest-rank percentile on the ascending sorted values:
/// `index = ceil(p / 100 * n) - 1`, clamped to `0..n`. `p` is in percent, `0.0..=100.0`.
/// The product `p * n` is formed before dividing by 100 so whole-number percentiles hit exact
/// integers (95 * 20 / 100 = 19, never 19.000000000000004).
pub fn percentile_nearest_rank(values: &[f64], p: f64) -> Result<f64, String> {
    validate_samples(values)?;
    if !p.is_finite() || !(0.0..=100.0).contains(&p) {
        return Err(format!("percentile must be within 0..=100, got {p}"));
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));
    let n = sorted.len();
    let rank = (p * n as f64 / 100.0).ceil() as i64 - 1;
    let index = rank.clamp(0, n as i64 - 1) as usize;
    Ok(sorted[index])
}

/// The ranking input. Reported under its own name, `latency_median_us`.
pub fn median(values: &[f64]) -> Result<f64, String> {
    percentile_nearest_rank(values, 50.0)
}

/// Empirical p95, or `Ok(None)` (unavailable) below `min_samples` valid samples.
pub fn p95_if_sufficient(values: &[f64], min_samples: usize) -> Result<Option<f64>, String> {
    validate_samples(values)?;
    if values.len() < min_samples {
        return Ok(None);
    }
    percentile_nearest_rank(values, 95.0).map(Some)
}
