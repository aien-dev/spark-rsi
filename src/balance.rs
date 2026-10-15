use crate::models::BalanceVerdict;

/// Native Rust balance kernel: scores the tension between Drive and Humanity.
pub struct BalanceKernel;

impl BalanceKernel {
    /// Scalar evaluation of one drive score against one humanity score.
    pub fn evaluate(drive: f64, humanity: f64) -> BalanceVerdict {
        Self::scalar(drive, humanity)
    }

    /// Evaluation of 4-lane drive and humanity vectors: each side is summed, then scored.
    pub fn evaluate_simd(drive_vec: [f32; 4], humanity_vec: [f32; 4]) -> BalanceVerdict {
        let d_sum: f32 = drive_vec.iter().sum();
        let h_sum: f32 = humanity_vec.iter().sum();
        let mut v = Self::scalar(d_sum as f64, h_sum as f64);
        v.mode = "vector".to_string();
        v
    }

    fn scalar(drive: f64, humanity: f64) -> BalanceVerdict {
        if drive == 0.0 && humanity == 0.0 {
            return BalanceVerdict {
                kernel: "rust".to_string(),
                mode: "scalar".to_string(),
                drive: 0.0,
                humanity: 0.0,
                ratio: 0.0,
                score: 0.0,
                verdict: "dormant".to_string(),
                guidance: "Baseline absent. Both drive and humanity are zero.".to_string(),
            };
        }

        if humanity == 0.0 {
            return BalanceVerdict {
                kernel: "rust".to_string(),
                mode: "scalar".to_string(),
                drive,
                humanity: 0.0,
                ratio: 999.0,
                score: 0.1,
                verdict: "drive_dominant".to_string(),
                guidance: "Humanity absent. Restraint and ethics required.".to_string(),
            };
        }

        if drive == 0.0 {
            return BalanceVerdict {
                kernel: "rust".to_string(),
                mode: "scalar".to_string(),
                drive: 0.0,
                humanity,
                ratio: 0.0,
                score: 0.1,
                verdict: "humanity_dominant".to_string(),
                guidance: "Drive absent. Ambition and curiosity required.".to_string(),
            };
        }

        let ratio = drive / humanity;
        let (verdict, guidance, score) = if ratio > 2.0 {
            (
                "drive_dominant".to_string(),
                "Drive exceeds humanity threshold. Slow down and verify discipline.".to_string(),
                2.0 / ratio,
            )
        } else if ratio < 0.5 {
            (
                "humanity_dominant".to_string(),
                "Humanity suppresses drive. Increase problem-solving velocity.".to_string(),
                ratio * 2.0,
            )
        } else {
            let s = if ratio <= 1.0 { ratio } else { 1.0 / ratio };
            (
                "balanced".to_string(),
                "Tension harmonized. Proceed with atomic ratification.".to_string(),
                s,
            )
        };

        BalanceVerdict {
            kernel: "rust".to_string(),
            mode: "scalar".to_string(),
            drive,
            humanity,
            ratio,
            score,
            verdict,
            guidance,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scalar_balanced() {
        let v = BalanceKernel::scalar(10.0, 10.0);
        assert_eq!(v.verdict, "balanced");
        assert_eq!(v.ratio, 1.0);
        assert_eq!(v.score, 1.0);
    }

    #[test]
    fn test_scalar_drive_dominant() {
        let v = BalanceKernel::scalar(30.0, 5.0);
        assert_eq!(v.verdict, "drive_dominant");
        assert!(v.ratio > 2.0);
    }

    #[test]
    fn test_scalar_humanity_dominant() {
        let v = BalanceKernel::scalar(2.0, 10.0);
        assert_eq!(v.verdict, "humanity_dominant");
        assert!(v.ratio < 0.5);
    }
}
