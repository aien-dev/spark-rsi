use crate::models::BalanceVerdict;
use std::path::Path;
use std::process::Command;

pub struct BalanceKernel;

impl BalanceKernel {
    pub fn evaluate(
        drive: f64,
        humanity: f64,
        kernel_path: Option<&str>,
    ) -> Result<BalanceVerdict, String> {
        // 1. Try precompiled Mojo binary
        let binary_path = kernel_path.unwrap_or("mojo/balance_bin");
        if Path::new(binary_path).exists() {
            if let Ok(out) = Command::new(binary_path)
                .arg(format!("{:.0}", drive))
                .arg(format!("{:.0}", humanity))
                .output()
            {
                if out.status.success() {
                    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if let Ok(verdict) = serde_json::from_str::<BalanceVerdict>(&text) {
                        return Ok(verdict);
                    }
                }
            }
        }

        // 2. Try mojo runner with mojo/balance.mojo
        let mojo_script = "mojo/balance.mojo";
        if Path::new(mojo_script).exists() {
            if let Ok(out) = Command::new("mojo")
                .arg(mojo_script)
                .arg(format!("{:.0}", drive))
                .arg(format!("{:.0}", humanity))
                .output()
            {
                if out.status.success() {
                    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    // Strip Crashpad warnings if present
                    let json_line = text
                        .lines()
                        .find(|l| l.trim().starts_with('{') && l.trim().ends_with('}'))
                        .unwrap_or(&text);
                    if let Ok(verdict) = serde_json::from_str::<BalanceVerdict>(json_line) {
                        return Ok(verdict);
                    }
                }
            }
        }

        // 3. High-performance native Rust fallback
        Ok(Self::rust_fallback(drive, humanity))
    }

    pub fn evaluate_simd(
        drive_vec: [f32; 4],
        humanity_vec: [f32; 4],
        kernel_path: Option<&str>,
    ) -> Result<BalanceVerdict, String> {
        let binary_path = kernel_path.unwrap_or("mojo/balance_bin");
        if Path::new(binary_path).exists() {
            let mut cmd = Command::new(binary_path);
            for d in drive_vec {
                cmd.arg(format!("{:.0}", d));
            }
            for h in humanity_vec {
                cmd.arg(format!("{:.0}", h));
            }
            if let Ok(out) = cmd.output() {
                if out.status.success() {
                    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    let json_line = text
                        .lines()
                        .find(|l| l.trim().starts_with('{') && l.trim().ends_with('}'))
                        .unwrap_or(&text);
                    if let Ok(verdict) = serde_json::from_str::<BalanceVerdict>(json_line) {
                        return Ok(verdict);
                    }
                }
            }
        }

        // Rust fallback calculation for 4-lane vector
        let d_sum: f32 = drive_vec.iter().sum();
        let h_sum: f32 = humanity_vec.iter().sum();
        let mut v = Self::rust_fallback(d_sum as f64, h_sum as f64);
        v.mode = "simd-rust-fallback".to_string();
        Ok(v)
    }

    fn rust_fallback(drive: f64, humanity: f64) -> BalanceVerdict {
        if drive == 0.0 && humanity == 0.0 {
            return BalanceVerdict {
                kernel: "rust-fallback".to_string(),
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
                kernel: "rust-fallback".to_string(),
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
                kernel: "rust-fallback".to_string(),
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
            kernel: "rust-fallback".to_string(),
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
    fn test_rust_fallback_balanced() {
        let v = BalanceKernel::rust_fallback(10.0, 10.0);
        assert_eq!(v.verdict, "balanced");
        assert_eq!(v.ratio, 1.0);
        assert_eq!(v.score, 1.0);
    }

    #[test]
    fn test_rust_fallback_drive_dominant() {
        let v = BalanceKernel::rust_fallback(30.0, 5.0);
        assert_eq!(v.verdict, "drive_dominant");
        assert!(v.ratio > 2.0);
    }

    #[test]
    fn test_rust_fallback_humanity_dominant() {
        let v = BalanceKernel::rust_fallback(2.0, 10.0);
        assert_eq!(v.verdict, "humanity_dominant");
        assert!(v.ratio < 0.5);
    }
}
