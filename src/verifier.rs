use crate::models::InvariantReport;
use std::fs;
use std::path::Path;
use std::process::Command;

pub const FORBIDDEN_BUZZWORDS: &[&str] = &[
    "delve",
    "tapestry",
    "testament",
    "beacon",
    "crucial",
    "pivotal",
    "elevate",
    "game-changer",
    "unleash",
    "harness",
    "seamlessly",
];

pub const ANTITHESIS_TROPES: &[&str] = &["it's not ", "it is not ", "not only ", "not just "];

pub const TRANSITIONAL_FLUFF: &[&str] =
    &["furthermore", "moreover", "in conclusion", "at its core"];

pub struct InvariantVerifier;

impl InvariantVerifier {
    pub fn verify_unslop_text(text: &str) -> (bool, usize, usize, Vec<String>, Vec<String>) {
        let em_count = text.matches('\u{2014}').count();
        let en_count = text.matches('\u{2013}').count();

        let lower = text.to_lowercase();
        let mut buzzwords_found = Vec::new();
        for &bw in FORBIDDEN_BUZZWORDS {
            if lower.contains(bw) {
                buzzwords_found.push(bw.to_string());
            }
        }

        let mut tropes_found = Vec::new();
        for &trope in ANTITHESIS_TROPES {
            if lower.contains(trope) {
                tropes_found.push(trope.trim().to_string());
            }
        }
        for &fluff in TRANSITIONAL_FLUFF {
            if lower.contains(fluff) {
                tropes_found.push(fluff.to_string());
            }
        }

        let clean =
            em_count == 0 && en_count == 0 && buzzwords_found.is_empty() && tropes_found.is_empty();
        (clean, em_count, en_count, buzzwords_found, tropes_found)
    }

    pub fn scan_dir_for_secrets(root: &Path) -> (bool, Vec<String>) {
        let mut leaks = Vec::new();
        Self::scan_dir_secrets_inner(root, &mut leaks, 0);
        let clean = leaks.is_empty();
        (clean, leaks)
    }

    fn scan_dir_secrets_inner(dir: &Path, leaks: &mut Vec<String>, depth: usize) {
        if depth > 8 {
            return;
        }
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();

            if name == "target" || name == ".git" {
                continue;
            }

            let path_str = path.display().to_string();
            if path_str.ends_with("src/verifier.rs")
                || path_str.ends_with("tests/integration_tests.rs")
            {
                continue;
            }

            if path.is_file() {
                if name == ".env" || name.starts_with(".env.") {
                    leaks.push(format!(
                        "Found prohibited env file on disk: {}",
                        path.display()
                    ));
                }

                if let Ok(content) = fs::read_to_string(&path) {
                    let sec_sigs = [
                        concat!("-----BEGIN ", "OPENSSH PRIVATE KEY-----"),
                        concat!("-----BEGIN ", "RSA PRIVATE KEY-----"),
                        concat!("-----BEGIN ", "EC PRIVATE KEY-----"),
                        concat!("-----BEGIN ", "PRIVATE KEY-----"),
                    ];
                    for sig in sec_sigs {
                        if content.contains(sig) {
                            leaks
                                .push(format!("Found private key signature in {}", path.display()));
                            break;
                        }
                    }
                }
            } else if path.is_dir() {
                Self::scan_dir_secrets_inner(&path, leaks, depth + 1);
            }
        }
    }

    pub fn verify_compilation_and_tests(
        target_dir: &Path,
    ) -> (bool, Option<String>, bool, Option<String>) {
        let cargo_toml = target_dir.join("Cargo.toml");
        if !cargo_toml.exists() {
            return (
                true,
                None,
                true,
                Some("No Cargo.toml present; skipped".to_string()),
            );
        }

        let check_res = Command::new("cargo")
            .arg("check")
            .arg("--manifest-path")
            .arg(&cargo_toml)
            .output();

        let (compile_passed, compile_err) = match check_res {
            Ok(out) => {
                if out.status.success() {
                    (true, None)
                } else {
                    let err = String::from_utf8_lossy(&out.stderr).to_string();
                    (false, Some(err))
                }
            }
            Err(e) => (false, Some(format!("Failed to spawn cargo check: {}", e))),
        };

        if !compile_passed {
            return (false, compile_err, false, None);
        }

        let test_res = Command::new("cargo")
            .arg("test")
            .arg("--manifest-path")
            .arg(&cargo_toml)
            .arg("--")
            .arg("--test-threads=1")
            .arg("--nocapture")
            .output();

        let (test_passed, test_summary) = match test_res {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                let summary = if out.status.success() {
                    "All tests passed".to_string()
                } else {
                    format!("Test failures:\n{}\n{}", stdout, stderr)
                };
                (out.status.success(), Some(summary))
            }
            Err(e) => (false, Some(format!("Failed to spawn cargo test: {}", e))),
        };

        (compile_passed, compile_err, test_passed, test_summary)
    }

    pub fn run_full_verification(target_dir: &Path) -> InvariantReport {
        Self::run_full_verification_scoped(target_dir, true)
    }

    /// Runs invariants with build checks optionally disabled.
    /// Non-code proposals (markdown sanitization) must not be gated by compilation,
    /// because the sandbox cannot resolve sibling path dependencies.
    pub fn run_full_verification_scoped(
        target_dir: &Path,
        run_build_checks: bool,
    ) -> InvariantReport {
        let mut notes = Vec::new();

        let mut total_em = 0;
        let mut total_en = 0;
        let mut buzzwords = Vec::new();
        let mut tropes = Vec::new();

        let check_files = ["README.md", "docs/PHILOSOPHY.md", "CONTRIBUTING.md"];
        for rel in &check_files {
            let p = target_dir.join(rel);
            if p.exists() {
                if let Ok(content) = fs::read_to_string(&p) {
                    let (_, em, en, bw, tr) = Self::verify_unslop_text(&content);
                    total_em += em;
                    total_en += en;
                    buzzwords.extend(bw);
                    tropes.extend(tr);
                }
            }
        }
        buzzwords.sort();
        buzzwords.dedup();
        tropes.sort();
        tropes.dedup();

        let unslop_clean =
            total_em == 0 && total_en == 0 && buzzwords.is_empty() && tropes.is_empty();
        if !unslop_clean {
            notes.push(format!(
                "Unslop violation: em_dashes={}, en_dashes={}, buzzwords={:?}, tropes={:?}",
                total_em, total_en, buzzwords, tropes
            ));
        }

        let (secrets_clean, leaks) = Self::scan_dir_for_secrets(target_dir);
        if !secrets_clean {
            notes.push(format!("Zero disk secrets violation: {:?}", leaks));
        }

        let (compile_ok, compile_err, test_ok, test_summary) = if run_build_checks {
            Self::verify_compilation_and_tests(target_dir)
        } else {
            (
                true,
                None,
                true,
                Some("Skipped: non-code proposal".to_string()),
            )
        };

        if !compile_ok {
            notes.push("Compilation failed".to_string());
        }
        if !test_ok {
            notes.push("Tests failed".to_string());
        }

        let passed = unslop_clean && secrets_clean && compile_ok && test_ok;

        InvariantReport {
            passed,
            unslop_clean,
            em_dash_detected: total_em,
            en_dash_detected: total_en,
            forbidden_buzzwords_detected: buzzwords,
            antithesis_tropes_detected: tropes,
            zero_disk_secrets_clean: secrets_clean,
            secret_leaks: leaks,
            compilation_passed: compile_ok,
            compilation_error: compile_err,
            tests_passed: test_ok,
            test_output_summary: test_summary,
            notes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unslop_clean_text() {
        let sample = "High performance Rust code running on SparkOS hardware.";
        let (clean, em, en, bw, tr) = InvariantVerifier::verify_unslop_text(sample);
        assert!(clean);
        assert_eq!(em, 0);
        assert_eq!(en, 0);
        assert!(bw.is_empty());
        assert!(tr.is_empty());
    }

    #[test]
    fn test_unslop_detects_em_dash() {
        let sample = "This is good \u{2014} but that is bad.";
        let (clean, em, _, _, _) = InvariantVerifier::verify_unslop_text(sample);
        assert!(!clean);
        assert_eq!(em, 1);
    }

    #[test]
    fn test_unslop_detects_buzzwords() {
        let sample = "We will delve into this crucial topic.";
        let (clean, _, _, bw, _) = InvariantVerifier::verify_unslop_text(sample);
        assert!(!clean);
        assert!(bw.contains(&"delve".to_string()));
        assert!(bw.contains(&"crucial".to_string()));
    }
}
