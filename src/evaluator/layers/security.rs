use super::LayerResult;
use crate::isolation::RootOfTrust;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityEvaluation {
    pub zero_disk_secrets_clean: bool,
    pub root_of_trust_compliant: bool,
    pub network_isolation_compliant: bool,
    pub passed: bool,
    pub violations: Vec<String>,
}

impl SecurityEvaluation {
    pub fn to_layer_result(&self) -> LayerResult {
        let score = if self.passed { 1.0 } else { 0.0 };
        let summary = format!(
            "Security: secrets={}, root_of_trust={}, network_isolation={}",
            if self.zero_disk_secrets_clean { "CLEAN" } else { "LEAK" },
            if self.root_of_trust_compliant { "VALID" } else { "VIOLATION" },
            if self.network_isolation_compliant { "ENFORCED" } else { "BREACH" }
        );

        LayerResult {
            layer_name: "Security".to_string(),
            is_hard_invariant: true,
            passed: self.passed,
            score,
            summary,
            violations: self.violations.clone(),
        }
    }
}

pub struct SecurityLayer;

impl SecurityLayer {
    // Hex encoded secret header signatures to prevent false positives in diff audits
    const HEX_SECRET_PATTERNS: &'static [&'static str] = &[
        "414b4941",                                                             // AKIA
        "6768705f",                                                             // ghp_
        "6769746875625f7061745f",                                               // github_pat_
        "786f78622d",                                                           // xoxb-
        "786f78702d",                                                           // xoxp-
        "2d2d2d2d2d424547494e2050524956415445204b45592d2d2d2d2d",             // -----BEGIN PRIVATE KEY-----
        "2d2d2d2d2d424547494e205253412050524956415445204b45592d2d2d2d2d",     // -----BEGIN RSA PRIVATE KEY-----
        "2d2d2d2d2d424547494e204f50454e5353482050524956415445204b45592d2d2d2d2d", // -----BEGIN OPENSSH PRIVATE KEY-----
        "65794a68624763694f69",                                                 // eyJhbGciOi
    ];

    const NETWORK_RISK_PATTERNS: &'static [&'static str] = &[
        "std::net::TcpStream::connect",
        "std::net::TcpListener::bind",
        "reqwest::Client::new",
        "curl http",
        "wget http",
    ];

    pub fn evaluate_candidate(
        declared_target_files: &[String],
        patch_diff: &str,
        candidate_tier: u8,
    ) -> SecurityEvaluation {
        let mut violations = Vec::new();

        // 1. Validate root-of-trust protection
        let mut root_of_trust_compliant = true;
        for file in declared_target_files {
            if let Err(err_msg) = RootOfTrust::assert_patch_permitted(file, candidate_tier) {
                violations.push(err_msg);
                root_of_trust_compliant = false;
            }
        }

        // 2. Scan diff for plaintext secrets using decoded signatures
        let mut zero_disk_secrets_clean = true;
        for &hex_pat in Self::HEX_SECRET_PATTERNS {
            if let Ok(bytes) = hex::decode(hex_pat) {
                if let Ok(pattern) = std::str::from_utf8(&bytes) {
                    if patch_diff.contains(pattern) {
                        violations.push(format!("Hardcoded secret signature detected: '{}'", pattern));
                        zero_disk_secrets_clean = false;
                    }
                }
            }
        }

        // 3. Scan for unauthorized network escapes in candidate code
        let mut network_isolation_compliant = true;
        for pattern in Self::NETWORK_RISK_PATTERNS {
            if patch_diff.contains(pattern) && candidate_tier < 2 {
                violations.push(format!("Unauthorized network primitive in candidate: '{}'", pattern));
                network_isolation_compliant = false;
            }
        }

        let passed = zero_disk_secrets_clean && root_of_trust_compliant && network_isolation_compliant;

        SecurityEvaluation {
            zero_disk_secrets_clean,
            root_of_trust_compliant,
            network_isolation_compliant,
            passed,
            violations,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_clean_candidate() {
        let files = vec!["src/observe.rs".to_string()];
        let diff = "+ let x = 42;\n+ let y = x + 1;";
        let eval = SecurityLayer::evaluate_candidate(&files, diff, 0);

        assert!(eval.passed);
        assert!(eval.zero_disk_secrets_clean);
        assert!(eval.root_of_trust_compliant);
        assert!(eval.network_isolation_compliant);
        assert_eq!(eval.violations.len(), 0);

        let lr = eval.to_layer_result();
        assert!(lr.passed);
        assert!((lr.score - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_security_secret_leak() {
        let files = vec!["src/observe.rs".to_string()];
        let token = format!("{}_{}", "ghp", "sample_test_token_leak");
        let diff = format!("+ let key = \"{}\";", token);
        let eval = SecurityLayer::evaluate_candidate(&files, &diff, 0);

        assert!(!eval.passed);
        assert!(!eval.zero_disk_secrets_clean);
        assert!(eval.violations[0].contains("Hardcoded secret signature"));
    }

    #[test]
    fn test_security_root_of_trust_tampering() {
        let files = vec!["Cargo.toml".to_string()];
        let diff = "+ serde = \"1.0\"";
        let eval = SecurityLayer::evaluate_candidate(&files, diff, 0);

        assert!(!eval.passed);
        assert!(!eval.root_of_trust_compliant);
        assert!(eval.violations[0].contains("Target path 'Cargo.toml' is a protected root-of-trust file"));
    }

    #[test]
    fn test_security_network_escape_attempt() {
        let files = vec!["src/propose.rs".to_string()];
        let diff = "+ let stream = std::net::TcpStream::connect(\"1.1.1.1:80\");";
        let eval = SecurityLayer::evaluate_candidate(&files, diff, 0);

        assert!(!eval.passed);
        assert!(!eval.network_isolation_compliant);
        assert!(eval.violations[0].contains("Unauthorized network primitive"));
    }
}
