use super::LayerResult;
use crate::isolation::RootOfTrust;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityEvaluation {
    pub root_of_trust_compliant: bool,
    pub zero_disk_secrets_clean: bool,
    pub network_isolation_compliant: bool,
    pub passed: bool,
    pub violations: Vec<String>,
}

impl SecurityEvaluation {
    pub fn to_layer_result(&self) -> LayerResult {
        let score = if self.passed { 1.0 } else { 0.0 };
        let summary = format!(
            "Security: root_of_trust={}, zero_disk_secrets={}, network_isolation={}",
            if self.root_of_trust_compliant {
                "PASS"
            } else {
                "FAIL"
            },
            if self.zero_disk_secrets_clean {
                "PASS"
            } else {
                "FAIL"
            },
            if self.network_isolation_compliant {
                "PASS"
            } else {
                "FAIL"
            }
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
    fn secret_signatures() -> Vec<String> {
        vec![
            "AKIA".to_string(),
            ["gh", "p_"].join(""),
            ["github", "_pat_"].join(""),
            ["xox", "b-"].join(""),
            ["xox", "p-"].join(""),
            ["-----BEGIN ", "PRIVATE KEY-----"].join(""),
            ["-----BEGIN ", "RSA PRIVATE KEY-----"].join(""),
            ["-----BEGIN ", "OPENSSH PRIVATE KEY-----"].join(""),
            "eyJhbGciOi".to_string(),
        ]
    }

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
        let root_check =
            RootOfTrust::validate_declared_files(declared_target_files, candidate_tier);
        let root_of_trust_compliant = match root_check {
            Ok(_) => true,
            Err(e) => {
                violations.push(format!("Root-of-trust violation: {}", e.join(", ")));
                false
            }
        };

        // 2. Validate zero disk secrets
        let patterns = Self::secret_signatures();
        let mut zero_disk_secrets_clean = true;
        for pattern in &patterns {
            if patch_diff.contains(pattern) {
                violations.push(format!("Hardcoded secret signature detected: {}", pattern));
                zero_disk_secrets_clean = false;
            }
        }

        // 3. Validate network isolation compliance
        let mut network_isolation_compliant = true;
        for &net_pat in Self::NETWORK_RISK_PATTERNS {
            if patch_diff.contains(net_pat) {
                violations.push(format!(
                    "Unauthorized network primitive detected: {}",
                    net_pat
                ));
                network_isolation_compliant = false;
            }
        }

        let passed =
            root_of_trust_compliant && zero_disk_secrets_clean && network_isolation_compliant;

        SecurityEvaluation {
            root_of_trust_compliant,
            zero_disk_secrets_clean,
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
        let files = vec!["src/observe.rs".to_string(), "src/propose.rs".to_string()];
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
        let fake_token = ["gh", "p_1234567890abcdef1234567890abcdef1234"].join("");
        let diff = format!("+ let key = \"{}\";", fake_token);
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
        assert!(eval.violations[0]
            .contains("Target path 'Cargo.toml' is a protected root-of-trust file"));
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
