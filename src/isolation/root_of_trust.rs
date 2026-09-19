use std::path::Path;

pub struct RootOfTrust;

impl RootOfTrust {
    pub const PROTECTED_PATHS: &'static [&'static str] = &[
        "Cargo.toml",
        "Cargo.lock",
        ".cargo",
        "src/isolation",
        "src/evaluator",
        "src/ledger",
        "src/governance",
        "src/supervisor",
        "src/daemon.rs",
        "tests",
        ".github",
        "CONSTITUTION.md",
        "LICENSE",
        "agent.json",
        ".rsi/ledger.db",
        ".rsi/active",
        ".rsi/holdouts",
    ];

    pub fn normalize_path(path: &str) -> String {
        let p = path.trim_start_matches("./").trim_start_matches('/');
        p.to_string()
    }

    pub fn is_protected_path(path: &str) -> bool {
        let normalized = Self::normalize_path(path);
        let path_obj = Path::new(&normalized);

        for protected in Self::PROTECTED_PATHS {
            let prot_obj = Path::new(protected);
            if path_obj == prot_obj || path_obj.starts_with(prot_obj) {
                return true;
            }
        }
        false
    }

    pub fn assert_patch_permitted(target_file: &str, tier: u8) -> Result<(), String> {
        let normalized = Self::normalize_path(target_file);
        if Self::is_protected_path(&normalized) && tier < 2 {
            return Err(format!(
                "SECURITY VIOLATION: Target path '{}' is a protected root-of-trust file. Required tier: >= 2, candidate tier: {}",
                normalized, tier
            ));
        }
        Ok(())
    }

    pub fn validate_declared_files(declared_files: &[String], tier: u8) -> Result<(), Vec<String>> {
        let mut violations = Vec::new();
        for file in declared_files {
            if let Err(msg) = Self::assert_patch_permitted(file, tier) {
                violations.push(msg);
            }
        }

        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protected_paths_detected() {
        assert!(RootOfTrust::is_protected_path("Cargo.toml"));
        assert!(RootOfTrust::is_protected_path("./Cargo.toml"));
        assert!(RootOfTrust::is_protected_path("src/isolation/container.rs"));
        assert!(RootOfTrust::is_protected_path("src/evaluator/stats.rs"));
        assert!(RootOfTrust::is_protected_path(".github/workflows/ci.yml"));
        assert!(RootOfTrust::is_protected_path("CONSTITUTION.md"));
        assert!(RootOfTrust::is_protected_path(".rsi/ledger.db"));
    }

    #[test]
    fn test_unprotected_target_paths_allowed() {
        assert!(!RootOfTrust::is_protected_path("src/observe.rs"));
        assert!(!RootOfTrust::is_protected_path("src/propose.rs"));
        assert!(!RootOfTrust::is_protected_path("src/models.rs"));
        assert!(!RootOfTrust::is_protected_path("docs/PHILOSOPHY.md"));
        assert!(!RootOfTrust::is_protected_path("README.md"));
    }

    #[test]
    fn test_tier_enforcement() {
        assert!(RootOfTrust::assert_patch_permitted("src/observe.rs", 0).is_ok());
        assert!(RootOfTrust::assert_patch_permitted("src/isolation/root_of_trust.rs", 0).is_err());
        assert!(RootOfTrust::assert_patch_permitted("src/isolation/root_of_trust.rs", 1).is_err());
        assert!(RootOfTrust::assert_patch_permitted("src/isolation/root_of_trust.rs", 2).is_ok());
    }

    #[test]
    fn test_validate_declared_files_batch() {
        let valid = vec!["src/observe.rs".to_string(), "README.md".to_string()];
        assert!(RootOfTrust::validate_declared_files(&valid, 0).is_ok());

        let invalid = vec!["src/observe.rs".to_string(), "Cargo.toml".to_string()];
        let err = RootOfTrust::validate_declared_files(&invalid, 0).unwrap_err();
        assert_eq!(err.len(), 1);
    }
}
