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

    /// Lexical normalization: drops leading `/`, `.` and empty components and
    /// resolves `..`. A path that climbs above the repository root, or holds a
    /// backslash or NUL, comes back as `..` so callers fail closed.
    pub fn normalize_path(path: &str) -> String {
        match Self::normalize_strict(path) {
            Ok(p) => p,
            Err(_) => "..".to_string(),
        }
    }

    /// Strict normalization. Refuses backslashes, NUL, and any `..` that climbs
    /// above the repository root.
    pub fn normalize_strict(path: &str) -> Result<String, String> {
        if path.contains('\\') || path.contains('\0') {
            return Err(format!("path {:?} contains a backslash or NUL", path));
        }
        let mut stack: Vec<&str> = Vec::new();
        for comp in path.split('/') {
            match comp {
                "" | "." => {}
                ".." => {
                    if stack.pop().is_none() {
                        return Err(format!("path {:?} climbs above the repository root", path));
                    }
                }
                c => stack.push(c),
            }
        }
        Ok(stack.join("/"))
    }

    pub fn is_protected_path(path: &str) -> bool {
        let normalized = match Self::normalize_strict(path) {
            Ok(p) => p,
            // Anything that cannot be normalized is treated as protected.
            Err(_) => return true,
        };
        if normalized.is_empty() {
            return true;
        }
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
        let normalized = Self::normalize_strict(target_file)
            .map_err(|e| format!("SECURITY VIOLATION: {}", e))?;
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
    fn test_dotdot_and_escape_forms_cannot_bypass_protection() {
        // Before the fix these normalized to themselves and were not protected.
        assert!(RootOfTrust::is_protected_path("src/../Cargo.toml"));
        assert!(RootOfTrust::is_protected_path(
            "docs/../.github/workflows/ci.yml"
        ));
        assert!(RootOfTrust::is_protected_path(
            "src//isolation/container.rs"
        ));
        assert!(RootOfTrust::is_protected_path("../outside.rs"));
        assert!(RootOfTrust::is_protected_path(
            "src\\isolation\\container.rs"
        ));
        assert!(RootOfTrust::assert_patch_permitted("src/../Cargo.toml", 0).is_err());
        // Climbing out of the repository is refused even at tier 2.
        assert!(RootOfTrust::assert_patch_permitted("../../etc/passwd", 2).is_err());
        assert!(RootOfTrust::assert_patch_permitted("docs/../README.md", 0).is_ok());
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
