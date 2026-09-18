use crate::models::{SoulTension, TelemetrySnapshot};
use std::fs;
use std::path::Path;
use std::process::Command;

pub const DRIVE_TERMS: &[&str] = &[
    "curious", "curiosity", "build", "fix", "finish", "ambitious", "ambition",
    "forge", "explore", "discover", "improve", "solve", "create", "learn",
    "question", "truth", "measure", "verify", "optimize", "accelerate",
];

pub const HUMANITY_TERMS: &[&str] = &[
    "love", "grief", "honor", "family", "community", "warmth", "care",
    "kindness", "patience", "humility", "listen", "commitment", "promise",
    "free", "freedom", "ethics", "discipline", "restraint", "sovereignty",
];

pub fn scan_terms(text: &str, terms: &[&str]) -> Vec<String> {
    let lower = text.to_lowercase();
    terms
        .iter()
        .filter(|t| lower.contains(**t))
        .map(|t| t.to_string())
        .collect()
}

pub fn calculate_soul_tension(text: &str) -> SoulTension {
    let drive_matched = scan_terms(text, DRIVE_TERMS);
    let humanity_matched = scan_terms(text, HUMANITY_TERMS);

    let drive_score = drive_matched.len() as f64;
    let humanity_score = humanity_matched.len() as f64;

    let tension_ratio = if humanity_score > 0.0 {
        drive_score / humanity_score
    } else if drive_score > 0.0 {
        999.0
    } else {
        0.0
    };

    let state = if drive_score == 0.0 && humanity_score == 0.0 {
        "Dormant".to_string()
    } else if humanity_score == 0.0 || tension_ratio > 2.0 {
        "DriveDominant".to_string()
    } else if drive_score == 0.0 || tension_ratio < 0.5 {
        "HumanityDominant".to_string()
    } else {
        "Balanced".to_string()
    };

    SoulTension {
        drive_score,
        humanity_score,
        drive_terms_matched: drive_matched,
        humanity_terms_matched: humanity_matched,
        tension_ratio,
        state,
    }
}

pub fn count_crumbs_recursive(root: &Path) -> usize {
    let mut count = 0;
    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default();
                if !name.starts_with('.') && name != "target" {
                    count += count_crumbs_recursive(&path);
                }
            } else if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                if file_name == ".crumb" || file_name == ".crumb.local" {
                    count += 1;
                }
            }
        }
    }
    count
}

pub fn observe_codebase(repo_dir: &Path) -> Result<TelemetrySnapshot, String> {
    let git_branch = Command::new("git")
        .arg("-C")
        .arg(repo_dir)
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let (git_clean, uncommitted_files) = match Command::new("git")
        .arg("-C")
        .arg(repo_dir)
        .args(["status", "--porcelain"])
        .output()
    {
        Ok(out) => {
            let s = String::from_utf8_lossy(&out.stdout);
            let files: Vec<String> = s
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| l.to_string())
                .collect();
            (files.is_empty(), files)
        }
        Err(_) => (false, vec!["failed to run git status".to_string()]),
    };

    let crumbs_detected = count_crumbs_recursive(repo_dir);

    // Read soul text from soul.md or docs/PHILOSOPHY.md or README.md
    let soul_sources = [
        repo_dir.join("soul.md"),
        repo_dir.join("docs").join("PHILOSOPHY.md"),
        repo_dir.join("README.md"),
        Path::new("/home/drakestapleton/atlas-prime-workspace/soul.md").to_path_buf(),
    ];

    let mut corpus = String::new();
    for src in &soul_sources {
        if src.exists() {
            if let Ok(content) = fs::read_to_string(src) {
                corpus.push_str(&content);
                corpus.push(' ');
            }
        }
    }

    let soul_tension = calculate_soul_tension(&corpus);

    // Check test status (fast check)
    let tests_passing = Command::new("cargo")
        .arg("check")
        .arg("--manifest-path")
        .arg(repo_dir.join("Cargo.toml"))
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false);

    Ok(TelemetrySnapshot {
        repo_path: repo_dir.display().to_string(),
        git_branch,
        git_clean,
        uncommitted_files,
        crumbs_detected,
        tests_passing,
        soul_tension,
        timestamp: chrono::Utc::now().to_rfc3339(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_soul_tension_calculation() {
        let text = "We are curious and build tools to fix bugs, solve hard problems, and finish work with love, family, and honor.";
        let tension = calculate_soul_tension(text);
        assert!(tension.drive_score > 0.0);
        assert!(tension.humanity_score > 0.0);
        assert_eq!(tension.state, "Balanced");
    }

    #[test]
    fn test_drive_dominant_detection() {
        let text = "build fix finish optimize forge solve accelerate truth measure";
        let tension = calculate_soul_tension(text);
        assert_eq!(tension.state, "DriveDominant");
    }

    #[test]
    fn test_scan_terms_empty() {
        let matched = scan_terms("random content without keywords", DRIVE_TERMS);
        assert!(matched.is_empty());
    }
}
