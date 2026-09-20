use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactRecord {
    pub relative_path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub is_executable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidateManifest {
    pub manifest_version: String,
    pub candidate_id: String,
    pub parent_commit_sha: String,
    pub proposal_id: String,
    pub code_tier: String,
    pub declared_files: Vec<String>,
    pub primary_metric: String,
    pub expected_delta_pct: f64,
    pub regression_budgets: HashMap<String, f64>,
    pub protected_metric_limits: HashMap<String, f64>,
    pub timestamp_utc: String,
}

impl CandidateManifest {
    pub fn new(
        candidate_id: &str,
        parent_commit_sha: &str,
        proposal_id: &str,
        code_tier: &str,
        declared_files: Vec<String>,
        primary_metric: &str,
        expected_delta_pct: f64,
    ) -> Self {
        let mut regression_budgets = HashMap::new();
        regression_budgets.insert("latency_p95_degradation_pct".to_string(), 1.0);
        regression_budgets.insert("latency_p99_degradation_pct".to_string(), 1.0);
        regression_budgets.insert("rss_growth_pct".to_string(), 2.0);

        let mut protected_metric_limits = HashMap::new();
        protected_metric_limits.insert("host_memory_ceiling_mb".to_string(), 49152.0);

        Self {
            manifest_version: "1.0.0".to_string(),
            candidate_id: candidate_id.to_string(),
            parent_commit_sha: parent_commit_sha.to_string(),
            proposal_id: proposal_id.to_string(),
            code_tier: code_tier.to_string(),
            declared_files,
            primary_metric: primary_metric.to_string(),
            expected_delta_pct,
            regression_budgets,
            protected_metric_limits,
            timestamp_utc: chrono::Utc::now().to_rfc3339(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactManifest {
    pub manifest_version: String,
    pub candidate_id: String,
    pub builder_image_digest: String,
    pub source_bundle_digest: String,
    pub artifacts: Vec<ArtifactRecord>,
    pub manifest_digest: String,
    pub timestamp_utc: String,
}

impl ArtifactManifest {
    pub fn compute_file_sha256(path: &Path) -> Result<String, String> {
        let bytes = fs::read(path).map_err(|e| format!("Failed to read file {:?}: {}", path, e))?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        Ok(hex::encode(hasher.finalize()))
    }

    pub fn compute_source_digest(dir: &Path) -> Result<String, String> {
        let mut file_entries = Vec::new();
        Self::collect_files_sorted(dir, dir, &mut file_entries)?;

        let mut hasher = Sha256::new();
        for (rel_path, abs_path) in file_entries {
            let file_hash = Self::compute_file_sha256(&abs_path)?;
            hasher.update(rel_path.as_bytes());
            hasher.update(file_hash.as_bytes());
        }

        Ok(hex::encode(hasher.finalize()))
    }

    fn collect_files_sorted(
        base: &Path,
        current: &Path,
        acc: &mut Vec<(String, PathBuf)>,
    ) -> Result<(), String> {
        if !current.exists() {
            return Ok(());
        }
        let mut entries = Vec::new();
        for entry in fs::read_dir(current).map_err(|e| e.to_string())?.flatten() {
            entries.push(entry.path());
        }
        entries.sort();

        for path in entries {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            if name == "target" || name == ".git" || name == "node_modules" {
                continue;
            }
            if path.is_dir() {
                Self::collect_files_sorted(base, &path, acc)?;
            } else if path.is_file() {
                let rel = path
                    .strip_prefix(base)
                    .map_err(|e| e.to_string())?
                    .to_string_lossy()
                    .to_string();
                acc.push((rel, path));
            }
        }
        Ok(())
    }

    pub fn generate_from_output_dir(
        candidate_id: &str,
        builder_image_digest: &str,
        source_bundle_digest: &str,
        output_dir: &Path,
    ) -> Result<Self, String> {
        let mut file_entries = Vec::new();
        Self::collect_files_sorted(output_dir, output_dir, &mut file_entries)?;

        let mut records = Vec::new();
        let mut digest_hasher = Sha256::new();
        digest_hasher.update(candidate_id.as_bytes());
        digest_hasher.update(builder_image_digest.as_bytes());
        digest_hasher.update(source_bundle_digest.as_bytes());

        for (rel_path, abs_path) in file_entries {
            let meta = fs::metadata(&abs_path).map_err(|e| e.to_string())?;
            let sha = Self::compute_file_sha256(&abs_path)?;
            let is_exec = (meta.permissions().mode() & 0o111) != 0;

            digest_hasher.update(rel_path.as_bytes());
            digest_hasher.update(sha.as_bytes());
            digest_hasher.update(meta.len().to_be_bytes());

            records.push(ArtifactRecord {
                relative_path: rel_path,
                sha256: sha,
                size_bytes: meta.len(),
                is_executable: is_exec,
            });
        }

        let manifest_digest = hex::encode(digest_hasher.finalize());

        Ok(Self {
            manifest_version: "1.0.0".to_string(),
            candidate_id: candidate_id.to_string(),
            builder_image_digest: builder_image_digest.to_string(),
            source_bundle_digest: source_bundle_digest.to_string(),
            artifacts: records,
            manifest_digest,
            timestamp_utc: chrono::Utc::now().to_rfc3339(),
        })
    }

    pub fn verify_integrity(&self, output_dir: &Path) -> Result<bool, String> {
        let mut expected_paths = HashSet::new();
        for record in &self.artifacts {
            let full_path = output_dir.join(&record.relative_path);
            if !full_path.exists() {
                return Ok(false);
            }
            let actual_sha = Self::compute_file_sha256(&full_path)?;
            if actual_sha != record.sha256 {
                return Ok(false);
            }
            expected_paths.insert(record.relative_path.clone());
        }

        // Active scan for extra unmanifested files
        let mut on_disk_entries = Vec::new();
        Self::collect_files_sorted(output_dir, output_dir, &mut on_disk_entries)?;

        for (rel_path, _) in on_disk_entries {
            if !expected_paths.contains(&rel_path) {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_candidate_manifest_creation() {
        let manifest = CandidateManifest::new(
            "cand-001",
            "6ac8ae95cf13fd618c855ca1c0c67e6f8455fc5d",
            "hyp-001",
            "TARGET",
            vec!["src/observe.rs".to_string()],
            "latency_p95_us",
            -12.5,
        );
        assert_eq!(manifest.candidate_id, "cand-001");
        assert_eq!(manifest.code_tier, "TARGET");
        assert_eq!(manifest.expected_delta_pct, -12.5);
        assert!(manifest
            .regression_budgets
            .contains_key("latency_p95_degradation_pct"));
        assert!(manifest
            .protected_metric_limits
            .contains_key("host_memory_ceiling_mb"));
    }

    #[test]
    fn test_artifact_manifest_generation_and_integrity() {
        let tmp = tempfile::tempdir().unwrap();
        let file1 = tmp.path().join("libsample.so");
        let file2 = tmp.path().join("config.json");

        fs::write(&file1, "mock shared library binary content").unwrap();
        fs::write(&file2, "{\"key\":\"value\"}").unwrap();

        let source_digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let builder_img = "docker.io/library/spark-rsi-builder@sha256:abcd1234";

        let manifest = ArtifactManifest::generate_from_output_dir(
            "cand-test",
            builder_img,
            source_digest,
            tmp.path(),
        )
        .unwrap();

        assert_eq!(manifest.artifacts.len(), 2);
        assert!(!manifest.manifest_digest.is_empty());
        assert!(manifest.verify_integrity(tmp.path()).unwrap());

        // Tamper with file
        fs::write(&file1, "tampered content").unwrap();
        assert!(!manifest.verify_integrity(tmp.path()).unwrap());
    }

    #[test]
    fn test_artifact_manifest_rejects_unmanifested_extra_file() {
        let tmp = tempfile::tempdir().unwrap();
        let file1 = tmp.path().join("main_binary");
        fs::write(&file1, "compiled binary bytes").unwrap();

        let manifest = ArtifactManifest::generate_from_output_dir(
            "cand-test",
            "builder-img",
            "source-digest",
            tmp.path(),
        )
        .unwrap();

        assert!(manifest.verify_integrity(tmp.path()).unwrap());

        // Inject extra unauthorized file
        let rogue = tmp.path().join("backdoor.sh");
        fs::write(&rogue, "#!/bin/sh\nexit 0").unwrap();

        assert!(!manifest.verify_integrity(tmp.path()).unwrap());
    }
}
