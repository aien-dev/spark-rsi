//! The canary workload: the digest-pinned set of requests, expected outcomes, deadlines and
//! permitted nondeterminism the supervisor issues. It lives under the RSI state directory and
//! is owned by the operator. The candidate never rewrites it and never sets its own passing
//! criteria.

use super::{canonical_json, domain_digest, sha256_hex, CANARY_PROTOCOL_VERSION, WORKLOAD_VERSION};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub const WORKLOAD_DOMAIN: &str = "spark-rsi/canary-workload/v1";
pub const REQUEST_DOMAIN: &str = "spark-rsi/canary-request/v1";

/// How much the observed output may differ from `expected_output`. Version 1 permits none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Nondeterminism {
    Exact,
}

impl Nondeterminism {
    pub fn as_str(&self) -> &'static str {
        match self {
            Nondeterminism::Exact => "exact",
        }
    }
}

/// One challenge the supervisor sends. The worker only ever sees `input`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryRequestSpec {
    pub request_id: String,
    pub input: String,
    pub expected_output: String,
    pub deadline_ms: u64,
    pub nondeterminism: Nondeterminism,
}

impl CanaryRequestSpec {
    /// Binds the request to its workload, input, expected outcome and deadline.
    pub fn request_digest(&self, workload_id: &str) -> String {
        domain_digest(
            REQUEST_DOMAIN,
            &[
                workload_id.as_bytes(),
                self.request_id.as_bytes(),
                self.input.as_bytes(),
                self.expected_output.as_bytes(),
                &self.deadline_ms.to_le_bytes(),
                self.nondeterminism.as_str().as_bytes(),
            ],
        )
    }

    /// The result digest a correct answer produces: SHA-256 of the expected output bytes.
    pub fn expected_result_digest(&self) -> String {
        sha256_hex(self.expected_output.as_bytes())
    }

    /// Whether `output` satisfies this request under its permitted nondeterminism.
    pub fn matches_output(&self, output: &str) -> bool {
        match self.nondeterminism {
            Nondeterminism::Exact => output == self.expected_output,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.request_id.trim().is_empty() {
            return Err("canary request id is required".to_string());
        }
        if self.request_id.chars().any(char::is_control) {
            return Err(format!(
                "canary request id {:?} contains a control character",
                self.request_id
            ));
        }
        if self.deadline_ms == 0 {
            return Err(format!(
                "canary request {} has a zero deadline",
                self.request_id
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryWorkloadManifest {
    pub workload_version: u16,
    pub workload_id: String,
    pub protocol_version: u16,
    pub requests: Vec<CanaryRequestSpec>,
}

/// A workload read from disk together with the digest it was verified against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedWorkload {
    pub manifest: CanaryWorkloadManifest,
    pub digest: String,
    pub path: PathBuf,
}

impl CanaryWorkloadManifest {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let manifest: Self = serde_json::from_slice(bytes)
            .map_err(|e| format!("canary workload does not parse: {}", e))?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.workload_version != WORKLOAD_VERSION {
            return Err(format!(
                "canary workload version {} is not supported (expected {})",
                self.workload_version, WORKLOAD_VERSION
            ));
        }
        if self.protocol_version != CANARY_PROTOCOL_VERSION {
            return Err(format!(
                "canary workload protocol version {} is not supported (expected {})",
                self.protocol_version, CANARY_PROTOCOL_VERSION
            ));
        }
        if self.workload_id.trim().is_empty() || self.workload_id.chars().any(char::is_control) {
            return Err("canary workload id is required and must be printable".to_string());
        }
        if self.requests.is_empty() {
            return Err("canary workload has no requests".to_string());
        }
        let mut ids = BTreeSet::new();
        for req in &self.requests {
            req.validate()?;
            if !ids.insert(req.request_id.as_str()) {
                return Err(format!(
                    "canary workload repeats request id {}",
                    req.request_id
                ));
            }
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        canonical_json(self)
    }

    /// Workload digest: domain-separated SHA-256 of the canonical bytes. Reformatting the file
    /// on disk does not change it; changing any request, outcome or deadline does.
    pub fn digest(&self) -> String {
        domain_digest(WORKLOAD_DOMAIN, &[&self.canonical_bytes()])
    }

    pub fn request(&self, request_id: &str) -> Option<&CanaryRequestSpec> {
        self.requests.iter().find(|r| r.request_id == request_id)
    }

    /// Reads and validates the workload at `path`.
    pub fn load(path: &Path) -> Result<PinnedWorkload, String> {
        let bytes = std::fs::read(path)
            .map_err(|e| format!("cannot read canary workload {:?}: {}", path, e))?;
        let manifest = Self::parse(&bytes)?;
        let digest = manifest.digest();
        Ok(PinnedWorkload {
            manifest,
            digest,
            path: path.to_path_buf(),
        })
    }

    /// Reads the workload at `path` and refuses it unless its digest equals the operator's
    /// pinned `expected_digest`.
    pub fn load_pinned(path: &Path, expected_digest: &str) -> Result<PinnedWorkload, String> {
        let loaded = Self::load(path)?;
        if loaded.digest != expected_digest {
            return Err(format!(
                "canary workload {:?} has digest {}, pinned digest is {}",
                path, loaded.digest, expected_digest
            ));
        }
        Ok(loaded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> CanaryWorkloadManifest {
        CanaryWorkloadManifest {
            workload_version: 1,
            workload_id: "fixture-v1".into(),
            protocol_version: 1,
            requests: vec![
                CanaryRequestSpec {
                    request_id: "req-001".into(),
                    input: "ping".into(),
                    expected_output: "pong".into(),
                    deadline_ms: 2000,
                    nondeterminism: Nondeterminism::Exact,
                },
                CanaryRequestSpec {
                    request_id: "req-002".into(),
                    input: "add 2 3".into(),
                    expected_output: "5".into(),
                    deadline_ms: 2000,
                    nondeterminism: Nondeterminism::Exact,
                },
            ],
        }
    }

    #[test]
    fn digest_ignores_formatting_but_not_content() {
        let a = sample();
        let pretty = serde_json::to_vec_pretty(&a).unwrap();
        let reparsed = CanaryWorkloadManifest::parse(&pretty).unwrap();
        assert_eq!(reparsed.digest(), a.digest());

        let mut b = sample();
        b.requests[0].expected_output = "PONG".into();
        assert_ne!(b.digest(), a.digest());
        assert_ne!(
            b.requests[0].request_digest(&b.workload_id),
            a.requests[0].request_digest(&a.workload_id)
        );

        let mut c = sample();
        c.requests[0].deadline_ms = 1999;
        assert_ne!(c.digest(), a.digest());
    }

    #[test]
    fn validation_fails_closed() {
        let mut dup = sample();
        dup.requests[1].request_id = "req-001".into();
        assert!(dup.validate().unwrap_err().contains("repeats"));

        let mut empty = sample();
        empty.requests.clear();
        assert!(empty.validate().unwrap_err().contains("no requests"));

        let mut version = sample();
        version.protocol_version = 2;
        assert!(version.validate().unwrap_err().contains("protocol version"));

        let mut deadline = sample();
        deadline.requests[0].deadline_ms = 0;
        assert!(deadline.validate().unwrap_err().contains("zero deadline"));

        let unknown_field = br#"{"workload_version":1,"workload_id":"w","protocol_version":1,"requests":[],"passing_criteria":"any"}"#;
        assert!(CanaryWorkloadManifest::parse(unknown_field).is_err());
    }

    #[test]
    fn exact_matching_and_expected_digest() {
        let w = sample();
        let r = w.request("req-001").unwrap();
        assert!(r.matches_output("pong"));
        assert!(!r.matches_output("pong\n"));
        assert_eq!(r.expected_result_digest(), sha256_hex(b"pong"));
        assert!(w.request("req-404").is_none());
    }

    #[test]
    fn pinned_load_refuses_a_different_digest() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("workload.json");
        std::fs::write(&path, serde_json::to_vec(&sample()).unwrap()).unwrap();
        let loaded = CanaryWorkloadManifest::load(&path).unwrap();
        assert_eq!(loaded.digest, sample().digest());
        assert!(CanaryWorkloadManifest::load_pinned(&path, &loaded.digest).is_ok());
        let err = CanaryWorkloadManifest::load_pinned(&path, &sha256_hex(b"other")).unwrap_err();
        assert!(err.contains("pinned digest"));
    }
}
