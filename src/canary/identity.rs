//! The bound candidate identity chain: source patch digest, evaluated tree digest, built
//! executable digest, generation id. The supervisor launches only the executable whose digest
//! is in the chain, every observation carries that executable digest, and the quota validator
//! compares the executable digest, never the patch digest.

use super::{canonical_json, domain_digest, is_hex_digest, sha256_hex, IDENTITY_VERSION};
use crate::isolation::ArtifactManifest;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const IDENTITY_DOMAIN: &str = "spark-rsi/candidate-identity/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateIdentity {
    pub identity_version: u16,
    /// SHA-256 of the proposal's patch bytes.
    pub patch_digest: String,
    /// Digest of the evaluated tree (`ArtifactManifest::compute_source_digest`).
    pub tree_digest: String,
    /// SHA-256 of the executable file the supervisor launches.
    pub executable_digest: String,
    pub generation_id: String,
}

impl CandidateIdentity {
    pub fn new(
        patch_digest: &str,
        tree_digest: &str,
        executable_digest: &str,
        generation_id: &str,
    ) -> Self {
        Self {
            identity_version: IDENTITY_VERSION,
            patch_digest: patch_digest.to_string(),
            tree_digest: tree_digest.to_string(),
            executable_digest: executable_digest.to_string(),
            generation_id: generation_id.to_string(),
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.identity_version != IDENTITY_VERSION {
            return Err(format!(
                "candidate identity version {} is not supported (expected {})",
                self.identity_version, IDENTITY_VERSION
            ));
        }
        for (name, value) in [
            ("patch_digest", &self.patch_digest),
            ("tree_digest", &self.tree_digest),
            ("executable_digest", &self.executable_digest),
        ] {
            if !is_hex_digest(value) {
                return Err(format!("candidate identity {} is not a hex SHA-256", name));
            }
        }
        if self.generation_id.trim().is_empty() {
            return Err("candidate identity generation id is required".to_string());
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        canonical_json(self)
    }

    /// One digest binding the whole chain, for ledger commitments and reports.
    pub fn binding_digest(&self) -> String {
        domain_digest(
            IDENTITY_DOMAIN,
            &[
                self.patch_digest.as_bytes(),
                self.tree_digest.as_bytes(),
                self.executable_digest.as_bytes(),
                self.generation_id.as_bytes(),
            ],
        )
    }

    /// Re-hashes the file at `path` and refuses it unless it is the executable in the chain.
    /// Call this right before launching.
    pub fn verify_executable(&self, path: &Path) -> Result<(), String> {
        let actual = digest_file(path)?;
        if actual != self.executable_digest {
            return Err(format!(
                "executable {:?} hashes to {}, not the candidate's {}; refusing to launch",
                path, actual, self.executable_digest
            ));
        }
        Ok(())
    }
}

pub fn digest_bytes(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}

pub fn digest_file(path: &Path) -> Result<String, String> {
    let bytes =
        std::fs::read(path).map_err(|e| format!("cannot read {:?} for hashing: {}", path, e))?;
    Ok(sha256_hex(&bytes))
}

/// Digest of a source tree, skipping `target`, `.git` and `node_modules`.
pub fn tree_digest(root: &Path) -> Result<String, String> {
    ArtifactManifest::compute_source_digest(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> CandidateIdentity {
        CandidateIdentity::new(
            &sha256_hex(b"patch"),
            &sha256_hex(b"tree"),
            &sha256_hex(b"exe"),
            "gen-0001",
        )
    }

    #[test]
    fn binding_digest_covers_every_link() {
        let a = sample();
        let mut b = sample();
        b.executable_digest = sha256_hex(b"other exe");
        assert_ne!(a.binding_digest(), b.binding_digest());
        let mut c = sample();
        c.generation_id = "gen-0002".into();
        assert_ne!(a.binding_digest(), c.binding_digest());
        assert!(a.validate().is_ok());
    }

    #[test]
    fn executable_verification_refuses_other_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let exe = tmp.path().join("worker");
        std::fs::write(&exe, b"built bytes").unwrap();
        let id = CandidateIdentity::new(
            &sha256_hex(b"patch"),
            &sha256_hex(b"tree"),
            &digest_file(&exe).unwrap(),
            "gen-0001",
        );
        assert!(id.verify_executable(&exe).is_ok());
        std::fs::write(&exe, b"swapped bytes").unwrap();
        assert!(id
            .verify_executable(&exe)
            .unwrap_err()
            .contains("refusing to launch"));
        assert!(id.verify_executable(&tmp.path().join("missing")).is_err());
    }

    #[test]
    fn validation_requires_hex_digests_and_a_generation() {
        let mut bad = sample();
        bad.patch_digest = "not hex".into();
        assert!(bad.validate().is_err());
        let mut empty = sample();
        empty.generation_id = " ".into();
        assert!(empty.validate().is_err());
    }
}
