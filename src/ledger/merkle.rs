use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleCheckpoint {
    pub up_to_sequence: u64,
    pub merkle_root: String,
    pub block_count: u64,
    pub timestamp_utc: String,
    pub signature: Option<String>,
}

impl MerkleCheckpoint {
    pub fn new(up_to_sequence: u64, merkle_root: String, block_count: u64) -> Self {
        Self {
            up_to_sequence,
            merkle_root,
            block_count,
            timestamp_utc: chrono::Utc::now().to_rfc3339(),
            signature: None,
        }
    }

    pub fn sign(&mut self, signing_key: &SigningKey) {
        let sig: Signature = signing_key.sign(self.merkle_root.as_bytes());
        self.signature = Some(format!("p256:{}", hex::encode(sig.to_bytes())));
    }

    pub fn verify_signature(&self, verifying_key: &VerifyingKey) -> bool {
        if let Some(ref sig_str) = self.signature {
            if let Some(hex_str) = sig_str.strip_prefix("p256:") {
                if let Ok(sig_bytes) = hex::decode(hex_str) {
                    if let Ok(sig) = Signature::from_slice(&sig_bytes) {
                        return verifying_key.verify(self.merkle_root.as_bytes(), &sig).is_ok();
                    }
                }
            }
        }
        false
    }
}

pub fn compute_merkle_root(leaf_hashes: &[String]) -> String {
    if leaf_hashes.is_empty() {
        return "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    }
    if leaf_hashes.len() == 1 {
        return leaf_hashes[0].clone();
    }

    let mut current_level: Vec<String> = leaf_hashes.to_vec();

    while current_level.len() > 1 {
        let mut next_level = Vec::new();
        let len = current_level.len();
        let mut i = 0;

        while i < len {
            let left = &current_level[i];
            let right = if i + 1 < len {
                &current_level[i + 1]
            } else {
                // Odd leaf: duplicate right child as per standard Merkle tree specification
                &current_level[i]
            };

            let mut hasher = Sha256::new();
            hasher.update(left.as_bytes());
            hasher.update(right.as_bytes());
            next_level.push(format!("{:x}", hasher.finalize()));

            i += 2;
        }

        current_level = next_level;
    }

    current_level[0].clone()
}
