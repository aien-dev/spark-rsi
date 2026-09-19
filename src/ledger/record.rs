use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BlockType {
    Genesis,
    Evaluation,
    Promotion,
    Rollback,
    PromotionEvidence,
}

impl std::fmt::Display for BlockType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockType::Genesis => write!(f, "GENESIS"),
            BlockType::Evaluation => write!(f, "EVALUATION"),
            BlockType::Promotion => write!(f, "PROMOTION"),
            BlockType::Rollback => write!(f, "ROLLBACK"),
            BlockType::PromotionEvidence => write!(f, "PROMOTION_EVIDENCE"),
        }
    }
}

impl std::str::FromStr for BlockType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "GENESIS" => Ok(BlockType::Genesis),
            "EVALUATION" => Ok(BlockType::Evaluation),
            "PROMOTION" => Ok(BlockType::Promotion),
            "ROLLBACK" => Ok(BlockType::Rollback),
            "PROMOTION_EVIDENCE" => Ok(BlockType::PromotionEvidence),
            _ => Err(format!("Unknown BlockType: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PromotionEvidencePayload {
    pub meta_candidate_block_hash: String,
    pub downstream_cycle_id: String,
    pub downstream_ledger_block_hash: String,
    pub capability_improvement_proof: String,
    pub final_classification: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LedgerBlock {
    pub sequence: u64,
    pub block_type: BlockType,
    pub timestamp_utc: String,
    pub prev_block_hash: String,
    pub payload_json: String,
    pub payload_digest: String,
    pub blob_hashes: Vec<String>,
    pub block_hash: String,
}

impl LedgerBlock {
    pub const GENESIS_PREV_HASH: &'static str =
        "0000000000000000000000000000000000000000000000000000000000000000";

    pub fn new(
        sequence: u64,
        block_type: BlockType,
        timestamp_utc: String,
        prev_block_hash: String,
        payload_json: String,
        blob_hashes: Vec<String>,
    ) -> Self {
        let payload_digest = Self::compute_payload_digest(&payload_json);
        let block_hash = Self::compute_block_hash(
            sequence,
            block_type,
            &timestamp_utc,
            &prev_block_hash,
            &payload_digest,
            &blob_hashes,
        );

        Self {
            sequence,
            block_type,
            timestamp_utc,
            prev_block_hash,
            payload_json,
            payload_digest,
            blob_hashes,
            block_hash,
        }
    }

    pub fn compute_payload_digest(payload_json: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(payload_json.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    pub fn compute_block_hash(
        sequence: u64,
        block_type: BlockType,
        timestamp_utc: &str,
        prev_block_hash: &str,
        payload_digest: &str,
        blob_hashes: &[String],
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(sequence.to_le_bytes());
        hasher.update(block_type.to_string().as_bytes());
        hasher.update(timestamp_utc.as_bytes());
        hasher.update(prev_block_hash.as_bytes());
        hasher.update(payload_digest.as_bytes());
        for bh in blob_hashes {
            hasher.update(bh.as_bytes());
        }
        format!("{:x}", hasher.finalize())
    }

    pub fn verify_integrity(&self) -> Result<(), String> {
        let expected_payload_digest = Self::compute_payload_digest(&self.payload_json);
        if self.payload_digest != expected_payload_digest {
            return Err(format!(
                "Payload digest mismatch at sequence {}: stored={}, computed={}",
                self.sequence, self.payload_digest, expected_payload_digest
            ));
        }

        let expected_block_hash = Self::compute_block_hash(
            self.sequence,
            self.block_type,
            &self.timestamp_utc,
            &self.prev_block_hash,
            &self.payload_digest,
            &self.blob_hashes,
        );

        if self.block_hash != expected_block_hash {
            return Err(format!(
                "Block hash mismatch at sequence {}: stored={}, computed={}",
                self.sequence, self.block_hash, expected_block_hash
            ));
        }

        Ok(())
    }
}
