use crate::evaluator::EvaluationReceipt;
use crate::ledger::blob::BlobStore;
use crate::ledger::merkle::{compute_merkle_root, MerkleCheckpoint};
use crate::ledger::record::{BlockType, LedgerBlock, PromotionEvidencePayload};
use crate::ledger::schema::init_schema;
use crate::supervisor::GenerationInfo;
use p256::ecdsa::{SigningKey, VerifyingKey};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LedgerAuditReport {
    pub total_blocks: u64,
    pub total_blobs: u64,
    pub latest_sequence: u64,
    pub latest_block_hash: String,
    pub merkle_root: String,
    pub checkpoint_verified: bool,
    pub signature_verified: bool,
    pub chain_valid: bool,
    pub audit_timestamp_utc: String,
}

#[derive(Clone)]
pub struct ImprovementLedger {
    conn: Arc<Mutex<Connection>>,
    blob_store: BlobStore,
    pub rsi_root: PathBuf,
}

impl ImprovementLedger {
    pub fn open(rsi_root: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(rsi_root)
            .map_err(|e| format!("Failed to create rsi_root dir {:?}: {}", rsi_root, e))?;

        let db_path = rsi_root.join("ledger.db");
        let conn = Connection::open(&db_path)
            .map_err(|e| format!("Failed to open SQLite database at {:?}: {}", db_path, e))?;

        init_schema(&conn).map_err(|e| format!("Failed to initialize ledger schema: {}", e))?;

        let blob_store = BlobStore::new(rsi_root)?;
        let ledger = Self {
            conn: Arc::new(Mutex::new(conn)),
            blob_store,
            rsi_root: rsi_root.to_path_buf(),
        };

        // Initialize Genesis block if database is fresh
        if ledger.latest_block()?.is_none() {
            ledger.init_genesis()?;
        }

        Ok(ledger)
    }

    fn init_genesis(&self) -> Result<LedgerBlock, String> {
        let genesis_payload = serde_json::json!({
            "system": "spark-rsi",
            "law": "Build the cage, build the measuring instruments, then give the animal a bigger brain.",
            "standard": "Sovereign Reciprocal Commons License (SRCL-1.0)"
        })
        .to_string();

        let block = LedgerBlock::new(
            0,
            BlockType::Genesis,
            chrono::Utc::now().to_rfc3339(),
            LedgerBlock::GENESIS_PREV_HASH.to_string(),
            genesis_payload,
            Vec::new(),
        );

        self.insert_block_internal(&block)?;
        Ok(block)
    }

    fn insert_block_internal(&self, block: &LedgerBlock) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let blob_hashes_json = serde_json::to_string(&block.blob_hashes)
            .map_err(|e| format!("Failed to serialize blob_hashes: {}", e))?;

        conn.execute(
            "INSERT INTO blocks (
                sequence, block_type, timestamp_utc, prev_block_hash,
                payload_json, payload_digest, blob_hashes_json, block_hash
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                block.sequence as i64,
                block.block_type.to_string(),
                block.timestamp_utc,
                block.prev_block_hash,
                block.payload_json,
                block.payload_digest,
                blob_hashes_json,
                block.block_hash,
            ],
        )
        .map_err(|e| format!("Failed to insert block sequence {}: {}", block.sequence, e))?;

        Ok(())
    }

    pub fn latest_block(&self) -> Result<Option<LedgerBlock>, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let mut stmt = conn
            .prepare(
                "SELECT sequence, block_type, timestamp_utc, prev_block_hash,
                        payload_json, payload_digest, blob_hashes_json, block_hash
                 FROM blocks ORDER BY sequence DESC LIMIT 1",
            )
            .map_err(|e| e.to_string())?;

        let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
        if let Some(row) = rows.next().map_err(|e| e.to_string())? {
            let block = Self::row_to_block(row)?;
            Ok(Some(block))
        } else {
            Ok(None)
        }
    }

    pub fn get_block(&self, sequence: u64) -> Result<Option<LedgerBlock>, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let mut stmt = conn
            .prepare(
                "SELECT sequence, block_type, timestamp_utc, prev_block_hash,
                        payload_json, payload_digest, blob_hashes_json, block_hash
                 FROM blocks WHERE sequence = ?1 LIMIT 1",
            )
            .map_err(|e| e.to_string())?;

        let mut rows = stmt.query([sequence as i64]).map_err(|e| e.to_string())?;
        if let Some(row) = rows.next().map_err(|e| e.to_string())? {
            let block = Self::row_to_block(row)?;
            Ok(Some(block))
        } else {
            Ok(None)
        }
    }

    pub fn get_block_by_hash(&self, block_hash: &str) -> Result<Option<LedgerBlock>, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let mut stmt = conn
            .prepare(
                "SELECT sequence, block_type, timestamp_utc, prev_block_hash,
                        payload_json, payload_digest, blob_hashes_json, block_hash
                 FROM blocks WHERE block_hash = ?1 LIMIT 1",
            )
            .map_err(|e| e.to_string())?;

        let mut rows = stmt.query([block_hash]).map_err(|e| e.to_string())?;
        if let Some(row) = rows.next().map_err(|e| e.to_string())? {
            let block = Self::row_to_block(row)?;
            Ok(Some(block))
        } else {
            Ok(None)
        }
    }

    pub fn all_blocks(&self) -> Result<Vec<LedgerBlock>, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let mut stmt = conn
            .prepare(
                "SELECT sequence, block_type, timestamp_utc, prev_block_hash,
                        payload_json, payload_digest, blob_hashes_json, block_hash
                 FROM blocks ORDER BY sequence ASC",
            )
            .map_err(|e| e.to_string())?;

        let rows = stmt
            .query_map([], |row| {
                let seq: i64 = row.get(0)?;
                let bt_str: String = row.get(1)?;
                let ts: String = row.get(2)?;
                let prev_hash: String = row.get(3)?;
                let payload_json: String = row.get(4)?;
                let payload_digest: String = row.get(5)?;
                let blob_hashes_json: String = row.get(6)?;
                let block_hash: String = row.get(7)?;

                let block_type = bt_str.parse::<BlockType>().unwrap_or(BlockType::Evaluation);
                let blob_hashes: Vec<String> =
                    serde_json::from_str(&blob_hashes_json).unwrap_or_default();

                Ok(LedgerBlock {
                    sequence: seq as u64,
                    block_type,
                    timestamp_utc: ts,
                    prev_block_hash: prev_hash,
                    payload_json,
                    payload_digest,
                    blob_hashes,
                    block_hash,
                })
            })
            .map_err(|e| e.to_string())?;

        let mut blocks = Vec::new();
        for r in rows {
            blocks.push(r.map_err(|e| e.to_string())?);
        }
        Ok(blocks)
    }

    fn row_to_block(row: &rusqlite::Row) -> Result<LedgerBlock, String> {
        let seq: i64 = row.get(0).map_err(|e| e.to_string())?;
        let bt_str: String = row.get(1).map_err(|e| e.to_string())?;
        let ts: String = row.get(2).map_err(|e| e.to_string())?;
        let prev_hash: String = row.get(3).map_err(|e| e.to_string())?;
        let payload_json: String = row.get(4).map_err(|e| e.to_string())?;
        let payload_digest: String = row.get(5).map_err(|e| e.to_string())?;
        let blob_hashes_json: String = row.get(6).map_err(|e| e.to_string())?;
        let block_hash: String = row.get(7).map_err(|e| e.to_string())?;

        let block_type = bt_str
            .parse::<BlockType>()
            .map_err(|e| format!("Failed to parse block_type: {}", e))?;
        let blob_hashes: Vec<String> = serde_json::from_str(&blob_hashes_json)
            .map_err(|e| format!("Failed to parse blob_hashes_json: {}", e))?;

        Ok(LedgerBlock {
            sequence: seq as u64,
            block_type,
            timestamp_utc: ts,
            prev_block_hash: prev_hash,
            payload_json,
            payload_digest,
            blob_hashes,
            block_hash,
        })
    }

    pub fn append_block(
        &self,
        block_type: BlockType,
        payload_json: String,
        blob_hashes: Vec<String>,
    ) -> Result<LedgerBlock, String> {
        let latest = self.latest_block()?.ok_or_else(|| {
            "Cannot append to uninitialized ledger (Genesis block missing)".to_string()
        })?;

        let next_sequence = latest.sequence + 1;
        let prev_block_hash = latest.block_hash;
        let timestamp_utc = chrono::Utc::now().to_rfc3339();

        let block = LedgerBlock::new(
            next_sequence,
            block_type,
            timestamp_utc,
            prev_block_hash,
            payload_json,
            blob_hashes,
        );

        self.insert_block_internal(&block)?;
        Ok(block)
    }

    pub fn append_evaluation(
        &self,
        receipt: &EvaluationReceipt,
        raw_metrics: Option<&[u8]>,
    ) -> Result<LedgerBlock, String> {
        let mut blob_hashes = Vec::new();

        if let Some(metric_bytes) = raw_metrics {
            let digest = self.blob_store.put_blob(metric_bytes)?;
            let conn = self.conn.lock().map_err(|e| e.to_string())?;
            let now = chrono::Utc::now().to_rfc3339();
            let _ = conn.execute(
                "INSERT OR IGNORE INTO blobs_index (digest, size_bytes, created_at) VALUES (?1, ?2, ?3)",
                params![digest, metric_bytes.len() as i64, now],
            );
            blob_hashes.push(digest);
        }

        let payload_json = serde_json::to_string(receipt)
            .map_err(|e| format!("Failed to serialize EvaluationReceipt: {}", e))?;

        self.append_block(BlockType::Evaluation, payload_json, blob_hashes)
    }

    pub fn append_promotion(
        &self,
        gen_info: &GenerationInfo,
        receipt_digest: &str,
    ) -> Result<LedgerBlock, String> {
        let payload = serde_json::json!({
            "generation_id": gen_info.generation_id,
            "installed_path": gen_info.installed_path.to_string_lossy(),
            "receipt_digest": receipt_digest,
            "state": format!("{:?}", gen_info.state),
            "staged_timestamp": gen_info.staged_timestamp,
        })
        .to_string();

        self.append_block(BlockType::Promotion, payload, Vec::new())
    }

    pub fn append_rollback(
        &self,
        generation_id: &str,
        reason: &str,
    ) -> Result<LedgerBlock, String> {
        let payload = serde_json::json!({
            "generation_id": generation_id,
            "reason": reason,
            "rolled_back_at": chrono::Utc::now().to_rfc3339(),
        })
        .to_string();

        self.append_block(BlockType::Rollback, payload, Vec::new())
    }

    pub fn append_promotion_evidence(
        &self,
        evidence: &PromotionEvidencePayload,
    ) -> Result<LedgerBlock, String> {
        let payload_json = serde_json::to_string(evidence)
            .map_err(|e| format!("Failed to serialize PromotionEvidencePayload: {}", e))?;

        self.append_block(BlockType::PromotionEvidence, payload_json, Vec::new())
    }

    pub fn checkpoint(&self, signing_key: Option<&SigningKey>) -> Result<MerkleCheckpoint, String> {
        let blocks = self.all_blocks()?;
        if blocks.is_empty() {
            return Err("Cannot create checkpoint on empty ledger".to_string());
        }

        let leaf_hashes: Vec<String> = blocks.iter().map(|b| b.block_hash.clone()).collect();
        let up_to_sequence = blocks.last().unwrap().sequence;
        let merkle_root = compute_merkle_root(&leaf_hashes);
        let block_count = blocks.len() as u64;

        let mut checkpoint = MerkleCheckpoint::new(up_to_sequence, merkle_root, block_count);

        if let Some(key) = signing_key {
            checkpoint.sign(key);
        }

        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT OR REPLACE INTO checkpoints (
                up_to_sequence, merkle_root, block_count, timestamp_utc, signature
            ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                checkpoint.up_to_sequence as i64,
                checkpoint.merkle_root,
                checkpoint.block_count as i64,
                checkpoint.timestamp_utc,
                checkpoint.signature,
            ],
        )
        .map_err(|e| format!("Failed to store Merkle checkpoint: {}", e))?;

        Ok(checkpoint)
    }

    pub fn latest_checkpoint(&self) -> Result<Option<MerkleCheckpoint>, String> {
        let conn = self.conn.lock().map_err(|e| e.to_string())?;
        let mut stmt = conn
            .prepare(
                "SELECT up_to_sequence, merkle_root, block_count, timestamp_utc, signature
                 FROM checkpoints ORDER BY up_to_sequence DESC LIMIT 1",
            )
            .map_err(|e| e.to_string())?;

        let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
        if let Some(row) = rows.next().map_err(|e| e.to_string())? {
            let seq: i64 = row.get(0).map_err(|e| e.to_string())?;
            let root: String = row.get(1).map_err(|e| e.to_string())?;
            let count: i64 = row.get(2).map_err(|e| e.to_string())?;
            let ts: String = row.get(3).map_err(|e| e.to_string())?;
            let sig: Option<String> = row.get(4).map_err(|e| e.to_string())?;

            Ok(Some(MerkleCheckpoint {
                up_to_sequence: seq as u64,
                merkle_root: root,
                block_count: count as u64,
                timestamp_utc: ts,
                signature: sig,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn blob_store(&self) -> &BlobStore {
        &self.blob_store
    }

    pub fn verify_chain_integrity(
        &self,
        verifying_key: Option<&VerifyingKey>,
    ) -> Result<LedgerAuditReport, String> {
        let blocks = self.all_blocks()?;
        if blocks.is_empty() {
            return Err("Audit failed: ledger is empty (no Genesis block)".to_string());
        }

        let mut total_blobs = 0;
        let mut leaf_hashes = Vec::new();

        // 1. Validate Genesis block invariants
        let genesis = &blocks[0];
        if genesis.sequence != 0 {
            return Err(format!(
                "Audit failed: Genesis block sequence is {}, expected 0",
                genesis.sequence
            ));
        }
        if genesis.block_type != BlockType::Genesis {
            return Err(format!(
                "Audit failed: Genesis block type is {:?}, expected GENESIS",
                genesis.block_type
            ));
        }
        if genesis.prev_block_hash != LedgerBlock::GENESIS_PREV_HASH {
            return Err(format!(
                "Audit failed: Genesis block prev_block_hash is {}, expected {}",
                genesis.prev_block_hash,
                LedgerBlock::GENESIS_PREV_HASH
            ));
        }
        genesis.verify_integrity()?;
        leaf_hashes.push(genesis.block_hash.clone());

        // 2. Iterate through block chain validating strict sequence and hash links
        for i in 1..blocks.len() {
            let block = &blocks[i];
            let prev_block = &blocks[i - 1];

            if block.sequence != i as u64 {
                return Err(format!(
                    "Audit failed: Block sequence gap at index {}: sequence is {}",
                    i, block.sequence
                ));
            }

            if block.prev_block_hash != prev_block.block_hash {
                return Err(format!(
                    "Audit failed: Hash chain broken at sequence {}. Stored prev_hash={}, predecessor hash={}",
                    block.sequence, block.prev_block_hash, prev_block.block_hash
                ));
            }

            // Verify payload digest and block hash
            block.verify_integrity()?;

            // Verify all referenced blobs exist and are uncorrupted
            for bh in &block.blob_hashes {
                total_blobs += 1;
                if !self.blob_store.verify_blob(bh) {
                    return Err(format!(
                        "Audit failed: Content-addressed blob {} missing or corrupted at block sequence {}",
                        bh, block.sequence
                    ));
                }
            }

            leaf_hashes.push(block.block_hash.clone());
        }

        // 3. Compute and verify Merkle root
        let computed_merkle_root = compute_merkle_root(&leaf_hashes);
        let mut checkpoint_verified = false;
        let mut signature_verified = false;

        if let Some(checkpoint) = self.latest_checkpoint()? {
            if checkpoint.up_to_sequence == blocks.last().unwrap().sequence {
                if checkpoint.merkle_root == computed_merkle_root {
                    checkpoint_verified = true;
                } else {
                    return Err(format!(
                        "Audit failed: Checkpoint Merkle root mismatch: stored={}, computed={}",
                        checkpoint.merkle_root, computed_merkle_root
                    ));
                }

                if let Some(vk) = verifying_key {
                    if checkpoint.verify_signature(vk) {
                        signature_verified = true;
                    } else {
                        return Err(
                            "Audit failed: Checkpoint Merkle root signature verification failed"
                                .to_string(),
                        );
                    }
                }
            }
        }

        let latest = blocks.last().unwrap();
        Ok(LedgerAuditReport {
            total_blocks: blocks.len() as u64,
            total_blobs,
            latest_sequence: latest.sequence,
            latest_block_hash: latest.block_hash.clone(),
            merkle_root: computed_merkle_root,
            checkpoint_verified,
            signature_verified,
            chain_valid: true,
            audit_timestamp_utc: chrono::Utc::now().to_rfc3339(),
        })
    }
}
