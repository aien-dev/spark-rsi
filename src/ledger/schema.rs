use rusqlite::{Connection, Result};

pub fn init_schema(conn: &Connection) -> Result<()> {
    // 1. Enable WAL mode and synchronous NORMAL for high concurrency durability
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;

    // 2. Blocks table: append-only sequential ledger
    conn.execute(
        "CREATE TABLE IF NOT EXISTS blocks (
            sequence INTEGER PRIMARY KEY,
            block_type TEXT NOT NULL,
            timestamp_utc TEXT NOT NULL,
            prev_block_hash TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            payload_digest TEXT NOT NULL,
            blob_hashes_json TEXT NOT NULL,
            block_hash TEXT NOT NULL UNIQUE
        );",
        [],
    )?;

    // 3. Checkpoints table: signed Merkle tree roots
    conn.execute(
        "CREATE TABLE IF NOT EXISTS checkpoints (
            up_to_sequence INTEGER PRIMARY KEY,
            merkle_root TEXT NOT NULL,
            block_count INTEGER NOT NULL,
            timestamp_utc TEXT NOT NULL,
            signature TEXT
        );",
        [],
    )?;

    // 4. Blobs index table: content-addressed blob metadata
    conn.execute(
        "CREATE TABLE IF NOT EXISTS blobs_index (
            digest TEXT PRIMARY KEY,
            size_bytes INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );",
        [],
    )?;

    Ok(())
}
