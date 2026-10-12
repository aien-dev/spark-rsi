//! Append-only JSON lines under `<rsi_root>/measure/`.
//!
//! Writes are synced. Reads are strict: every newline-terminated line must parse as a current
//! schema record. A trailing line with no newline is a torn write that never completed; the
//! reader skips it and the next append drops it before writing.

use super::{CycleSampleRecord, SCHEMA_VERSION};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub const MEASURE_DIR: &str = "measure";
pub const COMPLETE_FILE: &str = "stage-samples.jsonl";
pub const PARTIAL_FILE: &str = "partial-cycles.jsonl";

pub struct SampleLog {
    dir: PathBuf,
}

impl SampleLog {
    pub fn new(rsi_root: &Path) -> Self {
        Self {
            dir: rsi_root.join(MEASURE_DIR),
        }
    }

    pub fn complete_path(&self) -> PathBuf {
        self.dir.join(COMPLETE_FILE)
    }

    pub fn partial_path(&self) -> PathBuf {
        self.dir.join(PARTIAL_FILE)
    }

    pub fn append_complete(&self, record: &CycleSampleRecord) -> Result<(), String> {
        self.append(&self.complete_path(), record)
    }

    pub fn append_partial(&self, record: &CycleSampleRecord) -> Result<(), String> {
        self.append(&self.partial_path(), record)
    }

    /// Completed cycles in append order. A missing file is an empty log, not an error.
    pub fn read_complete(&self) -> Result<Vec<CycleSampleRecord>, String> {
        read_records(&self.complete_path())
    }

    pub fn read_partial(&self) -> Result<Vec<CycleSampleRecord>, String> {
        read_records(&self.partial_path())
    }

    fn append(&self, path: &Path, record: &CycleSampleRecord) -> Result<(), String> {
        if record.schema_version != SCHEMA_VERSION {
            return Err(format!(
                "refusing to write schema_version {} (current is {SCHEMA_VERSION})",
                record.schema_version
            ));
        }
        let mut line = serde_json::to_string(record).map_err(|e| e.to_string())?;
        line.push('\n');
        std::fs::create_dir_all(&self.dir).map_err(|e| format!("create {:?}: {e}", self.dir))?;
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(path)
            .map_err(|e| format!("open {path:?}: {e}"))?;
        drop_torn_tail(&mut file, path)?;
        file.write_all(line.as_bytes())
            .map_err(|e| format!("write {path:?}: {e}"))?;
        file.sync_all().map_err(|e| format!("sync {path:?}: {e}"))?;
        if let Ok(dir) = File::open(&self.dir) {
            let _ = dir.sync_all();
        }
        Ok(())
    }
}

/// Truncates anything after the last newline: a record that never finished writing.
fn drop_torn_tail(file: &mut File, path: &Path) -> Result<(), String> {
    let mut bytes = Vec::new();
    file.seek(SeekFrom::Start(0))
        .and_then(|_| file.read_to_end(&mut bytes))
        .map_err(|e| format!("read {path:?}: {e}"))?;
    if bytes.is_empty() || bytes.ends_with(b"\n") {
        return Ok(());
    }
    let keep = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
    file.set_len(keep as u64)
        .map_err(|e| format!("truncate torn tail of {path:?}: {e}"))
}

fn read_records(path: &Path) -> Result<Vec<CycleSampleRecord>, String> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("read {path:?}: {e}")),
    };
    let complete_len = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
    let text = std::str::from_utf8(&bytes[..complete_len])
        .map_err(|e| format!("{path:?} is not valid UTF-8: {e}"))?;
    let mut records = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let record: CycleSampleRecord =
            serde_json::from_str(line).map_err(|e| format!("{path:?} line {}: {e}", i + 1))?;
        if record.schema_version != SCHEMA_VERSION {
            return Err(format!(
                "{path:?} line {}: unsupported schema_version {}",
                i + 1,
                record.schema_version
            ));
        }
        records.push(record);
    }
    Ok(records)
}
