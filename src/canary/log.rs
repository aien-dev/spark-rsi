//! The per-generation observation log: append-only JSON lines, one canonical record per line,
//! opened with a header and closed with a seal that commits the digest of everything before
//! it. Every append is synced to disk before it is acknowledged. A partial trailing record
//! (a crash mid-write) is detected and excluded. The store refuses an observation id it
//! already holds unless the record is byte-identical, in which case the retry is idempotent;
//! a different record under a known id is a conflict.
//!
//! Only a sealed log can be handed to the quota validator (`SealedObservationLog`).

use super::{
    canonical_json, domain_digest, is_hex_digest, CanaryObservationV2, OBSERVATION_LOG_VERSION,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const LOG_DOMAIN: &str = "spark-rsi/canary-observation-log/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogHeader {
    pub log_version: u16,
    pub generation_id: String,
    pub workload_digest: String,
    pub candidate_executable_digest: String,
    pub opened_at_ms: u64,
}

impl LogHeader {
    pub fn new(
        generation_id: &str,
        workload_digest: &str,
        candidate_executable_digest: &str,
        opened_at_ms: u64,
    ) -> Self {
        Self {
            log_version: OBSERVATION_LOG_VERSION,
            generation_id: generation_id.to_string(),
            workload_digest: workload_digest.to_string(),
            candidate_executable_digest: candidate_executable_digest.to_string(),
            opened_at_ms,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.log_version != OBSERVATION_LOG_VERSION {
            return Err(format!(
                "observation log version {} is not supported (expected {})",
                self.log_version, OBSERVATION_LOG_VERSION
            ));
        }
        if self.generation_id.trim().is_empty() {
            return Err("observation log generation id is required".to_string());
        }
        if !is_hex_digest(&self.workload_digest) {
            return Err("observation log workload digest is not a hex SHA-256".to_string());
        }
        if !is_hex_digest(&self.candidate_executable_digest) {
            return Err(
                "observation log candidate executable digest is not a hex SHA-256".to_string(),
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogObservation {
    pub observation: CanaryObservationV2,
    pub observation_digest: String,
}

/// Something the supervisor refused: an unauthenticated or wrong-generation message, an
/// unsolicited or duplicate result. Informational; never counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogRejection {
    pub reason: String,
    pub observed_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogSeal {
    /// Unique observations before the seal.
    pub observation_count: u64,
    /// Of those, the measured verified successes.
    pub qualifying_count: u64,
    /// Domain-separated SHA-256 of every byte of the file before the seal line.
    pub log_digest: String,
    pub sealed_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "record", rename_all = "snake_case")]
pub enum LogRecord {
    Header(LogHeader),
    Observation(LogObservation),
    Rejection(LogRejection),
    Seal(LogSeal),
}

impl LogRecord {
    /// The exact bytes of this record on disk: canonical JSON and a newline.
    pub fn to_line(&self) -> Vec<u8> {
        let mut line = canonical_json(self);
        line.push(b'\n');
        line
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendOutcome {
    Appended,
    /// The same id with a byte-identical record was already stored.
    Idempotent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogState {
    Missing,
    Unsealed {
        observations: usize,
        partial_tail: bool,
    },
    Sealed {
        observations: usize,
    },
    Invalid(String),
}

/// What the parser found in a log's bytes.
struct Parsed {
    header: Option<LogHeader>,
    observations: Vec<CanaryObservationV2>,
    rejections: Vec<LogRejection>,
    /// The seal and the byte offset where its line starts.
    seal: Option<(LogSeal, usize)>,
    /// Byte offset just past the last complete line.
    complete_end: usize,
    partial_tail: bool,
}

fn parse_log(bytes: &[u8]) -> Result<Parsed, String> {
    let mut parsed = Parsed {
        header: None,
        observations: Vec::new(),
        rejections: Vec::new(),
        seal: None,
        complete_end: 0,
        partial_tail: false,
    };
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    let mut offset = 0usize;
    let mut line_no = 0usize;
    while offset < bytes.len() {
        let Some(rel) = bytes[offset..].iter().position(|&b| b == b'\n') else {
            parsed.partial_tail = true;
            break;
        };
        let line_start = offset;
        let line_end = offset + rel;
        offset = line_end + 1;
        line_no += 1;
        if parsed.seal.is_some() {
            return Err(format!(
                "observation log line {} comes after the seal",
                line_no
            ));
        }
        let line = &bytes[line_start..line_end];
        let record: LogRecord = serde_json::from_slice(line)
            .map_err(|e| format!("observation log line {} does not parse: {}", line_no, e))?;
        if record.to_line() != bytes[line_start..offset] {
            return Err(format!(
                "observation log line {} is not in canonical encoding",
                line_no
            ));
        }
        match record {
            LogRecord::Header(h) => {
                if line_no != 1 {
                    return Err(format!(
                        "observation log line {} is a header; only line 1 may be",
                        line_no
                    ));
                }
                h.validate()?;
                parsed.header = Some(h);
            }
            LogRecord::Observation(o) => {
                let header = parsed
                    .header
                    .as_ref()
                    .ok_or("observation log has no header")?;
                o.observation.validate()?;
                let digest = o.observation.digest_hex();
                if o.observation_digest != digest {
                    return Err(format!(
                        "observation {} carries digest {} but hashes to {}",
                        o.observation.observation_id, o.observation_digest, digest
                    ));
                }
                check_bindings(header, &o.observation)?;
                match seen.get(&o.observation.observation_id) {
                    Some(previous) if previous == &digest => {}
                    Some(_) => {
                        return Err(format!(
                            "observation id {} conflicts with a different record",
                            o.observation.observation_id
                        ));
                    }
                    None => {
                        seen.insert(o.observation.observation_id.clone(), digest);
                        parsed.observations.push(o.observation);
                    }
                }
            }
            LogRecord::Rejection(r) => {
                if parsed.header.is_none() {
                    return Err("observation log has no header".to_string());
                }
                parsed.rejections.push(r);
            }
            LogRecord::Seal(s) => {
                if parsed.header.is_none() {
                    return Err("observation log has no header".to_string());
                }
                parsed.seal = Some((s, line_start));
            }
        }
        parsed.complete_end = offset;
    }
    if parsed.header.is_none() && parsed.complete_end > 0 {
        return Err("observation log has no header".to_string());
    }
    Ok(parsed)
}

fn check_bindings(header: &LogHeader, obs: &CanaryObservationV2) -> Result<(), String> {
    if obs.generation_id != header.generation_id {
        return Err(format!(
            "observation {} belongs to generation {}, log is for {}",
            obs.observation_id, obs.generation_id, header.generation_id
        ));
    }
    if obs.workload_digest != header.workload_digest {
        return Err(format!(
            "observation {} carries workload digest {}, log is for {}",
            obs.observation_id, obs.workload_digest, header.workload_digest
        ));
    }
    if obs.candidate_executable_digest != header.candidate_executable_digest {
        return Err(format!(
            "observation {} carries executable digest {}, log is for {}",
            obs.observation_id, obs.candidate_executable_digest, header.candidate_executable_digest
        ));
    }
    Ok(())
}

fn log_digest_of(bytes_before_seal: &[u8]) -> String {
    domain_digest(LOG_DOMAIN, &[bytes_before_seal])
}

/// Reports the state of the log at `path` without requiring it to be valid.
pub fn inspect(path: &Path) -> LogState {
    if !path.exists() {
        return LogState::Missing;
    }
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => return LogState::Invalid(format!("cannot read {:?}: {}", path, e)),
    };
    match parse_log(&bytes) {
        Err(e) => LogState::Invalid(e),
        Ok(p) => match p.seal {
            Some(_) => LogState::Sealed {
                observations: p.observations.len(),
            },
            None => LogState::Unsealed {
                observations: p.observations.len(),
                partial_tail: p.partial_tail,
            },
        },
    }
}

/// Appends observations and rejections for one generation, each synced before return.
#[derive(Debug)]
pub struct ObservationLogWriter {
    path: PathBuf,
    file: File,
    header: LogHeader,
    seen: BTreeMap<String, String>,
}

impl ObservationLogWriter {
    /// Creates a new log. Refuses to overwrite an existing file.
    pub fn create(path: &Path, header: LogHeader) -> Result<Self, String> {
        header.validate()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {:?}: {}", parent, e))?;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| format!("cannot create observation log {:?}: {}", path, e))?;
        write_synced(&mut file, &LogRecord::Header(header.clone()).to_line())?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            header,
            seen: BTreeMap::new(),
        })
    }

    /// Reopens an unsealed log after a restart. The header on disk must equal `expected`;
    /// a partial trailing record is dropped; every stored id is remembered so replays are
    /// refused. A sealed log cannot be reopened.
    pub fn reopen(path: &Path, expected: &LogHeader) -> Result<Self, String> {
        expected.validate()?;
        let bytes = std::fs::read(path)
            .map_err(|e| format!("cannot read observation log {:?}: {}", path, e))?;
        let parsed = parse_log(&bytes)?;
        let header = parsed
            .header
            .ok_or_else(|| format!("observation log {:?} has no header", path))?;
        if &header != expected {
            return Err(format!(
                "observation log {:?} was opened for generation {} with other bindings; refusing",
                path, header.generation_id
            ));
        }
        if parsed.seal.is_some() {
            return Err(format!(
                "observation log {:?} is already sealed; a sealed log is never reopened",
                path
            ));
        }
        let file = OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|e| format!("cannot open observation log {:?}: {}", path, e))?;
        if parsed.partial_tail {
            file.set_len(parsed.complete_end as u64)
                .map_err(|e| format!("cannot drop partial record in {:?}: {}", path, e))?;
            file.sync_all().map_err(|e| e.to_string())?;
        }
        let mut file = OpenOptions::new()
            .append(true)
            .open(path)
            .map_err(|e| format!("cannot open observation log {:?}: {}", path, e))?;
        file.flush().map_err(|e| e.to_string())?;
        let seen = parsed
            .observations
            .iter()
            .map(|o| (o.observation_id.clone(), o.digest_hex()))
            .collect();
        Ok(Self {
            path: path.to_path_buf(),
            file,
            header,
            seen,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn header(&self) -> &LogHeader {
        &self.header
    }

    pub fn contains(&self, observation_id: &str) -> bool {
        self.seen.contains_key(observation_id)
    }

    pub fn stored_count(&self) -> usize {
        self.seen.len()
    }

    /// Stores `obs`. A byte-identical retry is idempotent; a different record under a known id
    /// is refused; a record for another generation, workload or executable is refused.
    pub fn append_observation(
        &mut self,
        obs: &CanaryObservationV2,
    ) -> Result<AppendOutcome, String> {
        obs.validate()?;
        check_bindings(&self.header, obs)?;
        let digest = obs.digest_hex();
        if let Some(previous) = self.seen.get(&obs.observation_id) {
            if previous == &digest {
                return Ok(AppendOutcome::Idempotent);
            }
            return Err(format!(
                "observation id {} conflicts with a different record",
                obs.observation_id
            ));
        }
        let record = LogRecord::Observation(LogObservation {
            observation: obs.clone(),
            observation_digest: digest.clone(),
        });
        write_synced(&mut self.file, &record.to_line())?;
        self.seen.insert(obs.observation_id.clone(), digest);
        Ok(AppendOutcome::Appended)
    }

    pub fn append_rejection(&mut self, reason: &str, observed_at_ms: u64) -> Result<(), String> {
        let record = LogRecord::Rejection(LogRejection {
            reason: reason.to_string(),
            observed_at_ms,
        });
        write_synced(&mut self.file, &record.to_line())
    }

    /// Re-reads the file, verifies it, commits its digest in a seal record and returns the
    /// verified sealed log. Consumes the writer: nothing is appended after the seal.
    pub fn seal(self, sealed_at_ms: u64) -> Result<SealedObservationLog, String> {
        let ObservationLogWriter { path, mut file, .. } = self;
        let bytes = std::fs::read(&path)
            .map_err(|e| format!("cannot re-read observation log {:?}: {}", path, e))?;
        let parsed = parse_log(&bytes)?;
        if parsed.seal.is_some() {
            return Err(format!("observation log {:?} is already sealed", path));
        }
        if parsed.partial_tail {
            return Err(format!(
                "observation log {:?} ends in a partial record; refusing to seal",
                path
            ));
        }
        let seal = LogSeal {
            observation_count: parsed.observations.len() as u64,
            qualifying_count: parsed
                .observations
                .iter()
                .filter(|o| o.is_qualifying())
                .count() as u64,
            log_digest: log_digest_of(&bytes),
            sealed_at_ms,
        };
        write_synced(&mut file, &LogRecord::Seal(seal).to_line())?;
        drop(file);
        SealedObservationLog::load(&path)
    }
}

fn write_synced(file: &mut File, line: &[u8]) -> Result<(), String> {
    file.write_all(line)
        .map_err(|e| format!("cannot append to observation log: {}", e))?;
    file.sync_all()
        .map_err(|e| format!("cannot sync observation log: {}", e))
}

/// A log that was closed with a seal and verified: header present, every record canonical and
/// well-formed, every observation bound to the header, ids unique, the seal digest equal to the
/// digest of the bytes before it, nothing after the seal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedObservationLog {
    pub path: Option<PathBuf>,
    pub header: LogHeader,
    pub observations: Vec<CanaryObservationV2>,
    pub rejections: Vec<LogRejection>,
    pub seal: LogSeal,
}

impl SealedObservationLog {
    pub fn load(path: &Path) -> Result<Self, String> {
        let bytes = std::fs::read(path)
            .map_err(|e| format!("cannot read observation log {:?}: {}", path, e))?;
        let mut sealed = Self::verify_bytes(&bytes)?;
        sealed.path = Some(path.to_path_buf());
        Ok(sealed)
    }

    pub fn verify_bytes(bytes: &[u8]) -> Result<Self, String> {
        let parsed = parse_log(bytes)?;
        let header = parsed.header.ok_or("observation log has no header")?;
        let (seal, seal_start) = parsed.seal.ok_or("observation log is not sealed")?;
        if parsed.partial_tail || parsed.complete_end != bytes.len() {
            return Err("observation log has bytes after the seal".to_string());
        }
        let expected = log_digest_of(&bytes[..seal_start]);
        if seal.log_digest != expected {
            return Err(format!(
                "observation log seal digest {} does not match the log bytes ({})",
                seal.log_digest, expected
            ));
        }
        if seal.observation_count != parsed.observations.len() as u64 {
            return Err(format!(
                "observation log seal counts {} observations, log holds {}",
                seal.observation_count,
                parsed.observations.len()
            ));
        }
        let qualifying = parsed
            .observations
            .iter()
            .filter(|o| o.is_qualifying())
            .count() as u64;
        if seal.qualifying_count != qualifying {
            return Err(format!(
                "observation log seal counts {} qualifying observations, log holds {}",
                seal.qualifying_count, qualifying
            ));
        }
        Ok(Self {
            path: None,
            header,
            observations: parsed.observations,
            rejections: parsed.rejections,
            seal,
        })
    }

    pub fn log_digest(&self) -> &str {
        &self.seal.log_digest
    }

    pub fn qualifying(&self) -> impl Iterator<Item = &CanaryObservationV2> {
        self.observations.iter().filter(|o| o.is_qualifying())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canary::observation::{ObservationInput, Provenance, VerifiedStatus};
    use crate::canary::sha256_hex;

    fn header() -> LogHeader {
        LogHeader::new(
            "gen-0001",
            &sha256_hex(b"workload"),
            &sha256_hex(b"exe"),
            1_700_000_000_000,
        )
    }

    fn obs(request_id: &str, status: VerifiedStatus) -> CanaryObservationV2 {
        CanaryObservationV2::new(ObservationInput {
            generation_id: "gen-0001",
            request_id,
            request_digest: &sha256_hex(request_id.as_bytes()),
            workload_digest: &sha256_hex(b"workload"),
            candidate_executable_digest: &sha256_hex(b"exe"),
            result_digest: Some(&sha256_hex(b"pong")),
            elapsed_us: 500,
            observed_at_ms: 1_700_000_000_500,
            status,
            provenance: Provenance::Measured,
        })
    }

    #[test]
    fn write_seal_and_verify_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("canary").join("gen-0001.jsonl");
        let mut w = ObservationLogWriter::create(&path, header()).unwrap();
        assert_eq!(
            w.append_observation(&obs("req-001", VerifiedStatus::VerifiedSuccess))
                .unwrap(),
            AppendOutcome::Appended
        );
        assert_eq!(
            w.append_observation(&obs("req-001", VerifiedStatus::VerifiedSuccess))
                .unwrap(),
            AppendOutcome::Idempotent
        );
        w.append_rejection("unsolicited result for req-009", 1_700_000_000_600)
            .unwrap();
        w.append_observation(&obs("req-002", VerifiedStatus::WrongResult))
            .unwrap();
        assert_eq!(
            inspect(&path),
            LogState::Unsealed {
                observations: 2,
                partial_tail: false
            }
        );
        let sealed = w.seal(1_700_000_001_000).unwrap();
        assert_eq!(sealed.observations.len(), 2);
        assert_eq!(sealed.rejections.len(), 1);
        assert_eq!(sealed.seal.observation_count, 2);
        assert_eq!(sealed.seal.qualifying_count, 1);
        assert_eq!(sealed.qualifying().count(), 1);
        assert_eq!(inspect(&path), LogState::Sealed { observations: 2 });
        let reloaded = SealedObservationLog::load(&path).unwrap();
        assert_eq!(reloaded, sealed);
    }

    #[test]
    fn conflicting_record_under_a_known_id_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("gen.jsonl");
        let mut w = ObservationLogWriter::create(&path, header()).unwrap();
        w.append_observation(&obs("req-001", VerifiedStatus::VerifiedSuccess))
            .unwrap();
        let mut changed = obs("req-001", VerifiedStatus::VerifiedSuccess);
        changed.elapsed_us = 1;
        let err = w.append_observation(&changed).unwrap_err();
        assert!(err.contains("conflicts"));
    }

    #[test]
    fn foreign_bindings_are_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("gen.jsonl");
        let mut w = ObservationLogWriter::create(&path, header()).unwrap();
        let mut other_gen = obs("req-001", VerifiedStatus::VerifiedSuccess);
        other_gen.generation_id = "gen-0002".into();
        other_gen.observation_id =
            crate::canary::observation_id("gen-0002", "req-001", &other_gen.request_digest);
        assert!(w
            .append_observation(&other_gen)
            .unwrap_err()
            .contains("belongs to generation"));
        let mut other_exe = obs("req-001", VerifiedStatus::VerifiedSuccess);
        other_exe.candidate_executable_digest = sha256_hex(b"other");
        assert!(w
            .append_observation(&other_exe)
            .unwrap_err()
            .contains("executable digest"));
    }

    #[test]
    fn unsealed_tampered_and_appended_logs_do_not_verify() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("gen.jsonl");
        let mut w = ObservationLogWriter::create(&path, header()).unwrap();
        w.append_observation(&obs("req-001", VerifiedStatus::VerifiedSuccess))
            .unwrap();
        assert!(SealedObservationLog::load(&path)
            .unwrap_err()
            .contains("not sealed"));
        let sealed = w.seal(1).unwrap();
        let bytes = std::fs::read(&path).unwrap();

        // Flip a byte inside the observation line.
        let mut tampered = bytes.clone();
        let idx = String::from_utf8_lossy(&bytes)
            .find("\"elapsed_us\":500")
            .unwrap();
        tampered[idx + "\"elapsed_us\":".len()] = b'9';
        let err = SealedObservationLog::verify_bytes(&tampered).unwrap_err();
        assert!(
            err.contains("hashes to") || err.contains("seal digest"),
            "{}",
            err
        );

        // Append a record after the seal.
        let mut appended = bytes.clone();
        appended.extend_from_slice(
            &LogRecord::Rejection(LogRejection {
                reason: "late".into(),
                observed_at_ms: 2,
            })
            .to_line(),
        );
        assert!(SealedObservationLog::verify_bytes(&appended)
            .unwrap_err()
            .contains("after the seal"));

        // Partial bytes after the seal.
        let mut partial = bytes.clone();
        partial.extend_from_slice(b"{\"kind\":\"rejection\"");
        assert!(SealedObservationLog::verify_bytes(&partial)
            .unwrap_err()
            .contains("after the seal"));

        // Drop an observation line but keep the seal: digest mismatch.
        let text = String::from_utf8(bytes.clone()).unwrap();
        let mut lines: Vec<&str> = text.lines().collect();
        lines.remove(1);
        let shortened = format!("{}\n", lines.join("\n"));
        let err = SealedObservationLog::verify_bytes(shortened.as_bytes()).unwrap_err();
        assert!(err.contains("seal digest"), "{}", err);

        // A sealed log is never reopened.
        assert!(ObservationLogWriter::reopen(&path, &header())
            .unwrap_err()
            .contains("already sealed"));
        assert_eq!(sealed.observations.len(), 1);
    }

    #[test]
    fn reopen_drops_a_partial_tail_and_remembers_ids() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("gen.jsonl");
        let mut w = ObservationLogWriter::create(&path, header()).unwrap();
        w.append_observation(&obs("req-001", VerifiedStatus::VerifiedSuccess))
            .unwrap();
        drop(w);
        // Simulate a crash mid-write.
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"{\"kind\":\"observation\",\"record\":{\"obs")
            .unwrap();
        drop(f);
        assert_eq!(
            inspect(&path),
            LogState::Unsealed {
                observations: 1,
                partial_tail: true
            }
        );
        let mut w = ObservationLogWriter::reopen(&path, &header()).unwrap();
        assert!(w.contains(&obs("req-001", VerifiedStatus::VerifiedSuccess).observation_id));
        assert_eq!(
            w.append_observation(&obs("req-001", VerifiedStatus::VerifiedSuccess))
                .unwrap(),
            AppendOutcome::Idempotent
        );
        w.append_observation(&obs("req-002", VerifiedStatus::Timeout).with_no_result())
            .unwrap();
        let sealed = w.seal(5).unwrap();
        assert_eq!(sealed.observations.len(), 2);
        assert_eq!(sealed.seal.qualifying_count, 1);

        let mut other = header();
        other.generation_id = "gen-0009".into();
        let tmp2 = tempfile::tempdir().unwrap();
        let path2 = tmp2.path().join("gen.jsonl");
        let w2 = ObservationLogWriter::create(&path2, header()).unwrap();
        drop(w2);
        assert!(ObservationLogWriter::reopen(&path2, &other)
            .unwrap_err()
            .contains("refusing"));
    }

    #[test]
    fn create_never_overwrites() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("gen.jsonl");
        let _w = ObservationLogWriter::create(&path, header()).unwrap();
        assert!(ObservationLogWriter::create(&path, header()).is_err());
    }

    impl CanaryObservationV2 {
        fn with_no_result(mut self) -> Self {
            self.result_digest = None;
            self
        }
    }
}
