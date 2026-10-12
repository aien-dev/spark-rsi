//! Supervisor-driven canary contract: the shared definitions every M2 worker builds on.
//!
//! Approved plan: docs/plans/2026-10-12-evidence-driven-rsi-cut.md. Glossary: CONTEXT.md.
//! Format reference: docs/CANARY-CONTRACT.md.
//!
//! The one rule above everything: no candidate-controlled statement can independently
//! establish that a canary passed. The supervisor issues every request, measures the elapsed
//! time itself, compares the answer against the pinned workload, and durably records the
//! verified observation. Only such observations reach the quota validator.
//!
//! Pieces, in the order a cycle uses them:
//! - [`adapter`]: the declared canary adapter manifest a target repository ships
//!   (`canary-adapter.toml`). No manifest, no canary: the target fails closed.
//! - [`workload`]: the digest-pinned request set with expected outcomes and deadlines, owned
//!   by the operator under the RSI state directory, never by the candidate.
//! - [`identity`]: the bound candidate identity chain (patch, evaluated tree, built
//!   executable, generation).
//! - the wire protocol: `ExecuteRequest` and `ExecuteResult` in [`crate::supervisor::ipc`].
//! - [`observation`]: the version 2 observation record, its canonical encoding, digest and
//!   derived identity.
//! - [`log`]: the per-generation append-only observation log, sealed with a final digest.
//! - [`admission`]: the hand-off from a sealed log to the quota validator.
//!
//! Every digest is lowercase hex SHA-256. Structured digests are domain separated: the domain
//! string and then each field are written length-prefixed (u64 little endian, then the bytes),
//! the same scheme as the version 2 evaluation receipt. Canonical JSON is one object with keys
//! in byte order, no insignificant whitespace, integers only (never floats).

pub mod adapter;
pub mod admission;
pub mod identity;
pub mod log;
pub mod observation;
pub mod workload;

pub use adapter::{CanaryAdapterManifest, LoadedAdapterManifest, ADAPTER_MANIFEST_FILE};
pub use admission::{admit_sealed_quota, SealedQuotaDecision};
pub use identity::CandidateIdentity;
pub use log::{
    AppendOutcome, LogHeader, LogRecord, LogRejection, LogSeal, LogState, ObservationLogWriter,
    SealedObservationLog,
};
pub use observation::{
    observation_id, result_digest, CanaryObservationV2, Provenance, VerifiedStatus,
};
pub use workload::{CanaryRequestSpec, CanaryWorkloadManifest, Nondeterminism, PinnedWorkload};

use sha2::{Digest, Sha256};

/// Version of the supervisor-to-worker execute protocol: `ExecuteRequest`, `ExecuteResult`
/// and the `protocol_version` a worker states in `Ready`.
pub const CANARY_PROTOCOL_VERSION: u16 = 1;
/// Version of [`CanaryObservationV2`]. Version 1 is `crate::canary_observation`, kept as is.
pub const OBSERVATION_RECORD_VERSION: u16 = 2;
/// Version of the observation log line format.
pub const OBSERVATION_LOG_VERSION: u16 = 1;
/// Version of the workload manifest.
pub const WORKLOAD_VERSION: u16 = 1;
/// Version of the adapter manifest.
pub const ADAPTER_MANIFEST_VERSION: u16 = 1;
/// Version of the candidate identity chain.
pub const IDENTITY_VERSION: u16 = 1;

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Domain-separated, length-prefixed SHA-256 over `fields`.
pub(crate) fn domain_digest(domain: &str, fields: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    crate::evaluator::put_field(&mut h, domain.as_bytes());
    for f in fields {
        crate::evaluator::put_field(&mut h, f);
    }
    hex::encode(h.finalize())
}

/// Sixty-four lowercase hex characters.
pub(crate) fn is_hex_digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Canonical JSON: keys in byte order at every level, no whitespace, serde_json string
/// escaping. Independent of serde_json's map ordering feature. Only plain structs of strings,
/// integers, booleans, enums and vectors are encoded here, so serialization cannot fail.
pub(crate) fn canonical_json<T: serde::Serialize>(value: &T) -> Vec<u8> {
    let v = serde_json::to_value(value).expect("canary records serialize to JSON values");
    let mut out = Vec::new();
    write_canonical(&v, &mut out);
    out
}

fn write_canonical(v: &serde_json::Value, out: &mut Vec<u8>) {
    use serde_json::Value;
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Value::Number(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Value::String(s) => write_json_string(s, out),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, out);
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push(b'{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_json_string(k, out);
                out.push(b':');
                write_canonical(&map[*k], out);
            }
            out.push(b'}');
        }
    }
}

fn write_json_string(s: &str, out: &mut Vec<u8>) {
    let encoded = serde_json::to_string(s).expect("strings serialize");
    out.extend_from_slice(encoded.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_json_sorts_keys_and_strips_whitespace() {
        #[derive(serde::Serialize)]
        struct Rec {
            zeta: u64,
            alpha: String,
            mid: Vec<u16>,
        }
        let bytes = canonical_json(&Rec {
            zeta: 7,
            alpha: "a\"b\n".into(),
            mid: vec![2, 1],
        });
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "{\"alpha\":\"a\\\"b\\n\",\"mid\":[2,1],\"zeta\":7}"
        );
    }

    #[test]
    fn hex_digest_check_is_strict() {
        assert!(is_hex_digest(&sha256_hex(b"x")));
        assert!(!is_hex_digest(&sha256_hex(b"x").to_uppercase()));
        assert!(!is_hex_digest("abc"));
    }

    #[test]
    fn domain_digest_separates_domains_and_field_boundaries() {
        assert_ne!(domain_digest("a", &[b"xy"]), domain_digest("b", &[b"xy"]));
        assert_ne!(
            domain_digest("a", &[b"x", b"y"]),
            domain_digest("a", &[b"xy"])
        );
    }
}
