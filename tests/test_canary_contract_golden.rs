//! Golden tests for the frozen contracts of the evidence-driven RSI cut
//! (docs/plans/2026-10-12-evidence-driven-rsi-cut.md, "Narrow contract freeze").
//!
//! Three families are pinned: (1) the canonical canary observation encoding and digests of the
//! new version 2 records, (2) the existing signed evaluation receipt bytes, digest and
//! verification, (3) the existing ledger record encoding, hash and validation. A change to any
//! pinned value is a format change and needs a new version, never an edit of the pin.

use p256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};
use spark_rsi::canary::observation::ObservationInput;
use spark_rsi::canary::{
    observation_id, CanaryAdapterManifest, CanaryObservationV2, CanaryRequestSpec,
    CanaryWorkloadManifest, CandidateIdentity, LogHeader, Nondeterminism, ObservationLogWriter,
    Provenance, SealedObservationLog, VerifiedStatus, CANARY_PROTOCOL_VERSION,
};
use spark_rsi::evaluator::layers::LayerResult;
use spark_rsi::evaluator::{EvaluationMetricsSummary, EvaluationReceipt, ReceiptBindingV2};
use spark_rsi::ledger::{compute_merkle_root, BlockType, LedgerBlock};
use spark_rsi::supervisor::ipc::{SupervisorMessage, WorkerMessage};

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

// ------------------------------------------------------------------ pinned values

const EXPECTED_WORKLOAD_CANONICAL: &str = "{\"protocol_version\":1,\"requests\":[{\"deadline_ms\":2000,\"expected_output\":\"pong\",\"input\":\"ping\",\"nondeterminism\":\"exact\",\"request_id\":\"req-001\"},{\"deadline_ms\":2000,\"expected_output\":\"5\",\"input\":\"add 2 3\",\"nondeterminism\":\"exact\",\"request_id\":\"req-002\"}],\"workload_id\":\"golden-v1\",\"workload_version\":1}";
const EXPECTED_WORKLOAD_DIGEST: &str =
    "9431eef86afb1c4cd80a8ae023fbf391519d94ab67f6cd9820ae096bb0710870";
const EXPECTED_REQUEST_001_DIGEST: &str =
    "f4b3d03bdbef5edb951f4a5a314989098226748eb720e81c382fbebd86e18017";
const EXPECTED_ADAPTER_DIGEST: &str =
    "4bcfa2c308cc84ea007827def1dbd5d8b5d038a3c676030374ff07621a5320e6";
const EXPECTED_IDENTITY_BINDING_DIGEST: &str =
    "dabd4116b1c49c42716973eb65110e439601396086adc2d35c9cb169e429360a";
const EXPECTED_OBSERVATION_ID: &str =
    "4b269fce18d83d73147676b7358c998a548a99ceebed02816d37a059926b8181";
const EXPECTED_OBSERVATION_CANONICAL: &str = "{\"candidate_executable_digest\":\"86b30dc0591deb3800c70226d5ed326e20f01f9f8288036acdc7b5bd4c86af75\",\"elapsed_us\":1234,\"generation_id\":\"gen-golden-0001\",\"observation_id\":\"4b269fce18d83d73147676b7358c998a548a99ceebed02816d37a059926b8181\",\"observed_at_ms\":1700000000000,\"provenance\":\"measured\",\"record_version\":2,\"request_digest\":\"f4b3d03bdbef5edb951f4a5a314989098226748eb720e81c382fbebd86e18017\",\"request_id\":\"req-001\",\"result_digest\":\"9795c5ff8937f23526ccb207a5684c1fc94a7854e19c021b39d944e51f5baef2\",\"status\":\"verified_success\",\"workload_digest\":\"9431eef86afb1c4cd80a8ae023fbf391519d94ab67f6cd9820ae096bb0710870\"}";
const EXPECTED_OBSERVATION_DIGEST: &str =
    "550f4dd46e1f3c197b6d8d973061bd978c722b332d5a416681216e8bf5e845c7";
const EXPECTED_LOG_BYTES: &str = "{\"kind\":\"header\",\"record\":{\"candidate_executable_digest\":\"86b30dc0591deb3800c70226d5ed326e20f01f9f8288036acdc7b5bd4c86af75\",\"generation_id\":\"gen-golden-0001\",\"log_version\":1,\"opened_at_ms\":1700000000000,\"workload_digest\":\"9431eef86afb1c4cd80a8ae023fbf391519d94ab67f6cd9820ae096bb0710870\"}}\n{\"kind\":\"observation\",\"record\":{\"observation\":{\"candidate_executable_digest\":\"86b30dc0591deb3800c70226d5ed326e20f01f9f8288036acdc7b5bd4c86af75\",\"elapsed_us\":1234,\"generation_id\":\"gen-golden-0001\",\"observation_id\":\"4b269fce18d83d73147676b7358c998a548a99ceebed02816d37a059926b8181\",\"observed_at_ms\":1700000000000,\"provenance\":\"measured\",\"record_version\":2,\"request_digest\":\"f4b3d03bdbef5edb951f4a5a314989098226748eb720e81c382fbebd86e18017\",\"request_id\":\"req-001\",\"result_digest\":\"9795c5ff8937f23526ccb207a5684c1fc94a7854e19c021b39d944e51f5baef2\",\"status\":\"verified_success\",\"workload_digest\":\"9431eef86afb1c4cd80a8ae023fbf391519d94ab67f6cd9820ae096bb0710870\"},\"observation_digest\":\"550f4dd46e1f3c197b6d8d973061bd978c722b332d5a416681216e8bf5e845c7\"}}\n{\"kind\":\"rejection\",\"record\":{\"observed_at_ms\":1700000000600,\"reason\":\"unsolicited result for req-009\"}}\n{\"kind\":\"observation\",\"record\":{\"observation\":{\"candidate_executable_digest\":\"86b30dc0591deb3800c70226d5ed326e20f01f9f8288036acdc7b5bd4c86af75\",\"elapsed_us\":2000000,\"generation_id\":\"gen-golden-0001\",\"observation_id\":\"24e16074b967433cf803587aeb02d52c62817a8666e62ab2dcfe4e51bb5d0fe2\",\"observed_at_ms\":1700000002000,\"provenance\":\"measured\",\"record_version\":2,\"request_digest\":\"dfb1b215f345dc50033819a285844ec5ac12ccb07d5c64023c06a343b7cb3dbe\",\"request_id\":\"req-002\",\"result_digest\":null,\"status\":\"timeout\",\"workload_digest\":\"9431eef86afb1c4cd80a8ae023fbf391519d94ab67f6cd9820ae096bb0710870\"},\"observation_digest\":\"2830ea7d18215ec481d598814d0771e27426ebd1211e73237c8dd0e92e9e74a1\"}}\n{\"kind\":\"seal\",\"record\":{\"log_digest\":\"fb5479def502a60f902285ca26fecd75a6130957f7a4f01ba0759f743bc53ee8\",\"observation_count\":2,\"qualifying_count\":1,\"sealed_at_ms\":1700000003000}}\n";
const EXPECTED_LOG_DIGEST: &str =
    "fb5479def502a60f902285ca26fecd75a6130957f7a4f01ba0759f743bc53ee8";
const EXPECTED_RECEIPT_V2_DIGEST: &str =
    "764766d8efa6457fee8d32b17e2a6e5b42661a51afd4824f16830dac1c1b65e2";
const EXPECTED_RECEIPT_V2_SIGNATURE: &str = "tpm2-p256:99d2faabc3456a1e66c67b01b14f4e027884ad7bfdd8f84dad110b0bcf9f23887d8f640a1fa69b547943766da1d833c2782ffa603591981099fd9341dcbbd797";
const EXPECTED_RECEIPT_V1_DIGEST: &str =
    "2f89a865a7cd6ea329b9df0f31ced5629e4cba6e629e91834737b8caa22cd817";
const EXPECTED_PROTOCOL_KEY_FINGERPRINT: &str =
    "8cbc48b78519c7a8a48f92d6e9e60f06645e872e6d148b660a5aef6afc990905";
const EXPECTED_PROTOCOL_RECEIPT_DIGEST: &str =
    "a7f3ac2e08162a5f2f49805d8cf4f6c8a7f38fe6bb0f2e74437d9bbfce1cdccf";
const EXPECTED_PROTOCOL_RECEIPT_SIGNATURE: &str = "41b9f0735b4ecceb3e390eeb1eca82f09173ce393ab0bbb8f03d4b5c55a216027d1d0df88d5ac064ac70d7ecd63d29af8e3de04c3ff09dada42a6fa8e09c7240";
const EXPECTED_LEDGER_PAYLOAD_DIGEST: &str =
    "7b8e7b835fe25b68a1acf315430c15febccecb74f2ec198c4adf83ded8ba6c5d";
const EXPECTED_LEDGER_BLOCK_HASH: &str =
    "250ea0215642b8e1c221456e4a86d2249ffe3ac9b7d1999c7cca39e0c734a492";
const EXPECTED_MERKLE_ROOT: &str =
    "507f253911e35467cca570f695cd66b8e32baef97704eb4061b9b638070336f2";

const ADAPTER_TEXT: &str = "manifest_version = 1\nprotocol_version = 1\nexecutable = \"release/rsi-canary-fixture\"\nargs = [\"--adapter\"]\nworkload_id = \"golden-v1\"\nresponse_format = \"utf8-exact\"\n";

// ------------------------------------------------------------------ fixtures

fn workload() -> CanaryWorkloadManifest {
    CanaryWorkloadManifest {
        workload_version: 1,
        workload_id: "golden-v1".into(),
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

fn identity() -> CandidateIdentity {
    CandidateIdentity::new(
        &sha(b"golden patch"),
        &sha(b"golden tree"),
        &sha(b"golden executable bytes"),
        "gen-golden-0001",
    )
}

fn success_observation() -> CanaryObservationV2 {
    let w = workload();
    let id = identity();
    CanaryObservationV2::new(ObservationInput {
        generation_id: &id.generation_id,
        request_id: "req-001",
        request_digest: &w.requests[0].request_digest(&w.workload_id),
        workload_digest: &w.digest(),
        candidate_executable_digest: &id.executable_digest,
        result_digest: Some(&sha(b"pong")),
        elapsed_us: 1234,
        observed_at_ms: 1_700_000_000_000,
        status: VerifiedStatus::VerifiedSuccess,
        provenance: Provenance::Measured,
    })
}

fn timeout_observation() -> CanaryObservationV2 {
    let w = workload();
    let id = identity();
    CanaryObservationV2::new(ObservationInput {
        generation_id: &id.generation_id,
        request_id: "req-002",
        request_digest: &w.requests[1].request_digest(&w.workload_id),
        workload_digest: &w.digest(),
        candidate_executable_digest: &id.executable_digest,
        result_digest: None,
        elapsed_us: 2_000_000,
        observed_at_ms: 1_700_000_002_000,
        status: VerifiedStatus::Timeout,
        provenance: Provenance::Measured,
    })
}

fn golden_log() -> (Vec<u8>, SealedObservationLog) {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("gen-golden-0001.jsonl");
    let w = workload();
    let id = identity();
    let mut writer = ObservationLogWriter::create(
        &path,
        LogHeader::new(
            &id.generation_id,
            &w.digest(),
            &id.executable_digest,
            1_700_000_000_000,
        ),
    )
    .unwrap();
    writer.append_observation(&success_observation()).unwrap();
    writer
        .append_rejection("unsolicited result for req-009", 1_700_000_000_600)
        .unwrap();
    writer.append_observation(&timeout_observation()).unwrap();
    let sealed = writer.seal(1_700_000_003_000).unwrap();
    (std::fs::read(&path).unwrap(), sealed)
}

fn layer(name: &str, passed: bool, score: f64) -> LayerResult {
    LayerResult {
        layer_name: name.to_string(),
        is_hard_invariant: true,
        passed,
        score,
        summary: format!("{} summary", name),
        violations: Vec::new(),
    }
}

fn base_receipt() -> EvaluationReceipt {
    EvaluationReceipt {
        cycle_id: "cycle-golden".to_string(),
        candidate_id: "cand-golden".to_string(),
        parent_id: "parent-golden".to_string(),
        evaluated_at: "2026-10-12T00:00:00Z".to_string(),
        evaluator_version: "1.0.0".to_string(),
        passed_all_hard_invariants: true,
        passed_statistical_gates: true,
        admitted: true,
        layer_results: vec![
            layer("correctness", true, 1.0),
            layer("security", true, 0.5),
        ],
        metrics_summary: Some(EvaluationMetricsSummary {
            latency_delta_pct: -1.0,
            p_value: 0.01,
            p95_ci_upper_degradation_pct: 0.5,
            p99_ci_upper_degradation_pct: 0.7,
            rss_growth_pct: 0.1,
            candidate_resident_mb: 12,
        }),
        receipt_digest: String::new(),
        signature: None,
        format_version: 1,
        binding: None,
    }
}

fn v2_binding() -> ReceiptBindingV2 {
    ReceiptBindingV2 {
        subject_path: "README.md".to_string(),
        subject_sha256: sha(b"golden readme"),
        holdout_set_sha256: sha(b"golden holdouts"),
        holdouts_total: 4,
        holdouts_passed: 4,
        policy_sha256: sha(b"golden policy"),
        evaluator_binary_sha256: sha(b"golden judge binary"),
    }
}

fn judge_key() -> SigningKey {
    SigningKey::from_slice(&[7u8; 32]).unwrap()
}

// ------------------------------------------------------------------ (1) canary records

#[test]
fn workload_canonical_bytes_and_digests_are_frozen() {
    let w = workload();
    assert_eq!(
        String::from_utf8(w.canonical_bytes()).unwrap(),
        EXPECTED_WORKLOAD_CANONICAL
    );
    assert_eq!(w.digest(), EXPECTED_WORKLOAD_DIGEST);
    assert_eq!(
        w.requests[0].request_digest(&w.workload_id),
        EXPECTED_REQUEST_001_DIGEST
    );
}

#[test]
fn adapter_manifest_digest_is_frozen() {
    let m = CanaryAdapterManifest::parse(ADAPTER_TEXT).unwrap();
    assert_eq!(m.workload_id, "golden-v1");
    assert_eq!(
        CanaryAdapterManifest::digest_of_text(ADAPTER_TEXT),
        EXPECTED_ADAPTER_DIGEST
    );
}

#[test]
fn candidate_identity_binding_digest_is_frozen() {
    assert_eq!(
        identity().binding_digest(),
        EXPECTED_IDENTITY_BINDING_DIGEST
    );
}

#[test]
fn observation_encoding_id_and_digest_are_frozen() {
    let o = success_observation();
    assert_eq!(
        o.observation_id,
        observation_id("gen-golden-0001", "req-001", &o.request_digest)
    );
    assert_eq!(o.observation_id, EXPECTED_OBSERVATION_ID);
    assert_eq!(
        String::from_utf8(o.canonical_bytes()).unwrap(),
        EXPECTED_OBSERVATION_CANONICAL
    );
    assert_eq!(o.digest_hex(), EXPECTED_OBSERVATION_DIGEST);
    o.validate().unwrap();
    // The record round-trips through JSON unchanged.
    let back: CanaryObservationV2 = serde_json::from_slice(&o.canonical_bytes()).unwrap();
    assert_eq!(back, o);
}

#[test]
fn sealed_log_bytes_and_digest_are_frozen() {
    let (bytes, sealed) = golden_log();
    assert_eq!(
        String::from_utf8(bytes.clone()).unwrap(),
        EXPECTED_LOG_BYTES
    );
    assert_eq!(sealed.log_digest(), EXPECTED_LOG_DIGEST);
    assert_eq!(sealed.seal.observation_count, 2);
    assert_eq!(sealed.seal.qualifying_count, 1);
    let verified = SealedObservationLog::verify_bytes(&bytes).unwrap();
    assert_eq!(verified.observations, sealed.observations);
    assert_eq!(verified.seal, sealed.seal);
}

#[test]
fn execute_protocol_wire_format_is_frozen() {
    let req = SupervisorMessage::ExecuteRequest {
        protocol_version: CANARY_PROTOCOL_VERSION,
        generation_id: "gen-golden-0001".into(),
        request_id: "req-001".into(),
        request_digest: "aa".repeat(32),
        workload_digest: "bb".repeat(32),
        input: "ping".into(),
        deadline_ms: 2000,
    };
    assert_eq!(
        serde_json::to_string(&req).unwrap(),
        format!(
            "{{\"ExecuteRequest\":{{\"protocol_version\":1,\"generation_id\":\"gen-golden-0001\",\"request_id\":\"req-001\",\"request_digest\":\"{}\",\"workload_digest\":\"{}\",\"input\":\"ping\",\"deadline_ms\":2000}}}}",
            "aa".repeat(32),
            "bb".repeat(32)
        )
    );
    let res = WorkerMessage::ExecuteResult {
        protocol_version: CANARY_PROTOCOL_VERSION,
        generation_id: "gen-golden-0001".into(),
        request_id: "req-001".into(),
        output: "pong".into(),
        worker_latency_us: Some(900),
    };
    assert_eq!(
        serde_json::to_string(&res).unwrap(),
        "{\"ExecuteResult\":{\"protocol_version\":1,\"generation_id\":\"gen-golden-0001\",\"request_id\":\"req-001\",\"output\":\"pong\",\"worker_latency_us\":900}}"
    );
    let ready = WorkerMessage::Ready {
        generation_id: "gen-golden-0001".into(),
        pid: 4242,
        auth_token: String::new(),
        protocol_version: CANARY_PROTOCOL_VERSION,
    };
    assert_eq!(
        serde_json::to_string(&ready).unwrap(),
        "{\"Ready\":{\"generation_id\":\"gen-golden-0001\",\"pid\":4242,\"auth_token\":\"\",\"protocol_version\":1}}"
    );
    // A Ready from an older worker has no protocol version and reads as 0: never ready.
    let legacy: WorkerMessage = serde_json::from_str(
        "{\"Ready\":{\"generation_id\":\"gen-old\",\"pid\":1,\"auth_token\":\"\"}}",
    )
    .unwrap();
    match legacy {
        WorkerMessage::Ready {
            protocol_version, ..
        } => assert_eq!(protocol_version, 0),
        other => panic!("expected Ready, got {:?}", other),
    }
    // A result without the diagnostic latency still parses.
    let bare: WorkerMessage = serde_json::from_str(
        "{\"ExecuteResult\":{\"protocol_version\":1,\"generation_id\":\"g\",\"request_id\":\"r\",\"output\":\"o\"}}",
    )
    .unwrap();
    match bare {
        WorkerMessage::ExecuteResult {
            worker_latency_us, ..
        } => assert_eq!(worker_latency_us, None),
        other => panic!("expected ExecuteResult, got {:?}", other),
    }
}

// ------------------------------------------------------------------ (2) evaluation receipts

#[test]
fn evaluation_receipt_v2_digest_signature_and_verification_are_frozen() {
    let judge = judge_key();
    let mut r = base_receipt();
    r.bind_and_sign_v2(v2_binding(), &judge).unwrap();
    assert_eq!(r.format_version, 2);
    assert_eq!(r.receipt_digest, EXPECTED_RECEIPT_V2_DIGEST);
    assert_eq!(r.signature.as_deref(), Some(EXPECTED_RECEIPT_V2_SIGNATURE));
    assert!(r.verify_digest());
    assert!(r.verify_signature(judge.verifying_key()));
    r.verify_for_promotion(
        judge.verifying_key(),
        &sha(b"golden readme"),
        &sha(b"golden policy"),
        &sha(b"golden holdouts"),
    )
    .unwrap();
    // Any change to a bound field breaks the digest and the signature.
    let mut tampered = r.clone();
    tampered.binding.as_mut().unwrap().holdouts_passed = 3;
    assert!(!tampered.verify_digest());
    assert!(!tampered.verify_signature(judge.verifying_key()));
    let other = SigningKey::from_slice(&[9u8; 32]).unwrap();
    assert!(!r.verify_signature(other.verifying_key()));
}

#[test]
fn evaluation_receipt_v1_digest_is_frozen() {
    let r = base_receipt();
    let digest = EvaluationReceipt::compute_digest(
        &r.cycle_id,
        &r.candidate_id,
        &r.parent_id,
        r.admitted,
        &r.layer_results,
    );
    assert_eq!(digest, EXPECTED_RECEIPT_V1_DIGEST);
}

#[test]
fn protocol_signed_evaluation_receipt_digest_and_signature_are_frozen() {
    use aien_evaluation_protocol::{
        CryptographicTier, EvaluationReceipt as ProtocolReceipt, SoftwareP256Signer, Verdict,
        VerifierIdentity, VerifierSigner,
    };
    use aien_protocol_types::{Digest32, EvaluationId, Timestamp};
    use std::sync::Arc;

    let signer = Arc::new(SoftwareP256Signer::new(
        SigningKey::from_slice(&[0x42u8; 32]).unwrap(),
    ));
    assert_eq!(signer.key_fingerprint(), EXPECTED_PROTOCOL_KEY_FINGERPRINT);
    let receipt = ProtocolReceipt {
        protocol_version: 1,
        evaluation_id: EvaluationId(uuid::Uuid::from_u128(
            0x0123_4567_89ab_cdef_0123_4567_89ab_cdef,
        )),
        request_digest: Digest32([0x11; 32]),
        subject_digest: Digest32([0x22; 32]),
        plan_digest: Digest32([0x33; 32]),
        evidence_root: Digest32([0x44; 32]),
        outcomes_root: Digest32([0x55; 32]),
        verdict: Verdict::Pass,
        verifier: VerifierIdentity {
            principal_id: "rsi-golden".to_string(),
            key_id: signer.key_fingerprint(),
            trust_epoch: 1,
            trusted_build_digest: Digest32([0x66; 32]),
            policy_bundle_digest: Digest32([0x77; 32]),
        },
        started_at: Timestamp(1_700_000_000_000),
        completed_at: Timestamp(1_700_000_000_500),
    };
    assert_eq!(
        hex::encode(receipt.compute_receipt_digest().0),
        EXPECTED_PROTOCOL_RECEIPT_DIGEST
    );
    let signed = receipt.sign_with_signer(signer.as_ref()).unwrap();
    assert_eq!(
        hex::encode(&signed.signature),
        EXPECTED_PROTOCOL_RECEIPT_SIGNATURE
    );
    assert!(signed
        .verify_with(&signer.verifying_key(), CryptographicTier::Tier2SoftwareKey)
        .unwrap());
    let wrong = SigningKey::from_slice(&[0x99u8; 32]).unwrap();
    assert!(!matches!(
        signed.verify_with(wrong.verifying_key(), CryptographicTier::Tier2SoftwareKey),
        Ok(true)
    ));
    let mut tampered = signed.clone();
    tampered.receipt.verdict = Verdict::Fail;
    assert!(!matches!(
        tampered.verify_with(&signer.verifying_key(), CryptographicTier::Tier2SoftwareKey),
        Ok(true)
    ));
    assert!(!matches!(
        signed.verify_with(&signer.verifying_key(), CryptographicTier::Tier4HardwareTpm),
        Ok(true)
    ));
}

// ------------------------------------------------------------------ (3) ledger records

#[test]
fn ledger_block_encoding_hash_and_validation_are_frozen() {
    let payload = "{\"candidate\":\"cand-golden\",\"verdict\":\"admitted\"}".to_string();
    let block = LedgerBlock::new(
        1,
        BlockType::Evaluation,
        "2026-10-12T00:00:00+00:00".to_string(),
        LedgerBlock::GENESIS_PREV_HASH.to_string(),
        payload,
        vec![sha(b"golden blob")],
    );
    assert_eq!(block.payload_digest, EXPECTED_LEDGER_PAYLOAD_DIGEST);
    assert_eq!(block.block_hash, EXPECTED_LEDGER_BLOCK_HASH);
    block.verify_integrity().unwrap();
    let mut tampered = block.clone();
    tampered.payload_json = "{\"candidate\":\"cand-golden\",\"verdict\":\"refused\"}".into();
    assert!(tampered.verify_integrity().is_err());
    let mut relinked = block.clone();
    relinked.prev_block_hash = sha(b"another parent");
    assert!(relinked.verify_integrity().is_err());
    assert_eq!(
        compute_merkle_root(&[block.block_hash.clone(), sha(b"leaf-2"), sha(b"leaf-3")]),
        EXPECTED_MERKLE_ROOT
    );
}

// ------------------------------------------------------------------ pin generator

/// Prints every pinned value. Run with `--ignored --nocapture` when a format is deliberately
/// versioned; never to make a failing pin pass.
#[test]
#[ignore]
fn print_pins() {
    let w = workload();
    let o = success_observation();
    let (bytes, sealed) = golden_log();
    let judge = judge_key();
    let mut r2 = base_receipt();
    r2.bind_and_sign_v2(v2_binding(), &judge).unwrap();
    let r1 = base_receipt();
    let block = LedgerBlock::new(
        1,
        BlockType::Evaluation,
        "2026-10-12T00:00:00+00:00".to_string(),
        LedgerBlock::GENESIS_PREV_HASH.to_string(),
        "{\"candidate\":\"cand-golden\",\"verdict\":\"admitted\"}".to_string(),
        vec![sha(b"golden blob")],
    );
    println!(
        "PIN workload_canonical={}",
        String::from_utf8(w.canonical_bytes()).unwrap()
    );
    println!("PIN workload_digest={}", w.digest());
    println!(
        "PIN request_001_digest={}",
        w.requests[0].request_digest(&w.workload_id)
    );
    println!(
        "PIN adapter_digest={}",
        CanaryAdapterManifest::digest_of_text(ADAPTER_TEXT)
    );
    println!(
        "PIN identity_binding_digest={}",
        identity().binding_digest()
    );
    println!("PIN observation_id={}", o.observation_id);
    println!(
        "PIN observation_canonical={}",
        String::from_utf8(o.canonical_bytes()).unwrap()
    );
    println!("PIN observation_digest={}", o.digest_hex());
    println!(
        "PIN log_bytes={}",
        serde_json::to_string(&String::from_utf8(bytes).unwrap()).unwrap()
    );
    println!("PIN log_digest={}", sealed.log_digest());
    println!("PIN receipt_v2_digest={}", r2.receipt_digest);
    println!("PIN receipt_v2_signature={}", r2.signature.unwrap());
    println!(
        "PIN receipt_v1_digest={}",
        EvaluationReceipt::compute_digest(
            &r1.cycle_id,
            &r1.candidate_id,
            &r1.parent_id,
            r1.admitted,
            &r1.layer_results
        )
    );
    {
        use aien_evaluation_protocol::{
            EvaluationReceipt as ProtocolReceipt, SoftwareP256Signer, Verdict, VerifierIdentity,
            VerifierSigner,
        };
        use aien_protocol_types::{Digest32, EvaluationId, Timestamp};
        let signer = SoftwareP256Signer::new(SigningKey::from_slice(&[0x42u8; 32]).unwrap());
        let receipt = ProtocolReceipt {
            protocol_version: 1,
            evaluation_id: EvaluationId(uuid::Uuid::from_u128(
                0x0123_4567_89ab_cdef_0123_4567_89ab_cdef,
            )),
            request_digest: Digest32([0x11; 32]),
            subject_digest: Digest32([0x22; 32]),
            plan_digest: Digest32([0x33; 32]),
            evidence_root: Digest32([0x44; 32]),
            outcomes_root: Digest32([0x55; 32]),
            verdict: Verdict::Pass,
            verifier: VerifierIdentity {
                principal_id: "rsi-golden".to_string(),
                key_id: signer.key_fingerprint(),
                trust_epoch: 1,
                trusted_build_digest: Digest32([0x66; 32]),
                policy_bundle_digest: Digest32([0x77; 32]),
            },
            started_at: Timestamp(1_700_000_000_000),
            completed_at: Timestamp(1_700_000_000_500),
        };
        let signed = receipt.sign_with_signer(&signer).unwrap();
        println!("PIN protocol_key_fingerprint={}", signer.key_fingerprint());
        println!(
            "PIN protocol_receipt_digest={}",
            hex::encode(receipt.compute_receipt_digest().0)
        );
        println!(
            "PIN protocol_receipt_signature={}",
            hex::encode(&signed.signature)
        );
    }
    println!("PIN ledger_payload_digest={}", block.payload_digest);
    println!("PIN ledger_block_hash={}", block.block_hash);
    println!(
        "PIN merkle_root={}",
        compute_merkle_root(&[block.block_hash.clone(), sha(b"leaf-2"), sha(b"leaf-3")])
    );
}
