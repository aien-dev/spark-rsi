use aien_evaluation_protocol::Verdict;
use aien_protocol_types::{ArtifactRef, Digest32, Timestamp};
use spark_rsi::safety_envelope::CanarySafetyEnvelope;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[tokio::test]
async fn test_canary_safety_envelope_evaluation_and_rollback_enforcement() {
    let envelope = CanarySafetyEnvelope::new_with_ephemeral_key("rsi-daemon-01");

    let subject = ArtifactRef {
        artifact_id: uuid::Uuid::new_v4(),
        digest: Digest32([0x99; 32]),
        media_type: "application/rust".to_string(),
        byte_size: 4096,
    };

    let rollback_executed = Arc::new(AtomicBool::new(false));
    let rollback_flag = rollback_executed.clone();

    let receipt = envelope
        .evaluate_and_enforce(&subject, "rsi-production", Timestamp(1000), || async move {
            rollback_flag.store(true, Ordering::SeqCst);
            Ok(())
        })
        .await
        .unwrap();

    // If the gate failed, rollback must be true and verdict Fail; if passed, verdict Pass and rollback false
    if receipt.receipt.verdict == Verdict::Pass {
        assert!(!rollback_executed.load(Ordering::SeqCst));
    } else {
        assert_eq!(receipt.receipt.verdict, Verdict::Fail);
        assert!(rollback_executed.load(Ordering::SeqCst));
    }
}
