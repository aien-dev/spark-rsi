//! DUAL diagnostic price reader (ADR 0031 section 7.5 and 10).
//!
//! Golden vectors in tests/fixtures/dual/golden.txt were produced by the omega
//! C encoder (branch dual/0a-records, commit
//! f056b77f64ee94a80f4ed2899b5f9495aa3ef840). Every hostile case below is
//! compared against the C decoder's RxDualStatus recorded in the same file.

use sha2::Digest as _;
use spark_rsi::dual::{
    decode_constraint, decode_controller, decode_price_vector, decode_resource, digest_constraint,
    digest_controller, digest_price_vector, digest_resource, encode_constraint, encode_controller,
    encode_price_vector, encode_resource, verify_digest, Class, Digest32, FreshState, Kind,
    LambdaState, PriceVector, Refusal, ScarcityDiagnostic, UnavailableReason, Unit, VerifyError,
};
use std::collections::HashMap;
use std::path::Path;

struct Golden {
    bytes: HashMap<String, Vec<u8>>,
    status: HashMap<String, i32>,
}

fn golden() -> Golden {
    let text = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/dual/golden.txt"),
    )
    .expect("golden fixture");
    let mut bytes = HashMap::new();
    let mut status = HashMap::new();
    for line in text.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts[0] == "status" {
            status.insert(parts[1].to_string(), parts[2].parse::<i32>().unwrap());
        } else {
            bytes.insert(parts[0].to_string(), hex::decode(parts[1]).unwrap());
        }
    }
    Golden { bytes, status }
}

impl Golden {
    fn b(&self, name: &str) -> &[u8] {
        self.bytes
            .get(name)
            .unwrap_or_else(|| panic!("fixture {name}"))
    }
    fn d(&self, name: &str) -> Digest32 {
        let v = self.b(&format!("{name}.digest"));
        let mut d = [0u8; 32];
        d.copy_from_slice(v);
        d
    }
    fn st(&self, case: &str) -> i32 {
        *self
            .status
            .get(case)
            .unwrap_or_else(|| panic!("status {case}"))
    }
}

fn tag(s: &str) -> Digest32 {
    sha2::Sha256::digest(s.as_bytes()).into()
}

// ------------------------------------------------------------ round trips

#[test]
fn golden_resource_round_trip_and_digest() {
    let g = golden();
    let r = decode_resource(g.b("resource_kv")).unwrap();
    assert_eq!(r.resource_id, 5);
    assert_eq!(r.unit, Unit::KvBlocks);
    assert_eq!(r.scale, 1024.0);
    assert_eq!(r.contract, tag("contract-kv"));
    assert_eq!(encode_resource(&r), g.b("resource_kv"));
    assert_eq!(digest_resource(&r), g.d("resource_kv"));
    verify_digest(Kind::Resource, g.b("resource_kv"), &g.d("resource_kv")).unwrap();
}

#[test]
fn golden_constraints_round_trip_and_digest() {
    let g = golden();
    let cases: [(&str, u32, Unit, Class, f64, LambdaState, u64); 7] = [
        (
            "constraint_fresh_soft_ns",
            2,
            Unit::Ns,
            Class::Soft,
            0.42,
            LambdaState::Fresh,
            3,
        ),
        (
            "constraint_fresh_soft_kv",
            5,
            Unit::KvBlocks,
            Class::Soft,
            0.42,
            LambdaState::Fresh,
            3,
        ),
        (
            "constraint_fresh_capacity",
            9,
            Unit::Bytes,
            Class::Capacity,
            0.1,
            LambdaState::Fresh,
            0,
        ),
        (
            "constraint_stale",
            5,
            Unit::KvBlocks,
            Class::Soft,
            0.42,
            LambdaState::Stale,
            4,
        ),
        (
            "constraint_uncalibrated",
            7,
            Unit::Pj,
            Class::Soft,
            3.0,
            LambdaState::Uncalibrated,
            0,
        ),
        (
            "constraint_frozen",
            11,
            Unit::Watt,
            Class::Soft,
            0.7,
            LambdaState::Frozen,
            2,
        ),
        (
            "constraint_negzero_lambda",
            3,
            Unit::Ns,
            Class::Soft,
            0.0,
            LambdaState::Fresh,
            0,
        ),
    ];
    for (name, id, unit, class, lambda, state, tick) in cases {
        let s = decode_constraint(g.b(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(s.resource_id, id, "{name}");
        assert_eq!(s.unit, unit, "{name}");
        assert_eq!(s.class, class, "{name}");
        assert_eq!(s.lambda, lambda, "{name}");
        assert_eq!(s.lambda_state, state, "{name}");
        assert_eq!(s.tick, tick, "{name}");
        assert_eq!(s.generation, 7, "{name}");
        assert_eq!(s.budget, 4096.0);
        assert_eq!(s.estimate, 3900.5);
        assert_eq!(s.uncertainty, 12.25);
        assert_eq!(s.evidence_root, tag("evidence-root"));
        assert_eq!(encode_constraint(&s), g.b(name), "{name} re-encode");
        assert_eq!(digest_constraint(&s), g.d(name), "{name} digest");
        verify_digest(Kind::Constraint, g.b(name), &g.d(name)).unwrap();
        assert_eq!(g.b(name).len(), 294);
    }
}

#[test]
fn golden_controller_round_trip_and_digest() {
    let g = golden();
    let c = decode_controller(g.b("controller")).unwrap();
    assert_eq!(c.eta, 0.05);
    assert_eq!(c.rho, 0.01);
    assert_eq!(c.k_sigma, 2.0);
    assert_eq!(c.max_age, 16);
    assert_eq!(c.cadence, 1);
    assert_eq!(c.entries, vec![(2, 10.0), (5, 10.0), (9, 1.0)]);
    assert_eq!(encode_controller(&c), g.b("controller"));
    assert_eq!(digest_controller(&c), g.d("controller"));
    verify_digest(Kind::Controller, g.b("controller"), &g.d("controller")).unwrap();
}

#[test]
fn golden_price_vectors_round_trip_and_state_digests() {
    let g = golden();
    let a = decode_price_vector(g.b("pricevec_a")).unwrap();
    assert_eq!(a.generation, 7);
    assert_eq!(a.context, tag("decision-context"));
    assert_eq!(
        a.entries,
        vec![
            (2, g.d("constraint_fresh_soft_ns")),
            (5, g.d("constraint_fresh_soft_kv")),
            (9, g.d("constraint_fresh_capacity")),
        ]
    );
    assert_eq!(encode_price_vector(&a), g.b("pricevec_a"));
    assert_eq!(digest_price_vector(&a), g.d("pricevec_a"));
    assert_eq!(g.b("pricevec_a").len(), 154);

    let b = decode_price_vector(g.b("pricevec_b")).unwrap();
    assert_eq!(
        b.entries,
        vec![
            (5, g.d("constraint_stale")),
            (7, g.d("constraint_uncalibrated"))
        ]
    );
    assert_eq!(digest_price_vector(&b), g.d("pricevec_b"));

    let c = decode_price_vector(g.b("pricevec_c")).unwrap();
    assert_eq!(
        c.entries,
        vec![
            (7, g.d("constraint_uncalibrated")),
            (9, g.d("constraint_fresh_capacity"))
        ]
    );
    assert_eq!(digest_price_vector(&c), g.d("pricevec_c"));
    for name in ["pricevec_a", "pricevec_b", "pricevec_c"] {
        verify_digest(Kind::PriceVector, g.b(name), &g.d(name)).unwrap();
    }
}

#[test]
fn negative_zero_on_the_wire_decodes_and_digests_canonically() {
    let g = golden();
    let canonical = g.b("constraint_negzero_lambda").to_vec();
    // lambda occupies bytes 170..178; set the sign bit so the wire says -0.0
    let mut wire = canonical.clone();
    wire[177] |= 0x80;
    assert_ne!(wire, canonical);
    let s = decode_constraint(&wire).expect("-0.0 is finite and not negative");
    assert_eq!(s.lambda, 0.0);
    assert_eq!(
        encode_constraint(&s),
        canonical,
        "re-encoding canonicalizes -0.0"
    );
    assert_eq!(digest_constraint(&s), g.d("constraint_negzero_lambda"));
}

// --------------------------------------------------------- hostile inputs

fn mutate_constraint(base: &[u8], case: &str) -> Vec<u8> {
    let mut m = base.to_vec();
    match case {
        "wrong_kind" => m[0] = 4,
        "wrong_version" => m[1] = 2,
        "truncated" => {
            m.pop();
        }
        "trailing" => m.push(0),
        "class_invariant" => m[10] = 1,
        "class_undeclared" => m[10] = 0,
        "unit_none" => m[6] = 0,
        "unit_unknown" => m[6] = 16,
        "lambda_negative" => m[177] |= 0x80,
        "lambda_nan" => m[170..178].copy_from_slice(&f64::NAN.to_bits().to_le_bytes()),
        "lambda_inf" => m[170..178].copy_from_slice(&f64::INFINITY.to_bits().to_le_bytes()),
        "uncertainty_negative" => m[137] |= 0x80,
        "fresh_without_calibration" => m[138..170].fill(0),
        "evidence_root_zero" => m[230..262].fill(0),
        "parent_zero_with_tick" => m[262..294].fill(0),
        "tick_zero_with_parent" => m[222..230].fill(0),
        "estimate_kind_zero" => m[118] = 0,
        "estimate_kind_four" => m[118] = 4,
        "lambda_state_zero" => m[178] = 0,
        "lambda_state_six" => m[178] = 6,
        "measured_without_observation" => m[54..86].fill(0),
        "budget_contract_zero" => m[22..54].fill(0),
        other => panic!("unknown case {other}"),
    }
    m
}

#[test]
fn hostile_constraints_refused_with_the_c_status() {
    let g = golden();
    let base = g.b("constraint_fresh_soft_kv");
    let cases = [
        ("wrong_kind", Refusal::Kind),
        ("wrong_version", Refusal::Encoding),
        ("truncated", Refusal::Encoding),
        ("trailing", Refusal::Encoding),
        ("class_invariant", Refusal::Class),
        ("class_undeclared", Refusal::Class),
        ("unit_none", Refusal::Unit),
        ("unit_unknown", Refusal::Unit),
        ("lambda_negative", Refusal::Range),
        ("lambda_nan", Refusal::NonFinite),
        ("lambda_inf", Refusal::NonFinite),
        ("uncertainty_negative", Refusal::Range),
        ("fresh_without_calibration", Refusal::Calibration),
        ("evidence_root_zero", Refusal::Digest),
        ("parent_zero_with_tick", Refusal::Digest),
        ("tick_zero_with_parent", Refusal::Digest),
        ("estimate_kind_zero", Refusal::Kind),
        ("estimate_kind_four", Refusal::Kind),
        ("lambda_state_zero", Refusal::Range),
        ("lambda_state_six", Refusal::Range),
        ("measured_without_observation", Refusal::Digest),
        ("budget_contract_zero", Refusal::Digest),
    ];
    assert_eq!(
        cases.len(),
        g.status.keys().filter(|k| !k.starts_with("pv_")).count(),
        "every C constraint status in the fixture is covered"
    );
    for (case, expected) in cases {
        let r = decode_constraint(&mutate_constraint(base, case));
        let err = r
            .as_ref()
            .err()
            .unwrap_or_else(|| panic!("{case} must be refused"));
        assert_eq!(*err, expected, "{case}");
        assert_eq!(err.c_status(), g.st(case), "{case} matches the C decoder");
        // a refused record never reaches a diagnostic as a price
        let diag = ScarcityDiagnostic::from_records(
            g.b("pricevec_a"),
            &[&mutate_constraint(base, case)],
            None,
        );
        assert!(!diag.is_available(), "{case}");
    }
}

fn mutate_pv(base: &[u8], case: &str) -> Vec<u8> {
    let mut m = base.to_vec();
    match case {
        "pv_wrong_kind" => m[0] = 2,
        "pv_wrong_version" => m[1] = 0,
        "pv_truncated" => m.truncate(m.len() - 5),
        "pv_trailing" => m.push(7),
        "pv_unordered_ids" => {
            m[46] = 5;
            m[82] = 2;
        }
        "pv_duplicate_ids" => m[82] = 2,
        "pv_zero_state_digest" => m[50..82].fill(0),
        "pv_zero_context" => m[10..42].fill(0),
        "pv_n_zero" => {
            m[42] = 0;
            m.truncate(46);
        }
        "pv_n_too_large" => m[42] = 33,
        other => panic!("unknown case {other}"),
    }
    m
}

#[test]
fn hostile_price_vectors_refused_with_the_c_status() {
    let g = golden();
    let base = g.b("pricevec_a");
    let cases = [
        ("pv_wrong_kind", Refusal::Kind),
        ("pv_wrong_version", Refusal::Encoding),
        ("pv_truncated", Refusal::Encoding),
        ("pv_trailing", Refusal::Encoding),
        ("pv_unordered_ids", Refusal::Resource),
        ("pv_duplicate_ids", Refusal::Resource),
        ("pv_zero_state_digest", Refusal::Digest),
        ("pv_zero_context", Refusal::Digest),
        ("pv_n_zero", Refusal::Range),
        ("pv_n_too_large", Refusal::Range),
    ];
    assert_eq!(
        cases.len(),
        g.status.keys().filter(|k| k.starts_with("pv_")).count()
    );
    let all: Vec<&[u8]> = vec![
        g.b("constraint_fresh_soft_ns"),
        g.b("constraint_fresh_soft_kv"),
        g.b("constraint_fresh_capacity"),
    ];
    for (case, expected) in cases {
        let r = decode_price_vector(&mutate_pv(base, case));
        let err = r
            .as_ref()
            .err()
            .unwrap_or_else(|| panic!("{case} must be refused"));
        assert_eq!(*err, expected, "{case}");
        assert_eq!(err.c_status(), g.st(case), "{case} matches the C decoder");
        let diag = ScarcityDiagnostic::from_records(&mutate_pv(base, case), &all, None);
        match diag {
            ScarcityDiagnostic::Unavailable { reason, .. } => assert!(
                matches!(
                    reason,
                    UnavailableReason::Malformed | UnavailableReason::Refused
                ),
                "{case}: {reason:?}"
            ),
            other => panic!("{case}: {other:?}"),
        }
    }
}

#[test]
fn decoding_the_wrong_kind_through_every_decoder_is_refused() {
    let g = golden();
    assert_eq!(
        decode_resource(g.b("constraint_fresh_soft_kv")),
        Err(Refusal::Kind)
    );
    assert_eq!(decode_constraint(g.b("pricevec_a")), Err(Refusal::Kind));
    assert_eq!(decode_controller(g.b("resource_kv")), Err(Refusal::Kind));
    assert_eq!(decode_price_vector(g.b("controller")), Err(Refusal::Kind));
    assert_eq!(decode_constraint(&[]), Err(Refusal::Encoding));
    assert_eq!(decode_constraint(&[2]), Err(Refusal::Encoding));
}

// ------------------------------------------------- negative control: flip

#[test]
fn negative_control_flipped_byte_fails_digest_verification() {
    let g = golden();
    // Flip a byte inside estimate_ref (86..118): the record still decodes,
    // so only the digest can catch it.
    let mut flipped = g.b("constraint_fresh_soft_kv").to_vec();
    flipped[100] ^= 0x01;
    decode_constraint(&flipped).expect("structurally valid");
    let r = verify_digest(Kind::Constraint, &flipped, &g.d("constraint_fresh_soft_kv"));
    assert!(
        matches!(r, Err(VerifyError::DigestMismatch { .. })),
        "{r:?}"
    );
    // the untouched bytes verify, proving the control is the flip
    verify_digest(
        Kind::Constraint,
        g.b("constraint_fresh_soft_kv"),
        &g.d("constraint_fresh_soft_kv"),
    )
    .unwrap();

    // Same flip seen through the diagnostic: the vector's state digest no
    // longer names any supplied record, so no price is read.
    let diag = ScarcityDiagnostic::from_records(
        g.b("pricevec_a"),
        &[
            g.b("constraint_fresh_soft_ns"),
            &flipped,
            g.b("constraint_fresh_capacity"),
        ],
        None,
    );
    assert!(matches!(
        diag,
        ScarcityDiagnostic::Unavailable {
            reason: UnavailableReason::Missing,
            ..
        }
    ));

    // Flip in the vector itself against its expected digest.
    let mut pv = g.b("pricevec_a").to_vec();
    pv[20] ^= 0x80; // inside context
    let diag = ScarcityDiagnostic::from_records(&pv, &[], Some(&g.d("pricevec_a")));
    assert!(matches!(
        diag,
        ScarcityDiagnostic::Unavailable {
            reason: UnavailableReason::DigestMismatch,
            ..
        }
    ));
}

// ------------------------------------------------------ dominant scarcity

#[test]
fn dominant_scarcity_tie_breaks_on_lowest_resource_id_and_flags_capacity() {
    let g = golden();
    let diag = ScarcityDiagnostic::from_records(
        g.b("pricevec_a"),
        &[
            // supplied out of order on purpose: matching is by digest
            g.b("constraint_fresh_capacity"),
            g.b("constraint_fresh_soft_kv"),
            g.b("constraint_fresh_soft_ns"),
            g.b("constraint_stale"), // unrelated extra record is ignored
        ],
        Some(&g.d("pricevec_a")),
    );
    match diag {
        ScarcityDiagnostic::Available {
            resource_id,
            unit,
            class,
            diagnostic_only,
            lambda,
            generation,
            ref evidence_root,
            state,
        } => {
            // ids 2 and 5 both carry lambda 0.42: lowest id wins
            assert_eq!(resource_id, 2);
            assert_eq!(unit, Unit::Ns);
            assert_eq!(class, Class::Soft);
            assert!(!diagnostic_only);
            assert_eq!(lambda, 0.42);
            assert_eq!(generation, 7);
            assert_eq!(*evidence_root, hex::encode(tag("evidence-root")));
            assert_eq!(state, FreshState::Fresh);
        }
        other => panic!("{other:?}"),
    }
    let s = diag.summary();
    assert!(s.starts_with("dominant fresh calibrated scarcity: resource 2 (NS), class SOFT, lambda 0.42, generation 7, evidence root "));
    assert!(s.ends_with(", state FRESH"));

    // CAPACITY: reported, flagged diagnostic only, never "relaxable";
    // the UNCALIBRATED lambda 3.0 beside it is ignored.
    let diag = ScarcityDiagnostic::from_records(
        g.b("pricevec_c"),
        &[
            g.b("constraint_uncalibrated"),
            g.b("constraint_fresh_capacity"),
        ],
        Some(&g.d("pricevec_c")),
    );
    match &diag {
        ScarcityDiagnostic::Available {
            resource_id,
            class,
            diagnostic_only,
            lambda,
            ..
        } => {
            assert_eq!(*resource_id, 9);
            assert_eq!(*class, Class::Capacity);
            assert!(*diagnostic_only);
            assert_eq!(*lambda, 0.1);
        }
        other => panic!("{other:?}"),
    }
    assert!(diag
        .summary()
        .contains("CAPACITY (diagnostic only, never relaxable)"));
    let json = serde_json::to_value(&diag).unwrap();
    assert_eq!(json["status"], "available");
    assert_eq!(json["diagnostic_only"], true);
    assert_eq!(json["state"], "FRESH");
}

#[test]
fn non_fresh_prices_are_unavailable_never_zero() {
    let g = golden();
    let diag = ScarcityDiagnostic::from_records(
        g.b("pricevec_b"),
        &[g.b("constraint_stale"), g.b("constraint_uncalibrated")],
        Some(&g.d("pricevec_b")),
    );
    assert_eq!(
        match &diag {
            ScarcityDiagnostic::Unavailable { reason, .. } => *reason,
            other => panic!("{other:?}"),
        },
        UnavailableReason::Stale
    );
    assert!(diag
        .summary()
        .starts_with("scarcity reading unavailable: price is STALE"));
    let json = serde_json::to_value(&diag).unwrap();
    assert_eq!(json["status"], "unavailable");
    assert_eq!(json["reason"], "STALE");
    assert!(
        json.get("lambda").is_none(),
        "no lambda is ever reported as zero"
    );

    // Only an UNCALIBRATED state: reason UNCALIBRATED, lambda 3.0 not surfaced.
    let s = decode_constraint(g.b("constraint_uncalibrated")).unwrap();
    let pv = PriceVector {
        generation: 7,
        context: tag("decision-context"),
        entries: vec![(7, digest_constraint(&s))],
    };
    let diag = ScarcityDiagnostic::from_records(
        &encode_price_vector(&pv),
        &[g.b("constraint_uncalibrated")],
        None,
    );
    assert!(matches!(
        diag,
        ScarcityDiagnostic::Unavailable {
            reason: UnavailableReason::Uncalibrated,
            ..
        }
    ));

    // FROZEN alone: reason FROZEN.
    let f = decode_constraint(g.b("constraint_frozen")).unwrap();
    let pv = PriceVector {
        generation: 7,
        context: tag("decision-context"),
        entries: vec![(11, digest_constraint(&f))],
    };
    let diag = ScarcityDiagnostic::from_records(
        &encode_price_vector(&pv),
        &[g.b("constraint_frozen")],
        None,
    );
    assert!(matches!(
        diag,
        ScarcityDiagnostic::Unavailable {
            reason: UnavailableReason::Frozen,
            ..
        }
    ));
}

#[test]
fn vector_state_must_name_the_right_resource_and_generation() {
    let g = golden();
    let ns = decode_constraint(g.b("constraint_fresh_soft_ns")).unwrap();
    let kv = decode_constraint(g.b("constraint_fresh_soft_kv")).unwrap();

    // digest for id 2 actually names the id 5 record
    let pv = PriceVector {
        generation: 7,
        context: tag("decision-context"),
        entries: vec![(2, digest_constraint(&kv)), (5, digest_constraint(&ns))],
    };
    let diag = ScarcityDiagnostic::from_records(
        &encode_price_vector(&pv),
        &[
            g.b("constraint_fresh_soft_ns"),
            g.b("constraint_fresh_soft_kv"),
        ],
        None,
    );
    assert!(matches!(
        diag,
        ScarcityDiagnostic::Unavailable {
            reason: UnavailableReason::DigestMismatch,
            ..
        }
    ));

    // a state at another generation than the vector
    let mut old = ns.clone();
    old.generation = 6;
    let old_bytes = encode_constraint(&old);
    let pv = PriceVector {
        generation: 7,
        context: tag("decision-context"),
        entries: vec![(2, digest_constraint(&old))],
    };
    let diag = ScarcityDiagnostic::from_records(&encode_price_vector(&pv), &[&old_bytes], None);
    match diag {
        ScarcityDiagnostic::Unavailable { reason, detail } => {
            assert_eq!(reason, UnavailableReason::Refused);
            assert!(detail.contains("generation 6 differs from vector generation 7"));
        }
        other => panic!("{other:?}"),
    }

    // a referenced record that was never supplied
    let diag = ScarcityDiagnostic::from_records(
        g.b("pricevec_a"),
        &[
            g.b("constraint_fresh_soft_ns"),
            g.b("constraint_fresh_capacity"),
        ],
        None,
    );
    assert!(matches!(
        diag,
        ScarcityDiagnostic::Unavailable {
            reason: UnavailableReason::Missing,
            ..
        }
    ));

    // wrong expected digest for a good vector
    let diag = ScarcityDiagnostic::from_records(
        g.b("pricevec_a"),
        &[
            g.b("constraint_fresh_soft_ns"),
            g.b("constraint_fresh_soft_kv"),
            g.b("constraint_fresh_capacity"),
        ],
        Some(&g.d("pricevec_b")),
    );
    assert!(matches!(
        diag,
        ScarcityDiagnostic::Unavailable {
            reason: UnavailableReason::DigestMismatch,
            ..
        }
    ));
}

// ---------------------------------------------------- default + directory

#[test]
fn default_is_missing_and_old_configs_still_deserialize() {
    let d = ScarcityDiagnostic::default();
    assert_eq!(
        d,
        ScarcityDiagnostic::Unavailable {
            reason: UnavailableReason::Missing,
            detail: "no price vector configured".to_string(),
        }
    );
    assert!(d
        .summary()
        .starts_with("scarcity reading unavailable: price is MISSING"));
    assert!(spark_rsi::models::RsiConfig::default()
        .dual_price_vector_dir
        .is_none());

    // A config serialized before the new key existed still loads with None.
    let old = serde_json::json!({
        "target_repo": ".", "cortex_url": "http://127.0.0.1:18080", "cortex_space": "s",
        "mojo_kernel_path": "mojo/balance_bin", "loop_interval_secs": 60,
        "sandbox_root": "/tmp/spark-rsi-sandbox"
    });
    let cfg: spark_rsi::models::RsiConfig = serde_json::from_value(old).unwrap();
    assert!(cfg.dual_price_vector_dir.is_none());
    // RsiCycleResult.scarcity carries #[serde(default)], so a result written
    // before the field existed deserializes to the same default.
    assert_eq!(
        serde_json::from_str::<ScarcityDiagnostic>(
            &serde_json::to_string(&ScarcityDiagnostic::default()).unwrap()
        )
        .unwrap(),
        ScarcityDiagnostic::default()
    );
}

#[test]
fn load_from_dir_reads_vector_constraints_and_optional_digest() {
    let g = golden();
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path();
    assert!(matches!(
        ScarcityDiagnostic::load_from_dir(p),
        ScarcityDiagnostic::Unavailable {
            reason: UnavailableReason::Missing,
            ..
        }
    ));
    assert!(matches!(
        ScarcityDiagnostic::load_from_dir(&p.join("does-not-exist")),
        ScarcityDiagnostic::Unavailable {
            reason: UnavailableReason::Missing,
            ..
        }
    ));

    std::fs::write(p.join("price_vector.bin"), g.b("pricevec_a")).unwrap();
    std::fs::write(p.join("ns.constraint.bin"), g.b("constraint_fresh_soft_ns")).unwrap();
    std::fs::write(p.join("kv.constraint.bin"), g.b("constraint_fresh_soft_kv")).unwrap();
    std::fs::write(
        p.join("cap.constraint.bin"),
        g.b("constraint_fresh_capacity"),
    )
    .unwrap();
    std::fs::write(p.join("notes.txt"), "ignored").unwrap();
    let diag = ScarcityDiagnostic::load_from_dir(p);
    assert!(
        matches!(diag, ScarcityDiagnostic::Available { resource_id: 2, .. }),
        "{diag:?}"
    );

    std::fs::write(
        p.join("price_vector.sha256"),
        hex::encode(g.d("pricevec_a")),
    )
    .unwrap();
    assert!(ScarcityDiagnostic::load_from_dir(p).is_available());

    std::fs::write(
        p.join("price_vector.sha256"),
        hex::encode(g.d("pricevec_b")),
    )
    .unwrap();
    assert!(matches!(
        ScarcityDiagnostic::load_from_dir(p),
        ScarcityDiagnostic::Unavailable {
            reason: UnavailableReason::DigestMismatch,
            ..
        }
    ));

    std::fs::write(p.join("price_vector.sha256"), "zz").unwrap();
    assert!(matches!(
        ScarcityDiagnostic::load_from_dir(p),
        ScarcityDiagnostic::Unavailable {
            reason: UnavailableReason::Malformed,
            ..
        }
    ));
}

// -------------------------------------------------- no authority path

#[test]
fn authority_paths_do_not_reference_the_dual_reader() {
    // Source-level guard: ranking, evaluation layers, judging, ratification,
    // promotion and the safety envelope never read DUAL output (ADR 0031 s6:
    // "a consumer that reads a DualPriceVector as a gate input fails its gate").
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let guarded = [
        "src/graph/mod.rs",
        "src/evaluator/mod.rs",
        "src/evaluator/layers/mod.rs",
        "src/evaluator/layers/correctness.rs",
        "src/evaluator/layers/security.rs",
        "src/evaluator/layers/performance.rs",
        "src/evaluator/layers/resource_efficiency.rs",
        "src/evaluator/layers/style.rs",
        "src/evaluator/layers/longitudinal_replay.rs",
        "src/actor/judge.rs",
        "src/ratify.rs",
        "src/diff_gate.rs",
        "src/canary_observation.rs",
        "src/safety_envelope.rs",
        "src/meta/mod.rs",
        "src/verifier.rs",
    ];
    for rel in guarded {
        let text = std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"));
        for needle in [
            "dual::",
            "ScarcityDiagnostic",
            "scarcity",
            "lambda_state",
            "PriceVector",
        ] {
            assert!(!text.contains(needle), "{rel} references {needle}");
        }
    }
    // The fixed bottleneck weights are untouched.
    let graph = std::fs::read_to_string(root.join("src/graph/mod.rs")).unwrap();
    assert!(graph.contains("let score = (c * 0.4) + (lat_ratio * 0.4) + (err_factor * 0.2);"));
}
