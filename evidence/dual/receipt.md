# Receipt: RSI DUAL diagnostic price reader (ADR 0031 section 7.5 and 10)

Verdict: **RSI DUAL diagnostic reader IMPLEMENTED; diagnostic only; no authority; production unchanged.**

## Identity
- Repository: aien-dev/spark-rsi, branch `dual/rsi-price-reader`
- Base: `f5f1ca2247057c40c7f93b71b60508c1f400271b` (GitHub main, "Fix stale RatificationRecord in evidence-graph test (#31)", committed 2026-10-02T12:47:00-05:00; fresh clone 2026-10-04, HEAD matched the SHA named in the brief)
- Candidate: `d58dd0c1c4c2d26bd9a49736ced0c6f07087bf2b` (implementation, tests, fixtures) followed by crumb-only refresh commit `c532e3c`; this receipt and its own crumb refresh are the commits after it
- Encoding copied from: aien-dev/omega branch `dual/0a-records`, commit `f056b77f64ee94a80f4ed2899b5f9495aa3ef840` (2026-10-04T13:00:33-05:00, PR aien-dev/omega#266), files `src/dual/rx_dual.h`, `src/dual/rx_dual.c`, `src/sha256.c`, `docs/dual/DUAL_RECORDS.md`
- Sibling path dependency for the build: aien-dev/aien-protocols main at `89d9153` (required by Cargo.toml path deps; CI checks it out the same way)
- Toolchain: `rustc 1.98.1 (48a229cea 2026-09-01)`, `cargo 1.98.1 (797e8a9bc 2026-08-05)`, gcc (system) for the throwaway generator
- Host: DGX Spark, Linux 7.0.0-1019-nvidia

## What was built
- `src/dual/records.rs`: decoders and canonical encoders for RxDualResource (kind 1), RxDualConstraintState (kind 2), RxDualController (kind 3), RxDualPriceVector (kind 4); enum values (Unit 1..15, Class 2/3, EstimateKind 1..3, LambdaState 1..5) and refusal codes copied from `rx_dual.h` at the omega commit above; `Refusal::c_status()` reproduces the C `RxDualStatus` so parity is testable. Digest = SHA-256(domain || 0x00 || canonical encoding) over the validated record's re-encoding (so a non-canonical -0.0 on the wire gets the canonical digest, as in C).
- `src/dual/diagnostic.rs`: `ScarcityDiagnostic` with exactly two shapes. `Available { resource_id, unit, class, diagnostic_only, lambda, generation, evidence_root, state: FRESH }` for the largest FRESH calibrated lambda in a verified price vector (tie: lowest resource_id; CAPACITY => `diagnostic_only: true`). `Unavailable { reason: Missing | Stale | Frozen | Uncalibrated | Refused | DigestMismatch | Malformed, detail }`. Verification: price vector decodes; optional expected vector digest matches; every `state[i]` digest names a supplied constraint record (matched by recomputed digest); that record's resource_id equals `resource_id[i]` and its generation equals the vector's. No FRESH price => reason by precedence REFUSED, STALE, FROZEN, UNCALIBRATED over the states present. A missing, stale, refused or uncalibrated price is never read as zero.
- Integration: `RsiConfig.dual_price_vector_dir: Option<String>` (serde default None; CLI `--dual-price-vector-dir` on `cycle` and `daemon`), `RsiCycleResult.scarcity` (serde default = Unavailable Missing, old JSON still deserializes). In `RsiEngine::run_cycle` the diagnostic is read after `rank_bottlenecks`; when a directory is configured one rationale line is added to the proposer's `DiagnosticContext` violations and one log line is emitted. When not configured nothing else changes.
- Directory layout read by `ScarcityDiagnostic::load_from_dir`: `price_vector.bin`, any `*.constraint.bin`, optional `price_vector.sha256` (hex). This is RSI's own file convention until the DUAL producer defines a transport (DUAL-0a is records only).

## Dependency decision
No new dependency. `sha2 = "0.10"` and `hex = "0.4"` were already in Cargo.toml (used by the ledger and daemon), so the digest recomputation uses them. No in-house sha256 crate exists in this workspace; the omega C `src/sha256.c` was used only by the throwaway generator, not linked into the crate. Cargo.lock unchanged.

## Commands and results (run in the fresh clone)
| Step | Command | Result |
|---|---|---|
| baseline | `cargo check --all-targets` at f5f1ca2 | Finished, exit 0 |
| baseline | `cargo test -- --test-threads=1` at f5f1ca2 | 18 test binaries, 183 passed, 0 failed, exit 0 |
| golden | `gcc -std=c11 -Wall -Wextra gen.c rx_dual.c sha256.c -lm` then `./gen` | 12 records + digests, 32 hostile statuses, all nonzero (first run had two wrong byte offsets which returned 0; offsets corrected to 22 and 54 and rerun) |
| candidate | `cargo check --all-targets` | exit 0 |
| candidate | `cargo fmt --all -- --check` | exit 0 |
| candidate | `cargo test --test test_dual_price_reader` | 15 passed, 0 failed |
| candidate | `cargo test -- --test-threads=1` (CI invocation) | 19 test binaries, 198 passed, 0 failed, exit 0 |
| candidate | `cargo clippy --all-targets -- -D warnings` | 19 errors, all pre-existing in files this PR does not touch (src/propose/kernel_autotune.rs, src/supervisor/ipc.rs, src/propose/max_client.rs, src/meta/tier.rs, src/meta/ab_fork.rs, src/evaluator/stats.rs, src/evaluator/mod.rs, src/evaluator/metrics.rs); 0 findings in src/dual, tests/test_dual_price_reader.rs, src/daemon.rs, src/models.rs, src/main.rs, src/lib.rs. CI (.github/workflows/ci.yml) runs fmt, check, build and test, not clippy |
| crumbs | `crumb compile .` then `crumb verify .` before each commit; `crumb validate .` | verify OK (26 crumbs current after the crumb refresh commit); validate OK |
| authority files | `git diff --name-only f5f1ca2 d58dd0c -- src/graph/mod.rs src/evaluator src/ratify.rs src/actor/judge.rs src/canary_observation.rs src/safety_envelope.rs src/meta src/diff_gate.rs` | only `.crumb` files listed; no Rust source in those areas changed |

## Tests (tests/test_dual_price_reader.rs, 15)
- Golden round trips: resource, 7 constraints (FRESH SOFT x2, FRESH CAPACITY, STALE, UNCALIBRATED, FROZEN, -0.0 lambda), controller, 3 price vectors: decode, field values, byte-exact re-encode, digest equal to the C digest, `verify_digest` OK.
- Hostile constraints (22 cases) and hostile price vectors (10 cases): each refused, and `Refusal::c_status()` equals the C decoder's RxDualStatus recorded in the fixture (kind -7, version/truncation/trailing -8, class -4, unit -3, negative -6, NaN/Inf -2, FRESH without calibration -17, missing digests and tick/parent linkage -10, unordered/duplicate ids -9, bad counts -6). Every C status line in the fixture is covered (asserted by count).
- Wrong kind through every decoder refused; empty and 1-byte inputs refused.
- -0.0 on the wire decodes (finite, not negative), re-encodes to +0.0, digest equals the canonical fixture digest.
- Negative control: a flipped bit inside estimate_ref of a valid constraint still decodes, fails `verify_digest` with DigestMismatch while the untouched bytes verify; through the diagnostic it yields Unavailable Missing (no record carries the named digest); a flipped byte in the vector against its expected digest yields DigestMismatch.
- Dominant selection: vector A (ids 2 and 5 both lambda 0.42 SOFT, id 9 CAPACITY 0.1) => id 2 (tie-break lowest id), diagnostic_only false, generation 7, evidence root hex of the fixture; vector C (UNCALIBRATED lambda 3.0, CAPACITY FRESH 0.1) => id 9 CAPACITY with diagnostic_only true, uncalibrated ignored; vector B (STALE, UNCALIBRATED) => Unavailable Stale with no lambda field; UNCALIBRATED alone => Uncalibrated; FROZEN alone => Frozen.
- Linkage: state digest naming the wrong resource => DigestMismatch; state at another generation => Refused (RxDualStatus -11 named in detail); referenced record not supplied => Missing; wrong expected vector digest => DigestMismatch.
- Default: `ScarcityDiagnostic::default()` is Unavailable Missing; `RsiConfig::default().dual_price_vector_dir` is None; a pre-existing RsiCycleResult JSON without `scarcity` deserializes to the default.
- Directory loader: empty dir and absent dir => Missing; vector + 3 constraints => Available id 2; matching `price_vector.sha256` => Available; wrong digest file => DigestMismatch; non-hex digest file => Malformed.
- Source guard: src/graph/mod.rs, evaluator and layers, judge, ratify, diff_gate, canary_observation, safety_envelope, meta, verifier contain no reference to the reader; the fixed weights line `(c * 0.4) + (lat_ratio * 0.4) + (err_factor * 0.2)` is present unchanged.

## Not done / UNVERIFIED
- Not run against a live DUAL producer: none exists yet (DUAL-0a is records only). The directory layout is RSI's own interim convention.
- Clippy on the untouched baseline was not rerun separately; the "pre-existing" claim rests on the finding paths, none of which this PR touches.
- The golden generator (evidence/dual/gen.c) is kept for reproducibility only; it is not built by cargo or CI.
- Hostile status lines "measured_without_observation" and "budget_contract_zero" were first generated with wrong byte offsets (status 0); the generator was corrected and rerun before the fixture was committed. The committed fixture has no status 0 line.
