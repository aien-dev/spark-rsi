# Qualification report: evidence-driven RSI cut (M1 + M2)

Date: 2026-10-12. Revision under test: see `run-correct/environment.json` (branch
`feat/evidence-driven-rsi-cut`, integration PR aien-dev/spark-rsi#44). Host: NVIDIA DGX Spark
(GB10, 20 cores, 121 GiB), rustc 1.98.1. Plan: `docs/plans/2026-10-12-evidence-driven-rsi-cut.md`.
Ticket: #43.

## What was run

Two real cycles of `examples/canary_qualification` against the fixture target
(`fixtures/canary-target`) with the operator-pinned workload (10 requests, 2000 ms deadline each,
`exact` nondeterminism):

1. `run-correct`: the fixture answers every request correctly.
2. `run-wrong-answer`: the fixture answers request 3 wrongly. The plan requires that the real run
   include at least one failing request; this run is that case.

Each cycle went through the real pipeline: Observe, Propose (the unslop proposal from the README
em dash), BuildJail (bubblewrap, `cargo build --release --offline` of the fixture from the
evaluated tree), JudgeEvaluation (the in-process judge over the holdouts), then the
supervisor-driven canary: identity chain (patch digest, evaluated tree digest, staged executable
digest, generation id), executable re-hashed before launch, versioned authenticated readiness,
ten supervisor-issued requests measured on the supervisor's clock, a sealed observation log, a
ledger commitment block, quota admission, safety envelope, promotion gate.

## Results

| | run-correct | run-wrong-answer |
|---|---|---|
| executable digest | `870722da2227135d0d53c1575a8f2ca5dcf41c630415d4dda389073af0f2341e` | same |
| workload digest | `d21ca53e23457bd1da84e0cc2115999208312eea03f30616a5c3d46e97e39bab` | same |
| observations recorded (qualifying) | 10 (10) | 3 (2) |
| first failure | none | req-003: WrongResult |
| early safety revert | no | yes, worker stopped after request 3 |
| sealed log digest | `656369180cb7b506457b03037cddd65005d66f2e73f21e7a07cb01123541306a` | `63cf4282a17e0b6ce3997a7fd0d7e306fce064be42c2995c9df0e575d1c3f05d` |
| ledger commitment block | `7a2bc9e5c69064930251c4b08680dbe52f70d4fc1f1bf599929fe7164133d738` | `46895b6b874f00a970821d42cdeb8de2ae319e9840764b2247c6a830aee9ce86` |
| quota admission | admitted, 10 of 10 | refused: WrongResult on req-003 |
| safety envelope | passed; recorded as a reference evaluation | not reached |
| promotion gate | refused: no pinned judge public key | not reached |
| durable generation | none | none |
| verdict against the mode's prediction | as predicted | as predicted |

Both logs verify independently (`sealed-log.json`), both ledgers audit clean (`ledger-audit.json`),
and the commitment block precedes the quota decision in both ledgers (`ledger-blocks.json`).

## Evidence files, per run directory

- `summary.md`: the decisions in one table, as printed by the run.
- `cycle-result.json`: the full `RsiCycleResult` including the `canary` summary.
- `workload.json` and `workload.sha256`: the pinned workload and its digest.
- `canary-adapter.toml`: the adapter manifest the target shipped.
- `observations.jsonl`: the sealed observation log exactly as written (header, observations,
  rejections, seal).
- `sealed-log.json`: the log re-verified by `SealedObservationLog::load` after the run.
- `ledger-blocks.json` and `ledger-audit.json`: every ledger block of the cycle and the chain audit
  with the signed checkpoint verified against the cycle's key.
- `stage-samples.jsonl`: the M1 stage samples the cycle recorded (first cycle of its workload key,
  so the ranking that produced the proposal was structural).
- `config.json` and `environment.json`: the exact configuration, revision, toolchain and host.

## Adversarial CI

All of the following run in `cargo test` and passed in the full CI-mirror gate
(`tests/gates/run.sh test`, exit 0) on this revision:

- `tests/test_canary_execution.rs` (15 tests, real fixture process over a real socket): correct
  run, wrong answer, fabricated self-report, duplicate results, replay on a new connection across
  a restart, timeout, answer to the wrong request, premature promotion frames, wrong secret, old
  protocol version, wrong generation, bare silent connection, crash and reopen without double
  counting, a failure recorded before a restart, a mismatched executable digest, a workload that
  does not match its pin.
- `tests/test_no_synthetic_trust_inputs.rs` daemon tests (5, real build jail): correct fixture
  reaches the later gates, wrong answer is refused and rolled back, no adapter is refused before
  any worker starts, mismatched or missing workload pin, exemption is explicit configuration and
  never covers executable changes.
- `tests/test_m1_measurement.rs` (18) and `tests/test_canary_contract_golden.rs` (10 frozen
  encodings), plus the supervisor, canary and measure unit tests.

## What this qualifies, and what it does not

Qualified: the canary execution pipeline. Evidence reaches admission only when the supervisor
issued the request, measured the answer itself, matched it against the pinned workload, and sealed
it into a log bound to the exact executable it launched. Self-reports, duplicates, replays, wrong
outputs, timeouts, unauthenticated or wrong-generation connections, mismatched digests and
corrupted logs cannot qualify, and a single failed request reverts the candidate.

Not qualified:

- RSI's ability to improve itself. The target was a fixture, not spark-rsi. spark-rsi as the first
  real adapter target is the next milestone.
- The safety envelope as a production evaluator. It evaluates through
  `aien_probe::DeterministicReferenceBackend`; that is recorded in the ledger and the cycle
  result, and replacing or qualifying that evaluator is a separate follow-on cut.
- Production latency reliability. Ten requests prove quota and replay protection, not tail
  latency.

## Remaining production limitations

1. The promotion gate refuses every candidate in this cut: the in-process judge signs with the
   daemon's own key and produces no version 2 binding, so no candidate becomes durable until the
   separate judge is wired in (issue #35). This is fail closed by design, and it means the full
   promotion path has not yet been exercised end to end.
2. The safety envelope is a reference evaluation (above).
3. The canary worker is not jailed. It runs as the daemon's user with an allowlisted environment
   (`PATH`, `HOME`, `LANG`, `LC_ALL`, `TMPDIR`, `RUST_BACKTRACE`, `RSI_CANARY_*`, and a fresh
   per-run `SUPERVISOR_SECRET`).
4. Readiness listens on a same-user Unix socket. A stray same-user connection that stays silent
   can consume the readiness deadline; the result is a failed canary, never a false pass.
5. The build jail writes to the shared output root `/tmp/spark-rsi-target`; the executable is
   copied into the staged generation and re-hashed, but a concurrent writer to that directory
   between the build and the copy is not defended against.
6. The qualification ran with the inference endpoint and the memory service unreachable, so the
   proposal exercised was the unslop proposal; the model-generated proposal path was not
   exercised.
7. Measurement starts cold: the first cycles of a workload key rank structurally until three
   compatible completed samples exist per stage. The soak runner reads the same samples but does
   not record its own.
8. The shared explain fixture was re-blessed; aienos must refresh its copy and pin
   (aien-dev/aienos#337).
