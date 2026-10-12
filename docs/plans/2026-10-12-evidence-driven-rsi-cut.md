# Evidence-Driven RSI: the M1 + M2 cut

Status: approved plan, no code yet. Decided by Drake in a three-round design grilling on 2026-10-12.
Supersedes, for implementation purposes, the broader brief "AIEN Development Brief: Evidence-Driven Autonomous Engineering".

## The one rule above everything

**No candidate-controlled statement can independently establish that a canary passed.**

A candidate may answer a challenge. The supervisor must have sent that challenge, must measure the elapsed time
itself, must compare the answer against independently defined expectations, and must durably commit the verified
observation. Only the existing admission and promotion authorities act on that evidence. Tests that let a worker
self-report success into production admission are defects and must be rewritten.

**Every accepted canary observation must be demonstrably tied to the exact executable that was built,
independently checked by the supervisor, and admitted through one authoritative promotion path.**

Fixture qualification and production safety qualification are different things. Ten verified fixture requests
prove the canary mechanism works. They do not establish that every existing safety evaluator is ready to authorize
production changes; see the safety-envelope defect below.

## Scope

In scope, this cut only:

- **M1 Measurement.** Replace the hardcoded capability-graph numbers in `src/daemon.rs` with measured RSI stage
  timings from completed prior cycles.
- **M2 Execution and admission.** Make `admit_production_quota` receive real, authenticated, supervisor-driven
  observations instead of an empty slice.

Deferred, not authorized here: objective discharge (M3), residual-unknown registry (M4), RSI and explanation
interoperability (M5), REA investigation adapter (M6, filed as a mind-map idea).

## Pinned baseline

| Repository | Commit |
|---|---|
| spark-rsi | `f74a7dbdcd06` |
| aien-sovereign-core | `b323258396a9` |
| aien-protocols | `5c2316954e16` |
| aienos | `5cfba1bba3f8` |

## Verified defects at the baseline

- `src/daemon.rs` builds the capability graph with constant latency and memory values per node.
- `src/daemon.rs` calls `admit_production_quota(&[], ...)`; the quota can never be met.
- `src/supervisor/daemon.rs` discards `transaction_id` on `CanaryReport`, so replays count.
- The `CanaryReport` branch checks only the generation name, not whether that connection completed the handshake.
- `CanaryReport` carries worker-supplied success and latency, which go straight into `record_canary_transaction`.
- `run_cycle` stages a generation but never calls `spawn_worker` and never runs a canary workload.
- `HostSupervisor::record_canary_transaction` and `process_worker_message` both grant `Durable` on a counter.
- Handling `Ready` switches `active.sock` to the candidate before any admission decision.
- `rank_bottlenecks` sorts by score with no tie-break; non-finite scores compare as equal.
- `wait_for_readiness` returns success on any socket connection, even with no PONG or READY reply at all.
- `record_canary_transaction` treats a failed memory-budget read as within budget (`unwrap_or(true)`).
- `stage_canary` only copies the candidate directory; nothing compiles, launches or drives an executable.
- The candidate digest passed to the quota validator is the hash of `proposal.proposed_patch`, not of the
  evaluated tree or the executable launched.
- `admit_production_quota` checks only non-empty id and status, candidate digest match, the `Measured` label and
  duplicate consistency. It does not check that the status is a verified success.
- `CanarySafetyEnvelope` runs its probes through `DeterministicReferenceBackend` on the production call path, so its
  signed result is a reference evaluation, not independently established production safety.
- The hypothesis contract is built from the graph's `latency_p95_us`, so a cold-start cycle can claim a measured
  latency target from invented numbers.
- Every winning proposal, whatever its kind, is sent into the canary path.

## Decisions

### Terminology

- **Closure** keeps its existing meaning: the `aien-closure` / `verify-closure` dependency-graph proof check.
- **Discharge** is the new word for "an objective's required outcomes all have qualifying evidence". Deferred.
- An **obligation**, when it arrives, is an `aien-proof` Gate `Requirement` extended with an obligation id, an
  objective id and an out-of-scope disposition. No new evaluator.

### M1 Measurement

- Measure RSI's own pipeline stages (Observe, Propose, BuildJail, JudgeEvaluation, SupervisorCanary, CortexCommit),
  not the inference runtime.
- Ranking in a cycle uses samples from **completed prior cycles**, never the current one.
- Samples persist in an append-only stage-sample log under the RSI state directory, one record per cycle:
  cycle id, workload key, execution-profile fingerprint, per-stage duration and outcome, source commit, schema
  version. Failed and partial cycles are recorded in a separate partial-cycle set, never mixed into eligible samples.
- **Workload key**: normalized target repository identity, effective execution configuration, model name.
  The target commit is recorded for provenance but is not part of the key.
- **Execution-profile fingerprint**: model name, effective execution configuration, CPU count, memory capacity,
  GPU identity (`none` when absent). Canary adapter protocol version is recorded on canary-stage samples only.
  `require_latency_improvement` is an evaluation policy and is not an execution mode.
- **Sufficiency**: at least 3 compatible completed samples per stage from the most recent 20 compatible cycles.
  Both numbers are configuration.
- **Statistics**: median is the ranking input and is reported under its own name. Empirical p95 is reported only
  with at least 20 valid compatible samples; otherwise p95 is marked unavailable. One percentile algorithm,
  golden-tested. Zero never means missing: unavailable is an explicit state, with backward-compatible graph output.
- **Cold start**: rank on graph topology (betweenness centrality) only; latency and error terms are marked
  unavailable in the explanation. No "measured improvement" hypothesis may be generated from missing data: the
  hypothesis contract carries a numeric latency target only when the stage's latency is measured, otherwise it is
  an exploratory hypothesis with no performance claim.
- **Canary applicability** is policy-controlled by proposal kind and claim: executable production changes always
  go through canary admission; documentation and other non-executable changes may be exempted by explicit policy,
  never by default. Exemption never weakens the gates for anything that reaches production.
- **Claims**: a proposal of kind `Optimization`, or any proposal when `require_latency_improvement` is on, needs a
  measured diagnosis before promotion. Other kinds proceed on structural ranking.
- **Ordering**: score descending, then stage id ascending. Non-finite measurements are rejected before scoring.
- Removing measurements can never restore the old constants. Those constants are deleted.

### M2 Execution

- **Adapter manifest**: a target is eligible for canary only if it ships a declared canary adapter manifest naming
  the approved executable, arguments, protocol version, request workload and expected-response format. Unsupported
  targets fail closed. The supervisor verifies the executable is the exact built artifact under evaluation.
- **Wire protocol**: a small versioned supervisor-to-worker execute-request / result message pair added to the IPC
  enum. Worker `CanaryReport` self-reports become diagnostics only.
- **Workload**: a digest-pinned canary manifest under the RSI state directory with requests, expected outcomes,
  deadlines and permitted nondeterminism. The candidate cannot rewrite it or set its own passing criteria.
- **Candidate identity** is a bound chain: source patch digest, evaluated tree digest, built executable digest,
  generation id. The supervisor launches only the executable whose digest is in that chain, and every observation
  carries the executable digest. The quota validator compares against the executable digest, not the patch digest.
- **Readiness** means a valid versioned READY reply on the authenticated generation socket within the deadline.
  A bare connection, silence or an unknown reply is not ready.
- **Observation** binds: generation id, issued request id, request digest, workload digest, candidate executable
  digest, observed result digest, supervisor-measured elapsed time, supervisor timestamp, verified status,
  provenance.
- **Observation id**: domain-separated hash of (generation id, request id, request digest). Duplicates collide by
  construction; the store refuses known ids; conflicting records for one id are a verification failure.
  The supervisor tracks issued requests; an unsolicited response creates nothing. Incomplete requests after a
  restart are never counted as successes.
- **Authentication**: per-connection state `Unauthenticated -> Authenticated(generation_id)` set only by a
  successful HMAC handshake. Messages on unauthenticated connections or for another generation are rejected and
  the connection closed, logged as rejected, with no rollback. A worker timeout still fails the canary.
- **Storage**: per-generation append-only observation log, sealed with a final digest record. Partial trailing
  records are detected and excluded. The sealed log digest is committed to the RSI ledger before admission.
- `active.sock` is **not** switched on `Ready`. The candidate is exercised through its generation socket.

### M2 Admission

- The quota validator (`admit_production_quota`) is the single authority on evidence sufficiency.
  `record_canary_transaction` and `process_worker_message` stop granting `Durable`.
- Sequence: Collect -> Seal -> Verify -> Quota admission -> Safety envelope -> Judge / promotion gate -> Durable.
- The quota validator additionally requires each observation's verified status to be a supervisor-confirmed success
  with a result digest matching the workload's expected outcome. Only observations from the new execution protocol
  are eligible; the old `CanaryReport` path cannot produce one.
- Early safety reverts on a failed or slow request remain in the supervisor.
- A failed resource read is not proof that memory is within budget: a memory-budget read error reverts, it never
  passes.
- The safety envelope stays in the sequence, but its reference-backend evaluation is recorded as such. The
  qualification report must state plainly that production safety evaluation is not yet independently established.
  Replacing or qualifying that evaluator is a separate follow-on cut, not part of M2.

### Narrow contract freeze

- This file pins the four commits above.
- Golden tests, written before implementation, fix: (1) canonical canary-observation encoding and digest for the
  new versioned record, (2) existing signed evaluation receipt bytes, digest and verification, (3) existing ledger
  record encoding, hash and validation. Historical formats are untouched; new records carry their own version.

## Implementation sequence and ownership

1. **Contract foundation** (orchestrator, before any worker starts): adapter manifest format, wire protocol,
   observation schema and canonical encoding, durable log format, sealed-log hand-off interface to the quota
   validator, golden tests.
2. **M1 Measurement** (worker A): stage instrumentation, sample log, compatibility filtering, cold start,
   deterministic ranking, explanation marks unavailable values via the existing `MissingDoc` reason field.
3. **Harden the supervisor** (worker B, first half): strict readiness, generation binding, per-connection session
   authentication, no `active.sock` switch on Ready, memory-read failure reverts.
4. **M2 Execution** (worker B, second half): fixture crate implementing the adapter, supervisor-driven timed
   requests, independent result checking, replay protection, observation storage and sealing.
5. **M2 Admission** (worker C, the only worker that edits `src/daemon.rs`): build-artifact identity chain, wire
   `spawn_worker` and the request loop into `run_cycle`, remove premature durability, ledger commitment, quota
   integration with verified-success checks, canary applicability policy, rewrite self-report tests.
6. **Qualification**: adversarial CI plus one real DGX Spark run against the fixture crate, with the evidence
   package attached to the pull request and remaining production limitations stated in the report.

Workers run on Sonnet. Daemon changes land serially: A, then C.

## Qualification fixture

A dedicated Rust fixture crate inside this repository implementing the adapter protocol. It must be able to:
answer correctly, answer wrongly, fabricate self-reported success, send duplicate responses, replay after restart,
time out, return a wrong digest, and attempt premature promotion. Defaults for the fixture run: 10 supervisor-issued
requests, 2-second deadline each, both configurable. The real run must include at least one failing request.

A passing fixture run qualifies the canary execution pipeline. It does not qualify RSI's ability to improve
itself, and it does not qualify the safety envelope as a production evaluator. Both are later targets, with
spark-rsi as the first real adapter.

## Evidence package for the qualification pull request

Pinned workload manifest and digest, complete sealed observation log and its digest, matching ledger commitment,
candidate artifact identity, quota decision, safety-envelope and promotion decisions, the CI run showing the
exact revision and tests executed.

## Acceptance

- M1: different valid sample sets change the ranking deterministically; removing samples yields the cold-start
  structural ranking with unavailable markers, never the old constants; explanation output distinguishes measured
  from unavailable.
- M2: an authorized fixture with enough genuine supervisor-driven observations passes the quota and reaches the
  later gates. Zero observations, self-reports only, duplicates, replays, wrong outputs, mismatched candidate
  digests, corrupted logs, timeouts and unauthenticated connections cannot qualify. Fail-closed behaviour is never
  weakened.

## Delivery status (2026-10-12)

All six steps are implemented on the integration branch `feat/evidence-driven-rsi-cut`
(pull request #44, stacked on the plan pull request #38):

| Step | Delivery | Ticket |
|---|---|---|
| 1 Contract foundation | `src/canary/`, `docs/CANARY-CONTRACT.md`, golden tests (b13ea46) | #39 |
| 2 M1 Measurement | `src/measure/`, measured graph, exploratory hypotheses (PR #45) | #40 |
| 3 and 4 Supervisor hardening, M2 execution | `src/supervisor/canary_exec.rs`, `fixtures/canary-target` (PR #46) | #41 |
| 5 M2 Admission | identity chain, executor and quota wired into `run_cycle` (PR #47) | #42 |
| 6 Qualification | `examples/canary_qualification.rs`, `evidence/rsi-cut-2026-10-12/REPORT.md` | #43 |

The qualification report states what the fixture run qualifies and the remaining production
limitations. The one that matters most: the promotion gate refuses every candidate until the
separate judge is wired in (#35), so nothing becomes durable in this cut. That is fail closed by
design.
