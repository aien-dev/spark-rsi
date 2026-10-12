# Canary contract: supervisor-driven observations

Status: contract foundation (step 1 of docs/plans/2026-10-12-evidence-driven-rsi-cut.md).
Code: `src/canary/` and the `ExecuteRequest` / `ExecuteResult` pair in `src/supervisor/ipc.rs`.
Vocabulary: CONTEXT.md.

The one rule above everything: no candidate-controlled statement can independently establish
that a canary passed. Every accepted observation is tied to the exact executable that was built,
checked by the supervisor, and admitted through one authoritative promotion path.

## Digests

Every digest is lowercase hex SHA-256. Structured digests are domain separated: the domain string
and then each field are written length-prefixed (u64 little endian, then the bytes), the same
scheme as the version 2 evaluation receipt. Canonical JSON is one object with keys in byte order
at every level, no insignificant whitespace, serde_json string escaping, integers only.

| Digest | Domain | Fields |
|---|---|---|
| request | `spark-rsi/canary-request/v1` | workload id, request id, input, expected output, deadline ms (u64 LE), nondeterminism |
| workload | `spark-rsi/canary-workload/v1` | canonical bytes of the workload manifest |
| observation id | `spark-rsi/canary-observation-id/v2` | generation id, request id, request digest |
| observation | `spark-rsi/canary-observation/v2` | canonical bytes of the observation record |
| candidate identity | `spark-rsi/candidate-identity/v1` | patch digest, tree digest, executable digest, generation id |
| observation log | `spark-rsi/canary-observation-log/v1` | every byte of the log before the seal line |
| result | none | SHA-256 of the exact result bytes received |
| adapter manifest | none | SHA-256 of the exact manifest file bytes |

## Adapter manifest: `canary-adapter.toml`

Shipped at the root of the target repository. A target without one is not eligible for canary and
fails closed. It names how the built artifact is exercised; it never names a passing criterion.

```toml
manifest_version = 1
protocol_version = 1
executable = "release/rsi-canary-fixture"   # relative to the build output root, never climbing
args = ["--adapter"]
workload_id = "fixture-v1"                  # must equal the pinned workload's id
response_format = "utf8-exact"
```

## Workload manifest (JSON, under the RSI state directory)

Operator-owned. Its digest is pinned before the candidate starts and written on every observation.
`CanaryWorkloadManifest::load_pinned` refuses a file whose digest differs from the pin.

```json
{
  "workload_version": 1,
  "workload_id": "fixture-v1",
  "protocol_version": 1,
  "requests": [
    {"request_id": "req-001", "input": "ping", "expected_output": "pong",
     "deadline_ms": 2000, "nondeterminism": "exact"}
  ]
}
```

Version 1 permits only `exact` nondeterminism: the result bytes must equal the expected output.

## Wire protocol (version 1)

JSON lines over the generation's Unix socket, the existing `IpcConnection` framing.

1. The supervisor binds the generation socket `<rsi_root>/workers/<generation_id>.sock` before
   it spawns the worker, and passes `--socket <path>` to the declared executable.
2. The worker connects and sends `Ready { generation_id, pid, auth_token, protocol_version: 1 }`.
3. The supervisor sends `AuthChallenge { nonce }`; the worker answers
   `AuthResponse { response: HMAC-SHA256(secret, "<generation_id>:<nonce>") }`.
4. On success the connection is `Authenticated(generation_id, pid, protocol_version)` and the
   supervisor replies `Ping`. Readiness means exactly this, completed within the readiness
   deadline. A bare connection, silence, an older `Ready` without a protocol version, or an
   unknown reply is not ready.
5. For each request in the pinned workload, in order, the supervisor sends
   `ExecuteRequest { protocol_version, generation_id, request_id, request_digest,
   workload_digest, input, deadline_ms }`, starts its own clock, and waits up to `deadline_ms`
   for `ExecuteResult { protocol_version, generation_id, request_id, output, worker_latency_us }`.
6. The supervisor hashes `output`, compares it with the expected output, and records one
   observation per issued request. `worker_latency_us` and every `CanaryReport` are
   diagnostics; they never become observations.

Worker environment: the supervisor launches the worker with a cleared environment plus `PATH`,
`HOME`, `LANG`, `LC_ALL`, `TMPDIR`, `RUST_BACKTRACE`, every `RSI_CANARY_*` variable of the
daemon, and `SUPERVISOR_SECRET` set to a fresh secret minted for that run only. The daemon's
service credentials and the operator's supervisor secret never reach the candidate. The worker
is not jailed in this cut; that is a stated limitation, not a property.

Rejections (no observation is created, the event is logged as a rejection, no rollback):
a message on an unauthenticated connection, a message naming another generation, an
`ExecuteResult` for a request that was not issued or was already answered. A result for the
issued request with the wrong protocol version or generation is an `InvalidResponse`
observation. A missing result at the deadline is a `Timeout` observation. The connection closing
first is a `ConnectionClosed` observation. Every non-success observation is an early safety
revert in the supervisor and makes the generation unpromotable.

## Observation record (version 2)

```json
{"record_version":2,"observation_id":"<hex>","generation_id":"gen-...","request_id":"req-001",
 "request_digest":"<hex>","workload_digest":"<hex>","candidate_executable_digest":"<hex>",
 "result_digest":"<hex or null>","elapsed_us":1234,"observed_at_ms":1700000000000,
 "status":"verified_success","provenance":"measured"}
```

`status` is one of `verified_success`, `wrong_result`, `timeout`, `invalid_response`,
`connection_closed`. `provenance` is `measured` or `synthetic`; synthetic never counts.

## Observation log

`<rsi_root>/canary/observations/<generation_id>.jsonl`, one canonical record per line, each
`{"kind": ..., "record": {...}}` with kinds `header`, `observation`, `rejection`, `seal`. The
header binds the generation id, workload digest and candidate executable digest; every
observation must carry the same three. Each append is synced before it is acknowledged. The
store refuses a known observation id unless the record is byte-identical (idempotent retry); a
different record under a known id is a conflict. A partial trailing record is dropped on reopen.
The seal commits the observation count, the qualifying count and the digest of every byte before
it. Nothing may follow the seal. Only a sealed, verified log (`SealedObservationLog`) can be
handed to the quota validator.

## Candidate identity chain

`CandidateIdentity { patch_digest, tree_digest, executable_digest, generation_id }`. The
supervisor re-hashes the executable right before launching (`verify_executable`) and refuses
anything else. The quota validator compares the executable digest, never the patch digest.

## Hand-off to the quota validator

`canary::admit_sealed_quota(sealed, identity, workload, target)` is the single authority on
evidence sufficiency. It refuses: a target of zero; a log for another generation, executable or
workload; zero observations; any synthetic observation; any non-success observation; a request
not in the workload; a request digest that does not match the workload; a result digest that does
not equal the expected outcome; an elapsed time over the request deadline; and fewer unique
qualifying observations than the target. Version 1 observations
(`crate::canary_observation`) are history: the version 2 path never reads them.

Sequence in the engine (plan, M2 Admission): Collect -> Seal -> Verify -> Quota admission ->
Safety envelope -> Judge / promotion gate -> Durable. The sealed log digest is committed to the
RSI ledger before admission. The safety envelope's reference-backend evaluation is recorded as
such; it does not establish production safety.

## What this foundation does not do

It defines and freezes formats. It does not launch workers, drive requests, enforce per-connection
authentication, instrument stages, or wire anything into `run_cycle`. Those are steps 2 to 5 of
the plan and must use these definitions unchanged.
